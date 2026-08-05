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
use graphus_txn::View;

use crate::ast::{Expr, ExprKind, Label, RelDirection, RelType, SortDirection, VarLengthRange};
use crate::binding::BoundParameters;
use crate::eval::{EvalError, eval, eval_value};
use crate::function_registry::{self, FunctionRegistry};
use crate::graph_access::{
    CompositeSeekHits, ExpandDirection, GraphAccess, IndexSeekHits, KeyValues, NodeId, RelId,
    ScannedRel,
};
use crate::loadcsv::LoadCsvState;
use crate::logical::{CreatePart, ProjectionColumn, RemoveOp, SetOp, SortKey, Var, YieldColumn};
use crate::ordering::cmp_values;
use crate::physical::{PhysicalOp, PhysicalPlan, RangeBound, root_is_write};
use crate::procedure_registry::{self, ProcedureFailure, ProcedureRegistry};
use crate::runtime::{
    NodeRef, PathStep, PathValue, RelRef, Row, RowValue, cached_property_key, cmp_row_values,
    hash_row_value, row_values_equivalent,
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
    ///
    /// **Forced to `1` for a `PROFILE`d statement** (`rmp` task #752): the morsel workers read the store
    /// through a seam the profiling decorator does not sit on, so a parallel profiled run would silently
    /// *under-count* its `dbHits`. Running the profiled statement serially keeps every storage access
    /// attributable — an under-counted profile is a lie, and a lie is worse than a slower diagnostic.
    morsel_threads: usize,
    /// The `PROFILE` counter sink (`rmp` task #752), or `None` — the overwhelmingly common case — for an
    /// ordinary statement, which then builds no profiling shim and pays nothing.
    profile: Option<Arc<crate::profile::ProfileRecorder>>,
}

impl Ctx<'_> {
    /// Runs `f` with the graph seam switched to `view`, restoring the previous view **unconditionally**
    /// on the way out (`04 §5.1.4`, `rmp` #972).
    ///
    /// This is the whole of the per-operator polarity table: an operator wraps its **own** graph
    /// accesses in the view its openCypher semantics owe, and nothing else. It must never wrap a
    /// child's `next()` — that would impose this operator's polarity on the entire subtree, which is
    /// exactly the bug the table exists to avoid (a `Filter` is `Old`, but the `Create` beneath it is
    /// `New`).
    ///
    /// Nesting is safe precisely because of that discipline plus the restore: a `Filter` reading under
    /// `Old` may evaluate an `EXISTS { … }` whose inner `Produce` reads under `New` and hands `Old`
    /// back before the predicate finishes.
    ///
    /// The restore runs on the **error** path too, because `f` returns its `Result` rather than using
    /// `?` inside this function — a view left switched after an early return would silently re-polarise
    /// every subsequent read of the statement.
    fn with_view<R>(&mut self, view: View, f: impl FnOnce(&mut Self) -> R) -> R {
        let previous = self.graph.set_read_view(view);
        let out = f(self);
        self.graph.set_read_view(previous);
        out
    }

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

    /// **`PROFILE` instrumentation** (`rmp` task #752): a transparent shim wrapping the operator built
    /// for plan node `id`.
    ///
    /// It exists **only** when the statement carries the `PROFILE` prefix — an ordinary statement builds
    /// no `Profile` node at all, so the normal execution path keeps exactly the operator tree (and the
    /// exactly the per-row cost) it had before. On each pull it makes `id` the recorder's *current*
    /// operator (so every storage access the wrapped operator itself makes is attributed to it, while its
    /// children's accesses are attributed to them by their own shims), restores the previous one, and
    /// counts the row if one was produced.
    Profile {
        input: Box<Operator>,
        id: crate::profile::OpId,
        rec: Arc<crate::profile::ProfileRecorder>,
    },

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
        /// A predicate on the far endpoint, decided as each candidate end node is reached rather than
        /// by a `Filter` above the operator (`rmp` task #870, part b). The planner sets it only for a
        /// predicate that reads nothing but `to` and is pure per row, so it is evaluated against a
        /// one-column probe row binding just that endpoint.
        to_predicate: Option<Expr>,
        /// `true` for the **pruning** variable-length walk (`rmp` task #870, part a): emit each
        /// reachable end node once instead of one row per trail. The planner sets it only when the
        /// plan above provably consumes nothing but the distinct end node.
        pruning: bool,
        pending: VecDeque<Row>,
    },

    /// `AllRelationshipsScan` (`rmp` task #867): stream the enumerated relationships, binding each to
    /// the relationship variable plus both endpoints per the pattern arrow.
    ///
    /// The enumeration itself is eager (one `Vec<ScannedRel>` — 24 bytes per relationship, produced by a
    /// single sequential store scan), but the **rows are built lazily**, one relationship at a time.
    /// Materialising them all up front — the obvious `Operator::Buffered { rows }` — allocates a whole
    /// `Row` per result row before the first is consumed, and measured **slower than the
    /// `AllNodesScan` + `ExpandAll` plan it replaces** on a 20k-node / 200k-relationship store
    /// (151 ms vs 84 ms), because that plan streams: it buffers only the node rows and expands one
    /// anchor at a time. `pending` holds the at-most-two rows one relationship contributes (an
    /// undirected pattern binds both orientations).
    RelScan {
        /// The enumerated relationships, in seam order.
        scanned: Vec<ScannedRel>,
        /// How many of `scanned` have been emitted.
        cursor: usize,
        /// The `{from, relationship, to}` row shape, derived once at construction.
        shape: RelRowTemplate,
        /// The pattern arrow.
        direction: RelDirection,
        /// The rows the current relationship still owes (undirected binds two orientations).
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

    /// `QuantifiedPath` (QPP, GPM / Neo4j 5.9+): for each input row (anchor `from` bound), run a
    /// depth-first **trail** walk that repeats the interior single hop between `min` and `max` times,
    /// applying `interior_predicate` per iteration (with the iteration's *scalar*
    /// `group_start`/`group_end`/`relationship` bindings). Each accepted `k`-iteration walk emits one
    /// row binding the three interior group variables to the ordered lists of iteration start nodes /
    /// end nodes / relationships, and `to` to the final node. When `into`, only walks ending at the
    /// already-bound `to` are kept. `pending` holds the not-yet-emitted rows of the current input row.
    QuantifiedPath {
        input: Box<Operator>,
        from: Var,
        to: Var,
        group_start: Var,
        group_end: Var,
        relationship: Var,
        direction: RelDirection,
        /// The first interior relationship's type names, resolved to owned `String`s once at
        /// construction (hoisted out of the per-row expand hot loop, as for [`Expand`](Self::Expand)).
        type_names: Vec<String>,
        /// Interior hops beyond the first relationship (empty for the single-hop fast path), each with
        /// its own resolved type names, direction, and group variables.
        extra_hops: Vec<QppRuntimeStep>,
        min: u64,
        max: Option<u64>,
        prior_rels: Vec<Var>,
        interior_predicate: Option<Expr>,
        into: bool,
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

    /// `OptionalExpand` (`rmp` task #882): the fused one-hop `OPTIONAL MATCH` — expand from each
    /// driving row's bound anchor, apply the predicates that sat *inside* the `OPTIONAL MATCH`, and
    /// emit the driving row once with `null_variables` bound to `NULL` when — and only when — nothing
    /// survives.
    ///
    /// The traversal is [`Expand`](Self::Expand)'s, verbatim: the same two helpers
    /// (`bound_rel_expand` for a relationship variable that arrives already bound, else
    /// `expand_into_pending`), on the driving row itself. The driving row is what the replaced
    /// plan's `Argument` leaf reconstructed and what `merge_rows` folded every produced row back
    /// into, so the match path is row-for-row identical to it — including column order.
    ///
    /// **Streaming, one candidate at a time** — `pending` holds the current driving row's not-yet
    /// examined candidates and `matched` records whether any of them has already survived. A
    /// candidate is emitted the instant it passes, exactly as the `Filter` chain it replaces did, so
    /// a predicate that raises an error raises it on the same candidate at the same point rather than
    /// after the whole neighbourhood has been evaluated.
    OptionalExpand {
        input: Box<Operator>,
        from: Var,
        relationship: Var,
        to: Var,
        direction: RelDirection,
        /// The relationship-type names resolved once at construction (`rmp` #371), as for
        /// [`Expand`](Self::Expand).
        type_names: Vec<String>,
        types: Vec<RelType>,
        into: bool,
        /// The inside-`OPTIONAL MATCH` predicates, innermost-`Filter` first — evaluated in order, and
        /// each only on the candidates the earlier ones admitted.
        predicates: Vec<Expr>,
        null_variables: Vec<Var>,
        /// The driving row whose candidates `pending` holds, until its no-match decision is taken.
        base: Option<Row>,
        /// Whether any candidate of `base` has already survived (so no null row is owed).
        matched: bool,
        pending: VecDeque<Row>,
    },

    /// `NestedLoopJoin`: for each left row, run the right branch with the left bindings available.
    NestedLoop {
        left: Box<Operator>,
        right_template: Box<PhysicalOp>,
        /// The plan id of the right branch's root, for a `PROFILE`d statement (`rmp` #752); `None`
        /// otherwise. The template is re-numbered from it before each per-row rebuild so every rebuild
        /// accumulates into the plan operator's own counters.
        right_id: Option<crate::profile::OpId>,
        current_left: Option<Row>,
        current_right: Option<Box<Operator>>,
    },

    /// `SemiApply` / `AntiSemiApply` (`rmp` task #869): for each driving row, run the correlated inner
    /// branch **until its first row** and keep or drop the driving row on that verdict.
    ///
    /// Structurally this is [`NestedLoop`](Self::NestedLoop) with two differences, and both are the
    /// point of the operator: the inner branch is stopped after ONE `next()` instead of being drained,
    /// and its row is discarded instead of being merged — the driving row passes through unchanged, so
    /// no subquery-local binding ever reaches the outer scope.
    SemiApply {
        input: Box<Operator>,
        /// The inner branch's plan, rebuilt per driving row seeded with that row (correlation via its
        /// [`Argument`](PhysicalOp::Argument) leaf), exactly as `NestedLoop` rebuilds its right side.
        inner_template: Box<PhysicalOp>,
        /// The plan id of the inner branch's root, for a `PROFILE`d statement (`rmp` #752); `None`
        /// otherwise. Without this the per-row rebuilds would be unattributable and the subquery's
        /// `dbHits` would vanish from the report — which would make `EXPLAIN` show an access path whose
        /// cost `PROFILE` never accounted for (`rmp` #755 is the live precedent for that being a lie).
        inner_id: Option<crate::profile::OpId>,
        /// `true` for `AntiSemiApply`: keep the driving row iff the inner branch yields NOTHING.
        anti: bool,
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
        /// The plan id of the body's root, for a `PROFILE`d statement (`rmp` #752); `None` otherwise.
        /// See [`Operator::NestedLoop::right_id`].
        body_id: Option<crate::profile::OpId>,
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
        /// result row, output kind)`. The [`ProcOutputKind`] marks a
        /// [`ValueClass::Node`](crate::procedure_registry::ValueClass::Node) (`rmp` task #72) or
        /// [`ValueClass::Relationship`](crate::procedure_registry::ValueClass::Relationship)
        /// (`rmp` task #663) output, whose yielded id [`Value`] is bound as a structural
        /// [`RowValue::Node`] / [`RowValue::Rel`] (so result egress materializes it, composing MVCC +
        /// RBAC) instead of a plain [`RowValue::Value`].
        bindings: Vec<(String, usize, ProcOutputKind)>,
        /// `true` when the signature declares no outputs (the void pass-through case).
        void: bool,
        /// The driving row plus its pending procedure result rows.
        current: Option<(Row, VecDeque<Vec<Value>>)>,
    },
}

/// How a `CALL … YIELD` output column materializes into a result-row cell: a plain value, a structural
/// node ([`ValueClass::Node`](crate::procedure_registry::ValueClass::Node), `rmp` #72), or a structural
/// relationship ([`ValueClass::Relationship`](crate::procedure_registry::ValueClass::Relationship),
/// `rmp` #663). Resolved once at build time from the output field's declared class.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcOutputKind {
    /// A plain property value — bound as [`RowValue::Value`].
    Plain,
    /// A structural node — the yielded id is bound as [`RowValue::Node`].
    Node,
    /// A structural relationship — the yielded id is bound as [`RowValue::Rel`].
    Rel,
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

            // `PROFILE` shim (`rmp` #752): attribute this operator's own storage work to `id` while it
            // runs (a child re-enters with its own id and restores this one), and count the row it
            // emitted. Present only for a profiled statement.
            Operator::Profile { input, id, rec } => {
                let previous = rec.enter(*id);
                let produced = input.next(ctx);
                rec.leave(previous);
                if matches!(produced, Ok(Some(_))) {
                    rec.record_row(*id);
                }
                produced
            }

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
                    // OLD (`rmp` #972). Memgraph: *"newly set values should not affect filtering of
                    // old nodes and edges"* (`src/query/plan/operator.cpp`, `FilterCursor::Pull`). The
                    // predicate is the `WHERE` of a `MATCH`, and it must judge the rows the statement
                    // matched, not the rows the statement has since rewritten.
                    //
                    // Only the predicate is wrapped — never `input.next(ctx)` above it, which is a
                    // child's work under the child's own polarity.
                    let t =
                        ctx.with_view(View::Old, |ctx| predicate_truth(predicate, &row, ctx))?;
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
                    // NEW (`rmp` #972), and this one is **measured**, not reasoned.
                    //
                    // The intuition says `Old`: the path is made of the relationships an expansion
                    // produced, so it should be read the way they were. That is wrong, and the openCypher
                    // TCK says so — `clauses/merge/Merge5.feature` [10] "Merge should bind a path":
                    //
                    //     MERGE (a {num: 1}) MERGE (b {num: 2}) MERGE p = (a)-[:R]->(b) RETURN p
                    //
                    // binds a path over a relationship the SAME statement just created. Under `Old`
                    // `rel_data` cannot see it, the orientation lookup falls back to its default, and the
                    // path comes back pointing at the wrong endpoint. (Measured: the scenario is the one
                    // TCK regression the `Old` reading produced, 3913/3914.)
                    //
                    // The reason is that this operator does not *match* anything. Every id it uses is
                    // already bound in the row; it only materialises the path value from them — which is
                    // what `Produce` does, and `Produce` is `New`. Memgraph makes the same distinction by
                    // construction: its `ConstructNamedPath` reads no storage at all, taking orientation
                    // from the frame.
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
                // OLD (`rmp` #972): `UNWIND` is a read clause, and its list expression may read the
                // graph (`UNWIND [x IN nodes(p) | x.v] AS v`). It owes the same polarity as the
                // `WHERE` beside it — the state as the statement found it.
                let listv = ctx.with_view(View::Old, |ctx| {
                    eval(
                        list,
                        &base,
                        ctx.params,
                        ctx.graph,
                        ctx.functions,
                        &ctx.clock,
                    )
                })?;
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

            Operator::RelScan {
                scanned,
                cursor,
                shape,
                direction,
                pending,
            } => loop {
                if let Some(row) = pending.pop_front() {
                    return Ok(Some(row));
                }
                let Some(next) = scanned.get(*cursor) else {
                    return Ok(None);
                };
                *cursor += 1;
                push_rel_rows(pending, shape, *direction, next.rel, next.start, next.end);
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
                to_predicate,
                pruning,
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
                // OLD for every traversal below (`rmp` #972): an expansion must not follow the
                // relationships its own statement is creating. Memgraph constructs `Expand` /
                // `ExpandVariable` cursors under `storage::View::OLD` for the same reason.
                //
                // The wrap covers only this driving row's expansion — `input.next(ctx)` above already
                // ran, under the child's polarity.
                if base.get(&relationship.name).is_some() {
                    ctx.with_view(View::Old, |ctx| {
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
                        )
                    })?;
                    // `rmp` #870b: this traversal does not go through the walk that applies the
                    // far-endpoint predicate, so it is applied here instead. The planner declines to
                    // set `to_predicate` for a shape that can reach this branch, so this is a belt
                    // rather than a load-bearing path — but a predicate silently skipped would be a
                    // wrong answer, and that is not something to leave to a plan-time gate alone.
                    ctx.with_view(View::Old, |ctx| {
                        retain_rows_satisfying(pending, to_predicate.as_ref(), ctx)
                    })?;
                } else if let Some(range) = range {
                    ctx.with_view(View::Old, |ctx| {
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
                            to_predicate.as_ref(),
                            *pruning && !*into,
                            ctx,
                            pending,
                        )
                    })?;
                } else {
                    ctx.with_view(View::Old, |ctx| {
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
                        )
                    })?;
                    // As above: a fixed-length hop never carries a `to_predicate` today, and if one
                    // ever arrives here it is honoured rather than dropped.
                    ctx.with_view(View::Old, |ctx| {
                        retain_rows_satisfying(pending, to_predicate.as_ref(), ctx)
                    })?;
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
                // OLD (`rmp` #972): a shortest-path search is an expansion, and owes the expansion
                // polarity — it must not route through edges its own statement is creating.
                ctx.with_view(View::Old, |ctx| {
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
                    )
                })?;
            },

            Operator::QuantifiedPath {
                input,
                from,
                to,
                group_start,
                group_end,
                relationship,
                direction,
                type_names,
                extra_hops,
                min,
                max,
                prior_rels,
                interior_predicate,
                into,
                pending,
            } => loop {
                if let Some(row) = pending.pop_front() {
                    return Ok(Some(row));
                }
                let Some(base) = input.next(ctx)? else {
                    return Ok(None);
                };
                // OLD (`rmp` #972): a quantified path pattern is a variable-length expansion with an
                // interior predicate — both halves owe the expansion / filter polarity.
                ctx.with_view(View::Old, |ctx| {
                    quantified_path_into_pending(
                        &base,
                        from,
                        to,
                        group_start,
                        group_end,
                        relationship,
                        *direction,
                        type_names,
                        extra_hops,
                        *min,
                        *max,
                        prior_rels,
                        interior_predicate.as_ref(),
                        *into,
                        ctx,
                        pending,
                    )
                })?;
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

            // `rmp` task #882. Three phases per driving row, in this order: drain its candidates
            // (emitting the first that survives every predicate), then — only once the last candidate
            // has been examined — take the no-match decision, then advance.
            Operator::OptionalExpand {
                input,
                from,
                relationship,
                to,
                direction,
                type_names,
                types,
                into,
                predicates,
                null_variables,
                base,
                matched,
                pending,
            } => loop {
                // Phase 1 — candidates of the current driving row, one at a time. Each predicate is
                // evaluated only on the candidates the ones before it admitted, and the row is
                // returned the moment it passes them all: the evaluation order, the cancellation
                // checks and therefore the point at which an evaluation error surfaces are the
                // `Filter` chain's, unchanged.
                while let Some(candidate) = pending.pop_front() {
                    let mut survives = true;
                    for predicate in predicates.iter() {
                        ctx.check_cancelled()?;
                        // OLD (`rmp` #972): these ARE the `Filter` operators the fusion absorbed, so
                        // they owe the `Filter` polarity — the fusion must not change the answer.
                        let t = ctx.with_view(View::Old, |ctx| {
                            predicate_truth(predicate, &candidate, ctx)
                        })?;
                        if !t.is_true() {
                            survives = false;
                            break;
                        }
                    }
                    if survives {
                        *matched = true;
                        return Ok(Some(candidate));
                    }
                }
                // Phase 2 — the left-outer guarantee. The driving row survives with nulls when, and
                // only when, nothing above survived. `null_variables` is the lowerer's own set,
                // carried through the planner untouched, and setting it on the driving row is exactly
                // what `Optional`'s all-null row folded through `merge_rows` produced — the driving
                // row's own columns, with these overwritten. The row is MOVED out of `base`, so the
                // no-match path costs no clone at all (the replaced plan paid one per driving row).
                if let Some(driving) = base.take() {
                    if !*matched {
                        let mut row = driving;
                        for v in null_variables.iter() {
                            row.set(v.name.clone(), RowValue::NULL);
                        }
                        return Ok(Some(row));
                    }
                }
                // Phase 3 — advance. `pending` and `matched` are reset together with `base`, so a
                // driving row can never inherit the previous one's verdict.
                let Some(next_base) = input.next(ctx)? else {
                    return Ok(None);
                };
                *matched = false;
                // OLD (`rmp` #972): the same expansion polarity the un-fused `Expand` owes.
                if next_base.get(&relationship.name).is_some() {
                    ctx.with_view(View::Old, |ctx| {
                        bound_rel_expand(
                            &next_base,
                            from,
                            relationship,
                            to,
                            *direction,
                            types,
                            *into,
                            false,
                            &[],
                            ctx,
                            pending,
                        )
                    })?;
                } else {
                    ctx.with_view(View::Old, |ctx| {
                        expand_into_pending(
                            &next_base,
                            from,
                            relationship,
                            to,
                            *direction,
                            type_names,
                            *into,
                            &[],
                            ctx,
                            pending,
                        )
                    })?;
                }
                *base = Some(next_base);
            },

            Operator::NestedLoop {
                left,
                right_template,
                right_id,
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
                // `PROFILE` (`rmp` #752): re-number the template from the plan id of the branch it was
                // cloned from, so the rebuilt operators accumulate into the plan's own counters instead
                // of being unattributable.
                if let (Some(rec), Some(id)) = (ctx.profile.as_ref(), *right_id) {
                    rec.rebind_template(right_template, id);
                }
                // Re-instantiate the right branch seeded with the left row's bindings (correlation
                // via the Argument leaf), then loop to drain it.
                let right_op = build_operator_with_arg(right_template, &left_row, ctx)?;
                *current_left = Some(left_row);
                *current_right = Some(Box::new(right_op));
            },

            // `rmp` task #869 — the semi-join, and the short-circuit that is its reason to exist.
            //
            // Per driving row: rebuild the inner branch seeded with that row, ask it for ONE row, drop
            // the branch. `next()` is called exactly once, so an inner expand stops at its first
            // neighbour and an inner seek at its first hit — the driving row's verdict is settled and
            // every further inner row would be work whose answer is already known. That bound is what
            // a `PROFILE` measures: the inner operator's `dbHits` are bounded by one traversal per
            // driving row that matches, which is the acceptance criterion this operator is judged on.
            //
            // The driving row is MOVED into the result on the keep path — no clone, where the `Filter`
            // this replaced evaluated a whole correlated sub-plan through the expression evaluator and
            // the `NestedLoopJoin` shape would have `merge_rows`-cloned every produced row back.
            Operator::SemiApply {
                input,
                inner_template,
                inner_id,
                anti,
            } => loop {
                let Some(driving) = input.next(ctx)? else {
                    return Ok(None);
                };
                // `PROFILE` (`rmp` #752): re-number the template from the plan id of the branch it was
                // cloned from, so every per-row rebuild accumulates into the plan's own counters
                // instead of being unattributable. Identical to the `NestedLoop` arm above — and
                // load-bearing here, because the inner branch IS what the plan claims to have run.
                if let (Some(rec), Some(id)) = (ctx.profile.as_ref(), *inner_id) {
                    rec.rebind_template(inner_template, id);
                }
                let mut branch = build_operator_with_arg(inner_template, &driving, ctx)?;
                // ONE row, then the branch is dropped: the semi-join tests emptiness, nothing more.
                let matched = branch.next(ctx)?.is_some();
                if matched != *anti {
                    return Ok(Some(driving));
                }
                // Rejected: take the next driving row. Nothing of the inner branch survives the
                // iteration, so no subquery-local binding can reach the outer scope.
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
                body_id,
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
                    // `PROFILE` (`rmp` #752): re-number the body template from the plan id of the body it
                    // was cloned from, so each element's rebuild feeds the plan's own counters.
                    if let (Some(rec), Some(id)) = (ctx.profile.as_ref(), *body_id) {
                        rec.rebind_template(body_template, id);
                    }
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
                        for (variable, idx, kind) in bindings.iter() {
                            // `idx` was resolved against the signature's outputs at build time and
                            // the registry contract aligns each result row with them, so a short
                            // row is a registry bug — surface `null` rather than panic.
                            let value = out.get(*idx).cloned().unwrap_or(Value::Null);
                            // A `NODE`/`RELATIONSHIP`-classed output (`rmp` tasks #72, #663) carries the
                            // entity id as a `Value::Integer`; bind it as a structural `RowValue::Node` /
                            // `RowValue::Rel` so result egress materializes it (labels/type/properties
                            // through the same seam, composing MVCC + RBAC). A `null` id stays a null cell.
                            let cell = match (kind, &value) {
                                (ProcOutputKind::Node, Value::Integer(id)) => {
                                    RowValue::Node(NodeRef {
                                        id: NodeId(*id as u64),
                                    })
                                }
                                (ProcOutputKind::Rel, Value::Integer(id)) => {
                                    RowValue::Rel(RelRef {
                                        id: RelId(*id as u64),
                                    })
                                }
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
                // The `CALL` polarity (`rmp` #972). A **read-only** procedure is a read access path
                // like any other and runs under `Old`; a **writing** procedure is a write and runs
                // under `New`, because it must see — and be able to modify — what the statement has
                // already done.
                //
                // The classification is `is_reader_safe`, which is the registry's own "this body
                // performs no graph-store write" flag, and it defaults to `false`. That default is the
                // right way round here: an unclassified procedure is treated as a writer and keeps the
                // full read-your-own-writes view, so the failure mode of a missing classification is
                // the *previous* behaviour, never a procedure that cannot see its own work.
                let call_view = if ctx.procedures.is_reader_safe(name) {
                    View::Old
                } else {
                    View::New
                };
                let rows = ctx
                    .with_view(call_view, |ctx| {
                        ctx.procedures.invoke(name, &arg_values, &mut *ctx.graph)
                    })
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
            reject_over_deep_projection(&v)?;
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
        reject_over_deep_projection(&v)?;
        out.set(col.alias.clone(), v);
    }
    Ok(out)
}

/// Rejects a projected value that nests deeper than [`MAX_VALUE_DEPTH`](crate::value_depth::MAX_VALUE_DEPTH),
/// the runtime value-nesting-depth budget (`SEC-190`, CWE-674, rmp #589).
///
/// A `WITH`/`RETURN` projection is where a runtime value is **rebound**, and a self-referential chain
/// (`WITH [a] AS a`, `WITH collect(a) AS a`) adds one nesting level per clause with no clause-count
/// limit — so an attacker can build, from a shallow query under the message-size cap, a value nested
/// tens of thousands deep. Left unchecked it overflows the stack the first time a depth-recursive
/// consumer touches it (value collapse [`to_value`](crate::eval::to_value), the wire encoders, or the
/// derived recursive `Drop`), and a stack overflow is an **uncatchable process abort** — it would take
/// down every database and connection the server hosts.
///
/// Checking at each projection catches the chain **early** (at depth `MAX_VALUE_DEPTH + 1`, long before
/// it grows dangerous), so no bound row value ever exceeds the cap and every downstream recursive walk
/// stays comfortably inside a worker stack. The measurement is iterative (it never recurses the
/// attacker-controlled depth itself), so it is safe and `O(MAX_VALUE_DEPTH)`. Rejection is a recoverable
/// [`EvalError::ResourceLimit`] (the query fails cleanly; the connection and the server survive).
///
/// [`MAX_VALUE_DEPTH`](crate::value_depth::MAX_VALUE_DEPTH) is far above any legitimate Cypher value, so
/// conforming queries and the TCK are unaffected.
#[inline]
fn reject_over_deep_projection(v: &RowValue) -> Result<(), ExecError> {
    if crate::value_depth::rowvalue_depth_exceeds(v, crate::value_depth::MAX_VALUE_DEPTH) {
        return Err(ExecError::Eval(EvalError::ResourceLimit {
            detail: format!(
                "value nesting depth exceeds the limit of {}",
                crate::value_depth::MAX_VALUE_DEPTH
            ),
        }));
    }
    Ok(())
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

/// Bounds the total heap a **single base row's** variable-length / quantified-path expansion may
/// accumulate into `pending`, extending the shared per-value byte budget
/// ([`crate::value_size::max_value_bytes`], `rmp` #489 / #491 / `SEC-191`) to the trail-path queue
/// (`rmp` #656, the combinatorial vector — mirrors the `rmp` #550 breadth budget for decoded
/// collections).
///
/// A variable-length `*`/`+` or quantified-path walk over a **dense** (near-complete) graph
/// enumerates a super-polynomial number of trail (relationship-unique) paths, each materialised as a
/// full [`Row`] pushed into the operator's `pending` [`VecDeque`]. Left uncapped that is a
/// memory-exhaustion DoS: one crafted query grows `pending` until it OOMs the per-database engine
/// thread — every database that thread hosts dies with it. This budget charges each emitted row's
/// estimated footprint against the same configurable ceiling the value builders use, so the expansion
/// is rejected with a clean, typed [`EvalError::ResourceLimit`] the instant it would cross the budget
/// — never allocating the over-budget queue. Semantics are unchanged for any expansion that fits: the
/// openCypher trail paths a legitimate query returns are far below the 256 MiB default, and the
/// regression suite lowers the ceiling (via `BudgetOverride`) to measure the boundary cheaply.
struct PendingBudget {
    /// Estimated bytes charged so far across this base row's expansion.
    charged: usize,
    /// The effective ceiling, snapshot once at construction (a single `Relaxed` load; the override is
    /// a per-scope test/config knob, never changed mid-expansion).
    cap: usize,
}

impl PendingBudget {
    fn new() -> Self {
        Self {
            charged: 0,
            cap: crate::value_size::max_value_bytes(),
        }
    }

    /// Charges `row`'s estimated in-memory footprint against the budget, returning a typed
    /// [`EvalError::ResourceLimit`] once the running total for this expansion would exceed the ceiling.
    /// The estimate short-circuits per value at the ceiling, so a pathological row is detected in
    /// `O(budget)` work; the running total is checked *before* the row is enqueued, so the over-budget
    /// row is never retained.
    fn charge(&mut self, row: &Row) -> Result<(), ExecError> {
        let bytes = row.values().iter().fold(0usize, |acc, v| {
            acc.saturating_add(crate::value_size::estimate_rowvalue_bytes(v))
        });
        self.charged = self.charged.saturating_add(bytes);
        if self.charged > self.cap {
            return Err(ExecError::Eval(EvalError::ResourceLimit {
                detail: format!(
                    "variable-length / quantified-path expansion exceeds the per-query materialisation budget of {} bytes",
                    self.cap
                ),
            }));
        }
        Ok(())
    }
}

/// One frame of the iterative variable-length trail walk (`rmp` #656): a node to visit at a given
/// depth, its resolved incident relationships, and the cursor / self-loop-dedup state the walk pops
/// and repushes as it descends and backtracks. Replacing the former recursion with a heap-allocated
/// stack of these frames moves the walk's depth off the (finite) native thread stack, so an
/// arbitrarily long chain uses `O(1)` native stack and can never overflow it.
struct VarExpandFrame {
    /// Hop count from the anchor to this node (the trail length so far).
    depth: u64,
    /// The node this frame is visiting.
    current: NodeId,
    /// `None` until the frame is first visited (emit + resolve incidents); `Some` once its incident
    /// relationships have been fetched.
    incidents: Option<Vec<crate::graph_access::Incident>>,
    /// Cursor into `incidents` for the next candidate relationship.
    idx: usize,
    /// Self-loop dedup: a relationship reported once per side is considered at most once here (the
    /// per-node set the recursion allocated fresh per call).
    seen_rel: rustc_hash::FxHashSet<RelId>,
    /// Whether this frame currently holds a `trail` entry pushed for an in-progress child descent (to
    /// be popped when the frame resurfaces after that child's subtree completes).
    pushed: bool,
}

impl VarExpandFrame {
    /// A fresh frame entering `current` at `depth` (not yet visited: `incidents` unresolved).
    fn enter(depth: u64, current: NodeId) -> Self {
        Self {
            depth,
            current,
            incidents: None,
            idx: 0,
            seen_rel: rustc_hash::FxHashSet::default(),
            pushed: false,
        }
    }
}

/// Expands one base row's **variable-length** pattern (`-[r:T*m..n]->`) into `pending`: a
/// depth-first enumeration of the trails (relationship-unique walks, openCypher uniqueness) from
/// the anchor whose hop count lies in `[min, max]`. Each produced row binds the relationship
/// variable to the **list** of traversed relationships (in order) and — for expand-all — the far
/// endpoint to `to`; for expand-into only trails ending at the already-bound `to` are kept. A
/// `min` of 0 admits the zero-length trail (the anchor itself, an empty relationship list).
///
/// Trail semantics bound the search depth by the relationship count, so an unbounded `*`
/// terminates on any graph (cycles included). The walk is **iterative** (an explicit heap stack of
/// [`VarExpandFrame`]s, `rmp` #656): a long chain recurses `O(path length)` deep, which overflowed the
/// finite worker-thread stack and aborted the whole process — the heap stack removes that failure mode
/// entirely, and a [`PendingBudget`] bounds the trail-path materialisation.
///
/// # `to_predicate` — the far-endpoint predicate (`rmp` task #870, part b)
///
/// When present, a candidate end node must satisfy it for the trail to be emitted. It is decided
/// *before* the row is built, against a one-column probe row binding only `to` — which the planner's
/// confinement gate is what makes equivalent to deciding it on the full row. It never prunes the walk:
/// a node that fails it can still lie on the path to one that passes, so the traversal is untouched
/// and only the emission is filtered.
///
/// # `pruning` — the distinct-end-node walk (`rmp` task #870, part a)
///
/// When `true` the walk emits each reachable end node **once** rather than one row per trail, and
/// declines to expand a node it has already expanded at the same depth or shallower. Two details are
/// load-bearing and easy to "simplify" away:
///
/// * **Emission is never pruned.** A node whose subtree is skipped is still *reached*, and reaching it
///   is what emits it. Gating emission on the memo would lose end nodes.
/// * **Re-expansion on a strictly shallower arrival is required.** The memo is a depth, not a visited
///   flag: a node first met deep and later met shallow must be expanded again, because the second
///   arrival carries more remaining budget. A plain visited set breaks completeness at finite `max`.
///
/// The emitted **set** is exactly the plain walk's; the **order** is not — cutting a subtree can delay
/// a node's first arrival past another's. The planner is what keeps that unobservable. No relationship
/// variable is bound either, because a pruning walk represents no single trail. The soundness argument
/// — including why the rewrite is refused for `min >= 2` — lives on
/// `crate::physical::prune_var_length_expands`.
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
    to_predicate: Option<&Expr>,
    pruning: bool,
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
    let max = range.max;

    // Iterative depth-first trail walk with an explicit heap stack (`rmp` #656): the former recursion
    // descended ~O(path length) deep, overflowing the finite worker-thread stack on a long chain — an
    // uncatchable process abort (SIGABRT) that took every tenant with it. The explicit stack keeps the
    // walk's depth on the heap, so an arbitrarily long chain uses O(1) native stack and can never
    // overflow. `trail` (the relationship stack, traversal order) is popped/pushed in lockstep with the
    // frame stack, and the `PendingBudget` bounds the trail-path materialisation.
    let mut budget = PendingBudget::new();
    let mut trail: Vec<RelId> = Vec::new();
    let mut stack: Vec<VarExpandFrame> = vec![VarExpandFrame::enter(0, anchor)];
    // `rmp` #870a, both empty (and allocation-free) unless the pruning walk is in force. `decided`
    // records the end nodes whose emission verdict is already settled — emitted, or rejected by
    // `to_predicate` — so each contributes at most one row and the predicate runs at most once per
    // node. `expanded_at` records the shallowest depth at which a node's subtree has been explored;
    // reaching it again no shallower explores nothing new.
    //
    // Both grow with the number of *reachable nodes*, which the `PendingBudget` below does not cover
    // (it bounds materialised rows). That is deliberate and is a strict improvement on what it
    // replaces: the plain walk holds one row per *trail*, which on the graphs this rewrite targets is
    // exponentially larger than one `u64` per node.
    let mut decided: rustc_hash::FxHashSet<NodeId> = rustc_hash::FxHashSet::default();
    let mut expanded_at: rustc_hash::FxHashMap<NodeId, u64> = rustc_hash::FxHashMap::default();
    // The far-endpoint predicate's probe row, hoisted out of the walk: its schema is one column and
    // never changes, so only the value is re-pointed per candidate (`end_node_satisfies`).
    let mut probe = to_predicate.map(|_| {
        let mut row = Row::empty();
        row.set(to.name.clone(), RowValue::Node(NodeRef { id: anchor }));
        row
    });

    while let Some(mut frame) = stack.pop() {
        ctx.check_cancelled()?;

        // First visit of this node: emit the trail reaching it (if within `[min, max]` and, for
        // expand-into, ending at the bound target), then resolve its incident relationships.
        if frame.incidents.is_none() {
            // A pruning walk decides each end node once; `decided` is empty otherwise, so the plain
            // walk's condition is unchanged.
            let fresh = !pruning || !decided.contains(&frame.current);
            if fresh && frame.depth >= min && (!into || Some(frame.current) == target) {
                // `rmp` #870b: the far-endpoint predicate, decided BEFORE the row is built — that is
                // the saving. Confined to `to` by the planner, so a probe row binding only `to` is the
                // same evaluation as on the full row.
                let keep = match (to_predicate, probe.as_mut()) {
                    (Some(pred), Some(probe)) => {
                        end_node_satisfies(frame.current, pred, probe, ctx)?
                    }
                    // `probe` is built exactly when `to_predicate` is `Some`, so the mixed cases
                    // cannot occur; "no predicate" is the only real alternative.
                    _ => true,
                };
                if pruning {
                    decided.insert(frame.current);
                }
                if keep {
                    let mut row = base.clone();
                    // A pruning walk represents no single trail, so it binds no relationship list.
                    // The planner only sets `pruning` when nothing above reads that variable.
                    if !pruning {
                        row.set(
                            relationship.name.clone(),
                            RowValue::list(
                                trail
                                    .iter()
                                    .map(|&id| RowValue::Rel(RelRef { id }))
                                    .collect(),
                            ),
                        );
                    }
                    if !into {
                        row.set(
                            to.name.clone(),
                            RowValue::Node(NodeRef { id: frame.current }),
                        );
                    }
                    budget.charge(&row)?;
                    pending.push_back(row);
                }
            }
            if max.is_some_and(|m| frame.depth >= m) {
                // Maximum length reached: this node is a leaf, no further expansion. Its parent's
                // trail entry (if any) is undone when the parent frame resurfaces (see `pushed`).
                continue;
            }
            // `rmp` #870a: the pruning memo. Expanding this node again at the same depth or deeper
            // reaches no node it did not already reach from here with at least as much budget, so the
            // subtree is skipped. Emission above is deliberately NOT gated on this — a node whose
            // subtree is pruned is still *reached*, and reaching it is what emits it.
            if pruning {
                match expanded_at.entry(frame.current) {
                    std::collections::hash_map::Entry::Occupied(mut seen) => {
                        if *seen.get() <= frame.depth {
                            continue;
                        }
                        seen.insert(frame.depth);
                    }
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(frame.depth);
                    }
                }
            }
            // Deduplicate self-loops reported once per side (`04 §2.4`); the trail check enforces
            // relationship uniqueness across the whole walk.
            frame.incidents = Some(ctx.graph.expand(frame.current, dir, type_names));
        }

        // Undo the trail push made when this frame last descended into a child.
        if frame.pushed {
            trail.pop();
            frame.pushed = false;
        }

        // Advance to the next admissible incident (relationship-unique across the whole pattern).
        let inc_len = frame.incidents.as_ref().map_or(0, Vec::len);
        let mut chosen = None;
        while frame.idx < inc_len {
            let inc = frame
                .incidents
                .as_ref()
                .expect("INVARIANT: incidents resolved above")[frame.idx];
            frame.idx += 1;
            if !frame.seen_rel.insert(inc.rel)
                || trail.contains(&inc.rel)
                || forbidden.contains(&inc.rel)
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
            chosen = Some(inc);
            break;
        }
        match chosen {
            Some(inc) => {
                trail.push(inc.rel);
                frame.pushed = true;
                let child = VarExpandFrame::enter(frame.depth + 1, inc.neighbour);
                // Repush this frame (cursor advanced, trail entry outstanding), then the child on top so
                // the walk descends depth-first — the identical pre-order enumeration the recursion made.
                stack.push(frame);
                stack.push(child);
            }
            None => {
                // Exhausted: drop the frame (its trail entry, if any, was already undone above).
            }
        }
    }
    Ok(())
}

/// A resolved interior hop of a **multi-relationship** quantified path pattern, ready for the trail
/// walk: its group relationship / end-node variables, traversal direction, and relationship-type
/// names resolved to owned `String`s once at construction (hoisted out of the per-row expand hot
/// loop, as for the first hop's `type_names`).
#[derive(Debug, Clone)]
struct QppRuntimeStep {
    /// The group relationship variable for this hop (per-iteration list of its relationships).
    relationship: Var,
    /// The group node variable reached after this hop (per-iteration list of its end nodes).
    end_node: Var,
    /// This hop's traversal direction.
    direction: RelDirection,
    /// This hop's relationship-type names; empty means "any type".
    type_names: Vec<String>,
}

/// One resolved interior hop, unifying the first hop (from the operator's flat fields) with the
/// [`QppRuntimeStep`]s of a multi-relationship interior into a single ordered list for the trail walk.
struct QppHopRt<'a> {
    relationship: &'a Var,
    end_node: &'a Var,
    dir: ExpandDirection,
    type_names: &'a [String],
}

/// Runs a **quantified path pattern** (QPP, GPM / Neo4j 5.9+) trail walk from the base row's anchor,
/// producing one pending row per accepted `k`-iteration walk (`min ≤ k ≤ max`).
///
/// The interior path — the first hop `(group_start)-[relationship]-(group_end)` plus every extra hop
/// `-[rN]-(nodeN)` (`extra_hops`) — is repeated as a whole per iteration by a depth-first **trail**
/// walk (no relationship traversed twice, across every hop of every iteration — extended by
/// `prior_rels` over the whole surrounding pattern). Each *completed iteration* is pruned by
/// `interior_predicate`, evaluated with that iteration's **scalar** interior bindings
/// (`group_start`/`group_end`/`relationship` and every extra hop's `end_node`/`relationship`), so an
/// accepted walk is one whose every iteration satisfies the interior node label/property constraints,
/// the interior relationships' property/type constraints, and the inner `WHERE`. Every accepted walk
/// emits a row binding each interior group variable to the ordered **per-iteration** list (each
/// iteration's start node / hop-end nodes / hop relationships) and, when not `into`, `to` to the
/// final node. When `into`, only walks ending at the already-bound `to` node are kept.
#[allow(clippy::too_many_arguments)]
fn quantified_path_into_pending(
    base: &Row,
    from: &Var,
    to: &Var,
    group_start: &Var,
    group_end: &Var,
    relationship: &Var,
    direction: RelDirection,
    type_names: &[String],
    extra_hops: &[QppRuntimeStep],
    min: u64,
    max: Option<u64>,
    prior_rels: &[Var],
    interior_predicate: Option<&Expr>,
    into: bool,
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
    // An `into` walk whose bound target is not a node (a null from an OPTIONAL) can never match.
    if into && target.is_none() {
        return Ok(());
    }
    // Relationships earlier links of the same pattern already traversed — forbidden in this walk
    // (relationship isomorphism / trail spans the whole pattern, not just this segment).
    let forbidden = used_relationships(base, prior_rels);

    // The unified ordered hop list: the first hop (flat operator fields) followed by every extra hop.
    let mut hops: Vec<QppHopRt<'_>> = Vec::with_capacity(1 + extra_hops.len());
    hops.push(QppHopRt {
        relationship,
        end_node: group_end,
        dir: ExpandDirection::from_pattern(direction),
        type_names,
    });
    for step in extra_hops {
        hops.push(QppHopRt {
            relationship: &step.relationship,
            end_node: &step.end_node,
            dir: ExpandDirection::from_pattern(step.direction),
            type_names: &step.type_names,
        });
    }

    let mut st = QppWalk {
        base,
        group_start,
        to,
        hops: &hops,
        min,
        max,
        target,
        into,
        forbidden: &forbidden,
        interior_predicate,
        // Per-iteration accumulators (one element per completed iteration).
        iter_starts: Vec::new(),
        step_nodes: vec![Vec::new(); hops.len()],
        step_rels: vec![Vec::new(); hops.len()],
        // The flat trail across all hops of all iterations (for O(1)-ish uniqueness checks).
        trail: Vec::new(),
    };
    st.run(anchor, ctx, pending)
}

/// One frame of the iterative quantified-path trail walk (`rmp` #656). The walk alternates between
/// *iteration* boundaries (`Walk`) and *hop* traversals (`Step`) — the former recursion nested those
/// two functions ~O(path length · hops) deep, overflowing the finite worker-thread stack on a long
/// chain (an uncatchable SIGABRT). Driving the same depth-first enumeration through a heap-allocated
/// stack of these frames keeps the walk's depth on the heap, so an arbitrarily long walk uses O(1)
/// native stack and can never overflow. Frames are popped, mutated, and repushed (with the child on
/// top) so the traversal order is byte-identical to the recursion's pre-order.
enum QppFrame {
    /// Iteration boundary: `k` iterations completed, arriving at `current`. On first processing
    /// (`entered == false`) it emits the walk (if admissible) and, unless the maximum is reached,
    /// begins iteration `k` (pushes the start node, descends into hop 0). On re-entry
    /// (`entered == true`, the iteration's whole subtree finished) it pops that start node.
    Walk {
        k: u64,
        current: NodeId,
        entered: bool,
    },
    /// Hop traversal: traversing hop `hop_idx` of iteration `k` from `node`. `hop_idx == hops.len()`
    /// is the iteration-complete boundary (predicate check, then descend into iteration `k + 1`),
    /// latched one-shot by `idx`. For an interior hop (`hop_idx < hops.len()`), `idx` cursors the
    /// candidate incidents, `seen_rel` dedups self-loops, and `pushed` records an outstanding
    /// accumulator descent to undo when the frame resurfaces.
    Step {
        hop_idx: usize,
        node: NodeId,
        k: u64,
        incidents: Vec<crate::graph_access::Incident>,
        idx: usize,
        seen_rel: rustc_hash::FxHashSet<RelId>,
        pushed: bool,
    },
}

/// Mutable state of a quantified-path trail walk, threaded through the iteration so the argument list
/// stays manageable. Borrows the immutable operator parameters and owns the per-iteration accumulators
/// the walk pushes/pops.
struct QppWalk<'a> {
    base: &'a Row,
    group_start: &'a Var,
    to: &'a Var,
    hops: &'a [QppHopRt<'a>],
    min: u64,
    max: Option<u64>,
    target: Option<NodeId>,
    into: bool,
    forbidden: &'a rustc_hash::FxHashSet<RelId>,
    interior_predicate: Option<&'a Expr>,
    /// Start node of each completed iteration (the `group_start` group list).
    iter_starts: Vec<NodeId>,
    /// `step_nodes[h][i]` = the node reached after hop `h` in iteration `i` (hop `h`'s end-node list).
    step_nodes: Vec<Vec<NodeId>>,
    /// `step_rels[h][i]` = the relationship traversed at hop `h` in iteration `i` (hop `h`'s trail).
    step_rels: Vec<Vec<RelId>>,
    /// Every relationship used so far, across all hops of all iterations (trail-uniqueness set as a
    /// stack — pushed/popped in lockstep with the recursion).
    trail: Vec<RelId>,
}

impl QppWalk<'_> {
    /// Drives the quantified-path trail walk from `anchor` **iteratively** (`rmp` #656): an explicit
    /// heap stack of [`QppFrame`]s reproduces, in the identical pre-order, the enumeration the former
    /// mutually-recursive `walk`/`step` performed — but with the walk's depth on the heap, so an
    /// arbitrarily long chain uses O(1) native stack and can never overflow it. Each emitted row is
    /// charged against a [`PendingBudget`], so an adversarial dense graph is rejected with a clean,
    /// typed [`EvalError::ResourceLimit`] instead of exhausting memory.
    fn run(
        &mut self,
        anchor: NodeId,
        ctx: &mut Ctx<'_>,
        pending: &mut VecDeque<Row>,
    ) -> Result<(), ExecError> {
        let mut budget = PendingBudget::new();
        let mut stack: Vec<QppFrame> = vec![QppFrame::Walk {
            k: 0,
            current: anchor,
            entered: false,
        }];

        while let Some(frame) = stack.pop() {
            // Cancellation is polled per frame (at least once per visited node), so an adversarial
            // high-fan-out interior hop stays responsive.
            ctx.check_cancelled()?;
            match frame {
                QppFrame::Walk {
                    k,
                    current,
                    entered,
                } => {
                    if entered {
                        // The whole subtree of iteration `k` finished: undo this iteration's start-node
                        // push (the accumulator pop the recursion did after `step` returned).
                        self.iter_starts.pop();
                        continue;
                    }
                    // First arrival with `k` completed iterations: emit the walk if it meets the length
                    // bound and, for `into`, ends at the target.
                    if k >= self.min && (!self.into || Some(current) == self.target) {
                        self.emit(current, &mut budget, pending)?;
                    }
                    if self.max.is_some_and(|m| k >= m) {
                        // Maximum iterations reached: no further iteration. This is a leaf `Walk` (no
                        // start node was pushed), so nothing to undo — just drop it.
                        continue;
                    }
                    // Begin iteration `k`: record its start node, then traverse the interior from
                    // `current`. Repush this `Walk` (entered) beneath the hop-0 frame so it resurfaces to
                    // pop the start node once the iteration's subtree completes.
                    self.iter_starts.push(current);
                    let incidents =
                        ctx.graph
                            .expand(current, self.hops[0].dir, self.hops[0].type_names);
                    stack.push(QppFrame::Walk {
                        k,
                        current,
                        entered: true,
                    });
                    stack.push(QppFrame::Step {
                        hop_idx: 0,
                        node: current,
                        k,
                        incidents,
                        idx: 0,
                        seen_rel: rustc_hash::FxHashSet::default(),
                        pushed: false,
                    });
                }
                QppFrame::Step {
                    hop_idx,
                    node,
                    k,
                    incidents,
                    mut idx,
                    mut seen_rel,
                    pushed,
                } => {
                    if hop_idx == self.hops.len() {
                        // One full interior traversed. `idx` latches this boundary one-shot: 0 = first
                        // arrival — prune the whole iteration by the interior predicate (which may
                        // reference every interior variable), then descend into iteration `k + 1`;
                        // 1 = that child iteration finished, so this boundary frame is done. The
                        // accumulators for the final hop are owned by the parent `Step` (hop
                        // `hops.len() - 1`), which undoes them when it resurfaces, so this frame pushes /
                        // pops nothing itself.
                        if idx == 0 {
                            if let Some(pred) = self.interior_predicate {
                                if !self.iteration_predicate_holds(pred, ctx)? {
                                    continue; // iteration rejected
                                }
                            }
                            stack.push(QppFrame::Step {
                                hop_idx,
                                node,
                                k,
                                incidents,
                                idx: 1,
                                seen_rel,
                                pushed,
                            });
                            stack.push(QppFrame::Walk {
                                k: k + 1,
                                current: node,
                                entered: false,
                            });
                        }
                        continue;
                    }

                    // An interior hop. Undo the accumulator push from this frame's previous descent, if
                    // any, before advancing to the next incident.
                    if pushed {
                        self.trail.pop();
                        self.step_nodes[hop_idx].pop();
                        self.step_rels[hop_idx].pop();
                    }
                    // Advance to the next admissible incident (relationship-unique across the whole walk;
                    // self-loops deduped once per side).
                    let mut chosen = None;
                    while idx < incidents.len() {
                        let inc = incidents[idx];
                        idx += 1;
                        if !seen_rel.insert(inc.rel)
                            || self.trail.contains(&inc.rel)
                            || self.forbidden.contains(&inc.rel)
                        {
                            continue;
                        }
                        chosen = Some(inc);
                        break;
                    }
                    let Some(inc) = chosen else {
                        // Exhausted: drop the frame (its accumulators were already undone above).
                        continue;
                    };
                    self.step_rels[hop_idx].push(inc.rel);
                    self.step_nodes[hop_idx].push(inc.neighbour);
                    self.trail.push(inc.rel);
                    let child_hop = hop_idx + 1;
                    let child_incidents = if child_hop < self.hops.len() {
                        ctx.graph.expand(
                            inc.neighbour,
                            self.hops[child_hop].dir,
                            self.hops[child_hop].type_names,
                        )
                    } else {
                        // The iteration-complete boundary traverses no relationships.
                        Vec::new()
                    };
                    // Repush this frame (cursor advanced, one accumulator descent outstanding), then the
                    // child on top so the walk descends depth-first.
                    stack.push(QppFrame::Step {
                        hop_idx,
                        node,
                        k,
                        incidents,
                        idx,
                        seen_rel,
                        pushed: true,
                    });
                    stack.push(QppFrame::Step {
                        hop_idx: child_hop,
                        node: inc.neighbour,
                        k,
                        incidents: child_incidents,
                        idx: 0,
                        seen_rel: rustc_hash::FxHashSet::default(),
                        pushed: false,
                    });
                }
            }
        }
        Ok(())
    }

    /// Emits one row for a completed `k`-iteration walk ending at `current`, binding each interior
    /// group variable to its ordered per-iteration list and (unless `into`) the boundary `to` to the
    /// final node. The row is charged against `budget` before it is enqueued, so an adversarial dense
    /// graph is rejected before the over-budget queue is materialised (`rmp` #656).
    fn emit(
        &self,
        current: NodeId,
        budget: &mut PendingBudget,
        pending: &mut VecDeque<Row>,
    ) -> Result<(), ExecError> {
        let mut row = self.base.clone();
        row.set(
            self.group_start.name.clone(),
            RowValue::list(
                self.iter_starts
                    .iter()
                    .map(|&id| RowValue::Node(NodeRef { id }))
                    .collect(),
            ),
        );
        for (h, hop) in self.hops.iter().enumerate() {
            row.set(
                hop.end_node.name.clone(),
                RowValue::list(
                    self.step_nodes[h]
                        .iter()
                        .map(|&id| RowValue::Node(NodeRef { id }))
                        .collect(),
                ),
            );
            row.set(
                hop.relationship.name.clone(),
                RowValue::list(
                    self.step_rels[h]
                        .iter()
                        .map(|&id| RowValue::Rel(RelRef { id }))
                        .collect(),
                ),
            );
        }
        // The trailing boundary node: bound to the final node (for `into` it already equals the bound
        // target, so leave the existing binding untouched).
        if !self.into {
            row.set(
                self.to.name.clone(),
                RowValue::Node(NodeRef { id: current }),
            );
        }
        budget.charge(&row)?;
        pending.push_back(row);
        Ok(())
    }

    /// Evaluates the per-iteration interior predicate with the **current** iteration's scalar
    /// bindings: `group_start` = this iteration's start node, and each hop's `end_node`/`relationship`
    /// = that hop's node/relationship in this iteration (the last-pushed accumulator element). A
    /// non-`TRUE` (false / null under three-valued logic) result prunes the iteration.
    fn iteration_predicate_holds(&self, pred: &Expr, ctx: &mut Ctx<'_>) -> Result<bool, ExecError> {
        let mut probe = self.base.clone();
        // INVARIANT: called at iteration completion, so `iter_starts` and every `step_*[h]` hold this
        // iteration's element as their last entry.
        let start = *self
            .iter_starts
            .last()
            .expect("INVARIANT: iteration in progress has a start node");
        probe.set(
            self.group_start.name.clone(),
            RowValue::Node(NodeRef { id: start }),
        );
        for (h, hop) in self.hops.iter().enumerate() {
            let node = *self.step_nodes[h]
                .last()
                .expect("INVARIANT: every hop of a completed iteration has an end node");
            let rel = *self.step_rels[h]
                .last()
                .expect("INVARIANT: every hop of a completed iteration has a relationship");
            probe.set(
                hop.end_node.name.clone(),
                RowValue::Node(NodeRef { id: node }),
            );
            probe.set(
                hop.relationship.name.clone(),
                RowValue::Rel(RelRef { id: rel }),
            );
        }
        Ok(predicate_truth(pred, &probe, ctx)?.is_true())
    }
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

/// Whether the candidate end node `node` satisfies the far-endpoint predicate pushed into a
/// variable-length expansion (`rmp` task #870, part b).
///
/// `probe` is a **one-column row** binding only `to`, built once per driving row by the walk and
/// re-pointed at each candidate here — the schema never changes, so this costs no allocation in a
/// loop whose whole purpose is to avoid building rows.
///
/// Evaluating against a row that omits every other column is sound, and is why the planner's
/// [confinement gate](crate::physical) is load-bearing rather than decorative: it certifies the
/// predicate reads no variable other than `to`, so the columns this row omits are columns the
/// predicate cannot ask for. Parameters come from `ctx`, exactly as above the operator.
///
/// Verdicts go through [`predicate_truth`], which is the **same** function `Operator::Filter` uses —
/// deliberately, not incidentally. A hand-rolled `matches!(…, Boolean(true))` would agree with it on
/// `TRUE`, `FALSE` and `NULL` and silently disagree on the fourth case: `WHERE v.flag` where
/// `v.flag` is a string is a runtime type error, and mapping it to "row dropped" would make the same
/// query raise or not depending on whether the predicate was pushed.
fn end_node_satisfies(
    node: NodeId,
    predicate: &Expr,
    probe: &mut Row,
    ctx: &mut Ctx<'_>,
) -> Result<bool, ExecError> {
    probe.set_at(0, RowValue::Node(NodeRef { id: node }));
    Ok(predicate_truth(predicate, probe, ctx)?.is_true())
}

/// Drops from `pending` every row whose far endpoint fails `predicate` (`rmp` task #870, part b), a
/// no-op when there is no predicate.
///
/// The fallback application point for the expansion branches that do not run the trail walk (an
/// already-bound relationship variable, a fixed-length hop). Those branches build their rows first, so
/// this cannot save the materialisation the walk's early test does — it exists so that a predicate the
/// planner attached is *never silently skipped*, whatever branch the operator ends up taking. `to` is
/// already bound on every row they produce, so the predicate is evaluated against the row itself, and
/// through the same [`predicate_truth`] a `Filter` would use.
fn retain_rows_satisfying(
    pending: &mut VecDeque<Row>,
    predicate: Option<&Expr>,
    ctx: &mut Ctx<'_>,
) -> Result<(), ExecError> {
    let Some(predicate) = predicate else {
        return Ok(());
    };
    let mut kept = VecDeque::with_capacity(pending.len());
    for row in std::mem::take(pending) {
        if predicate_truth(predicate, &row, ctx)?.is_true() {
            kept.push_back(row);
        }
    }
    *pending = kept;
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
///
/// For a **`PROFILE`d** statement (`rmp` task #752) this wraps every operator it builds in an
/// [`Operator::Profile`] shim and, while the operator is being built, makes it the recorder's *current*
/// operator — because a leaf scan and every materialising operator (`Sort`, `Aggregation`, `HashJoin`, …)
/// do their storage work **here**, at build time, not on the first `next()`. Since this function is the
/// single entry point every child build recurses through, the shim is installed uniformly with no change
/// to any operator's own construction. An unprofiled statement takes the early return and is untouched.
fn build_operator(
    op: &PhysicalOp,
    arg: Option<&Row>,
    ctx: &mut Ctx<'_>,
) -> Result<Operator, ExecError> {
    let Some(rec) = ctx.profile.clone() else {
        return build_operator_unprofiled(op, arg, ctx);
    };
    // An operator the recorder does not know (which the executor cannot produce — it only ever builds the
    // plan's operators and the templates it has rebound) is built with no shim rather than have its work
    // attributed to some *other* operator's counter: a missing number is honest, a wrong one is not.
    let Some(id) = rec.id_of(op) else {
        return build_operator_unprofiled(op, arg, ctx);
    };
    let previous = rec.enter(id);
    let built = build_operator_unprofiled(op, arg, ctx);
    rec.leave(previous);
    Ok(Operator::Profile {
        input: Box::new(built?),
        id,
        rec,
    })
}

/// The MVCC [`View`] a **leaf** operator does its store work under (`04 §5.1.4`, `rmp` #972).
///
/// This is one half of the per-operator polarity table (the other half lives on the lazy operators in
/// [`Operator::next`]); it is a function rather than an inline `matches!` so the table can be read,
/// tested and cited in one place. It is **exhaustive on purpose** — no `_ =>` arm — so a new access
/// path cannot silently inherit a polarity nobody chose.
///
/// | Leaf | View | Why |
/// | --- | --- | --- |
/// | every node / relationship scan | `Old` | a scan must not see the rows its own statement is creating (the Halloween problem) |
/// | **every index seek**, of every kind | `Old` | identical semantics to the scan it replaces — a seek that read `New` while the scan read `Old` would make `CREATE INDEX` change the answer (`rmp` #738/#894) |
/// | `Argument` / `Empty` | `New` | they read no store at all |
/// | count-store answers | `New` | they are the `Aggregation` they replace, and their equivalence predicate already requires that no in-flight delta of this transaction exists (`rmp` #866) |
///
/// Memgraph plants the same polarity at the same place: every `ScanAll*` and `ScanAllByLabelProperty*`
/// cursor is constructed with `storage::View::OLD` (`src/query/plan/operator.cpp`), and the property
/// index re-verifies each candidate under that view rather than trusting the index entry
/// (`src/storage/v2/inmemory/label_property_index.cpp`).
fn leaf_read_view(op: &PhysicalOp) -> View {
    match op {
        // Scans and seeks: OLD, without exception. The seek list is spelled out rather than folded
        // into a catch-all precisely because a seek that disagreed with its scan fallback is the
        // "index changes the answer" defect class.
        PhysicalOp::AllNodesScan { .. }
        | PhysicalOp::NodeByLabelScan { .. }
        | PhysicalOp::TokenLookupScan { .. }
        | PhysicalOp::NodeIndexSeek { .. }
        | PhysicalOp::NodeIndexMultiSeek { .. }
        | PhysicalOp::NodeCompositeIndexSeek { .. }
        | PhysicalOp::NodeLabelScanEq { .. }
        | PhysicalOp::NodeIndexRangeSeek { .. }
        | PhysicalOp::NodeIndexScan { .. }
        | PhysicalOp::NodeIndexStartsWithSeek { .. }
        | PhysicalOp::SpatialIndexSeek { .. }
        | PhysicalOp::NodeTextIndexSeek { .. }
        | PhysicalOp::AllRelationshipsScan { .. }
        | PhysicalOp::RelIndexSeek { .. }
        | PhysicalOp::RelIndexMultiSeek { .. }
        | PhysicalOp::RelIndexRangeSeek { .. }
        | PhysicalOp::RelCompositeIndexSeek { .. }
        | PhysicalOp::RelSpatialIndexSeek { .. } => View::Old,

        // Non-leaves that read the store **lazily**, in `Operator::next`. They polarise their own
        // accesses there, per the decision table; polarising them *here* would impose one operator's
        // view on the entire subtree this call recursively builds, which is the exact mistake the
        // table exists to prevent.
        PhysicalOp::ExpandAll { .. }
        | PhysicalOp::ExpandInto { .. }
        | PhysicalOp::OptionalExpand { .. }
        | PhysicalOp::ShortestPath { .. }
        | PhysicalOp::QuantifiedPath { .. }
        | PhysicalOp::NamedPath { .. }
        | PhysicalOp::Filter { .. }
        | PhysicalOp::Unwind { .. }
        | PhysicalOp::ProcedureCall { .. } => View::New,

        // Row plumbing: they read no store at all, so the view cannot reach them.
        PhysicalOp::Argument { .. }
        | PhysicalOp::Empty
        | PhysicalOp::Projection { .. }
        | PhysicalOp::Aggregation { .. }
        | PhysicalOp::Sort { .. }
        | PhysicalOp::TopN { .. }
        | PhysicalOp::Skip { .. }
        | PhysicalOp::Limit { .. }
        | PhysicalOp::Eager { .. }
        | PhysicalOp::AdvanceCommand { .. }
        | PhysicalOp::NestedLoopJoin { .. }
        | PhysicalOp::HashJoin { .. }
        | PhysicalOp::ValueHashJoin { .. }
        | PhysicalOp::Union { .. }
        | PhysicalOp::Optional { .. }
        | PhysicalOp::SemiApply { .. }
        | PhysicalOp::LoadCsv { .. } => View::New,

        // The count-store accelerators read the maintained counters, not a version chain, so no view
        // reaches them — and they cannot disagree with the scan they replace, because the seam
        // **declines** whenever any transaction holds an uncommitted count delta and the
        // `Aggregation`-over-scan `fallback` child then runs verbatim, polarised by its own leaf.
        PhysicalOp::NodeCountFromCountStore { .. }
        | PhysicalOp::RelationshipCountFromCountStore { .. } => View::New,

        // Writes: `New` without exception. A write must see everything its transaction has done,
        // including the statement performing it — `MERGE`'s match sub-plan included, which is the one
        // match in the language that is deliberately `New`.
        PhysicalOp::Create { .. }
        | PhysicalOp::Merge { .. }
        | PhysicalOp::SetClause { .. }
        | PhysicalOp::Remove { .. }
        | PhysicalOp::Delete { .. }
        | PhysicalOp::Foreach { .. } => View::New,
    }
}

/// [`build_operator`] without the profiling shim: the operator construction itself.
///
/// **Note on where the polarity is applied.** Leaf scans and seeks materialise their rows *here*, at
/// build time, so [`leaf_read_view`] is applied around this whole dispatch — a leaf has no child to
/// contaminate. Every other operator does its store work lazily in [`Operator::next`], and polarises
/// its own accesses there; wrapping a non-leaf's construction would impose its polarity on the entire
/// subtree it recursively builds, which is the exact mistake the table exists to prevent.
fn build_operator_unprofiled(
    op: &PhysicalOp,
    arg: Option<&Row>,
    ctx: &mut Ctx<'_>,
) -> Result<Operator, ExecError> {
    let view = leaf_read_view(op);
    if view != View::New {
        return ctx.with_view(view, |ctx| build_operator_leaf(op, arg, ctx));
    }
    build_operator_leaf(op, arg, ctx)
}

/// The body of [`build_operator_unprofiled`], entered with the leaf polarity already installed.
fn build_operator_leaf(
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
            ordered,
            cached_property,
            ..
        } => {
            // The seek value is normally a literal or `$param`, but a correlated seek (`rmp` task
            // #708 — the right branch of a nested-loop join, e.g. `UNWIND rows AS t MATCH (b:L {p:
            // t.k})`) keys it off the LEFT row's bindings, which the join supplies as the correlation
            // row `arg`. Evaluating against `arg` (the empty row at the top level) resolves that
            // per-row key; a row-independent literal/param yields the same value against either.
            let empty = Row::empty();
            let seek = eval_value(
                value,
                arg.unwrap_or(&empty),
                ctx.params,
                ctx.graph,
                ctx.functions,
                &ctx.clock,
            )?;
            // `rmp` #879: ask the seam to hand back the value it reads while re-checking each
            // candidate, but only when the plan actually references it — otherwise a large result set
            // would retain one `Value` per row for nothing.
            let carry = carry_for(*cached_property);
            let hits = match ctx.graph.index_seek_eq(&label.name, property, &seek, carry) {
                Some(hits) => hits,
                // No index in the seam: fall back to a label scan + equality residual. That path
                // carries no value, so a later `n.p` reads the store — always correct, just not free.
                None => IndexSeekHits::ids(scan_filter_eq(label, property, &seek, ctx)),
            };
            let keyed = order_hits_if_requested(hits, property, *ordered, *cached_property, ctx);
            Ok(Operator::Buffered {
                rows: seek_rows(variable, property, keyed),
            })
        }
        PhysicalOp::NodeIndexMultiSeek {
            variable,
            label,
            property,
            values,
            ..
        } => {
            // Multi-value index equality seek (`rmp` task #868): `WHERE n.p IN [a, b, c]` /
            // `WHERE n.p = a OR n.p = b`. Evaluate the alternatives, collapse the identical ones, then
            // issue ONE descent per surviving value through the very same `index_seek_eq` seam the
            // single-value `NodeIndexSeek` above uses — so RBAC filtering (`AuthorizedGraph`), `dbHits`
            // accounting (`ProfilingGraph`), the off-thread reader's candidate memo (`ReadOnlyGraph`)
            // and the SSI read footprint all compose exactly as they do for `k` separate single-value
            // seeks, with no new seam and no new decline path.
            //
            // The alternatives are evaluated against the EMPTY row, never the correlation row: the
            // planner only emits this operator when no alternative references any variable
            // (`analyze_multi_value_predicate`), so there is nothing a driving row could supply.
            let seek_values = distinct_seek_values(values, ctx)?;
            let ids = match multi_index_seek_eq(&label.name, property, &seek_values, ctx)? {
                Some(ids) => ids,
                // WHOLE-union decline (`rmp` #738/#680): some value has no usable index, so take the
                // exact scan for the WHOLE predicate — ONE pass testing membership of the entire value
                // set, which is exactly the `scan + IN filter` plan this operator replaced. Never `k`
                // passes: see [`scan_filter_in`].
                None => scan_filter_in(label, property, &seek_values, ctx),
            };
            // Sort + dedup so the operator emits each node exactly once, ascending by id — byte-for-byte
            // the shape an `ordered: false` `NodeIndexSeek` emits (`index_seek_eq_recheck` sorts and
            // dedups its own result).
            //
            // This is LOAD-BEARING, not defensive. Cypher `=` is **not transitive** across the
            // `INTEGER`/`FLOAT` boundary: it compares a mixed pair as `f64`, so `9007199254740992` and
            // `9007199254740993` are unequal to each other while both equal `9007199254740992.0`. A node
            // holding that float therefore genuinely matches two alternatives that are not the same
            // value and so were not collapsed by `distinct_seek_values` — and without this dedup its row
            // would be emitted twice, a bag-cardinality bug the scan path does not have.
            Ok(Operator::Buffered {
                rows: nodes_to_rows(variable, sorted_deduped(ids)),
            })
        }
        PhysicalOp::NodeCompositeIndexSeek {
            variable,
            label,
            properties,
            values,
            cached_property,
            ..
        } => {
            // Composite (multi-property) equality seek (`rmp` task #657): evaluate each key's seek value
            // at run time, then route to the composite index seam. The seam returns a candidate SUPERSET
            // which it has already re-checked for the current per-key tuple; when no composite index is
            // available it returns `None` and we fall back to a label scan filtered by every key (the
            // operator consumed the equality conjuncts, so the fallback must re-apply them). Both paths
            // yield the identical node set.
            //
            // Each key value is normally a literal or `$param`, but a CORRELATED composite seek (`rmp`
            // task #729 — the right branch of a nested-loop join, e.g.
            // `UNWIND rows AS t MATCH (b:L {a: t.x, b: t.y})` with a composite `(a, b)` index) keys them
            // off the LEFT row's bindings, which the join supplies as the correlation row `arg`.
            // Evaluating against `arg` (the empty row at the top level) resolves each per-row key exactly
            // as the single-property `NodeIndexSeek` arm does for #708; a row-independent literal/param
            // yields the same value against either row.
            let empty = Row::empty();
            let mut seek_values = Vec::with_capacity(values.len());
            for value in values {
                seek_values.push(eval_value(
                    value,
                    arg.unwrap_or(&empty),
                    ctx.params,
                    ctx.graph,
                    ctx.functions,
                    &ctx.clock,
                )?);
            }
            let carry = carry_for(*cached_property);
            let hits = match ctx.graph.index_seek_composite_eq(
                &label.name,
                properties,
                &seek_values,
                carry,
            ) {
                Some(hits) => hits,
                None => CompositeSeekHits::ids(scan_filter_composite_eq(
                    label,
                    properties,
                    &seek_values,
                    ctx,
                )),
            };
            // `rmp` #879: every covered key's current value is available, so `RETURN n.a, n.b` over a
            // composite `(a, b)` seek touches the store zero further times — and referencing only a
            // SUBSET of the keys is served just as well, one entry per key.
            Ok(Operator::Buffered {
                rows: composite_seek_rows(variable, properties, hits),
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
            // Evaluated against the correlation row (like `NodeIndexSeek`, `rmp` task #708) so a
            // correlated equality resolves its per-row key; a literal/param value is row-independent.
            let empty = Row::empty();
            let seek = eval_value(
                value,
                arg.unwrap_or(&empty),
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
            ordered,
            cached_property,
            ..
        } => {
            // As with `NodeIndexSeek`, evaluate the bound against the correlation row so a
            // per-left-row correlated range seek (`rmp` task #708) resolves its key; a literal/param
            // bound is row-independent and yields the same value against the empty top-level row.
            let empty = Row::empty();
            let bound_val = eval_value(
                value,
                arg.unwrap_or(&empty),
                ctx.params,
                ctx.graph,
                ctx.functions,
                &ctx.clock,
            )?;
            let (lower, upper) = range_bounds(*bound, &bound_val);
            let carry = carry_for(*cached_property);
            let hits = match ctx
                .graph
                .index_seek_range(&label.name, property, lower, upper, carry)
            {
                Some(hits) => hits,
                None => {
                    IndexSeekHits::ids(scan_filter_range(label, property, *bound, &bound_val, ctx))
                }
            };
            let keyed = order_hits_if_requested(hits, property, *ordered, *cached_property, ctx);
            Ok(Operator::Buffered {
                rows: seek_rows(variable, property, keyed),
            })
        }
        PhysicalOp::NodeIndexScan {
            variable,
            label,
            property,
            ordered,
            cached_property,
            ..
        } => {
            // Existence via a full property-index scan (`rmp` task #665): an unbounded range over the
            // order-preserving index yields exactly the visible labelled nodes with a non-null value
            // for `property` (every index entry has a present value; the seam re-checks each candidate).
            // With no derived index in the seam (the off-thread reader, or a `MemGraph` reference seam)
            // this returns `None`; we fall back to a full label scan and rely on the residual
            // `IS NOT NULL` filter the planner attached above to trim the null-valued nodes — both paths
            // yield the identical node set.
            let carry = carry_for(*cached_property);
            let hits = match ctx
                .graph
                .index_seek_range(&label.name, property, None, None, carry)
            {
                Some(hits) => hits,
                None => IndexSeekHits::ids(ctx.graph.scan_nodes_by_label(&label.name)),
            };
            let keyed = order_hits_if_requested(hits, property, *ordered, *cached_property, ctx);
            Ok(Operator::Buffered {
                rows: seek_rows(variable, property, keyed),
            })
        }
        PhysicalOp::NodeIndexStartsWithSeek {
            variable,
            label,
            property,
            prefix,
            ..
        } => {
            // `n.p STARTS WITH <prefix>` served by a bounded range seek over `[prefix,
            // successor(prefix))` (`rmp` task #658). The prefix is evaluated at run time (a literal or,
            // after auto-parameterisation, a `$param`), so the bounds are computed here — the executor
            // needs no plan-time knowledge of the value. The seek returns a candidate SUPERSET; the
            // residual `STARTS WITH` filter above this operator (attached by the planner) restores
            // exactness (rejecting non-string / non-prefix values), so both the index and the scan
            // fallback below yield the identical node set.
            let prefix_val = eval_value(
                prefix,
                &Row::empty(),
                ctx.params,
                ctx.graph,
                ctx.functions,
                &ctx.clock,
            )?;
            let ids = match &prefix_val {
                Value::String(s) => {
                    let lower = Some((&prefix_val, true)); // inclusive lower = the prefix
                    // The exclusive upper is the string successor; `None` (an empty or all-`U+10FFFF`
                    // prefix) leaves the range open above — still a superset (the residual re-checks).
                    let successor = string_prefix_successor(s).map(Value::String);
                    // `KeyValues::Discard` (`rmp` #879): the prefix seek is out of this task's scope.
                    let seek = match &successor {
                        Some(succ) => ctx.graph.index_seek_range(
                            &label.name,
                            property,
                            lower,
                            Some((succ, false)),
                            KeyValues::Discard,
                        ),
                        None => ctx.graph.index_seek_range(
                            &label.name,
                            property,
                            lower,
                            None,
                            KeyValues::Discard,
                        ),
                    }
                    .map(|hits| hits.matched);
                    // No usable index at run time (e.g. the off-thread reader declines): fall back to a
                    // label scan — the residual `STARTS WITH` filter then does the exact trimming, and
                    // the SSI read footprint matches the scan path (`scan_nodes_by_label`).
                    seek.unwrap_or_else(|| ctx.graph.scan_nodes_by_label(&label.name))
                }
                // A non-string prefix (`STARTS WITH` of a null/number/etc.) matches nothing — every
                // `STARTS WITH` evaluates to `null`. Scan the label so the residual filter (which also
                // returns nothing) owns the SSI footprint, identical to the scan-path plan.
                _ => ctx.graph.scan_nodes_by_label(&label.name),
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
        PhysicalOp::NodeTextIndexSeek {
            variable,
            label,
            property,
            op,
            needle,
            ..
        } => {
            // `n.p CONTAINS/ENDS WITH/STARTS WITH <needle>` served by the trigram text index
            // (`rmp` task #662). The needle is evaluated at run time (a literal or, after
            // auto-parameterisation, a `$param`). The seek returns a candidate SUPERSET; the residual
            // predicate above this operator (attached by the planner) restores exactness (rejecting
            // non-string / non-matching values), so both the index and the scan fallback below yield
            // the identical node set. A non-string needle, a needle too short to form a trigram, or an
            // unavailable index at run time (e.g. the off-thread reader declines) all fall back to a
            // label scan — the residual filter then does the exact trimming, with the SSI read footprint
            // matching the scan path (`scan_nodes_by_label`).
            let needle_val = eval_value(
                needle,
                &Row::empty(),
                ctx.params,
                ctx.graph,
                ctx.functions,
                &ctx.clock,
            )?;
            let ids = match &needle_val {
                Value::String(s) => ctx
                    .graph
                    .index_seek_text(&label.name, property, *op, s)
                    .unwrap_or_else(|| ctx.graph.scan_nodes_by_label(&label.name)),
                // A non-string needle: the predicate evaluates to `null` for every node, so nothing
                // matches. Scan the label so the residual filter (which also returns nothing) owns the
                // SSI footprint, identical to the scan-path plan.
                _ => ctx.graph.scan_nodes_by_label(&label.name),
            };
            Ok(Operator::Buffered {
                rows: nodes_to_rows(variable, ids),
            })
        }
        PhysicalOp::RelIndexSeek {
            relationship,
            from,
            to,
            rel_type,
            property,
            value,
            direction,
            ..
        } => {
            // Relationship-property index equality seek (`rmp` task #659): evaluate the seek value, then
            // ask the seam for the candidate relationship ids of `rel_type` whose current `property`
            // equals it (already re-checked for visibility + current type + current value). When the seam
            // exposes no usable rel-property index — the off-thread reader, or a since-dropped index —
            // fall back to a typed relationship scan + equality filter, which yields the identical
            // relationship set. Either way, materialise each relationship's endpoints from its own record
            // honouring the pattern direction (an undirected pattern binds both orientations),
            // reproducing exactly the `Filter`-over-`ExpandAll`-over-`AllNodesScan` rows this seek replaced.
            let seek = eval_value(
                value,
                &Row::empty(),
                ctx.params,
                ctx.graph,
                ctx.functions,
                &ctx.clock,
            )?;
            let ids = match ctx.graph.index_seek_rel_eq(&rel_type.name, property, &seek) {
                Some(ids) => ids,
                None => rel_scan_filter_eq_ids(&rel_type.name, property, &seek, ctx),
            };
            Ok(Operator::Buffered {
                rows: rel_ids_to_rows(relationship, from, to, *direction, ids, ctx)?,
            })
        }
        PhysicalOp::RelIndexMultiSeek {
            relationship,
            from,
            to,
            rel_type,
            property,
            values,
            direction,
            ..
        } => {
            // Multi-value relationship-property seek (`rmp` task #868) — the relationship analogue of
            // `NodeIndexMultiSeek`, and `k` repetitions of the `RelIndexSeek` arm above. Same contracts:
            // identical alternatives collapse first; each surviving value takes one descent through
            // the existing `index_seek_rel_eq` seam (so the `AuthorizedGraph` decorator's decline for a
            // restricted principal, and the off-thread reader's decline, both apply unchanged); and the
            // union declines as a WHOLE to the typed scan + equality re-check when any value's seek
            // declines. Endpoints are materialised from each matched relationship's own record honouring
            // the pattern direction, exactly as the single-value seek does.
            let seek_values = distinct_seek_values(values, ctx)?;
            let ids = match multi_index_seek_rel_eq(&rel_type.name, property, &seek_values, ctx)? {
                Some(ids) => ids,
                None => rel_scan_filter_in_ids(&rel_type.name, property, &seek_values, ctx),
            };
            Ok(Operator::Buffered {
                rows: rel_ids_to_rows(
                    relationship,
                    from,
                    to,
                    *direction,
                    sorted_deduped(ids),
                    ctx,
                )?,
            })
        }
        PhysicalOp::RelIndexRangeSeek {
            relationship,
            from,
            to,
            rel_type,
            property,
            bound,
            value,
            direction,
            ..
        } => {
            // Relationship-property index RANGE seek (`rmp` task #680): evaluate the bound, then ask the
            // seam for the candidate relationship ids of `rel_type` whose current `property` satisfies it
            // (already re-checked for visibility + current type + the bound, under the same
            // `eval::satisfies_range` a `Filter` applies). When the seam exposes no usable rel-property
            // index — the off-thread reader, a RESTRICTED RBAC principal (the `AuthorizedGraph` decorator
            // declines the raw seek so per-property read grants still apply), a `Populating` index
            // (`rmp` #733), or one dropped since planning — fall back to a typed relationship scan + the
            // identical range filter, which yields the identical relationship set. Either way, materialise
            // each relationship's endpoints from its own record honouring the pattern direction (an
            // undirected pattern binds both orientations), reproducing exactly the
            // `Filter`-over-`ExpandAll`-over-`AllNodesScan` rows this seek replaced.
            //
            // The bound is evaluated against the empty row (like `RelIndexSeek`): the planner only emits
            // this operator for a value that does not reference the relationship variable, and no
            // correlated relationship seek exists (`contains_correlated_seek` covers the node seeks only).
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
                .index_seek_rel_range(&rel_type.name, property, lower, upper)
            {
                Some(ids) => ids,
                None => {
                    rel_scan_filter_range_ids(&rel_type.name, property, *bound, &bound_val, ctx)
                }
            };
            Ok(Operator::Buffered {
                rows: rel_ids_to_rows(relationship, from, to, *direction, ids, ctx)?,
            })
        }
        PhysicalOp::RelCompositeIndexSeek {
            relationship,
            from,
            to,
            rel_type,
            properties,
            values,
            direction,
            ..
        } => {
            // Composite (multi-property) relationship index equality seek (`rmp` task #666): evaluate
            // each key's seek value, then ask the seam for the candidate relationship ids of `rel_type`
            // whose current per-property tuple equals them (already re-checked for visibility + current
            // type + current values). When the seam exposes no usable composite relationship index — the
            // off-thread reader, or a since-dropped index — fall back to a typed relationship scan +
            // full-tuple equality filter, which yields the identical relationship set. Either way,
            // materialise each relationship's endpoints from its own record honouring the pattern
            // direction, exactly like the single-property relationship seek.
            let mut seek_values = Vec::with_capacity(values.len());
            for value in values {
                seek_values.push(eval_value(
                    value,
                    &Row::empty(),
                    ctx.params,
                    ctx.graph,
                    ctx.functions,
                    &ctx.clock,
                )?);
            }
            let ids = match ctx.graph.index_seek_rel_composite_eq(
                &rel_type.name,
                properties,
                &seek_values,
            ) {
                Some(ids) => ids,
                None => {
                    rel_scan_filter_composite_eq_ids(&rel_type.name, properties, &seek_values, ctx)
                }
            };
            Ok(Operator::Buffered {
                rows: rel_ids_to_rows(relationship, from, to, *direction, ids, ctx)?,
            })
        }
        PhysicalOp::RelSpatialIndexSeek {
            relationship,
            from,
            to,
            rel_type,
            property,
            center_x,
            center_y,
            radius,
            direction,
            ..
        } => {
            // Relationship spatial proximity seek (`rmp` task #664): ask the seam for the candidate
            // relationship ids of `rel_type` whose current point `property` is within `radius` of the
            // constant centre (already re-checked for visibility + current type). When the seam exposes
            // no usable relationship spatial index — the off-thread reader, or a since-dropped index —
            // fall back to a typed relationship scan (each relationship of the type once). Either way the
            // residual `distance(...) <op> r` filter above this operator does the exact trimming and MVCC
            // current-value re-check, so the index-accelerated and scan paths return the identical
            // relationship set (`rmp` task #664). Materialise each relationship's endpoints from its own
            // record honouring the pattern direction (an undirected pattern binds both orientations),
            // reproducing exactly the `Filter`-over-`ExpandAll`-over-`AllNodesScan` rows this seek replaced.
            let ids = match ctx.graph.index_seek_spatial_rel(
                &rel_type.name,
                property,
                *center_x,
                *center_y,
                *radius,
            ) {
                Some(ids) => ids,
                None => rel_scan_typed_ids(&rel_type.name, ctx),
            };
            Ok(Operator::Buffered {
                rows: rel_ids_to_rows(relationship, from, to, *direction, ids, ctx)?,
            })
        }
        PhysicalOp::AllRelationshipsScan {
            relationship,
            from,
            to,
            direction,
            types,
        } => Ok(Operator::RelScan {
            // The enumeration runs once, here; the rows are built lazily as the operator is pulled
            // (`rmp` task #867 — see `Operator::RelScan` for why eager row materialisation lost).
            scanned: all_rel_scan(types, ctx),
            cursor: 0,
            shape: RelRowTemplate::require(from, relationship, to)?,
            direction: *direction,
            pending: VecDeque::new(),
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

        // ---- count store (`rmp` task #866) -----------------------------------------------------
        // Ask the seam; on `Some(n)` emit the single row the aggregation would have produced, on
        // `None` build the fallback subtree and run it verbatim.
        //
        // The ask happens HERE, at operator-build time, and not one step earlier. The seam's answer
        // depends on live transaction state — whether any transaction holds an uncommitted count
        // delta, whether anything has committed since this statement's snapshot, whether this reader
        // is Snapshot-isolated — none of which is a property of the plan, and all of which a cached
        // plan ([`crate::plan_cache`]) would outlive. Deciding at plan time and consuming the verdict
        // at execution time is a TOCTOU; deciding here is not, because the seam evaluates its
        // predicate and reads its counter in the same instant, under one borrow, on the thread that
        // owns the store.
        //
        // `count(*)` and `count(v)` both land here and both produce the same number: the recognizer
        // only admits a bare scan below, and a scan binds a real entity on every row, so there is no
        // null for `count(v)` to skip. The result is `Value::Integer(i64)` — byte-identical to what
        // `Accumulator::finish` yields for `AggKind::Count`/`CountStar` — saturating rather than
        // wrapping on the (unreachable) `u64` overflow, matching the plan-description convention.
        PhysicalOp::NodeCountFromCountStore {
            column,
            label,
            fallback,
        } => match ctx
            .graph
            .count_store_nodes(label.as_ref().map(|l| l.name.as_str()))
        {
            Some(n) => Ok(count_store_row(column, n)),
            None => build_operator(fallback, arg, ctx),
        },
        PhysicalOp::RelationshipCountFromCountStore {
            column,
            types,
            fallback,
        } => {
            let names: Vec<String> = types.iter().map(|t| t.name.clone()).collect();
            match ctx.graph.count_store_rels(&names) {
                Some(n) => Ok(count_store_row(column, n)),
                None => build_operator(fallback, arg, ctx),
            }
        }

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
            to_predicate,
            pruning,
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
            to_predicate: to_predicate.clone(),
            pruning: *pruning,
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
            // `rmp` #870 rewrites only expand-ALL: an expand-into's far endpoint is bound by the
            // input, so a predicate on it is already pushed BELOW the operator by `rmp` #857, and
            // "distinct end nodes" is not a question the operator answers.
            to_predicate: None,
            pruning: false,
            pending: VecDeque::new(),
        }),
        // `rmp` task #882: the fused one-hop `OPTIONAL MATCH`. Everything the traversal needs is
        // resolved exactly as for `ExpandAll`/`ExpandInto` above — same `type_names` hoist (`rmp`
        // #371), same `into` flag — because the operator runs the *same* expansion helpers. What it
        // adds is the left-outer guarantee and the inside-`WHERE` predicates that decide it.
        PhysicalOp::OptionalExpand {
            input,
            from,
            relationship,
            to,
            direction,
            types,
            into,
            predicates,
            null_variables,
            arguments: _,
        } => Ok(Operator::OptionalExpand {
            input: Box::new(build_operator(input, arg, ctx)?),
            from: from.clone(),
            relationship: relationship.clone(),
            to: to.clone(),
            direction: *direction,
            type_names: types.iter().map(|t| t.name.clone()).collect(),
            types: types.clone(),
            into: *into,
            predicates: predicates.clone(),
            null_variables: null_variables.clone(),
            base: None,
            matched: false,
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
        PhysicalOp::QuantifiedPath {
            input,
            from,
            to,
            group_start,
            group_end,
            relationship,
            direction,
            types,
            extra_hops,
            min,
            max,
            prior_rels,
            interior_predicate,
            into,
        } => Ok(Operator::QuantifiedPath {
            input: Box::new(build_operator(input, arg, ctx)?),
            from: from.clone(),
            to: to.clone(),
            group_start: group_start.clone(),
            group_end: group_end.clone(),
            relationship: relationship.clone(),
            direction: *direction,
            type_names: types.iter().map(|t| t.name.clone()).collect(),
            extra_hops: extra_hops
                .iter()
                .map(|step| QppRuntimeStep {
                    relationship: step.relationship.clone(),
                    end_node: step.end_node.clone(),
                    direction: step.direction,
                    type_names: step.types.iter().map(|t| t.name.clone()).collect(),
                })
                .collect(),
            min: *min,
            max: *max,
            prior_rels: prior_rels.clone(),
            interior_predicate: interior_predicate.clone(),
            into: *into,
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
                // OLD (`rmp` #972). Every fused tier below SUBSUMES a leaf scan (and, in the
                // expand variants, a traversal and a filter) into one pass, so it owes the polarity
                // those operators owe. Its own shape gate refuses any plan with a write operator
                // between the scan and the consumer, so the projection / aggregation half — which
                // would otherwise owe NEW — can observe no difference: within one command there is
                // nothing for the two views to disagree about here.
                if let Some(rows) =
                    ctx.with_view(View::Old, |ctx| try_morsel_expand_project(op, ctx))?
                {
                    return Ok(Operator::Buffered { rows });
                }
                if let Some(rows) = ctx.with_view(View::Old, |ctx| {
                    try_morsel_scan_filter_project(op, &[], None, ctx)
                })? {
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
            // OLD for every fused tier below — see the note in the `Projection` arm (`rmp` #972).
            if let Some(rows) = ctx.with_view(View::Old, |ctx| {
                try_morsel_expand_aggregate(input, group_keys, aggregates, ctx)
            })? {
                return Ok(Operator::Buffered { rows });
            }
            // Morsel-driven parallel GROUPED aggregation OVER AN EXPAND (`rmp` #558 / #340 — the `top_liked`
            // class, the dominant social-analytics query): for a *large*
            // `MATCH (a:Label)-[r]->(b) [WHERE <pure>] WITH <bare keys>, <bare mergeable aggs>` (e.g.
            // `MATCH (:USER)-[:LIKE]->(a:ARTICLE) WITH a, count(*)`), partition the ANCHORS into contiguous
            // morsels, expand + filter + group + aggregate each concurrently on the dedicated pool (each
            // over a `Send` `ReadOnlyGraph`), then merge the partial group tables deterministically (serial
            // first-seen order, the #360 merge reused verbatim). Fuses the Slice-3c per-anchor expand with
            // the #360 grouped merge to cover the shape both decline (an interposed `Filter`/`Expand`).
            // Byte-identical to serial; declines (falls through) for any non-conforming shape, impure
            // filter/key, float/avg/overflow sum, below-threshold, knob<=1, RBAC restriction, standalone /
            // historical read, or a morsel error.
            if let Some(rows) = ctx.with_view(View::Old, |ctx| {
                try_morsel_expand_group_aggregate(input, group_keys, aggregates, ctx)
            })? {
                return Ok(Operator::Buffered { rows });
            }
            // Morsel-driven parallel FRONTIER-seeded grouped aggregation (`rmp` #575 — the reco `r3_fof3`
            // class: a single-seed multi-hop traversal → final `(f)-[:T]->(b)` expand → anti-join → grouped
            // `count(DISTINCT f)`). Materializes the multi-hop frontier serially (byte-identical markers +
            // isomorphism), then partitions the distinct anchors into contiguous morsels and expands +
            // filters (incl. the graph anti-join) + groups + aggregates each concurrently on the dedicated
            // pool, merging the partials deterministically (the #360 merge, reused verbatim). Covers exactly
            // the shape #558 declines (its final expand must anchor on a bare label scan, and it rejects the
            // anti-join pattern predicate); declines (falls through) for any non-conforming shape, knob<=1,
            // RBAC restriction, standalone / historical read, a non-constant seed, or a morsel error.
            if let Some(rows) = ctx.with_view(View::Old, |ctx| {
                try_morsel_frontier_fof_aggregate(input, group_keys, aggregates, ctx)
            })? {
                return Ok(Operator::Buffered { rows });
            }
            // Morsel-driven parallel GROUPED aggregation (`rmp` #360 — the actual LDBC-BI bottleneck): for
            // a *large* bare `MATCH (n:Label) RETURN <bare group keys>, <bare mergeable aggregates>`, split
            // the candidate-id vector into contiguous morsels, build a LOCAL group table per morsel
            // **concurrently** on the dedicated pool, then merge the partials deterministically (serial
            // first-seen order) on the engine thread. Byte-identical to serial (mergeable aggregates only:
            // count/sum-no-overflow-int/min/max/collect; avg/percentile/composite/filtered shapes decline).
            // This is the non-empty-GROUP-BY counterpart of the keyless Slice-3a tier below.
            if let Some(rows) = ctx.with_view(View::Old, |ctx| {
                try_morsel_group_aggregate(input, group_keys, aggregates, ctx)
            })? {
                return Ok(Operator::Buffered { rows });
            }
            if let Some(rows) = ctx.with_view(View::Old, |ctx| {
                try_morsel_label_aggregate(input, group_keys, aggregates, ctx)
            })? {
                return Ok(Operator::Buffered { rows });
            }
            // Parallel FOLD fast path (`rmp` #352, phase 1 of #336): the prior tier, kept as the base for
            // when the morsel knob is off (the global `rayon` pool's fold over a serially-projected
            // column). Bit-identical to serial; declines for any non-conforming shape, float/avg,
            // below-threshold, single-thread, RBAC restriction, or historical read.
            if let Some(rows) = ctx.with_view(View::Old, |ctx| {
                try_parallel_label_property_aggregate(input, group_keys, aggregates, ctx)
            })? {
                return Ok(Operator::Buffered { rows });
            }
            // Vectorized fast path (`rmp` #330): an analytical `MATCH (n:Label) RETURN agg(n.p)` over
            // a columnar-cached column folds the contiguous column in batches instead of pulling rows
            // one at a time. It produces the IDENTICAL result (shared accumulator arithmetic over the
            // MVCC-re-validated columnar scan) and declines to `None` for any shape it does not cover,
            // any uncached column, or under RBAC restriction — in which case the row-at-a-time Volcano
            // path below runs verbatim (the default + fallback).
            if let Some(rows) = ctx.with_view(View::Old, |ctx| {
                try_vectorized_label_property_aggregate(input, group_keys, aggregates, ctx)
            })? {
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
            if let Some(rows) = ctx.with_view(View::Old, |ctx| {
                try_morsel_scan_filter_project(input, keys, None, ctx)
            })? {
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
            if let Some(rows) = ctx.with_view(View::Old, |ctx| {
                try_morsel_scan_filter_project(input, keys, Some(n as usize), ctx)
            })? {
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
        PhysicalOp::AdvanceCommand { input } => {
            // The statement boundary of a `WITH` that follows a write (`04 §5.1.4`, `rmp` #972).
            //
            // DRAIN FIRST, then advance, then serve. The order is the guarantee, not a convenience:
            // the input is still producing the *previous* command's writes, and advancing while it runs
            // would stamp the tail of them with the next command's id. A downstream `OLD`-view read
            // would then see part of the earlier clause's work and not the rest — a split-brain view of
            // one clause, which is strictly worse than either polarity applied whole.
            //
            // Advancing under `View::New` is deliberate and not an oversight: this operator performs no
            // graph read of its own, and the row buffer it serves was produced under whatever polarity
            // each upstream operator owed.
            let mut inner = build_operator(input, arg, ctx)?;
            let mut rows = VecDeque::new();
            while let Some(row) = inner.next(ctx)? {
                rows.push_back(row);
            }
            ctx.graph.begin_command();
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
            // The right branch is a *clone* of the plan's subtree (it is rebuilt per left row), so its
            // nodes are not the plan's nodes. Remember the plan id of its root: before each rebuild the
            // template is re-numbered from it, so every rebuild accumulates into the same counters
            // (`rmp` #752).
            right_id: ctx.profile.as_ref().and_then(|r| r.id_of(right)),
            current_left: None,
            current_right: None,
        }),
        // `rmp` task #869: the semi-join. Built exactly like `NestedLoopJoin` above — same per-row
        // rebuild of a cloned template, same `id_of` capture so a `PROFILE`d run attributes every
        // rebuild to the one plan operator — because the correlation mechanism IS the same. What
        // differs is only how the branch is consumed, and that lives in `Operator::next`.
        PhysicalOp::SemiApply {
            input,
            inner,
            anti,
            predicate: _,
        } => Ok(Operator::SemiApply {
            input: Box::new(build_operator(input, arg, ctx)?),
            inner_template: inner.clone(),
            inner_id: ctx.profile.as_ref().and_then(|r| r.id_of(inner)),
            anti: *anti,
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
        PhysicalOp::ValueHashJoin {
            left,
            right,
            left_key,
            right_key,
        } => {
            // Both sides are independent (no correlation); materialise the join.
            let rows = value_hash_join_rows(left, right, left_key, right_key, arg, ctx)?;
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
            // As for the nested-loop right branch: the body is rebuilt per element from a clone, so its
            // plan id is remembered here and the template re-numbered from it before each rebuild.
            body_id: ctx.profile.as_ref().and_then(|r| r.id_of(body)),
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
            let output_kind = |idx: usize| match sig.outputs[idx].ty.class {
                crate::procedure_registry::ValueClass::Node => ProcOutputKind::Node,
                crate::procedure_registry::ValueClass::Relationship => ProcOutputKind::Rel,
                _ => ProcOutputKind::Plain,
            };
            let bindings: Vec<(String, usize, ProcOutputKind)> = match yields {
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
                        out.push((y.variable.name.clone(), idx, output_kind(idx)));
                    }
                    out
                }
                None => sig
                    .outputs
                    .iter()
                    .enumerate()
                    .map(|(i, o)| (o.name.clone(), i, output_kind(i)))
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

/// The single row a count-store operator emits (`rmp` task #866): `column` bound to `count`, and
/// nothing else.
///
/// Deliberately built from [`Row::empty`] and **not** from the correlation row, because that is exactly
/// what the [`Aggregation`](PhysicalOp::Aggregation) it replaces does: `aggregate_rows` starts each
/// output row empty and sets only the group-key and aggregate aliases, so an ungrouped count yields a
/// one-column row whether or not it sits under an `Apply`. Carrying the correlation row through here
/// would add columns the scan path never produces — a bag difference visible the moment the shape
/// appears inside a `CALL {}` subquery.
///
/// The `u64` counter becomes the `i64` [`Value::Integer`] that `Accumulator::finish` produces for
/// `AggKind::Count` / `AggKind::CountStar`, saturating rather than wrapping (the same convention as
/// `plan_description::clamp`); a live count above `i64::MAX` is unreachable in any storable graph.
fn count_store_row(column: &str, count: u64) -> Operator {
    let mut row = Row::empty();
    row.set(
        column.to_owned(),
        RowValue::Value(Value::Integer(i64::try_from(count).unwrap_or(i64::MAX))),
    );
    Operator::SingleRow {
        emitted: false,
        row,
    }
}

/// Rows for a label scan (each matching node bound to `variable`).
fn label_scan_rows(variable: &Var, label: &Label, ctx: &Ctx<'_>) -> VecDeque<Row> {
    nodes_to_rows(variable, ctx.graph.scan_nodes_by_label(&label.name))
}

/// Sorts `ids` into ascending Cypher `property` order (ties broken by node id) when `ordered` is set,
/// else returns them untouched (`rmp` task #665, part B — provided-order `ORDER BY`).
///
/// This is the executor half of the `Sort`-elision rewrite ([`elide_sort_over_ordered_index`](crate::physical)):
/// an index access marked `ordered` sorts its own candidate set by the property value, so an
/// `ORDER BY property ASC` above it needs no separate [`Sort`](crate::physical::PhysicalOp::Sort). It
/// reads the **current** visible value via `node_property` — the same value the elided `Sort` would
/// have evaluated for its key — so the result is a conforming `ORDER BY property ASC` total order on
/// **every** access path (the indexed seam, the scan fallback, the off-thread reader, the RBAC
/// decorator), independent of the order the candidates were produced in. A missing property is treated
/// as `null`, which the Cypher order ([`crate::ordering::cmp_values`]) ranks last — matching `ORDER BY`
/// semantics (these ops never actually emit a null-valued row, since the seam re-check and the residual
/// filter both drop them, but the fallback is defined regardless).
fn order_hits_if_requested(
    hits: IndexSeekHits,
    property: &str,
    ordered: bool,
    cache: bool,
    ctx: &Ctx<'_>,
) -> Vec<(NodeId, Option<Value>)> {
    let IndexSeekHits {
        matched,
        key_values,
    } = hits;
    // The seam either carried a value for EVERY id or for none (`SeekHits`'s parallel-vector
    // invariant), so this pairing can never mis-align a value with the wrong node.
    let carried = key_values.len() == matched.len();
    let mut keyed: Vec<(NodeId, Option<Value>)> = if carried {
        matched
            .into_iter()
            .zip(key_values.into_iter().map(Some))
            .collect()
    } else {
        matched.into_iter().map(|id| (id, None)).collect()
    };
    if !ordered {
        return keyed;
    }
    // Decorate-sort-undecorate: obtain each node's current property value exactly once (a comparator
    // that re-fetched would be O(n log n) property reads), then sort by (value ASC, node id ASC).
    //
    // `rmp` #879: when the seam already carried that value, this is where the FIRST of the two
    // eliminated reads disappears — the ordering key is the value the seek re-check read, moved (not
    // cloned, not re-read) into the sort. When it did not (the scan fallback), the historical store
    // read still happens, and its result is then good enough to cache: it came from the same fully
    // decorated seam (`ctx.graph`), so it carries the same MVCC visibility, the same RBAC masking and
    // the same SIREAD marker as any other read of that property.
    let mut decorated: Vec<(Value, NodeId)> = keyed
        .into_iter()
        .map(|(id, carried_value)| match carried_value {
            Some(v) => (v, id),
            None => (
                ctx.graph.node_property(id, property).unwrap_or(Value::Null),
                id,
            ),
        })
        .collect();
    decorated.sort_by(|(va, ia), (vb, ib)| crate::ordering::cmp_values(va, vb).then(ia.cmp(ib)));
    keyed = decorated
        .into_iter()
        .map(|(v, id)| (id, cache.then_some(v)))
        .collect();
    keyed
}

/// The seam's carry intent for an operator's plan-time `cached_property` flag (`rmp` task #879).
fn carry_for(cached_property: bool) -> KeyValues {
    if cached_property {
        KeyValues::Carry
    } else {
        KeyValues::Discard
    }
}

/// Wraps node ids into single-binding rows for `variable`.
fn nodes_to_rows(variable: &Var, ids: Vec<NodeId>) -> VecDeque<Row> {
    ids.into_iter()
        .map(|id| Row::from_pairs([(variable.name.clone(), RowValue::Node(NodeRef { id }))]))
        .collect()
}

/// Wraps a single-key node index access path's hits into single-binding rows, stamping each row with
/// the key value the seam already read for it (`rmp` task #879).
///
/// A row with no carried value is byte-identical to what [`nodes_to_rows`] builds, so an operator that
/// does not cache is unaffected — and a later `variable.property` on such a row reads the store, which
/// is the reference behaviour this feature must never diverge from.
fn seek_rows(variable: &Var, property: &str, keyed: Vec<(NodeId, Option<Value>)>) -> VecDeque<Row> {
    // One `(variable, property)` allocation for the whole operator; each row bumps its refcount.
    let key = cached_property_key(&variable.name, property);
    keyed
        .into_iter()
        .map(|(id, value)| {
            let mut row =
                Row::from_pairs([(variable.name.clone(), RowValue::Node(NodeRef { id }))]);
            if let Some(v) = value {
                row.cache_property(std::sync::Arc::clone(&key), id, v);
            }
            row
        })
        .collect()
}

/// The composite twin of [`seek_rows`]: one cache entry **per covered key**, so a later reference to
/// any subset of the composite key is served from the row (`rmp` task #879).
fn composite_seek_rows(
    variable: &Var,
    properties: &[String],
    hits: CompositeSeekHits,
) -> VecDeque<Row> {
    let CompositeSeekHits {
        matched,
        key_values,
    } = hits;
    if key_values.len() != matched.len() {
        return nodes_to_rows(variable, matched); // nothing carried (scan fallback / no cache asked)
    }
    let keys: Vec<_> = properties
        .iter()
        .map(|p| cached_property_key(&variable.name, p))
        .collect();
    matched
        .into_iter()
        .zip(key_values)
        .map(|(id, tuple)| {
            let mut row =
                Row::from_pairs([(variable.name.clone(), RowValue::Node(NodeRef { id }))]);
            // `tuple` is the composite key's values in `properties` order — the seam builds it by
            // reading them in exactly that order, so `zip` cannot mis-pair a key with a value.
            for (key, value) in keys.iter().zip(tuple) {
                row.cache_property(std::sync::Arc::clone(key), id, value);
            }
            row
        })
        .collect()
}

/// The visible relationships matching `types` (empty = any type), **each once** with both endpoints —
/// the enumeration [`Operator::RelScan`] streams (`rmp` task #867).
///
/// Prefers the seam's whole-store relationship scan
/// ([`scan_rels_by_type`](crate::graph_access::GraphAccess::scan_rels_by_type)), which reads the
/// relationship records directly. When the seam declines (`None` — the in-memory reference seam, a
/// restricted RBAC principal, or a storage fault) it falls back to the **reference** enumeration: every
/// node's *outgoing* incidences, which visits each relationship exactly once (a relationship has exactly
/// one start node, and `scan_nodes` yields each node once) and enforces MVCC visibility + RBAC through
/// the very same seam calls the `AllNodesScan` + `ExpandAll` path used.
///
/// Both routes yield the endpoints **without a second record read**: an `Outgoing` expand's anchor *is*
/// the relationship's start node and its `neighbour` the end, and the store scan reads them out of the
/// record it already decoded. The two agree on the *set*; the store scan additionally yields it in
/// ascending physical-id order rather than grouped by start node, which openCypher leaves unconstrained
/// for a pattern with no `ORDER BY`.
fn all_rel_scan(types: &[RelType], ctx: &Ctx<'_>) -> Vec<ScannedRel> {
    let type_names: Vec<String> = types.iter().map(|t| t.name.clone()).collect();
    if let Some(scanned) = ctx.graph.scan_rels_by_type(&type_names) {
        return scanned;
    }
    let mut out = Vec::new();
    for node in ctx.graph.scan_nodes() {
        for inc in ctx
            .graph
            .expand(node, ExpandDirection::Outgoing, &type_names)
        {
            out.push(ScannedRel {
                rel: inc.rel,
                start: node,
                end: inc.neighbour,
            });
        }
    }
    out
}

/// Evaluates a multi-value seek's alternatives and collapses the ones that are the **same Cypher
/// value**, preserving first-seen order (`rmp` task #868).
///
/// # Why the collapse is by value identity and not by Cypher equality
///
/// The obvious reading of "deduplicate by Cypher equality" is unsound, and `rmp` #868 measured it.
/// Cypher `=` compares a mixed `INTEGER`/`FLOAT` pair as `f64` ([`crate::equality`]), so at magnitudes
/// at or above 2^53 it merges values whose Cypher-equal *classes* differ:
/// `9007199254740993 = 9007199254740992.0` is `TRUE`, yet the class of the second also contains
/// `9007199254740992` while the class of the first does not. Collapsing those two alternatives into one
/// descent loses the rows only the other one reaches. Cypher `=` is not even transitive across that
/// boundary, which is also why the caller's final sort+dedup is load-bearing rather than defensive: one
/// node can genuinely match two alternatives that are not equal to each other.
///
/// Deduplicating by the *index key* ([`encode_single`](graphus_index::keycodec::encode_single)) is
/// wrong for the mirror-image reason: that key is **order-preserving**, and ordering is coarser than
/// equality. It folds an `i64` onto its `f64` magnitude, and it projects a `Duration` through an
/// approximate `duration_order_nanos` — so `9007199254740992`/`9007199254740993` and
/// `duration({days: 1})`/`duration({hours: 24})` each share one key while selecting different rows.
///
/// So the relation used here is **value identity** ([`seek_value_identity_key`]): two alternatives
/// collapse only when they are the same value, which makes their descent *and* their per-candidate
/// re-check identical by construction — no reasoning about equality classes required. Cypher-equal
/// alternatives that are *not* the same value (`1` and `1.0`, `0.0` and `-0.0`) simply take one descent
/// each and return the same rows, which the caller's dedup merges — a redundant descent, never a lost
/// row, and never a narrowed SSI footprint.
///
/// The key is hashed, so the loop is O(k) with no adversarial bucket, and an unencodable value —
/// `Null`, `List`, `Map` — never collapses at all. Not collapsing costs nothing: such a value makes the
/// seam decline and [`multi_index_seek_eq`] then abandons the union as a whole.
fn distinct_seek_values(values: &[Expr], ctx: &Ctx<'_>) -> Result<Vec<Value>, ExecError> {
    use std::collections::HashSet;

    let empty = Row::empty();
    let mut distinct: Vec<Value> = Vec::with_capacity(values.len());
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    for expr in values {
        // The alternatives are attacker-controlled in both count and content, and this whole operator
        // is built before the first `next()` — so poll the statement deadline here, or a long list
        // would burn CPU with no cancellation safe point (`rmp` #476).
        ctx.check_cancelled()?;
        let value = eval_value(
            expr,
            &empty,
            ctx.params,
            ctx.graph,
            ctx.functions,
            &ctx.clock,
        )?;
        // A repeated identity key means an earlier alternative already issues this exact descent.
        if let Some(key) = seek_value_identity_key(&value)
            && !seen.insert(key)
        {
            continue;
        }
        distinct.push(value);
    }
    Ok(distinct)
}

/// The value-identity key [`distinct_seek_values`] collapses on, or [`None`] for a value that must
/// never be collapsed (`rmp` task #868).
///
/// Two alternatives may be collapsed **only** when they are the same Cypher value, so the key has to be
/// *injective*: distinct values must never share one. Three classes need an explicit arm because their
/// `encode_single` key is deliberately **not** injective — it is an *ordering* key, and ordering is
/// coarser than equality:
///
/// * **`Integer`** — the order key folds an `i64` onto its `f64` magnitude, so `9007199254740992` and
///   `9007199254740993` share one key while selecting different rows. Keyed on the exact `i64` bits.
/// * **`Float`** — keyed on the exact bit pattern. `-0.0` and `+0.0` are deliberately **not** merged
///   even though Cypher `=` calls them equal: they encode to distinct SSI equality markers
///   ([`crate::read_source`] via `encode_equality_canonical`), so merging them would register one
///   marker where two are needed and let a concurrent `CREATE {p: -0.0}` escape a reader of `= 0.0`.
///   Two descents, one extra index probe, no narrowing of the read footprint.
/// * **`Duration`** — the order key is `duration_order_nanos`, an *approximate* projection
///   ([`graphus_index::keycodec`] documents that "equality remains strictly component-wise"), so
///   `duration({days: 1})` and `duration({hours: 24})` share one key and are **not** Cypher-equal.
///   Collapsing them lost every row the dropped alternative matched — the `rmp` #738 defect class, and
///   a real one: measured as a multi-seek returning `[1]` where the scan returned `[1, 2]`. Keyed on
///   the exact `(months, days, seconds, nanos)` tuple.
///
/// Every remaining class (`Boolean`, `String`, `Bytes`, `Date`, `LocalTime`, `ZonedTime`,
/// `LocalDateTime`, `ZonedDateTime`, `Point`) has an exact `encode_single` key and uses it directly.
/// `Null` / `List` / `Map` fail to encode and return [`None`]: they are never collapsed, which costs
/// nothing because they make the seam decline anyway.
fn seek_value_identity_key(value: &Value) -> Option<Vec<u8>> {
    let mut key = Vec::with_capacity(40);
    match value {
        Value::Integer(i) => {
            key.push(0u8);
            key.extend_from_slice(&i.to_be_bytes());
        }
        Value::Float(f) => {
            key.push(1u8);
            key.extend_from_slice(&f.to_bits().to_be_bytes());
        }
        Value::Duration(d) => {
            key.push(3u8);
            key.extend_from_slice(&d.months.to_be_bytes());
            key.extend_from_slice(&d.days.to_be_bytes());
            key.extend_from_slice(&d.seconds.to_be_bytes());
            key.extend_from_slice(&d.nanos.to_be_bytes());
        }
        other => {
            key.push(2u8);
            key.extend_from_slice(&graphus_index::keycodec::encode_single(other).ok()?);
        }
    }
    Some(key)
}

/// The union of one [`index_seek_eq`](crate::graph_access::GraphAccess::index_seek_eq) descent per
/// value, or [`None`] if **any** single value declines (`rmp` task #868).
///
/// # The whole-or-nothing decline contract (`rmp` #738 / #680)
///
/// The seam answers `None` for *"no usable index — take the exact scan"* and `Some(vec![])` for *"the
/// index is registered and nothing matches"*. Silently dropping a declining value from the union would
/// lose exactly the rows that value matched — a wrong answer, and the defect class `rmp` #738 named. The
/// `?` below is what makes that unexpressible: on the first decline the partially built `ids` is
/// **dropped** with the function's stack frame and the caller takes the exact scan for every value. There
/// is no code path that returns a filtered subset of the requested values.
///
/// Note this introduces no new seam and does not touch `index_seek_eq` itself, so every other caller of
/// it — including [`RecordStoreGraph::unique_conflict`](crate::record_graph), the UNIQUE / NODE KEY
/// constraint duplicate check, which has its own single-value scan fallback on `None` — is byte-identical
/// to before this task.
fn multi_index_seek_eq(
    label: &str,
    property: &str,
    values: &[Value],
    ctx: &Ctx<'_>,
) -> Result<Option<Vec<NodeId>>, ExecError> {
    let mut ids: Vec<NodeId> = Vec::new();
    for value in values {
        // `k` is attacker-controlled and this operator is built before the first `next()`, so poll the
        // statement deadline per descent (`rmp` #476).
        ctx.check_cancelled()?;
        // `KeyValues::Discard` (`rmp` #879): the multi-value union is out of this task's scope — one
        // id can arrive from two descents, so the operator would have to reconcile two carried values
        // before it could cache one. Declining to carry is always correct; the union reads the store.
        let Some(hit) = ctx
            .graph
            .index_seek_eq(label, property, value, KeyValues::Discard)
        else {
            // The WHOLE union is abandoned: the partially built `ids` dies with this `return`.
            return Ok(None);
        };
        ids.extend(hit.matched);
    }
    Ok(Some(ids))
}

/// The relationship analogue of [`multi_index_seek_eq`]: the union of one
/// [`index_seek_rel_eq`](crate::graph_access::GraphAccess::index_seek_rel_eq) descent per value, or
/// [`None`] if **any** single value declines (`rmp` task #868). The same `?` makes a partial union
/// unexpressible.
fn multi_index_seek_rel_eq(
    rel_type: &str,
    property: &str,
    values: &[Value],
    ctx: &Ctx<'_>,
) -> Result<Option<Vec<RelId>>, ExecError> {
    let mut ids: Vec<RelId> = Vec::new();
    for value in values {
        ctx.check_cancelled()?;
        let Some(hit) = ctx.graph.index_seek_rel_eq(rel_type, property, value) else {
            return Ok(None);
        };
        ids.extend(hit);
    }
    Ok(Some(ids))
}

/// Whether `value` is Cypher-equal to **at least one** of `values` — the positive half of the `IN`
/// predicate ([`crate::equality::is_in`]'s `TRUE` case), used by the multi-value seeks' whole-union
/// scan fallback (`rmp` task #868).
///
/// A linear scan with short-circuit, exactly the fold `is_in` performs, so the fallback does precisely
/// the work the pre-#868 `Filter(n.p IN [...])` over a scan did — and no hash structure is built, so
/// there is no adversarially-collidable bucket on this path.
fn matches_any_value(value: &Value, values: &[Value]) -> bool {
    values
        .iter()
        .any(|seek| crate::equality::equals(value, seek).is_true())
}

/// The whole-union scan fallback for a [`NodeIndexMultiSeek`](crate::physical::PhysicalOp::NodeIndexMultiSeek)
/// (`rmp` task #868): the visible nodes of `label` whose current `property` is Cypher-equal to any of
/// `values`.
///
/// **One** label scan, not one per value. Calling the single-value [`scan_filter_eq`] `k` times would
/// re-scan the whole label `k` times — a `k`-fold amplification over the `scan + IN filter` plan this
/// operator replaced, reachable by any client that puts one unencodable element (a `null`, a list) in
/// the list, and unavoidable for a restricted RBAC principal on the relationship path. This does the
/// identical work the pre-#868 plan did.
///
/// **RBAC** composes exactly as it did before this task: `scan_nodes_by_label` and `node_property` are
/// both `AuthorizedGraph`-decorated, so a non-traversable node never appears and a `DENY READ` on
/// `property` masks its value to `null`, which is Cypher-equal to nothing and so drops the row.
/// **SSI**: a label scan registers the blanket `Label` + every-live-node footprint, a strict superset
/// of the `k` precise `Equality` markers the served union registers — conservative, never a phantom.
fn scan_filter_in(label: &Label, property: &str, values: &[Value], ctx: &Ctx<'_>) -> Vec<NodeId> {
    ctx.graph
        .scan_nodes_by_label(&label.name)
        .into_iter()
        .filter(|&id| {
            ctx.graph
                .node_property(id, property)
                .is_some_and(|v| matches_any_value(&v, values))
        })
        .collect()
}

/// The relationship twin of [`scan_filter_in`] (`rmp` task #868): the visible relationships of
/// `rel_type` whose current `property` is Cypher-equal to any of `values`, **each id once**.
///
/// Shares [`rel_scan_ids_where`] with the single-value [`rel_scan_filter_eq_ids`], so the enumeration
/// — and therefore the visibility, RBAC and self-loop-deduplication semantics — is identical; only the
/// `keep` predicate widens from one value to the set. One pass, for the reason given on
/// [`scan_filter_in`]: this path is taken on **every** relationship multi-seek a restricted principal
/// issues, since `AuthorizedGraph::index_seek_rel_eq` declines outright for them.
fn rel_scan_filter_in_ids(
    rel_type: &str,
    property: &str,
    values: &[Value],
    ctx: &Ctx<'_>,
) -> Vec<RelId> {
    rel_scan_ids_where(rel_type, ctx, |rel| {
        ctx.graph
            .rel_property(rel, property)
            .is_some_and(|v| matches_any_value(&v, values))
    })
}

/// Sorts `ids` ascending and removes duplicates — the emission shape a multi-value seek shares with the
/// single-value seek it generalises (`rmp` task #868). Generic over the id type so the node and
/// relationship operators use one implementation.
fn sorted_deduped<T: Ord>(mut ids: Vec<T>) -> Vec<T> {
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Precise equality access (`rmp` task #325): the seam's `scan_filter_eq` reads every node to evaluate
/// the predicate but registers an SSI read dependency on **only the matching nodes** plus the precise
/// `Equality` predicate marker — the scan-path twin of `index_seek_eq`'s footprint. This replaces the
/// old fallback that ran `scan_nodes_by_label` (marking every live node) + a residual filter, whose
/// blanket marker produced reciprocal false aborts between transactions matching disjoint keys.
fn scan_filter_eq(label: &Label, property: &str, seek: &Value, ctx: &Ctx<'_>) -> Vec<NodeId> {
    // The seam also reports how many records it EXAMINED (`rmp` #752 — a `PROFILE`'s `dbHits` for this
    // fused scan+filter); the executor itself needs only the matches.
    ctx.graph
        .scan_filter_eq(&label.name, property, seek)
        .matched
}

/// Materialises a re-checked relationship-id set into rows for a
/// [`RelIndexSeek`](crate::physical::PhysicalOp::RelIndexSeek) (`rmp` task #659): binds `relationship`
/// plus both endpoints from each relationship's own record, honouring the pattern `direction`.
///
/// This reproduces **exactly** the row multiset the scan-path `Filter`-over-`ExpandAll`-over-
/// `AllNodesScan` produced. A directed pattern binds one orientation per relationship; an **undirected**
/// pattern binds **both** orientations — `(start, end)` and `(end, start)` — because an `ExpandAll` over
/// every anchor surfaces each non-self relationship once from each endpoint. A **self-loop**
/// (`start == end`) an `ExpandAll` reports once per anchor, so it binds a single row here too. Each id is
/// re-read via [`rel_data`](crate::graph_access::GraphAccess::rel_data), which also SIREAD-marks it and
/// drops any relationship no longer visible (defensive — the seam's candidates are already
/// visibility-re-checked; the scan fallback re-checks here).
fn rel_ids_to_rows(
    relationship: &Var,
    from: &Var,
    to: &Var,
    direction: RelDirection,
    ids: Vec<RelId>,
    ctx: &Ctx<'_>,
) -> Result<VecDeque<Row>, ExecError> {
    let shape = RelRowTemplate::require(from, relationship, to)?;
    let mut out = VecDeque::new();
    for rel in ids {
        let Some(data) = ctx.graph.rel_data(rel) else {
            continue; // no longer visible (defensive)
        };
        push_rel_rows(&mut out, &shape, direction, rel, data.start, data.end);
    }
    Ok(out)
}

/// Appends the row(s) one relationship contributes under the pattern arrow — **the single copy of the
/// orientation rule** shared by every relationship-producing operator (the index seeks via
/// [`rel_ids_to_rows`], the relationship-type scan via [`Operator::RelScan`]; `rmp` task #867).
///
/// `start`/`end` are the relationship's **stored** endpoints; the arrow decides how they are bound:
/// `->` binds `(start, end)`, `<-` binds `(end, start)`, and `-` (undirected) binds **both**
/// orientations — one row each — except for a **self-loop** (`start == end`), which binds a single row.
/// That is exactly what the `ExpandAll`-over-`AllNodesScan` scan path produces: it surfaces each
/// non-self relationship once from each endpoint's expansion, and a self-loop once per anchor (deduped
/// by `Operator::Expand`'s per-anchor `seen_rel` set, and a self-loop has only one anchor).
///
/// # Why this rule lives in ONE place (`rmp` task #867)
///
/// It used to live in two. While `AllRelationshipsScan` was unreachable from any query, its
/// materialisation bound only the canonical `(start, end)` orientation for an undirected pattern — one
/// row per relationship — so `MATCH ()-[r]-() RETURN count(r)` would have silently **halved** the moment
/// the lowerer started emitting it. The bug was invisible precisely because the operator was dead code
/// and the (correct) seek copy of the rule was the only one ever exercised.
fn push_rel_rows(
    out: &mut VecDeque<Row>,
    shape: &RelRowTemplate,
    direction: RelDirection,
    rel: RelId,
    start: NodeId,
    end: NodeId,
) {
    match direction {
        RelDirection::LeftToRight => out.push_back(shape.row(start, rel, end)),
        RelDirection::RightToLeft => out.push_back(shape.row(end, rel, start)),
        RelDirection::Undirected => {
            out.push_back(shape.row(start, rel, end));
            if start != end {
                out.push_back(shape.row(end, rel, start));
            }
        }
    }
}

/// The pre-built `{from, relationship, to}` row shape every relationship-binding operator emits
/// (`rmp` task #659; the template technique is `rmp` #364's, lifted here by `rmp` task #867).
///
/// Building each row from [`Row::empty`] + three `set`s re-derives the schema per row — three name
/// clones and an `Arc` schema construction each time. Deriving the shape **once** and then cloning it
/// (an `Arc` bump) with three `set_at` writes by index is what `Operator::Expand` already does for its
/// per-edge rows; a whole-store relationship scan emits one row per relationship (two for an undirected
/// pattern), so it is exactly as hot.
struct RelRowTemplate {
    /// The shape, with placeholder values.
    template: Row,
    /// Column index of the source endpoint.
    from_idx: usize,
    /// Column index of the relationship.
    rel_idx: usize,
    /// Column index of the target endpoint.
    to_idx: usize,
}

impl RelRowTemplate {
    /// Derives the shape for the three variables, or [`None`] when they are **not distinct**.
    ///
    /// # Why this is fallible rather than asserted
    ///
    /// A pattern naming both endpoints the same variable (`MATCH (a)-[r:T]->(a)`) is a *connection
    /// check*, which no relationship-binding operator can serve: it materialises `from` and `to` as two
    /// independent columns, so one shared name collapses `from_idx == to_idx` and the second `set_at`
    /// overwrites the first — the `start == end` constraint silently vanishes and the operator returns
    /// rows the pattern excludes. That is exactly the pre-existing defect `rmp` task #867 found and fixed
    /// in the relationship seeks, so it must not be able to come back.
    ///
    /// The planner declines the shape upstream twice over — `fold_rel_scan_filter_chain` rejects
    /// `from.name == to.name` before building any seek, and `relationship_scan_link`'s
    /// anonymous-endpoint precondition makes it structurally unreachable for the scan — so this returns
    /// `None` for no query the planner can currently produce. It is nevertheless a **hard, always
    /// compiled** check rather than a `debug_assert!`: an assertion that vanishes in release turns a
    /// future planner mistake into a silent wrong answer in production and a green test suite in debug.
    /// Callers turn `None` into a runtime error, so the failure is loud.
    fn new(from: &Var, relationship: &Var, to: &Var) -> Option<Self> {
        if from.name == to.name || from.name == relationship.name || to.name == relationship.name {
            return None;
        }
        let mut template = Row::empty();
        template.set(from.name.clone(), RowValue::Node(NodeRef { id: NodeId(0) }));
        template.set(
            relationship.name.clone(),
            RowValue::Rel(RelRef { id: RelId(0) }),
        );
        template.set(to.name.clone(), RowValue::Node(NodeRef { id: NodeId(0) }));
        let index = |name: &str| {
            template
                .schema()
                .index_of_pub(name)
                .expect("INVARIANT: the column was just set on the template")
        };
        let (from_idx, rel_idx, to_idx) = (
            index(&from.name),
            index(&relationship.name),
            index(&to.name),
        );
        Some(Self {
            template,
            from_idx,
            rel_idx,
            to_idx,
        })
    }

    /// [`new`](Self::new), turning the decline into a loud runtime error naming the invariant.
    ///
    /// Every construction site is inside `build_operator_unprofiled`, which already returns
    /// [`ExecError`] — so failing the statement costs no new plumbing and is strictly better than the
    /// alternative it replaces (a wrong result bag).
    fn require(from: &Var, relationship: &Var, to: &Var) -> Result<Self, ExecError> {
        Self::new(from, relationship, to).ok_or_else(|| {
            ExecError::Eval(EvalError::TypeError {
                context: format!(
                    "a relationship operator must bind three distinct variables, got \
                     from={}, relationship={}, to={} (`rmp` task #867)",
                    from.name, relationship.name, to.name
                ),
            })
        })
    }

    /// One row binding the given endpoint / relationship / endpoint ids.
    fn row(&self, f: NodeId, rel: RelId, t: NodeId) -> Row {
        let mut row = self.template.clone();
        row.set_at(self.from_idx, RowValue::Node(NodeRef { id: f }));
        row.set_at(self.rel_idx, RowValue::Rel(RelRef { id: rel }));
        row.set_at(self.to_idx, RowValue::Node(NodeRef { id: t }));
        row
    }
}

/// The scan fallback for a [`RelIndexSeek`](crate::physical::PhysicalOp::RelIndexSeek) when the seam
/// exposes no usable relationship-property index (the off-thread reader, or an index dropped since
/// planning): the visible relationship ids of `rel_type` whose current `property` equals `seek` by
/// Cypher equality, **each id once** (`rmp` task #659).
///
/// Enumerates every relationship of the type from its start node (one incidence each) through the same
/// [`scan_nodes`](crate::graph_access::GraphAccess::scan_nodes) / [`expand`](crate::graph_access::GraphAccess::expand)
/// / [`rel_property`](crate::graph_access::GraphAccess::rel_property) seam the scan-path `ExpandAll` would,
/// so MVCC visibility and RBAC (relationship-type traversal + per-property read grants) are applied
/// identically. [`rel_ids_to_rows`] then applies the pattern direction to the returned set, yielding the
/// same rows the scan path would.
fn rel_scan_filter_eq_ids(
    rel_type: &str,
    property: &str,
    seek: &Value,
    ctx: &Ctx<'_>,
) -> Vec<RelId> {
    rel_scan_ids_where(rel_type, ctx, |rel| {
        ctx.graph
            .rel_property(rel, property)
            .is_some_and(|v| crate::equality::equals(&v, seek).is_true())
    })
}

/// The scan fallback for a [`RelIndexRangeSeek`](crate::physical::PhysicalOp::RelIndexRangeSeek) when
/// the seam exposes no usable relationship-property index — the off-thread reader, a **restricted** RBAC
/// principal (the [`AuthorizedGraph`](crate::authorized_graph::AuthorizedGraph) decorator declines the
/// raw seek), a `Populating` index (`rmp` #733), or one dropped since planning: the visible relationship
/// ids of `rel_type` whose current `property` satisfies the range bound, **each id once**
/// (`rmp` task #680).
///
/// The range analogue of [`rel_scan_filter_eq_ids`], sharing its enumeration ([`rel_scan_ids_where`]) so
/// MVCC visibility and RBAC compose identically. The predicate is evaluated by
/// [`crate::eval::satisfies_range`] — the same function the seam's per-candidate re-check applies — so
/// the seek and this fallback are **bag-equivalent** (the operator *consumes* the range conjunct, so
/// this fallback, not a residual `Filter`, is what restores exactness).
fn rel_scan_filter_range_ids(
    rel_type: &str,
    property: &str,
    bound: RangeBound,
    value: &Value,
    ctx: &Ctx<'_>,
) -> Vec<RelId> {
    let (lower, upper) = range_bounds(bound, value);
    rel_scan_ids_where(rel_type, ctx, |rel| {
        ctx.graph
            .rel_property(rel, property)
            .is_some_and(|v| crate::eval::satisfies_range(&v, lower, upper))
    })
}

/// Enumerates the visible relationships of `rel_type` **once each** and keeps those satisfying `keep` —
/// the single shared enumeration behind every relationship-seek scan fallback (`rmp` tasks #659, #664,
/// #666, #680).
///
/// Walks each relationship from its start node (one outgoing incidence per relationship) through the
/// same [`scan_nodes`](crate::graph_access::GraphAccess::scan_nodes) /
/// [`expand`](crate::graph_access::GraphAccess::expand) seam the scan-path `ExpandAll` would, so MVCC
/// visibility and RBAC (relationship-type traversal + per-property read grants, applied inside `keep`'s
/// [`rel_property`](crate::graph_access::GraphAccess::rel_property) reads) are enforced identically.
/// [`rel_ids_to_rows`] then applies the pattern direction to the returned set, yielding the same rows
/// the scan path would. The `seen` set is what makes a relationship whose endpoints are both scanned
/// appear exactly once (the seek's candidate set is likewise de-duplicated).
fn rel_scan_ids_where(
    rel_type: &str,
    ctx: &Ctx<'_>,
    mut keep: impl FnMut(RelId) -> bool,
) -> Vec<RelId> {
    let types = [rel_type.to_owned()];
    let mut seen = rustc_hash::FxHashSet::default();
    let mut ids = Vec::new();
    for node in ctx.graph.scan_nodes() {
        for inc in ctx.graph.expand(node, ExpandDirection::Outgoing, &types) {
            if !seen.insert(inc.rel) {
                continue;
            }
            if keep(inc.rel) {
                ids.push(inc.rel);
            }
        }
    }
    ids
}

/// The scan fallback for a
/// [`RelCompositeIndexSeek`](crate::physical::PhysicalOp::RelCompositeIndexSeek) when the seam exposes
/// no usable composite relationship index (the off-thread reader, or an index dropped since planning):
/// the visible relationship ids of `rel_type` whose current value of **every** key equals the
/// corresponding seek value by Cypher equality, **each id once** (`rmp` task #666).
///
/// The composite analogue of [`rel_scan_filter_eq_ids`]: it enumerates each relationship of the type
/// once (from its start node) through the same
/// [`scan_nodes`](crate::graph_access::GraphAccess::scan_nodes) /
/// [`expand`](crate::graph_access::GraphAccess::expand) /
/// [`rel_property`](crate::graph_access::GraphAccess::rel_property) seam the scan-path `ExpandAll`
/// would, so MVCC visibility and RBAC compose identically, then keeps only those matching the full
/// tuple. [`rel_ids_to_rows`] applies the pattern direction to the returned set.
fn rel_scan_filter_composite_eq_ids(
    rel_type: &str,
    properties: &[String],
    values: &[Value],
    ctx: &Ctx<'_>,
) -> Vec<RelId> {
    rel_scan_ids_where(rel_type, ctx, |rel| {
        properties
            .iter()
            .zip(values.iter())
            .all(|(property, value)| {
                ctx.graph
                    .rel_property(rel, property)
                    .is_some_and(|v| crate::equality::equals(&v, value).is_true())
            })
    })
}

/// The scan fallback for a [`RelSpatialIndexSeek`](crate::physical::PhysicalOp::RelSpatialIndexSeek)
/// when the seam exposes no usable relationship spatial index (the off-thread reader, or an index
/// dropped since planning): the visible relationship ids of `rel_type`, **each id once** (`rmp` task
/// #664).
///
/// Enumerates every relationship of the type from its start node (one incidence each) through the same
/// [`scan_nodes`](crate::graph_access::GraphAccess::scan_nodes) /
/// [`expand`](crate::graph_access::GraphAccess::expand) seam the scan-path `ExpandAll` would, so MVCC
/// visibility and RBAC (relationship-type traversal) are applied identically. Unlike
/// [`rel_scan_filter_eq_ids`] it applies **no** property filter — the residual `distance(...) <op> r`
/// filter above the operator does the exact trimming, so this need only return the typed candidate set.
/// [`rel_ids_to_rows`] then applies the pattern direction, yielding the same rows the scan path would.
fn rel_scan_typed_ids(rel_type: &str, ctx: &Ctx<'_>) -> Vec<RelId> {
    rel_scan_ids_where(rel_type, ctx, |_| true)
}

/// Fallback composite (multi-property) equality access (`rmp` task #657): scan the label and keep
/// nodes whose current value of **every** key equals the corresponding seek value by Cypher equality.
///
/// The path taken when the [`GraphAccess`](crate::graph_access::GraphAccess) seam has no usable
/// composite index (`index_seek_composite_eq` returned `None`) — a reference / off-thread read graph.
/// The composite [`NodeCompositeIndexSeek`](crate::physical::PhysicalOp::NodeCompositeIndexSeek)
/// operator **consumes** the equality conjuncts (they are not re-attached as a residual filter), so
/// this fallback must apply the full per-key equality predicate itself.
fn scan_filter_composite_eq(
    label: &Label,
    properties: &[String],
    values: &[Value],
    ctx: &Ctx<'_>,
) -> Vec<NodeId> {
    ctx.graph
        .scan_nodes_by_label(&label.name)
        .into_iter()
        .filter(|id| {
            properties
                .iter()
                .zip(values.iter())
                .all(|(property, value)| {
                    ctx.graph
                        .node_property(*id, property)
                        .is_some_and(|v| crate::equality::equals(&v, value).is_true())
                })
        })
        .collect()
}

/// Fallback range access: scan the label and keep nodes whose property satisfies the range bound.
///
/// The predicate is evaluated by [`crate::eval::satisfies_range`] — the **single source of truth** for
/// `<`/`<=`/`>`/`>=`, shared with the index seek's per-candidate re-check — so this fallback and the
/// [`NodeIndexRangeSeek`](crate::physical::PhysicalOp::NodeIndexRangeSeek) it stands in for return the
/// identical node set (`rmp` task #680).
fn scan_filter_range(
    label: &Label,
    property: &str,
    bound: RangeBound,
    value: &Value,
    ctx: &Ctx<'_>,
) -> Vec<NodeId> {
    let (lower, upper) = range_bounds(bound, value);
    ctx.graph
        .scan_nodes_by_label(&label.name)
        .into_iter()
        .filter(|id| {
            ctx.graph
                .node_property(*id, property)
                .is_some_and(|v| crate::eval::satisfies_range(&v, lower, upper))
        })
        .collect()
}

/// The exclusive upper bound for a `STARTS WITH prefix` range seek (`rmp` task #658): the shortest
/// string strictly greater than **every** string beginning with `prefix`, so that `[prefix,
/// successor)` covers exactly the prefix set under Cypher string order (Unicode code point ==
/// UTF-8 byte-lexicographic — the order [`cmp_values`](crate::ordering::cmp_values) and the
/// order-preserving property-index keycodec both use).
///
/// Computed by incrementing the **last** Unicode scalar of `prefix`; if that scalar is the maximum
/// (`U+10FFFF`) it **carries** — the trailing max scalar(s) are dropped and the preceding scalar is
/// incremented (`"a\u{10FFFF}"` -> `"b"`). Returns `None` when no finite successor exists (an empty
/// prefix, or a prefix of only `U+10FFFF` scalars); the caller then seeks with an open upper bound,
/// which is still a correct superset since the residual `STARTS WITH` filter restores exactness.
pub(crate) fn string_prefix_successor(prefix: &str) -> Option<String> {
    let mut chars: Vec<char> = prefix.chars().collect();
    while let Some(last) = chars.pop() {
        if let Some(next) = next_scalar(last) {
            let mut out: String = chars.into_iter().collect();
            out.push(next);
            return Some(out);
        }
        // `last` is `U+10FFFF`: it has been popped (the carry); retry with the preceding scalar.
    }
    None
}

/// The next Unicode scalar value after `c`, skipping the surrogate gap (`U+D800..=U+DFFF` are not
/// scalar values), or `None` if `c` is the maximum scalar `U+10FFFF`.
fn next_scalar(c: char) -> Option<char> {
    let mut n = c as u32 + 1;
    while n <= 0x10_FFFF {
        if let Some(ch) = char::from_u32(n) {
            return Some(ch);
        }
        n += 1; // step over the UTF-16 surrogate range (never valid `char`s)
    }
    None
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
    recognize_mergeable_bare_agg_vars(expr, &[scan_var])
}

/// The multi-variable form of [`recognize_mergeable_bare_agg`] (`rmp` task #558 / #340): whether `expr`
/// is a **bare, mergeable** aggregate whose single argument is pure per-row and references **at least one**
/// of `vars`. The grouped-over-expand tier passes the three expansion-row variables (`from`/`relationship`
/// /`to`), so an aggregate over any of them (e.g. `sum(l.weight)`, `count(b)`) is admitted, while a
/// constant-/param-only argument is still left to serial. The single-var
/// [`recognize_mergeable_bare_agg`] delegates here with a one-element slice, so its callers are unchanged.
fn recognize_mergeable_bare_agg_vars(expr: &Expr, vars: &[&str]) -> Option<bool> {
    match &expr.kind {
        // `count(*)`: pure i64 increment, always mergeable, no integer gate.
        ExprKind::CountStar => Some(false),
        ExprKind::FunctionCall {
            name,
            distinct,
            args,
        } => {
            let fname = name.join(".").to_ascii_lowercase();
            // Exactly one argument referencing one of `vars` (`count`/`sum`/`min`/`max`/`collect` are
            // single-argument); the argument must be pure per-row so the off-thread eval is deterministic
            // and cross-row-free, AND must reference a row variable (a constant-/param-only aggregate
            // argument is unusual and left to serial).
            let [arg] = args.as_slice() else {
                return None;
            };
            if !crate::morsel::is_pure_per_row_expr(arg) || !expr_references_any_var(arg, vars) {
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

/// Whether `expr` syntactically references **any** of `vars` (its property, or the bare variable) — the
/// multi-variable form of [`expr_references_var`] used by the grouped-over-expand recognizer to confirm a
/// group key / aggregate argument is anchored on one of the expansion-row variables (`rmp` task #558).
fn expr_references_any_var(expr: &Expr, vars: &[&str]) -> bool {
    vars.iter().any(|v| expr_references_var(expr, v))
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
        ExprKind::HasLabels { operand, .. }
        | ExprKind::TypePredicate { operand, .. }
        | ExprKind::NormalizedPredicate { operand, .. } => expr_references_var(operand, var),
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
        // Comprehensions / quantifiers / reduce / map projections / subqueries are rejected by the
        // purity gate before this is reached, so a conservative `false` is fine (the column already
        // declined).
        ExprKind::ListComprehension(_)
        | ExprKind::PatternComprehension(_)
        | ExprKind::Quantifier(_)
        | ExprKind::Reduce(_)
        | ExprKind::MapProjection(_)
        | ExprKind::ExistsSubquery(_)
        | ExprKind::CountSubquery(_)
        | ExprKind::CollectSubquery(_) => false,
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

/// If `(input, group_keys, aggregates)` is the **morsel-parallel-eligible grouped-aggregation-over-expand
/// shape** — a large `MATCH (a:Label)-[r(:T…)?]->(b) [WHERE <pure residual>] WITH <bare pure group keys>,
/// <bare mergeable aggregates>` (`rmp` task #558 / #340, the `top_liked` class:
/// `MATCH (:USER)-[:LIKE]->(a:ARTICLE) WITH a, count(*) AS likes …`) — partitions the **anchors** into
/// contiguous morsels, expands + filters + groups + aggregates each anchor's single hop **concurrently**
/// on the dedicated morsel pool (each over a `Send` [`ReadOnlyGraph`]), merges the partial group tables
/// deterministically on the engine thread (serial first-seen order), and returns the grouped rows.
/// Otherwise returns `None` so the caller falls through to the bare-scan grouped / keyless tiers and then
/// the serial [`aggregate_rows`], all of which run **verbatim**.
///
/// This is the fusion of the Slice-3c per-anchor `ExpandAll` (parallelizing the traversal) and the #360
/// grouped merge (parallelizing the group-by), which together cover the shape both those tiers **decline**:
/// #360 requires a bare scan directly under the `Aggregation` (an interposed `Filter` / `Expand` declines),
/// and Slice-3c only handles a single-group `count(*)` over the expand. The planner shapes the class as
/// `Aggregation → [Filter →] ExpandAll → NodeByLabelScan` (empirically confirmed: the far-endpoint label
/// `(a:ARTICLE)` lowers to an interposed `Filter(a:ARTICLE)`), which this tier peels.
///
/// # Byte-identical to serial, by construction
///
/// * **Same rows** — each morsel expands a *contiguous* anchor slice through the **same** lifted
///   `read_source::expand` body the serial `Operator::Expand` runs (self-loops deduplicated per anchor by
///   relationship id), applies the residual filter under the **same** three-valued logic, and folds the
///   surviving `(a, r, b)` rows — so the multiset of grouped rows is identical;
/// * **Same grouping** — each morsel keys its local table on the SAME SipHash digest ([`group_key_hash`])
///   plus the [`row_values_equivalent`] resolution serial's `aggregate_rows` uses (the engine-thread merge
///   re-keys identically);
/// * **Same values / visibility / SSI markers** — each morsel reads through the identical MVCC read body
///   and evaluates the filter / keys / aggregate arguments with the identical [`eval`]; the coarse
///   `PredicateRead::Label` + all-live-nodes footprint is registered on the engine thread by the seam, and
///   each morsel's per-anchor label-scan + per-edge + per-row property/label markers fold back via
///   `merge_morsel_buffer` (union = the serial scan→expand→filter marker set);
/// * **Same arithmetic** — every morsel folds into the SAME [`Accumulator`] the serial path uses; the
///   merge combines via [`Accumulator::combine`] (associative for `count`/`sum`/`min`/`max`,
///   order-preserving ascending-`lo` for `collect`/`DISTINCT`); `sum` is gated to a **no-overflow integer**
///   column; `avg` / percentile decline;
/// * **Same output order** — the merge emits groups sorted by global first-seen rank (over the SURVIVING
///   post-filter expansion rows — the serial first-seen rank space), **independent of the worker count**.
///
/// # Eligibility (ALL required, else `None`)
/// - the morsel knob is enabled: [`Ctx::morsel_threads`] `> 1`;
/// - `input` is a fixed-length fresh single-hop `ExpandAll` over a bare label scan, optionally wrapped in a
///   **single** `Filter` whose predicate is **pure per-row** ([`crate::morsel::is_pure_per_row_expr`]);
/// - there is **at least one** group key (the keyless single-`count` case is [`try_morsel_expand_aggregate`]
///   above), every group key is pure per-row and references an expansion-row variable
///   (`from`/`relationship`/`to`);
/// - every aggregate column is a **bare mergeable** aggregate over the expansion-row variables
///   ([`recognize_mergeable_bare_agg_vars`]);
/// - the estimated anchor-label cardinality is at least
///   [`MORSEL_MIN_ROWS`](crate::morsel::MORSEL_MIN_ROWS) (via `statistics().nodes_with_label`; no
///   statistics ⇒ decline);
/// - if any `sum` is requested, the merged column is provably **no-overflow integer** (checked after the
///   read, as #360);
/// - the seam returns `Some` from [`GraphAccess::morsel_label_scan`] (it declines for a restricted
///   principal — so per-relationship/endpoint RBAC is never bypassed by the off-thread expand — a
///   standalone / historical read, and `MemGraph`).
///
/// On any per-morsel error the tier discards every morsel's groups + buffers and returns `None`; the serial
/// fallback re-runs the pipeline, re-registering the markers and re-raising the identical error.
fn try_morsel_expand_group_aggregate(
    input: &PhysicalOp,
    group_keys: &[ProjectionColumn],
    aggregates: &[ProjectionColumn],
    ctx: &mut Ctx<'_>,
) -> Result<Option<VecDeque<Row>>, ExecError> {
    // --- cheap gate first (no seam work): the morsel knob must be enabled (>= 2 workers) ---
    if ctx.morsel_threads <= 1 {
        return Ok(None);
    }

    // --- recognize the GROUPED-over-expand shape: >= 1 group key, >= 1 aggregate ---
    if group_keys.is_empty() || aggregates.is_empty() {
        return Ok(None);
    }

    // Peel an optional interposed `Filter` (the far-endpoint label predicate `(b:Label)` lowers here, e.g.
    // `Filter(a:ARTICLE)`), then recognize the fixed-length fresh single-hop `ExpandAll` over a bare scan.
    let (filter, expand_op): (Option<&Expr>, &PhysicalOp) = match input {
        PhysicalOp::Filter { input, predicate } => (Some(predicate), input.as_ref()),
        other => (None, other),
    };
    let Some(shape) = recognize_morsel_expand(expand_op) else {
        return Ok(None);
    };

    // The expansion-row variables the residual filter / group keys / aggregate arguments may reference.
    let vars = [
        shape.from.name.as_str(),
        shape.relationship.name.as_str(),
        shape.to.name.as_str(),
    ];

    // The residual filter (if any) must be pure per-row so the off-thread eval is deterministic + cross-row
    // -free (a function call / subquery / comprehension in the WHERE declines to serial).
    if let Some(pred) = filter {
        if !crate::morsel::is_pure_per_row_expr(pred) {
            return Ok(None);
        }
    }

    // Every group key must be PURE per-row and reference an expansion-row variable (a constant group key is
    // degenerate and left to serial).
    for col in group_keys {
        if !crate::morsel::is_pure_per_row_expr(&col.expr)
            || !expr_references_any_var(&col.expr, &vars)
        {
            return Ok(None);
        }
    }

    // Every aggregate column must be a BARE MERGEABLE aggregate over an expansion-row variable; collect
    // whether any requires the no-overflow integer gate (i.e. is a `sum`).
    let mut any_sum = false;
    for col in aggregates {
        match recognize_mergeable_bare_agg_vars(&col.expr, &vars) {
            Some(needs_integer_gate) => any_sum |= needs_integer_gate,
            None => return Ok(None),
        }
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
    // scan→expand (incl. a supernode's fan-out) abandons rather than pinning every core.
    scan.deadline = ctx.token.deadline();

    // Cancellation (flag and an already-elapsed deadline) is polled once up front; each worker then polls
    // the deadline again — per anchor and within a high-degree anchor's expansion — while it runs.
    ctx.check_cancelled()?;

    let spec = crate::morsel::MorselExpandGroupSpec {
        from: shape.from,
        relationship: shape.relationship,
        to: shape.to,
        direction: shape.direction,
        types: shape.types,
        filter,
        group_keys,
        aggregates,
    };

    // --- expand + group + aggregate the anchors concurrently, merging deterministically (serial first-seen
    // order — the #360 merge, reused verbatim over the surviving-expansion-row rank space) ---
    let converged = crate::morsel::run_expand_group_aggregate_morsels(
        &scan,
        &spec,
        ctx.params,
        ctx.morsel_threads,
    );

    // If any morsel hit a storage / evaluation error, the parallel result is untrustworthy: decline WITHOUT
    // folding the buffers (dropped here). The serial fallback re-reads + re-expands through the live seam,
    // re-registering the identical markers AND re-raising the identical error.
    if converged.error.is_some() {
        return Ok(None);
    }

    // --- the no-overflow integer gate for `sum` (`rmp` #360, finding C): `saturating_add` is NOT
    // associative once any partition subtree clamps to the i64 rail, so a parallel `sum` is bit-identical to
    // serial ONLY when no sub-sum saturates. Checked on the merged accumulators; a pathological near-rail
    // column falls back to serial. ---
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

    // Finish each merged group into its output row, in serial first-seen order — the bare group key value
    // IS the column value and each aggregate value IS `acc.finish()` (the recognizer guaranteed bare
    // columns), exactly as the #360 grouped tier builds its rows.
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

/// Whether every pattern part of `ex` is a **purely structural** pattern (no inline property map / no
/// `WHERE` predicate / no full-query subquery) — so the existence check is a read-only, snapshot-
/// deterministic, cross-row-free graph read (`rmp` task #575). Such a predicate records byte-identical
/// SIREAD markers whether evaluated serially or per morsel. Inline properties / a `WHERE` could embed a
/// non-deterministic function (`rand()`), so they conservatively decline (the whole tier falls to serial).
fn is_structural_pattern_existence(ex: &crate::ast::ExistsSubquery) -> bool {
    if ex.full_query.is_some() || ex.predicate.is_some() || ex.pattern.is_empty() {
        return false;
    }
    ex.pattern.iter().all(|part| {
        let el = &part.element;
        el.start.properties.is_none()
            && el.chain.iter().all(|link| {
                link.node.properties.is_none() && link.relationship.properties.is_none()
            })
    })
}

/// Finds the relationship-type alternatives of the `ExpandAll` / `ExpandInto` in `op`'s (linear) sub-plan
/// that binds `rel_var` (`rmp` task #575). Used to prove a `prior_rels` edge of the SAME `MATCH` is of a
/// relationship TYPE disjoint from the final hop's — so relationship-isomorphism is vacuous (a different
/// type is always a different edge) and the frontier morsel need not re-check `r != prior`. Returns `None`
/// if `rel_var` is bound by an unrecognized op (⇒ the tier conservatively declines to serial).
fn find_expand_rel_types<'a>(
    op: &'a PhysicalOp,
    rel_var: &str,
) -> Option<&'a [crate::ast::RelType]> {
    match op {
        PhysicalOp::ExpandAll {
            input,
            relationship,
            types,
            ..
        }
        | PhysicalOp::ExpandInto {
            input,
            relationship,
            types,
            ..
        } => {
            if relationship.name == rel_var {
                Some(types)
            } else {
                find_expand_rel_types(input.as_ref(), rel_var)
            }
        }
        PhysicalOp::Filter { input, .. } => find_expand_rel_types(input.as_ref(), rel_var),
        _ => None,
    }
}

/// Whether `pred` is a residual filter the `rmp` #575 frontier tier may evaluate off the engine thread per
/// expansion row: either **pure per-row** ([`crate::morsel::is_pure_per_row_expr`]) OR a deterministic
/// **pattern-existence** predicate — a bare structural `(a)-[…]->(b)` written as a boolean (optionally
/// `NOT`-wrapped, or joined by `AND` / `OR` of such). Both are read-only, snapshot-deterministic, and
/// cross-row-free, so a morsel evaluating them records byte-identical SIREAD markers to the serial `Filter`.
fn is_frontier_residual_ok(pred: &Expr) -> bool {
    if crate::morsel::is_pure_per_row_expr(pred) {
        return true;
    }
    match &pred.kind {
        ExprKind::Unary {
            op: crate::ast::UnaryOp::Not,
            operand,
        } => is_frontier_residual_ok(operand),
        ExprKind::Binary {
            op: crate::ast::BinaryOp::And | crate::ast::BinaryOp::Or,
            lhs,
            rhs,
        } => is_frontier_residual_ok(lhs) && is_frontier_residual_ok(rhs),
        ExprKind::ExistsSubquery(ex) => is_structural_pattern_existence(ex),
        _ => false,
    }
}

/// If `(input, group_keys, aggregates)` is the **morsel-parallel-eligible frontier-FoF shape** — a
/// `MATCH (seed …)-…multi-hop…-(f) [WHERE …] MATCH (f)-[r(:T…)]->(b) [WHERE <pure/anti-join residual>]
/// RETURN <bare key>, <bare mergeable aggregate over f/r/b> [ORDER BY … LIMIT …]` (`rmp` task #575, the
/// reco `r3_fof3` class) — **materializes the frontier serially** (the earlier multi-hop sub-plan below the
/// final expand, so its markers + relationship-isomorphism are byte-identical to serial), then partitions
/// the distinct frontier anchors into contiguous morsels, **expands + filters + groups + aggregates each
/// concurrently** on the dedicated pool (each over a `Send` [`ReadOnlyGraph`], driving the final hop's
/// expand + the residual filters — including a graph anti-join pattern predicate — + the grouped fold),
/// merges the partials deterministically ([`converge_group_aggregate_outcomes`], reused verbatim), and
/// returns the grouped rows. Otherwise returns `None` so the caller falls through to the serial pipeline.
///
/// This covers exactly the shape the `rmp` #558 grouped-over-expand tier declines: #558 requires the final
/// `ExpandAll`'s input to be a **bare label scan**, whereas here it is an arbitrary sub-plan (a single-seed
/// multi-hop traversal), and #558's residual filter must be pure per-row (it rejects the anti-join pattern
/// predicate). This tier is **disjoint** from #558 by construction (it declines when the final expand is
/// anchored directly on a bare label scan — that IS #558's case).
///
/// # Byte-identical to serial, by construction
/// * the earlier sub-plan runs through the **real serial executor** (identical rows, visibility, isomorphism,
///   SIREAD markers); its distinct `from` node-ids are the frontier anchors (deduped: `count(DISTINCT f)`
///   collapses multiplicity and the final `MATCH` is a fresh pattern, so dedup is result- and marker-safe);
/// * each morsel drives the SAME lifted `read_source::expand` + the SAME [`eval`] (incl. the anti-join
///   pattern existence) the serial `Operator::Expand` / `Operator::Filter` run — byte-identical rows,
///   three-valued filter decisions, grouped values, and markers (folded via `merge_morsel_buffer`);
/// * a `count(DISTINCT <anchor>)` per group is the set-union of the morsels' partials over a **disjoint**
///   anchor partition — worker-count-independent — and the `ORDER BY … LIMIT` above re-sorts the groups,
///   so the final rows are identical regardless of the merge's group order.
///
/// # Eligibility (ALL required, else `None`)
/// - the morsel knob is enabled ([`Ctx::morsel_threads`] `> 1`);
/// - `input` is `[Filter …]* ExpandAll` where the `ExpandAll` is a **fixed-length, fresh** single hop
///   (`range` `None`, `prior_rels` empty, no inline rel-prop map) whose input is **not** a bare label scan
///   (that is #558's case);
/// - every residual `Filter` predicate above the expand is [`is_frontier_residual_ok`] (pure per-row or a
///   structural pattern-existence predicate — the anti-join);
/// - there is `>= 1` group key, every one **pure per-row**; every aggregate is a **bare mergeable**
///   aggregate over an expansion-row variable ([`recognize_mergeable_bare_agg_vars`]);
/// - the seam hands off a frontier read surface ([`GraphAccess::frontier_morsel_source`]) — `None` for a
///   standalone / historical / restricted-RBAC / `MemGraph` read, which then runs serially;
/// - every non-expansion variable the residual / keys / aggregates reference is **constant** across the
///   materialized frontier (e.g. the single seed `me`); a non-constant such variable declines to serial.
///
/// On any per-morsel error (incl. a `sum` overflow) the tier discards the parallel result and returns
/// `None`; the serial fallback re-runs the whole pipeline, re-registering the markers and re-raising the
/// identical error.
fn try_morsel_frontier_fof_aggregate(
    input: &PhysicalOp,
    group_keys: &[ProjectionColumn],
    aggregates: &[ProjectionColumn],
    ctx: &mut Ctx<'_>,
) -> Result<Option<VecDeque<Row>>, ExecError> {
    // --- cheap structural gates first (no seam work, no drain) ---
    if ctx.morsel_threads <= 1 {
        return Ok(None);
    }
    if group_keys.is_empty() || aggregates.is_empty() {
        return Ok(None);
    }

    // Peel the residual `Filter` chain above the final `ExpandAll` (top-down), collecting predicates.
    let mut residual_top_down: Vec<&Expr> = Vec::new();
    let mut cur = input;
    while let PhysicalOp::Filter { input, predicate } = cur {
        residual_top_down.push(predicate);
        cur = input.as_ref();
    }
    // The final hop: a fixed-length, fresh single `ExpandAll`.
    let PhysicalOp::ExpandAll {
        input: expand_input,
        from,
        relationship,
        to,
        direction,
        types,
        range,
        prior_rels,
        rel_props,
        to_predicate,
        pruning,
    } = cur
    else {
        return Ok(None);
    };
    // `rmp` #870's two fields ride on a variable-length hop only, which `range.is_some()` already
    // rejects; naming them keeps this tier's decline explicit, since the morsel path re-implements the
    // expansion and would otherwise not apply them.
    if range.is_some() || rel_props.is_some() || to_predicate.is_some() || *pruning {
        return Ok(None);
    }
    // Relationship-isomorphism with prior edges of the SAME `MATCH`: the final hop `r` must differ from
    // each `prior_rels` edge. A frontier morsel binds only the final-hop row (the prior edges live in the
    // materialized frontier, not the morsel row), so it cannot check `r != prior`. This is SAFE to ignore
    // ONLY when every prior edge is of a relationship TYPE disjoint from the final hop's types — then the
    // final edge can never coincide with a prior one (different type ⇒ different edge id), so the check is
    // vacuous. A same-type (or "any-type") prior edge could coincide, so decline to serial (which enforces
    // isomorphism per row). E.g. the `r1_friends` `(me)-[:FRIEND]-(f)-[:PURCHASED]->(p)` prior edge is
    // `FRIEND` and the final hop is `PURCHASED` — disjoint ⇒ engaged; a `(a)-[:R]-(b)-[:R]-(c)` chain would
    // decline.
    if !prior_rels.is_empty() {
        if types.is_empty() {
            return Ok(None); // final hop is "any type": a prior edge of any type could coincide.
        }
        for pr in prior_rels {
            let disjoint =
                find_expand_rel_types(expand_input.as_ref(), &pr.name).is_some_and(|pr_types| {
                    !pr_types.is_empty()
                        && !pr_types
                            .iter()
                            .any(|t| types.iter().any(|ft| ft.name == t.name))
                });
            if !disjoint {
                return Ok(None);
            }
        }
    }
    // Disjoint from the `rmp` #558 tier: it owns the case where the final expand is anchored directly on a
    // bare label scan. Here the anchor comes from a deeper sub-plan (a multi-hop traversal).
    if morsel_label_scan_leaf(expand_input.as_ref()).is_some() {
        return Ok(None);
    }

    // Residual predicates in serial APPLICATION order (innermost `Filter`, closest to the expand, first).
    let residual: Vec<&Expr> = residual_top_down.iter().rev().copied().collect();
    for pred in &residual {
        if !is_frontier_residual_ok(pred) {
            return Ok(None);
        }
    }

    // The expansion-row variables the group keys / aggregates may reference.
    let vars = [
        from.name.as_str(),
        relationship.name.as_str(),
        to.name.as_str(),
    ];
    for col in group_keys {
        if !crate::morsel::is_pure_per_row_expr(&col.expr) {
            return Ok(None);
        }
    }
    let mut any_sum = false;
    for col in aggregates {
        match recognize_mergeable_bare_agg_vars(&col.expr, &vars) {
            Some(needs_integer_gate) => any_sum |= needs_integer_gate,
            None => return Ok(None),
        }
    }

    // --- the engine-thread seam: capture the off-thread frontier read surface. `None` (standalone /
    // historical / restricted-RBAC / MemGraph) ⇒ decline BEFORE draining, so the serial pipeline runs
    // verbatim with no wasted work. ---
    let Some(fsrc) = ctx.graph.frontier_morsel_source() else {
        return Ok(None);
    };

    // --- materialize the frontier SERIALLY: drain the earlier sub-plan through the real executor (so its
    // rows, visibility, relationship-isomorphism, and SIREAD markers are byte-identical to serial), then
    // collect the DISTINCT anchor ids + the constant non-expansion bindings (e.g. the single seed `me`). ---
    let mut subop = build_operator(expand_input.as_ref(), None, ctx)?;
    let mut seen: rustc_hash::FxHashSet<u64> = rustc_hash::FxHashSet::default();
    let mut anchors: Vec<u64> = Vec::new();
    // Constant-binding candidates: snapshot every non-anchor binding on the first frontier row, then drop
    // any that later varies or goes missing. What survives is constant across the whole frontier.
    let mut consts: Option<Vec<(String, RowValue)>> = None;
    while let Some(row) = subop.next(ctx)? {
        let Some(anchor) = row.get(&from.name).and_then(RowValue::as_node) else {
            // A null / non-node anchor contributes no rows to the serial final expand either — skip it.
            continue;
        };
        if seen.insert(anchor.0) {
            anchors.push(anchor.0);
        }
        match &mut consts {
            None => {
                let mut cand = Vec::new();
                for name in row.columns() {
                    if name != &from.name {
                        if let Some(v) = row.get(name) {
                            cand.push((name.clone(), v.clone()));
                        }
                    }
                }
                consts = Some(cand);
            }
            Some(cand) => {
                cand.retain(|(name, val)| {
                    row.get(name)
                        .is_some_and(|v| crate::runtime::row_values_equivalent(v, val))
                });
            }
        }
    }
    let constants = consts.unwrap_or_default();
    // Drop the drained sub-operator's borrow of `ctx` before re-borrowing it below.
    drop(subop);

    // --- build the parallel bundle + spec, install the per-statement deadline, dispatch ---
    let scan = crate::morsel::MorselFrontierScan {
        anchors,
        source: fsrc.source,
        snapshot: fsrc.snapshot,
        registry: fsrc.registry,
        txn: fsrc.txn,
        // The per-statement wall-clock budget (`rmp` #476), so a runaway parallel expand abandons rather
        // than pinning every core.
        deadline: ctx.token.deadline(),
    };
    ctx.check_cancelled()?;

    let spec = crate::morsel::MorselFrontierExpandGroupSpec {
        from,
        relationship,
        to,
        direction: *direction,
        types,
        residual_filters: &residual,
        group_keys,
        aggregates,
        constants: &constants,
    };

    let converged = crate::morsel::run_frontier_expand_group_aggregate_morsels(
        &scan,
        &spec,
        ctx.params,
        ctx.morsel_threads,
    );

    // A per-morsel storage / evaluation error makes the parallel result untrustworthy: decline WITHOUT
    // folding the buffers (dropped here). The serial fallback re-runs the whole pipeline (re-materializing
    // the frontier + re-expanding through the live seam), re-registering the identical markers AND re-raising
    // the identical error.
    if converged.error.is_some() {
        return Ok(None);
    }

    // The no-overflow integer gate for `sum` (`rmp` #360, finding C): a parallel `sum` is bit-identical to
    // serial ONLY when no sub-sum saturates. Checked on the merged accumulators; a pathological near-rail
    // column falls back to serial.
    if any_sum
        && converged
            .groups
            .iter()
            .any(|g| g.accs.iter().any(Accumulator::sum_is_parallel_unsafe))
    {
        return Ok(None);
    }

    // Committed to the parallel result: record the engagement (observability), then fold the per-morsel SSI
    // buffers into this statement's tracker on the engine thread.
    ctx.graph.note_parallel_aggregate();
    for buffer in converged.buffers {
        ctx.graph.merge_morsel_buffer(buffer);
    }

    // Finish each merged group into its output row (the bare group key value IS the column value and each
    // aggregate value IS `acc.finish()`) — exactly as the #558 / #360 grouped tiers build their rows. The
    // `Sort` / `TopN` above the aggregation re-orders these serially, so the group order here is immaterial.
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
        to_predicate,
        pruning,
    } = op
    else {
        return None;
    };
    // Fixed-length, fresh single hop only (the `expand_into_pending` shape). Anything else → serial —
    // including `rmp` #870's variable-length-only state, named so this tier declines it explicitly
    // rather than by the accident of the `range` test.
    if range.is_some()
        || !prior_rels.is_empty()
        || rel_props.is_some()
        || to_predicate.is_some()
        || *pruning
    {
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
        ExprKind::HasLabels { operand, expr } => ExprKind::HasLabels {
            operand: rewrite(operand, subs),
            expr: expr.clone(),
        },
        ExprKind::TypePredicate {
            operand,
            negated,
            type_expr,
        } => ExprKind::TypePredicate {
            operand: rewrite(operand, subs),
            negated: *negated,
            type_expr: type_expr.clone(),
        },
        ExprKind::NormalizedPredicate {
            operand,
            negated,
            form,
        } => ExprKind::NormalizedPredicate {
            operand: rewrite(operand, subs),
            negated: *negated,
            form: *form,
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
        // `reduce` hoists an aggregate out of its enclosing-scope init / source list (its body cannot
        // legally hold one — the semantic pass rejects it — but is rewritten for symmetry).
        ExprKind::Reduce(r) => {
            let mut r = (**r).clone();
            r.init = rewrite(&r.init, subs);
            r.list = rewrite(&r.list, subs);
            r.body = rewrite(&r.body, subs);
            ExprKind::Reduce(Box::new(r))
        }
        // A map projection hoists an aggregate out of its entity and its literal entry values.
        ExprKind::MapProjection(mp) => {
            let mut mp = (**mp).clone();
            mp.entity = rewrite(&mp.entity, subs);
            for sel in &mut mp.selectors {
                if let crate::ast::MapProjectionSelector::Entry { value, .. } = sel {
                    *value = rewrite(value, subs);
                }
            }
            ExprKind::MapProjection(Box::new(mp))
        }
        // Pattern comprehensions / EXISTS / COUNT / COLLECT subqueries cannot host an *outer*
        // aggregate (their scopes are self-contained; the semantic pass rejects hoisting), so pass
        // them through unchanged.
        k @ (ExprKind::PatternComprehension(_)
        | ExprKind::ExistsSubquery(_)
        | ExprKind::CountSubquery(_)
        | ExprKind::CollectSubquery(_)) => k.clone(),
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
    /// Running sum of the **squares** of the numeric inputs (`Σxᵢ²`), maintained only for the
    /// standard-deviation kinds ([`AggKind::Stdev`] / [`AggKind::StdevP`]). Paired with `sum` (`Σxᵢ`)
    /// and `count` (`n`), it lets [`finish`](Self::finish) compute the variance in a single streaming
    /// pass — `(Σxᵢ² − (Σxᵢ)²/n)` — without buffering the values. All three components are additive, so
    /// the fold is associative and [`combine`](Self::combine) merges partitions exactly. Left at `0.0`
    /// for every non-stdev kind.
    sum_sq: f64,
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
    /// `stdev(expr)` — the **sample** standard deviation (Bessel-corrected, divides by `n - 1`).
    /// Neo4j semantics: nulls are ignored, and a group of fewer than two values yields `0.0`.
    Stdev,
    /// `stdevp(expr)` — the **population** standard deviation (divides by `n`). Neo4j semantics:
    /// nulls are ignored, and an empty group (or a single value) yields `0.0`.
    StdevP,
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
                    "stdev" => AggKind::Stdev,
                    "stdevp" => AggKind::StdevP,
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
            sum_sq: 0.0,
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
        // `SEC-190` (CWE-674, rmp #589): `collect` is a runtime value-materialisation point, and a
        // self-referential chain (`WITH collect(a) AS a`) nests one level deeper per clause. The
        // gathered element becomes one level deeper once wrapped in the collected list, so bound the
        // element to `MAX_VALUE_DEPTH - 1` to keep the finished list within `MAX_VALUE_DEPTH`. Without
        // this, the next clause's `eval(collect(a))` clones an ever-deeper `a` and overflows the stack
        // — an uncatchable process abort. The check is iterative (never recurses the attacker depth).
        let depth_limit = crate::value_depth::MAX_VALUE_DEPTH.saturating_sub(1);
        if crate::value_depth::rowvalue_depth_exceeds(&rv, depth_limit) {
            return Err(ExecError::Eval(EvalError::ResourceLimit {
                detail: format!(
                    "collected value nesting depth exceeds the limit of {}",
                    crate::value_depth::MAX_VALUE_DEPTH
                ),
            }));
        }
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
        // The `stdev`/`stdevp` squared-sum component is additive across partitions, so it merges
        // exactly like `sum`/`count`. It stays `0.0` for every other kind, making this a no-op there;
        // maintaining it here keeps the standard-deviation fold associative should a future recognizer
        // ever admit it to the parallel grouped tier (it is serial-only today).
        self.sum_sq += other.sum_sq;
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
            // `stdev`/`stdevp` fold each numeric input into the running `count`/`sum`/`sum_sq` triple
            // (`Σxᵢ`, `Σxᵢ²`), from which `finish` derives the sample / population variance. Like
            // `sum`/`avg`, a non-numeric argument is a runtime `TypeError` and nulls were already skipped.
            AggKind::Stdev | AggKind::StdevP => {
                let x = match &argv {
                    Value::Integer(i) => *i as f64,
                    Value::Float(f) => *f,
                    _ => {
                        return Err(ExecError::Eval(EvalError::TypeError {
                            context: "stdev/stdevp require numeric input".to_owned(),
                        }));
                    }
                };
                self.count += 1;
                self.sum += x;
                self.sum_sq += x * x;
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
            // Sample (`n - 1`) / population (`n`) standard deviation from the streaming triple.
            AggKind::Stdev => Value::Float(self.finish_stdev(true)),
            AggKind::StdevP => Value::Float(self.finish_stdev(false)),
        };
        RowValue::Value(value)
    }

    /// Computes the standard deviation from the streaming `count`/`sum`/`sum_sq` triple.
    ///
    /// `sample == true` applies Bessel's correction (divide the summed squared deviations by
    /// `n − 1`, the `stdev` semantics); `sample == false` divides by `n` (the `stdevp` /
    /// population semantics). Neo4j returns `0.0` rather than `null`/`NaN` for a degenerate group:
    /// a `stdev` of fewer than two values, or a `stdevp` of an empty group.
    ///
    /// The variance is `(Σxᵢ² − (Σxᵢ)²/n) / divisor`. Floating-point cancellation can drive the
    /// numerator a hair below zero for a group of (near-)identical values; the result is clamped to
    /// `0.0` before the square root so a mathematically-zero variance never yields `NaN`.
    fn finish_stdev(&self, sample: bool) -> f64 {
        let n = self.count as f64;
        let divisor = if sample { n - 1.0 } else { n };
        if divisor <= 0.0 {
            // stdev of <2 values, or stdevp of an empty group: Neo4j returns 0.0.
            return 0.0;
        }
        let variance = (self.sum_sq - (self.sum * self.sum) / n) / divisor;
        variance.max(0.0).sqrt()
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
    // Hash index over `build`: key-tuple digest -> the build rows whose key hashes there. Until
    // `rmp` task #865 this operator scanned EVERY build row for every probe row — quadratic, despite
    // the name. The digest is `group_key_hash`, which is consistent with `row_values_equivalent`, and a
    // bucket collision still falls back to the exact `keys_match` check, so join semantics are
    // unchanged. Same construction the grouping index already uses (`rmp` #314/#371): the digest is a
    // SipHash output, so bucketing it again under SipHash would be waste and `FxHashMap` is used.
    let mut index: rustc_hash::FxHashMap<u64, Vec<usize>> = rustc_hash::FxHashMap::default();
    while let Some(row) = left_op.next(ctx)? {
        ctx.check_cancelled()?;
        let key = key_of(&row, join_keys);
        index
            .entry(group_key_hash(&key))
            .or_default()
            .push(build.len());
        build.push((key, row));
    }
    let mut right_op = build_operator(right, arg, ctx)?;
    let mut out = VecDeque::new();
    while let Some(row) = right_op.next(ctx)? {
        ctx.check_cancelled()?;
        let key = key_of(&row, join_keys);
        let Some(bucket) = index.get(&group_key_hash(&key)) else {
            continue;
        };
        for &i in bucket {
            let (lkey, lrow) = &build[i];
            if keys_match(lkey, &key) {
                out.push_back(merge_rows(lrow, &row));
            }
        }
    }
    Ok(out)
}

/// Materialises a [`ValueHashJoin`](PhysicalOp::ValueHashJoin): hash the build side on `left_key`,
/// probe with `right_key` (`rmp` task #865).
///
/// # Bucket by equivalence, confirm with the ORIGINAL predicate
///
/// The index buckets rows by grouping **equivalence** (`group_key_hash`), but a bucket hit is confirmed
/// by evaluating the very equality this join replaced, over the merged row. Nothing else is sound:
///
/// * Comparing the two key *values* with `equality::equals` loses **entity identity**. A key that
///   evaluates to a node is not a scalar, and two distinct nodes carrying the same properties would
///   compare equal — which is exactly how the first version of this operator broke the openCypher TCK
///   scenarios "Join between node identities" (2 rows expected, 4 produced) and "Join between node
///   properties of disconnected nodes" (1 expected, 4).
/// * `null = null` is `null`, not true, and `NaN = NaN` is false — yet equivalence groups both together.
///
/// Re-evaluating the predicate is correct by construction: it is the same expression, on the same
/// merged row, that the `Filter` above the nested loop evaluated. It costs one evaluation per candidate
/// PAIR, but only for pairs sharing a bucket — so the join stays linear in the inputs wherever the key
/// is at all selective, which is the case it exists for.
///
/// A null key is dropped on both sides before indexing: `null` can never satisfy the equality, so such a
/// row can match nothing and keeping it would only grow the table.
fn value_hash_join_rows(
    left: &PhysicalOp,
    right: &PhysicalOp,
    left_key: &Expr,
    right_key: &Expr,
    arg: Option<&Row>,
    ctx: &mut Ctx<'_>,
) -> Result<VecDeque<Row>, ExecError> {
    // The predicate this join consumed, rebuilt once so each candidate pair can be confirmed with it.
    let predicate = Expr::new(
        ExprKind::Binary {
            op: crate::ast::BinaryOp::Eq,
            lhs: Box::new(left_key.clone()),
            rhs: Box::new(right_key.clone()),
        },
        left_key.span,
    );

    let mut left_op = build_operator(left, arg, ctx)?;
    let mut build: Vec<Row> = Vec::new();
    let mut index: rustc_hash::FxHashMap<u64, Vec<usize>> = rustc_hash::FxHashMap::default();
    while let Some(row) = left_op.next(ctx)? {
        ctx.check_cancelled()?;
        let key = eval(
            left_key,
            &row,
            ctx.params,
            ctx.graph,
            ctx.functions,
            &ctx.clock,
        )?;
        if matches!(key, RowValue::Value(Value::Null)) {
            continue;
        }
        let digest = group_key_hash(std::slice::from_ref(&key));
        index.entry(digest).or_default().push(build.len());
        build.push(row);
    }
    let mut right_op = build_operator(right, arg, ctx)?;
    let mut out = VecDeque::new();
    while let Some(row) = right_op.next(ctx)? {
        ctx.check_cancelled()?;
        let key = eval(
            right_key,
            &row,
            ctx.params,
            ctx.graph,
            ctx.functions,
            &ctx.clock,
        )?;
        if matches!(key, RowValue::Value(Value::Null)) {
            continue;
        }
        let Some(bucket) = index.get(&group_key_hash(std::slice::from_ref(&key))) else {
            continue;
        };
        for &i in bucket {
            let merged = merge_rows(&build[i], &row);
            let verdict = eval(
                &predicate,
                &merged,
                ctx.params,
                ctx.graph,
                ctx.functions,
                &ctx.clock,
            )?;
            if matches!(verdict, RowValue::Value(Value::Boolean(true))) {
                out.push_back(merged);
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
    let source = eval(value, row, ctx.params, ctx.graph, ctx.functions, &ctx.clock)?;
    // `SEC-190` (rmp #589): a `RowValue::Map` collapses via `to_value` (depth-recursive) below, and any
    // entry value is about to be persisted, so bound the depth before either can happen. A structural
    // map from an over-deep chain (`SET x = m` where `m` was self-nested) would otherwise overflow the
    // stack during collapse or on a later read — an uncatchable process abort.
    if crate::value_depth::rowvalue_depth_exceeds(&source, crate::value_depth::MAX_VALUE_DEPTH) {
        return Err(ExecError::Eval(EvalError::ResourceLimit {
            detail: format!(
                "value nesting depth exceeds the limit of {}",
                crate::value_depth::MAX_VALUE_DEPTH
            ),
        }));
    }
    match source {
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

/// Rejects a property [`Value`] about to be **persisted** that nests deeper than the runtime
/// value-nesting-depth budget (`SEC-190`, CWE-674, rmp #589).
///
/// The projection guard ([`reject_over_deep_projection`]) keeps a value bound in a *row* within the
/// budget; this keeps a value written to *storage* within it too, so the iterative accumulation loop
/// `SET n.p = [n.p]` (one nesting level added per statement, unbounded across a session) can never
/// persist a value whose later read (a depth-recursive decode) or encode would overflow the stack.
/// Rejection is a recoverable [`EvalError::ResourceLimit`]. The check is iterative and `O(cap)`.
#[inline]
fn reject_over_deep_value(v: &Value) -> Result<(), ExecError> {
    if crate::value_depth::depth_exceeds(v, crate::value_depth::MAX_VALUE_DEPTH) {
        return Err(ExecError::Eval(EvalError::ResourceLimit {
            detail: format!(
                "value nesting depth exceeds the limit of {}",
                crate::value_depth::MAX_VALUE_DEPTH
            ),
        }));
    }
    Ok(())
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
                // `SEC-190` (rmp #589): never persist a value nested past the depth budget. Storing an
                // ever-deeper property (`SET n.p = [n.p]` iterated across statements) would grow a value
                // whose later read/encode overflows the stack — an uncatchable process abort. Capping
                // the write keeps stored values shallow, so every read decodes safely.
                reject_over_deep_value(&v)?;
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
    /// The `PROFILE` counter sink (`rmp` task #752), shared with the caller so the measured counters
    /// outlive the cursor: the result summary is built *after* the statement finished. `None` for every
    /// ordinary statement, which then reads the store through the bare seam exactly as before.
    profile: Option<Arc<crate::profile::ProfileRecorder>>,
}

impl<'a> Cursor<'a> {
    /// The `PROFILE` recorder this cursor feeds, if the statement carried the `PROFILE` prefix
    /// (`rmp` task #752).
    ///
    /// The caller clones the `Arc` at open time and reads the counters once the cursor is drained — the
    /// recorder holds the plan too, so [`PlanDescription::profile`](crate::plan_description::PlanDescription::profile)
    /// can render the annotated plan with nothing else in hand.
    #[must_use]
    pub fn profile(&self) -> Option<&Arc<crate::profile::ProfileRecorder>> {
        self.profile.as_ref()
    }

    /// Runs `f` with a [`Ctx`] over this cursor's seam, interposing the [`ProfilingGraph`] counting
    /// decorator when — and only when — the statement is being profiled (`rmp` task #752).
    ///
    /// Every graph access the executor makes for this cursor goes through the `Ctx` this builds, so a
    /// profiled statement counts *all* of its storage work (including the result-materialisation reads at
    /// the egress boundary) and an unprofiled one pays nothing: no decorator is constructed and the seam
    /// is passed through untouched.
    fn with_ctx<R>(&mut self, f: impl FnOnce(&mut Operator, &mut Ctx<'_>) -> R) -> R {
        let mut decorated;
        let graph: &mut dyn GraphAccess = match &self.profile {
            Some(rec) => {
                decorated = crate::profile::ProfilingGraph::new(&mut *self.graph, Arc::clone(rec));
                &mut decorated
            }
            None => &mut *self.graph,
        };
        let mut ctx = Ctx {
            params: &self.params,
            token: &self.token,
            graph,
            functions: self.functions,
            procedures: self.procedures,
            clock: self.clock,
            morsel_threads: self.morsel_threads,
            profile: self.profile.clone(),
        };
        f(&mut self.root, &mut ctx)
    }

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
        // A write statement with no `RETURN` yields zero rows (openCypher write cardinality), but
        // its side effects must still happen: drain the operator tree once so every write `next()`
        // fires (e.g. `MATCH (n) SET n.x = 1` applies all N updates), then present an empty result.
        if !self.emits_rows {
            self.finished = true;
            return self.with_ctx(|root, ctx| {
                loop {
                    match root.next(ctx) {
                        Ok(Some(_)) => {}
                        Ok(None) => return Ok(None),
                        Err(e) => return Err(e),
                    }
                }
            });
        }
        let produced = self.with_ctx(|root, ctx| root.next(ctx));
        match produced {
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
            Some(row) => Ok(Some(self.materialize_row(&row))),
            None => Ok(None),
        }
    }

    /// Materializes an already-pulled [`Row`] through the cursor's graph seam (`04 §8.3`).
    ///
    /// The row-at-a-time counterpart to [`next_materialized`](Self::next_materialized) for callers
    /// that hold a [`Row`] (e.g. a `pull(n)` batch) and want its wire form. Resolution reads through
    /// the cursor's `&mut dyn GraphAccess`, so RBAC/MVCC apply exactly as for `next_materialized`.
    ///
    /// For a `PROFILE`d statement the reads go through the counting decorator too (`rmp` task #752), so
    /// the storage work of resolving a returned entity is measured, not silently dropped; it is attributed
    /// to the root operator, which is the operator that produced the row.
    #[must_use]
    pub fn materialize_row(&mut self, row: &Row) -> Vec<crate::result::MaterializedValue> {
        match &self.profile {
            Some(rec) => {
                let mut decorated =
                    crate::profile::ProfilingGraph::new(&mut *self.graph, Arc::clone(rec));
                crate::result::materialize_row(&mut decorated, row)
            }
            None => crate::result::materialize_row(self.graph, row),
        }
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
            // The `PROFILE` counters (`rmp` #752) survive a suspend/resume with the operator state, so a
            // statement parked for a slow consumer still reports the counts of its *whole* run.
            profile: self.profile,
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
    /// The `PROFILE` counter sink (`rmp` task #752), carried across the suspension; `None` otherwise.
    profile: Option<Arc<crate::profile::ProfileRecorder>>,
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
    ///
    /// **It must never open a statement** (`04 §5.1.4`, `rmp` #972). A suspended cursor is the *same*
    /// statement continuing, so the `command_id` must not move between batches: advancing it here
    /// would hide from a `CREATE` the rows it had already applied in an earlier batch of its own run.
    /// The fresh seam picks the current command back up from the `RecordStore`, which is exactly why
    /// the counter's home is the store and not any per-statement handle.
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
            profile: self.profile,
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
    plan: Arc<PhysicalPlan>,
    params: BoundParameters,
}

impl Executor {
    /// Builds an executor for `plan` bound with `params`.
    ///
    /// The plan is moved into a fresh [`Arc`] (the executor holds it shared internally so a caller that
    /// already has an `Arc<PhysicalPlan>` can avoid an extra deep clone via [`Executor::from_arc`]).
    pub fn new(plan: PhysicalPlan, params: BoundParameters) -> Self {
        Self {
            plan: Arc::new(plan),
            params,
        }
    }

    /// Builds an executor for an **already-shared** `plan` (`rmp` task #531).
    ///
    /// This is the server's plan-cache hot path: the engine's [`PlanCache`](crate::plan_cache::PlanCache)
    /// hands out `Arc<PhysicalPlan>` clones (an atomic refcount bump), so a cache-hit statement reaches
    /// execution with **zero** deep plan clones — the plan is read (never mutated) through the shared
    /// `Arc` during [`open`](Self::open) and the resulting [`Cursor`] owns its built operators
    /// independently of the plan. Behaviourally identical to [`Executor::new`]; it only avoids the
    /// per-statement deep clone [`Executor::new`] would perform on an owned plan.
    pub fn from_arc(plan: Arc<PhysicalPlan>, params: BoundParameters) -> Self {
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

        // `EXPLAIN` (`rmp` task #752): the statement is planned but **never executed**. Return here,
        // before `build_operator` — which is where leaf scans and every materialising operator do their
        // storage work — with an empty operator tree. No operator exists, so no store access and no side
        // effect is possible: `EXPLAIN CREATE (:X)` creates nothing, by construction rather than by a
        // promise. The result columns are still the query's real ones (Neo4j reports the statement's
        // `fields` for an EXPLAIN and simply streams no record), so the client sees the correct schema
        // with zero rows.
        if self.plan.prefix() == Some(crate::ast::QueryPrefix::Explain) {
            return Ok(Cursor {
                root: Operator::Buffered {
                    rows: VecDeque::new(),
                },
                params: self.params.clone(),
                token,
                graph,
                functions,
                procedures,
                clock,
                morsel_threads: 1,
                columns,
                finished: false,
                emits_rows: !root_is_write(&self.plan.root),
                profile: None,
            });
        }

        // `PROFILE` (`rmp` task #752): install the counter sink for this run. It holds the plan, so the
        // annotated description can be rendered from it alone once the statement finishes.
        let profile = match self.plan.prefix() {
            Some(crate::ast::QueryPrefix::Profile) => Some(Arc::new(
                crate::profile::ProfileRecorder::new(Arc::clone(&self.plan)),
            )),
            _ => None,
        };
        // The effective morsel-thread count for this statement (`rmp` task #339), read once from the
        // process-global knob at open and frozen for the cursor's lifetime. A profiled statement runs
        // **serially** (`rmp` #752): the morsel workers bypass the counting seam, so a parallel profiled
        // run would under-count its `dbHits` — a wrong number, which is worse than a slow one.
        let morsel_threads = if profile.is_some() {
            1
        } else {
            crate::morsel::morsel_threads()
        };
        // **Open the statement** (`04 §5.1.4`, `rmp` #972). This is the one cursor-open seam every
        // caller funnels through — the server, the TCK harness, the CLI and the tests alike — which is
        // why the advance lives here and not in `TxnCoordinator::statement()`: that function runs again
        // on **every resume** of a suspended cursor, and advancing there would hide from a `CREATE` the
        // rows it had already applied in earlier batches of the same statement.
        //
        // It is placed after the `EXPLAIN` early return above, so an explained statement leaves the
        // transaction's counter exactly where it found it — `EXPLAIN` executes nothing and must
        // therefore consume nothing.
        //
        // It is placed before `build_operator`, which is where the leaf scans actually read the store:
        // the scan must run *at* this statement, not at the previous one.
        graph.begin_command();
        let root = {
            let mut decorated;
            let graph: &mut dyn GraphAccess = match &profile {
                Some(rec) => {
                    decorated = crate::profile::ProfilingGraph::new(&mut *graph, Arc::clone(rec));
                    &mut decorated
                }
                None => &mut *graph,
            };
            let mut ctx = Ctx {
                params: &self.params,
                token: &token,
                graph,
                functions,
                procedures,
                clock,
                morsel_threads,
                profile: profile.clone(),
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
            profile,
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
        // **No `begin_command` here** (`04 §5.1.4`, `rmp` #972), deliberately. A seeded cursor drives a
        // correlated sub-plan of the statement already running — the body of an `EXISTS { … }` — not a
        // statement of its own. Advancing the counter mid-statement would move every write the enclosing
        // statement has yet to perform to a *later* command than the one its own `Produce` reads at, and
        // `View::New` hides a later command's writes: the outer `RETURN` would stop seeing its own
        // `CREATE`. The statement clock is re-captured only because it is per-`Cursor` state; the
        // command is per-*transaction* state and must not move.
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
                // A seeded cursor drives a **correlated sub-plan** (an `EXISTS { … }` body), which is
                // never a statement of its own and so never carries a query prefix. Its storage accesses
                // are still counted when the enclosing statement is profiled: it reads through the seam
                // the outer cursor handed it — the counting decorator — and they are attributed to the
                // outer operator that is evaluating the subquery, which is where the work belongs.
                profile: None,
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
            profile: None,
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
///
/// # Plan sharing (`rmp` task #531)
///
/// Takes the plan as a shared `Arc<PhysicalPlan>` (moved in) rather than a `&PhysicalPlan` it would deep
/// clone: the server's engine keeps compiled plans in an `Arc`-valued [`PlanCache`](crate::plan_cache::PlanCache),
/// so a cache-hit statement reaches execution with **no** deep plan clone (the `Arc` refcount bump is a
/// few nanoseconds versus the hundreds of nanoseconds a plan-tree clone costs). The plan is only read
/// during [`open_with_extensions`], and the returned [`Cursor`] owns its built operators, so the shared
/// plan can be dropped the moment the cursor is built.
pub fn execute_with_extensions_cancellable<'a>(
    plan: Arc<PhysicalPlan>,
    params: &BoundParameters,
    graph: &'a mut dyn GraphAccess,
    functions: &'a dyn FunctionRegistry,
    procedures: &'a dyn ProcedureRegistry,
    token: CancellationToken,
) -> Result<Cursor<'a>, ExecError> {
    Executor::from_arc(plan, params.clone())
        .open_with_extensions(graph, token, functions, procedures)
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
        // Delegate to the fallback (`rmp` task #866) — it IS the `Aggregation` this replaces, so the
        // declared columns are identical to the un-rewritten plan's by construction rather than by two
        // implementations that have to be kept in step. This matters even more than usual here: the
        // seam may decline and run that very subtree, and the column list is fixed before the statement
        // executes, so the two paths must declare the same columns whichever one ends up running.
        PhysicalOp::NodeCountFromCountStore { fallback, .. }
        | PhysicalOp::RelationshipCountFromCountStore { fallback, .. } => {
            result_columns(fallback, procedures)
        }
        PhysicalOp::Filter { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Eager { input }
        | PhysicalOp::AdvanceCommand { input }
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
        // `rmp` #882: the fused one-hop `OPTIONAL MATCH` declares exactly the columns the
        // `NestedLoopJoin(input, Optional(… Expand(Argument) …))` it replaces declared — the driving
        // relation's, then the `Argument`'s (all already present), then the expand's two, then the
        // `Optional`'s null set (also already present). Walking the same sequence keeps the declared
        // column list identical between the fused and the fallback plan, which matters because the
        // list is fixed before the statement runs and a client sees it either way.
        PhysicalOp::OptionalExpand {
            input,
            relationship,
            to,
            null_variables,
            arguments,
            ..
        } => {
            let mut cols = result_columns(input, procedures);
            let names = arguments
                .iter()
                .chain([relationship, to])
                .chain(null_variables.iter());
            for v in names {
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
        PhysicalOp::QuantifiedPath {
            input,
            to,
            group_start,
            group_end,
            relationship,
            extra_hops,
            ..
        } => {
            // The anchor `from` is bound by `input`; this operator introduces every interior group
            // variable (first hop plus each extra hop) and the trailing boundary node.
            let mut cols = result_columns(input, procedures);
            let mut push = |v: &Var| {
                if !cols.contains(&v.name) {
                    cols.push(v.name.clone());
                }
            };
            push(group_start);
            push(group_end);
            push(relationship);
            push(to);
            for step in extra_hops {
                push(&step.relationship);
                push(&step.end_node);
            }
            cols
        }
        // `rmp` #869. A semi-join emits its DRIVING rows unchanged: the inner branch is examined for
        // emptiness and discarded, so it contributes no column. Grouping it with the joins below —
        // which union both sides' columns — would leak a subquery-local variable into the outer scope
        // and change what `RETURN *` returns.
        PhysicalOp::SemiApply { input, .. } => result_columns(input, procedures),
        PhysicalOp::NestedLoopJoin { left, right }
        | PhysicalOp::HashJoin { left, right, .. }
        | PhysicalOp::ValueHashJoin { left, right, .. } => {
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
        | PhysicalOp::NodeIndexMultiSeek { variable, .. }
        | PhysicalOp::NodeCompositeIndexSeek { variable, .. }
        | PhysicalOp::NodeLabelScanEq { variable, .. }
        | PhysicalOp::NodeIndexRangeSeek { variable, .. }
        | PhysicalOp::NodeIndexScan { variable, .. }
        | PhysicalOp::NodeIndexStartsWithSeek { variable, .. }
        | PhysicalOp::SpatialIndexSeek { variable, .. }
        | PhysicalOp::NodeTextIndexSeek { variable, .. } => vec![variable.name.clone()],
        PhysicalOp::AllRelationshipsScan {
            relationship,
            from,
            to,
            ..
        }
        | PhysicalOp::RelIndexSeek {
            relationship,
            from,
            to,
            ..
        }
        | PhysicalOp::RelIndexMultiSeek {
            relationship,
            from,
            to,
            ..
        }
        | PhysicalOp::RelIndexRangeSeek {
            relationship,
            from,
            to,
            ..
        }
        | PhysicalOp::RelCompositeIndexSeek {
            relationship,
            from,
            to,
            ..
        }
        | PhysicalOp::RelSpatialIndexSeek {
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
    use crate::parser::MAX_QUERY_CLAUSES;
    use crate::parser::parse_tokens;
    use crate::physical::plan_physical;
    use crate::semantics::analyze;

    fn run(src: &str, graph: &mut MemGraph) -> Vec<Row> {
        run_with_catalog(src, graph, &IndexCatalog::empty())
    }

    fn run_with_catalog(src: &str, graph: &mut MemGraph, catalog: &IndexCatalog) -> Vec<Row> {
        run_with_catalog_and_params(src, graph, catalog, &crate::binding::Parameters::new())
    }

    fn run_with_catalog_and_params(
        src: &str,
        graph: &mut MemGraph,
        catalog: &IndexCatalog,
        params: &crate::binding::Parameters,
    ) -> Vec<Row> {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let plan = plan_physical(&lower(&analyze(&ast).expect("analyze")), catalog);
        let params = crate::binding::bind_parameters(&plan, params).expect("bind");
        execute(&plan, &params, graph)
            .expect("open")
            .collect_all()
            .expect("rows")
    }

    /// Like [`run_with_catalog_and_params`] but plans **cost-based** with the graph's own statistics,
    /// so a test exercises the optimiser (join reordering, access-path reversion) rather than only the
    /// rule-based tree.
    fn run_with_catalog_params_stats(
        src: &str,
        graph: &mut MemGraph,
        catalog: &IndexCatalog,
        params: &crate::binding::Parameters,
    ) -> Vec<Row> {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let logical = lower(&analyze(&ast).expect("analyze"));
        // Scope the immutable statistics borrow so `graph` is free for the mutable execute below.
        let plan = {
            let stats = graph.statistics();
            crate::physical::plan_physical_with_stats(&logical, catalog, stats)
        };
        let params = crate::binding::bind_parameters(&plan, params).expect("bind");
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
            profile: None,
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
    fn correlated_row_valued_index_seek_returns_exactly_the_scan_result() {
        // `rmp` task #708: a row-valued (correlated) equality anchor —
        // `UNWIND $rows AS t MATCH (b:Person {uid: t.uid})` — now lowers to a per-left-row
        // `NodeIndexSeek` keyed off the correlation row instead of a full label scan and filter. The
        // seek must NEVER change results: for every driving row the indexed seek path and the plain
        // scan+filter path must return the IDENTICAL node set (same rows, same multiplicity). This
        // pins that the executor evaluates the seek value against the correlation row (a regression
        // that evaluated it against the empty row would return zero rows and fail here).
        use crate::binding::Parameters;

        fn ids(
            src: &str,
            graph: &mut MemGraph,
            catalog: &IndexCatalog,
            params: &Parameters,
        ) -> Vec<u64> {
            let mut out: Vec<u64> = run_with_catalog_and_params(src, graph, catalog, params)
                .iter()
                .filter_map(|r| r.get("b").and_then(RowValue::as_node))
                .map(|id| id.0)
                .collect();
            out.sort_unstable();
            out
        }

        // Two identically-seeded graphs. The catalog is what routes the planner: `with_index` emits
        // the correlated `NodeIndexSeek`, `no_index` the plain label scan + filter (the `MemGraph`
        // seam serves both through `scan_filter_eq`, so this isolates the PLAN difference). Includes a
        // DUPLICATE uid (multigraph: two nodes share uid 3) so multiplicity is exercised, and the
        // driving rows include a uid with no match (99) so a non-match yields zero rows on both paths.
        let seed = |g: &mut MemGraph| {
            g.add_node(["Person"], [("uid", Value::Integer(1))]);
            g.add_node(["Person"], [("uid", Value::Integer(2))]);
            g.add_node(["Person"], [("uid", Value::Integer(3))]);
            g.add_node(["Person"], [("uid", Value::Integer(3))]); // duplicate uid (multigraph)
            g.add_node(["Person"], [("uid", Value::Integer(4))]);
        };
        let mut indexed = MemGraph::new();
        seed(&mut indexed);
        let mut plain = MemGraph::new();
        seed(&mut plain);

        let with_index = IndexCatalog::builder()
            .with_label_property("Person", "uid")
            .build();
        let no_index = IndexCatalog::empty();

        let rows = Value::List(vec![
            Value::Map(vec![("uid".to_owned(), Value::Integer(1))]),
            Value::Map(vec![("uid".to_owned(), Value::Integer(3))]), // matches BOTH duplicates
            Value::Map(vec![("uid".to_owned(), Value::Integer(99))]), // no match
            Value::Map(vec![("uid".to_owned(), Value::Integer(2))]),
        ]);
        let params = Parameters::new().with("rows", rows);

        // Every correlated formulation the planner sees (inline map, WHERE, WITH-projected key) must
        // agree with the plain scan and use the seek.
        for src in [
            "UNWIND $rows AS t MATCH (b:Person {uid: t.uid}) RETURN b",
            "UNWIND $rows AS t MATCH (b:Person) WHERE b.uid = t.uid RETURN b",
            "UNWIND $rows AS t WITH t.uid AS u MATCH (b:Person {uid: u}) RETURN b",
        ] {
            let seek = ids(src, &mut indexed, &with_index, &params);
            let scan = ids(src, &mut plain, &no_index, &params);
            assert_eq!(seek, scan, "index must not change results: {src}");
            // uid 1 (1 node) + uid 3 (2 nodes) + uid 99 (0) + uid 2 (1 node) = 4 rows.
            assert_eq!(seek.len(), 4, "expected 4 matched rows: {src}");

            // Also validate the COST-BASED plan (the optimiser must not break the correlated seek by
            // reordering it to the outer side or reverting it to a scan, `rmp` task #708).
            let mut cost_based: Vec<u64> =
                run_with_catalog_params_stats(src, &mut indexed, &with_index, &params)
                    .iter()
                    .filter_map(|r| r.get("b").and_then(RowValue::as_node))
                    .map(|id| id.0)
                    .collect();
            cost_based.sort_unstable();
            assert_eq!(
                cost_based, scan,
                "cost-based plan must not change results: {src}"
            );

            // The indexed plan must route through the correlated seek (else this proves nothing).
            let plan = {
                let toks = tokenize(src).expect("lex");
                let ast = parse_tokens(&toks, src).expect("parse");
                plan_physical(&lower(&analyze(&ast).expect("analyze")), &with_index)
            };
            let rendered = plan.to_string();
            assert!(
                rendered.contains("NodeIndexSeek"),
                "the correlated anchor must use the index seek:\n{rendered}"
            );
            assert!(
                !rendered.contains("NodeByLabelScan"),
                "the correlated anchor must NOT fall back to a label scan:\n{rendered}"
            );
        }
    }

    /// A `GraphAccess` seam over a [`MemGraph`] with a **real** in-process composite index on
    /// `(Account.tenant, Account.extid)` (a hash map from the canonical key tuple to node ids), plus a
    /// [`Cell`](std::cell::Cell) counting the **node records examined** by whichever access path runs:
    ///
    /// * [`index_seek_composite_eq`](GraphAccess::index_seek_composite_eq) does an O(1) hash lookup and
    ///   charges only the candidates it returns — the composite **seek** path (`rmp` task #729, post-fix).
    /// * [`scan_nodes_by_label`](GraphAccess::scan_nodes_by_label) charges every node of the label — the
    ///   label **scan** path a pre-#729 correlated composite anchor degrades to (its leading-prefix
    ///   `NodeIndexSeek` finds no single-key tree in a composite-only store and falls back to a full scan
    ///   per driving row).
    ///
    /// This lets a sweep over the node count `N` measure the per-driving-row cost of each path directly
    /// and deterministically (an examined-record count, not a wall-clock time), proving the seek stays
    /// flat in `N` while the scan grows linearly.
    struct CountingCompositeGraph {
        inner: MemGraph,
        composite: std::collections::HashMap<String, Vec<NodeId>>,
        examined: std::cell::Cell<usize>,
    }

    impl CountingCompositeGraph {
        /// Canonical string key for a composite tuple (deterministic for the `Integer` keys the sweep
        /// uses); both the build below and the seek lookup format values the same way.
        fn key_of(values: &[Value]) -> String {
            values
                .iter()
                .map(|v| format!("{v:?}"))
                .collect::<Vec<_>>()
                .join("|")
        }

        fn new(inner: MemGraph) -> Self {
            let mut composite: std::collections::HashMap<String, Vec<NodeId>> =
                std::collections::HashMap::new();
            for id in inner.scan_nodes_by_label("Account") {
                let tenant = inner.node_property(id, "tenant");
                let extid = inner.node_property(id, "extid");
                if let (Some(t), Some(e)) = (tenant, extid) {
                    composite.entry(Self::key_of(&[t, e])).or_default().push(id);
                }
            }
            Self {
                inner,
                composite,
                examined: std::cell::Cell::new(0),
            }
        }

        fn reset(&self) {
            self.examined.set(0);
        }
        fn examined(&self) -> usize {
            self.examined.get()
        }
    }

    impl crate::statistics::Statistics for CountingCompositeGraph {
        fn total_nodes(&self) -> u64 {
            self.inner.node_count() as u64
        }
        fn nodes_with_label(&self, label: &str) -> Option<u64> {
            Some(self.inner.scan_nodes_by_label(label).len() as u64)
        }
        fn total_relationships(&self) -> u64 {
            0
        }
        fn relationships_with_type(&self, _rel_type: &str) -> Option<u64> {
            Some(0)
        }
    }

    impl GraphAccess for CountingCompositeGraph {
        fn index_seek_composite_eq(
            &self,
            _label: &str,
            _properties: &[String],
            values: &[Value],
            _carry: KeyValues,
        ) -> Option<CompositeSeekHits> {
            // O(1) hash lookup; charge only the candidates returned (the seek's true storage cost).
            // Carries nothing (`rmp` #879): this stub measures how many records an access path reads,
            // and declining to carry keeps that measurement about the access path alone.
            let ids = self
                .composite
                .get(&Self::key_of(values))
                .cloned()
                .unwrap_or_default();
            self.examined.set(self.examined.get() + ids.len());
            Some(CompositeSeekHits::ids(ids))
        }
        fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
            // Charge every node record the scan touches (the label-scan path's true storage cost).
            let ids = self.inner.scan_nodes_by_label(label);
            self.examined.set(self.examined.get() + ids.len());
            ids
        }
        fn statistics(&self) -> Option<&dyn crate::statistics::Statistics> {
            Some(self)
        }
        fn scan_nodes(&self) -> Vec<NodeId> {
            self.inner.scan_nodes()
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

    #[test]
    fn correlated_composite_seek_per_row_cost_is_flat_in_n() {
        // `rmp` task #729 — the WHOLE POINT of the fix, measured. A batched load keyed on a composite
        // business key drives a FIXED number of rows against a store of `N` `:Account` nodes. Pre-fix
        // the correlated composite anchor degrades to a per-row LABEL SCAN (O(N) per row → O(D·N)
        // total); post-fix it is a per-row composite SEEK (O(1) per row → O(D) total, flat in N).
        //
        // Measured deterministically as node records EXAMINED (not wall-clock): the `CountingCompositeGraph`
        // seam charges the seek only its candidates and the scan every node it touches. The scan path
        // (`no_index` catalog) is the growing-slope proxy for the pre-fix cost; the seek path
        // (`with_index` composite catalog) is the flat line. Both are run on the SAME seam and asserted
        // to return the IDENTICAL rows, so the flatness is proven against a real, growing baseline.
        use crate::binding::Parameters;

        // A fixed batch of driving rows; each composite key `(tenant=i%7, extid=i)` hits exactly one node
        // (extid is unique). Independent of N.
        const D: i64 = 8;
        let rows = Value::List(
            (0..D)
                .map(|i| {
                    Value::Map(vec![
                        ("tn".to_owned(), Value::Integer(i % 7)),
                        ("ex".to_owned(), Value::Integer(i)),
                    ])
                })
                .collect(),
        );
        let params = Parameters::new().with("rows", rows);

        let with_index = IndexCatalog::builder()
            .with_label_composite("Account", ["tenant", "extid"])
            .build();
        let no_index = IndexCatalog::empty();

        // Runs `src` against `seam` with `catalog` (cost-based, so the optimiser is exercised too),
        // returning (sorted matched node ids, node records examined).
        fn run_measured(
            src: &str,
            seam: &mut CountingCompositeGraph,
            catalog: &IndexCatalog,
            params: &Parameters,
        ) -> (Vec<u64>, usize) {
            let toks = tokenize(src).expect("lex");
            let ast = parse_tokens(&toks, src).expect("parse");
            let logical = lower(&analyze(&ast).expect("analyze"));
            let plan = {
                let stats = seam.statistics();
                crate::physical::plan_physical_with_stats(&logical, catalog, stats)
            };
            let bound = crate::binding::bind_parameters(&plan, params).expect("bind");
            seam.reset();
            let mut ids: Vec<u64> = execute(&plan, &bound, seam)
                .expect("open")
                .collect_all()
                .expect("rows")
                .iter()
                .filter_map(|r| r.get("b").and_then(RowValue::as_node))
                .map(|id| id.0)
                .collect();
            ids.sort_unstable();
            (ids, seam.examined())
        }

        let src = "UNWIND $rows AS t MATCH (b:Account {tenant: t.tn, extid: t.ex}) RETURN b";

        let sweep = [250usize, 500, 1000, 2000, 4000];
        let mut seek_curve: Vec<(usize, usize)> = Vec::new();
        let mut scan_curve: Vec<(usize, usize)> = Vec::new();
        for &n in &sweep {
            let mut mem = MemGraph::new();
            for i in 0..n as i64 {
                mem.add_node(
                    ["Account"],
                    [
                        ("tenant", Value::Integer(i % 7)),
                        ("extid", Value::Integer(i)),
                    ],
                );
            }
            let mut seam = CountingCompositeGraph::new(mem);

            let (seek_ids, seek_examined) = run_measured(src, &mut seam, &with_index, &params);
            let (scan_ids, scan_examined) = run_measured(src, &mut seam, &no_index, &params);

            // Correctness during the measurement: seek and scan agree, and D rows match (extid unique).
            assert_eq!(seek_ids, scan_ids, "seek and scan disagree at N={n}");
            assert_eq!(seek_ids.len(), D as usize, "expected {D} matches at N={n}");

            seek_curve.push((n, seek_examined));
            scan_curve.push((n, scan_examined));
        }

        eprintln!("[#729 flat-cost] D={D} driving rows; examined node records vs N:");
        for ((n, seek), (_, scan)) in seek_curve.iter().zip(scan_curve.iter()) {
            eprintln!(
                "  N={n:>5}  seek={seek:>7}  scan={scan:>9}  scan/seek={:.1}x",
                *scan as f64 / (*seek).max(1) as f64
            );
        }

        // SEEK is FLAT: examined is constant across the whole sweep (D candidates, one per driving row,
        // independent of N).
        let seek_baseline = seek_curve[0].1;
        for &(n, examined) in &seek_curve {
            assert_eq!(
                examined, seek_baseline,
                "the composite SEEK must be flat in N: examined {examined} at N={n} != {seek_baseline}"
            );
        }
        assert_eq!(
            seek_baseline, D as usize,
            "the seek examines exactly one candidate per driving row"
        );

        // The no-index path examines N, not D*N: `rmp` task #865 recognises the branch-to-branch
        // equality as a value hash join, so the labelled anchors are scanned ONCE into a hash table and
        // probed per driving row rather than re-scanned for each. The cost lost its factor of D.
        for &(n, examined) in &scan_curve {
            assert_eq!(
                examined, n,
                "the no-index path builds one hash table over the anchors (#865): examined \
                 {examined} at N={n}"
            );
        }
        // The growth is still real: doubling N doubles the scan cost while the seek cost is unchanged —
        // the flat line is proven against a genuine slope, not asserted in a vacuum.
        assert!(
            scan_curve.last().unwrap().1 > 6 * scan_curve.first().unwrap().1,
            "the scan slope must grow with N across the sweep: {scan_curve:?}"
        );
    }

    #[test]
    fn correlated_composite_index_seek_returns_exactly_the_scan_result() {
        // `rmp` task #729: a row-valued (correlated) FULL-composite anchor —
        // `UNWIND $rows AS t MATCH (b:Account {tenant: t.tn, extid: t.ex})` over a composite
        // `(tenant, extid)` index — now lowers to a per-left-row `NodeCompositeIndexSeek` keyed off the
        // correlation row instead of a leading-prefix scan + residual filter. The seek must NEVER change
        // results: for every driving row the composite seek path and the plain scan+filter path must
        // return the IDENTICAL node set (same rows, same multiplicity). This pins that the executor
        // evaluates EACH key value against the correlation row — a regression that evaluated them against
        // the empty row would resolve every key to `null` and return zero rows, failing here.
        use crate::binding::Parameters;

        fn ids(
            src: &str,
            graph: &mut MemGraph,
            catalog: &IndexCatalog,
            params: &Parameters,
        ) -> Vec<u64> {
            let mut out: Vec<u64> = run_with_catalog_and_params(src, graph, catalog, params)
                .iter()
                .filter_map(|r| r.get("b").and_then(RowValue::as_node))
                .map(|id| id.0)
                .collect();
            out.sort_unstable();
            out
        }

        // Two identically-seeded graphs. `with_index` routes the planner to the correlated
        // `NodeCompositeIndexSeek`; `no_index` to the plain label scan + residual filters (the `MemGraph`
        // seam serves both through `scan_filter_composite_eq`, so this isolates the PLAN difference).
        // Includes a DUPLICATE composite key (two nodes share `(1, 3)`) so multiplicity is exercised,
        // and a decoy that matches only the LEADING key (`(1, 999)`: same tenant, different extid) so a
        // leading-prefix-only seek would over-match and be caught.
        let seed = |g: &mut MemGraph| {
            g.add_node(
                ["Account"],
                [("tenant", Value::Integer(1)), ("extid", Value::Integer(3))],
            );
            g.add_node(
                ["Account"],
                [("tenant", Value::Integer(1)), ("extid", Value::Integer(3))],
            ); // duplicate composite key
            g.add_node(
                ["Account"],
                [
                    ("tenant", Value::Integer(1)),
                    ("extid", Value::Integer(999)),
                ],
            ); // same tenant, other extid (leading-prefix decoy)
            g.add_node(
                ["Account"],
                [("tenant", Value::Integer(2)), ("extid", Value::Integer(3))],
            ); // same extid, other tenant
            g.add_node(
                ["Account"],
                [("tenant", Value::Integer(2)), ("extid", Value::Integer(7))],
            );
        };
        let mut indexed = MemGraph::new();
        seed(&mut indexed);
        let mut plain = MemGraph::new();
        seed(&mut plain);

        let with_index = IndexCatalog::builder()
            .with_label_composite("Account", ["tenant", "extid"])
            .build();
        let no_index = IndexCatalog::empty();

        let rows = Value::List(vec![
            Value::Map(vec![
                ("tn".to_owned(), Value::Integer(1)),
                ("ex".to_owned(), Value::Integer(3)),
            ]), // matches BOTH duplicates
            Value::Map(vec![
                ("tn".to_owned(), Value::Integer(2)),
                ("ex".to_owned(), Value::Integer(7)),
            ]), // matches exactly one
            Value::Map(vec![
                ("tn".to_owned(), Value::Integer(1)),
                ("ex".to_owned(), Value::Integer(5)),
            ]), // MISSING: tenant 1 exists but no extid 5 -> zero rows
            Value::Map(vec![
                ("tn".to_owned(), Value::Integer(9)),
                ("ex".to_owned(), Value::Integer(9)),
            ]), // MISSING: neither key present -> zero rows
        ]);
        let params = Parameters::new().with("rows", rows);

        for src in [
            "UNWIND $rows AS t MATCH (b:Account {tenant: t.tn, extid: t.ex}) RETURN b",
            "UNWIND $rows AS t MATCH (b:Account) WHERE b.tenant = t.tn AND b.extid = t.ex RETURN b",
            "UNWIND $rows AS t WITH t.tn AS tn, t.ex AS ex \
             MATCH (b:Account {tenant: tn, extid: ex}) RETURN b",
        ] {
            let seek = ids(src, &mut indexed, &with_index, &params);
            let scan = ids(src, &mut plain, &no_index, &params);
            assert_eq!(seek, scan, "composite index must not change results: {src}");
            // (1,3) matches 2 duplicates + (2,7) matches 1 + two missing keys = 3 rows total. The
            // leading-prefix decoy (1,999) must NOT appear (it would if only `tenant` were sought).
            assert_eq!(seek.len(), 3, "expected 3 matched rows: {src}");

            // Also validate the COST-BASED plan (the optimiser must not break the correlated composite
            // seek by reordering it to the outer side or reverting it to a scan, `rmp` task #729).
            let mut cost_based: Vec<u64> =
                run_with_catalog_params_stats(src, &mut indexed, &with_index, &params)
                    .iter()
                    .filter_map(|r| r.get("b").and_then(RowValue::as_node))
                    .map(|id| id.0)
                    .collect();
            cost_based.sort_unstable();
            assert_eq!(
                cost_based, scan,
                "cost-based plan must not change results: {src}"
            );

            // The indexed plan must route through the correlated composite seek (else this proves nothing).
            let plan = {
                let toks = tokenize(src).expect("lex");
                let ast = parse_tokens(&toks, src).expect("parse");
                plan_physical(&lower(&analyze(&ast).expect("analyze")), &with_index)
            };
            let rendered = plan.to_string();
            assert!(
                rendered.contains("NodeCompositeIndexSeek"),
                "the correlated anchor must use the composite index seek:\n{rendered}"
            );
            assert!(
                !rendered.contains("NodeByLabelScan"),
                "the correlated anchor must NOT fall back to a label scan:\n{rendered}"
            );
        }
    }

    /// A `GraphAccess` seam over a [`MemGraph`] with a **real** in-process single-property index on
    /// `(Person.uid)` (a hash map from the value to node ids) plus a [`Cell`](std::cell::Cell) counting
    /// the **anchor node records examined** (`rmp` task #730):
    ///
    /// * [`index_seek_eq`](GraphAccess::index_seek_eq) does an O(1) hash lookup and charges only the
    ///   candidates it returns — the pushed-through-expand **seek** (post-#730).
    /// * [`scan_nodes_by_label`](GraphAccess::scan_nodes_by_label) charges every `:Person` node — the
    ///   label **scan** a pre-#730 anchor takes per driving row (the anchor stays a `NodeByLabelScan`
    ///   beneath the expand, so each row reads the whole label).
    ///
    /// The traversal itself (`expand`, `node_property`, …) delegates to the inner graph and is identical
    /// on both paths, so the counter isolates the anchor access cost: a sweep over `N` proves the seek
    /// stays flat while the scan grows linearly.
    struct CountingAnchorGraph {
        inner: MemGraph,
        uid_index: std::collections::HashMap<String, Vec<NodeId>>,
        examined: std::cell::Cell<usize>,
    }

    impl CountingAnchorGraph {
        fn key_of(value: &Value) -> String {
            format!("{value:?}")
        }
        fn new(inner: MemGraph) -> Self {
            let mut uid_index: std::collections::HashMap<String, Vec<NodeId>> =
                std::collections::HashMap::new();
            for id in inner.scan_nodes_by_label("Person") {
                if let Some(uid) = inner.node_property(id, "uid") {
                    uid_index.entry(Self::key_of(&uid)).or_default().push(id);
                }
            }
            Self {
                inner,
                uid_index,
                examined: std::cell::Cell::new(0),
            }
        }
        fn reset(&self) {
            self.examined.set(0);
        }
        fn examined(&self) -> usize {
            self.examined.get()
        }
    }

    impl crate::statistics::Statistics for CountingAnchorGraph {
        fn total_nodes(&self) -> u64 {
            self.inner.node_count() as u64
        }
        fn nodes_with_label(&self, label: &str) -> Option<u64> {
            Some(self.inner.scan_nodes_by_label(label).len() as u64)
        }
        fn total_relationships(&self) -> u64 {
            self.inner.rel_count() as u64
        }
        fn relationships_with_type(&self, _rel_type: &str) -> Option<u64> {
            Some(self.inner.rel_count() as u64)
        }
    }

    impl GraphAccess for CountingAnchorGraph {
        fn index_seek_eq(
            &self,
            label: &str,
            property: &str,
            value: &Value,
            _carry: KeyValues,
        ) -> Option<IndexSeekHits> {
            if label != "Person" || property != "uid" {
                return None;
            }
            let ids = self
                .uid_index
                .get(&Self::key_of(value))
                .cloned()
                .unwrap_or_default();
            self.examined.set(self.examined.get() + ids.len());
            Some(IndexSeekHits::ids(ids))
        }
        fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
            let ids = self.inner.scan_nodes_by_label(label);
            if label == "Person" {
                self.examined.set(self.examined.get() + ids.len());
            }
            ids
        }
        fn statistics(&self) -> Option<&dyn crate::statistics::Statistics> {
            Some(self)
        }
        fn scan_nodes(&self) -> Vec<NodeId> {
            self.inner.scan_nodes()
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

    #[test]
    fn correlated_anchor_over_expand_per_row_cost_is_flat_in_n() {
        // `rmp` task #730 — the WHOLE POINT, measured. A batched read drives a FIXED number of rows,
        // each anchoring on a per-row key then expanding, against a store of `N` `:Person` anchors.
        // Pre-#730 the anchor beneath the expand is a per-row LABEL SCAN (O(N) per row → O(D·N) total);
        // post-#730 it is a per-row SEEK pushed through the traversal (O(1) per row → O(D) total).
        //
        // Measured deterministically as ANCHOR node records examined (not wall-clock): the
        // `CountingAnchorGraph` charges the seek only its candidates and the scan every `:Person`. The
        // scan path (`no_index`) is the growing-slope proxy for the pre-fix cost; the seek path
        // (`with_index`) is the flat line. Both run on the SAME seam and return the IDENTICAL rows, so
        // the flatness is proven against a real, growing baseline.
        use crate::binding::Parameters;

        const D: i64 = 8;
        let rows = Value::List(
            (0..D)
                .map(|i| Value::Map(vec![("uid".to_owned(), Value::Integer(i))]))
                .collect(),
        );
        let params = Parameters::new().with("rows", rows);

        let with_index = IndexCatalog::builder()
            .with_label_property("Person", "uid")
            .build();
        let no_index = IndexCatalog::empty();

        fn run_measured(
            src: &str,
            seam: &mut CountingAnchorGraph,
            catalog: &IndexCatalog,
            params: &Parameters,
        ) -> (usize, usize) {
            let toks = tokenize(src).expect("lex");
            let ast = parse_tokens(&toks, src).expect("parse");
            let logical = lower(&analyze(&ast).expect("analyze"));
            let plan = {
                let stats = seam.statistics();
                crate::physical::plan_physical_with_stats(&logical, catalog, stats)
            };
            let bound = crate::binding::bind_parameters(&plan, params).expect("bind");
            seam.reset();
            let rows = execute(&plan, &bound, seam)
                .expect("open")
                .collect_all()
                .expect("rows")
                .len();
            (rows, seam.examined())
        }

        let src = "UNWIND $rows AS t MATCH (b:Person)-[:R]->(c) WHERE b.uid = t.uid RETURN c.name AS name";

        // The no-index path expands from every anchor per driving row and `MemGraph::expand` is O(rels),
        // so the scan path is ~O(N²) — keep the sweep modest; the exact `scan == D*N` assertions below
        // prove linear growth rigorously without a huge N.
        let sweep = [200usize, 400, 800, 1600];
        let mut seek_curve: Vec<(usize, usize)> = Vec::new();
        let mut scan_curve: Vec<(usize, usize)> = Vec::new();
        for &n in &sweep {
            // Each :Person(uid=i) has one :R edge to a distinct :Thing (so every driving row yields 1
            // row); uid is unique so each seek returns 1 candidate.
            let mut mem = MemGraph::new();
            for i in 0..n as i64 {
                let p = mem.add_node(["Person"], [("uid", Value::Integer(i))]);
                let thing = mem.add_node(["Thing"], [("name", Value::String(format!("t{i}")))]);
                mem.add_rel("R", p, thing, NO_PROPS);
            }
            let mut seam = CountingAnchorGraph::new(mem);

            let (seek_rows, seek_examined) = run_measured(src, &mut seam, &with_index, &params);
            let (scan_rows, scan_examined) = run_measured(src, &mut seam, &no_index, &params);

            assert_eq!(
                seek_rows, scan_rows,
                "seek and scan row counts disagree at N={n}"
            );
            assert_eq!(seek_rows, D as usize, "expected {D} rows at N={n}");

            seek_curve.push((n, seek_examined));
            scan_curve.push((n, scan_examined));
        }

        eprintln!("[#730 flat-cost] D={D} driving rows; anchor records examined vs N:");
        for ((n, seek), (_, scan)) in seek_curve.iter().zip(scan_curve.iter()) {
            eprintln!(
                "  N={n:>5}  seek={seek:>7}  scan={scan:>9}  scan/seek={:.1}x",
                *scan as f64 / (*seek).max(1) as f64
            );
        }

        // SEEK is FLAT: examined is constant across the sweep (D candidates, one per driving row).
        let seek_baseline = seek_curve[0].1;
        for &(n, examined) in &seek_curve {
            assert_eq!(
                examined, seek_baseline,
                "the pushed SEEK must be flat in N: examined {examined} at N={n} != {seek_baseline}"
            );
        }
        assert_eq!(
            seek_baseline, D as usize,
            "the seek examines exactly one anchor candidate per driving row"
        );

        // The no-index path now examines N, not D*N — a planner improvement, not a regression.
        // `WHERE b.uid = t.uid` is an equality between two independent branches, and `rmp` task #865
        // recognises exactly that as a value hash join: the anchors are scanned ONCE into a hash table
        // and probed per driving row, instead of being re-scanned for every driving row. So the cost
        // lost its factor of D (it was 1600 at N=200 with D=8; it is now 200).
        //
        // It still grows with N, which is inherent — the table has to be built — so the contrast with
        // the seek survives: the seek stays flat at D while this grows linearly. What #730 guarantees is
        // asserted above and unchanged. Rows are compared seek-versus-scan at every N further up, so a
        // plan that got fast by getting WRONG would be caught there.
        for &(n, examined) in &scan_curve {
            assert_eq!(
                examined, n,
                "the no-index path builds one hash table over the anchors (#865): examined \
                 {examined} at N={n}"
            );
        }
        assert!(
            scan_curve.last().unwrap().1 > 6 * scan_curve.first().unwrap().1,
            "the scan slope must still grow with N across the sweep: {scan_curve:?}"
        );
    }

    #[test]
    fn correlated_anchor_over_expand_returns_exactly_the_scan_result() {
        // `rmp` task #730: a correlated anchor that expands, keyed by a `WHERE` after the pattern —
        // `UNWIND $rows AS t MATCH (b:Person)-[:R]->(c) WHERE b.uid = t.uid RETURN c` — now pushes the
        // anchor equality down onto the scan (a per-row `NodeIndexSeek`) with the expand running from
        // each seeked anchor. The push-down must NEVER change results: for every driving row the seek
        // path and the plain scan+filter path must return the IDENTICAL rows in the IDENTICAL ORDER and
        // multiplicity. Exercised with a DUPLICATE anchor uid (two `:Person` share uid 1 — multiplicity),
        // a DUPLICATE driving key (uid 1 twice — the batch fans out twice), and a MISSING key (uid 99 —
        // zero rows). A regression that pushed a wrong value or dropped/duplicated rows fails here.
        use crate::binding::Parameters;

        // Ordered `c.name` values the read returns (NOT sorted — order is part of the contract).
        fn names(
            src: &str,
            graph: &mut MemGraph,
            catalog: &IndexCatalog,
            params: &Parameters,
        ) -> Vec<String> {
            run_with_catalog_and_params(src, graph, catalog, params)
                .iter()
                .filter_map(|r| match r.value("name") {
                    Value::String(s) => Some(s),
                    _ => None,
                })
                .collect()
        }

        // uid 1 -> p1 (→ tA, tB) and p2 (→ tC): a duplicate anchor uid. uid 2 -> p3 (→ tD). uid 3 -> p4
        // (→ tE, unreachable from the driving rows). Two identically-seeded graphs isolate the PLAN
        // difference (`MemGraph` serves both index and scan through `scan_filter_eq`).
        let seed = |g: &mut MemGraph| {
            let p1 = g.add_node(["Person"], [("uid", Value::Integer(1))]);
            let p2 = g.add_node(["Person"], [("uid", Value::Integer(1))]); // duplicate anchor uid
            let p3 = g.add_node(["Person"], [("uid", Value::Integer(2))]);
            let p4 = g.add_node(["Person"], [("uid", Value::Integer(3))]);
            let ta = g.add_node(["Thing"], [("name", Value::String("tA".into()))]);
            let tb = g.add_node(["Thing"], [("name", Value::String("tB".into()))]);
            let tc = g.add_node(["Thing"], [("name", Value::String("tC".into()))]);
            let td = g.add_node(["Thing"], [("name", Value::String("tD".into()))]);
            let te = g.add_node(["Thing"], [("name", Value::String("tE".into()))]);
            g.add_rel("R", p1, ta, NO_PROPS);
            g.add_rel("R", p1, tb, NO_PROPS);
            g.add_rel("R", p2, tc, NO_PROPS);
            g.add_rel("R", p3, td, NO_PROPS);
            g.add_rel("R", p4, te, NO_PROPS);
        };
        let mut indexed = MemGraph::new();
        seed(&mut indexed);
        let mut plain = MemGraph::new();
        seed(&mut plain);

        let with_index = IndexCatalog::builder()
            .with_label_property("Person", "uid")
            .build();
        let no_index = IndexCatalog::empty();

        let rows = Value::List(vec![
            Value::Map(vec![("uid".to_owned(), Value::Integer(1))]),
            Value::Map(vec![("uid".to_owned(), Value::Integer(1))]), // duplicate driving key
            Value::Map(vec![("uid".to_owned(), Value::Integer(2))]),
            Value::Map(vec![("uid".to_owned(), Value::Integer(99))]), // missing key
        ]);
        let params = Parameters::new().with("rows", rows);

        let src = "UNWIND $rows AS t MATCH (b:Person)-[:R]->(c) WHERE b.uid = t.uid RETURN c.name AS name";

        let seek = names(src, &mut indexed, &with_index, &params);
        let scan = names(src, &mut plain, &no_index, &params);
        assert_eq!(
            seek, scan,
            "the pushed-through-expand seek must match the scan exactly (order + multiplicity)"
        );
        // uid 1 (×2 driving) → {tA, tB, tC} each time = 6 rows; uid 2 → {tD} = 1; uid 99 → none.
        assert_eq!(seek.len(), 7, "expected 7 rows: {seek:?}");
        {
            let mut sorted = seek.clone();
            sorted.sort();
            assert_eq!(
                sorted,
                vec!["tA", "tA", "tB", "tB", "tC", "tC", "tD"],
                "the exact multiset (duplicate anchor + duplicate driving key + missing key): {seek:?}"
            );
        }

        // Cost-based plan must agree too (the pushed seek is immovable, `rmp` #730).
        let cost_based: Vec<String> =
            run_with_catalog_params_stats(src, &mut indexed, &with_index, &params)
                .iter()
                .filter_map(|r| match r.value("name") {
                    Value::String(s) => Some(s),
                    _ => None,
                })
                .collect();
        assert_eq!(cost_based, scan, "cost-based plan must not change results");

        // The indexed plan must route through the pushed-down seek (else this proves nothing).
        let plan = {
            let toks = tokenize(src).expect("lex");
            let ast = parse_tokens(&toks, src).expect("parse");
            plan_physical(&lower(&analyze(&ast).expect("analyze")), &with_index)
        };
        let rendered = plan.to_string();
        assert!(
            rendered.contains("NodeIndexSeek(b:Person uid = t.uid"),
            "the anchor must seek beneath the expand:\n{rendered}"
        );
        assert!(
            !rendered.contains("NodeByLabelScan"),
            "the anchor must NOT stay a label scan:\n{rendered}"
        );
    }

    #[test]
    fn correlated_anchor_over_expand_value_bound_by_expand_matches_the_scan() {
        // `rmp` task #730 — the free-var safety guard, checked at the EXECUTOR level: a predicate whose
        // value references a variable bound by the traversal (`b.uid = c.uid`, `c` the expand's target)
        // must NOT be pushed. The planner keeps it a scan+filter; here we prove the RESULT is right (a
        // wrong push to the anchor would evaluate `c.uid` against an unbound variable and drop rows). The
        // indexed catalog and the empty catalog must agree.
        use crate::binding::Parameters;

        fn names(
            src: &str,
            graph: &mut MemGraph,
            catalog: &IndexCatalog,
            params: &Parameters,
        ) -> Vec<String> {
            let mut out: Vec<String> = run_with_catalog_and_params(src, graph, catalog, params)
                .iter()
                .filter_map(|r| match r.value("name") {
                    Value::String(s) => Some(s),
                    _ => None,
                })
                .collect();
            out.sort();
            out
        }

        // p1(uid=10)->tX(uid=10) [b.uid == c.uid ✓], p1->tY(uid=99) [✗]; p2(uid=20)->tZ(uid=20) [✓].
        let seed = |g: &mut MemGraph| {
            let p1 = g.add_node(["Person"], [("uid", Value::Integer(10))]);
            let p2 = g.add_node(["Person"], [("uid", Value::Integer(20))]);
            let tx = g.add_node(
                ["Thing"],
                [
                    ("uid", Value::Integer(10)),
                    ("name", Value::String("tX".into())),
                ],
            );
            let ty = g.add_node(
                ["Thing"],
                [
                    ("uid", Value::Integer(99)),
                    ("name", Value::String("tY".into())),
                ],
            );
            let tz = g.add_node(
                ["Thing"],
                [
                    ("uid", Value::Integer(20)),
                    ("name", Value::String("tZ".into())),
                ],
            );
            g.add_rel("R", p1, tx, NO_PROPS);
            g.add_rel("R", p1, ty, NO_PROPS);
            g.add_rel("R", p2, tz, NO_PROPS);
        };
        let mut indexed = MemGraph::new();
        seed(&mut indexed);
        let mut plain = MemGraph::new();
        seed(&mut plain);

        let with_index = IndexCatalog::builder()
            .with_label_property("Person", "uid")
            .build();
        let no_index = IndexCatalog::empty();

        // A driving row is present but the predicate is anchor-vs-target, independent of `t`.
        let params = Parameters::new().with(
            "rows",
            Value::List(vec![Value::Map(vec![("x".to_owned(), Value::Integer(0))])]),
        );

        let src = "UNWIND $rows AS t MATCH (b:Person)-[:R]->(c) WHERE b.uid = c.uid RETURN c.name AS name";
        let with = names(src, &mut indexed, &with_index, &params);
        let without = names(src, &mut plain, &no_index, &params);
        assert_eq!(
            with, without,
            "the un-pushable predicate must give identical results"
        );
        assert_eq!(
            with,
            vec!["tX", "tZ"],
            "only the b.uid == c.uid edges survive: {with:?}"
        );
    }

    #[test]
    fn two_variable_join_index_seek_returns_exactly_the_cartesian_filter_result() {
        // `rmp` task #732 (from the #708 merge): a two-variable JOIN predicate — `MATCH (a:Person),
        // (b:Person) WHERE a.uid = b.uid` — where one side is indexed now lowers to an index
        // nested-loop join (scan a, per-a seek b on b.uid = a.uid) instead of a cartesian product +
        // residual Filter. That is a SOUND, standard optimisation (the inner side sees the bound outer
        // variable), but it must NEVER change results. This pins the two edge cases the correlated
        // #708 test did not exercise for this shape: a DUPLICATE key (multiplicity) and a NULL key
        // (a NULL probe must yield zero matches, exactly as `a.uid = b.uid` is NULL/false for a NULL
        // operand — the one place a seek could silently diverge from a filter).
        fn pairs(src: &str, graph: &mut MemGraph, catalog: &IndexCatalog) -> Vec<(u64, u64)> {
            let mut out: Vec<(u64, u64)> = run_with_catalog(src, graph, catalog)
                .iter()
                .filter_map(|r| {
                    let a = r.get("a").and_then(RowValue::as_node)?;
                    let b = r.get("b").and_then(RowValue::as_node)?;
                    Some((a.0, b.0))
                })
                .collect();
            out.sort_unstable();
            out
        }

        let seed = |g: &mut MemGraph| {
            g.add_node(["Person"], [("uid", Value::Integer(1))]);
            g.add_node(["Person"], [("uid", Value::Integer(2))]);
            g.add_node(["Person"], [("uid", Value::Integer(2))]); // duplicate uid (multigraph)
            g.add_node(["Person"], [("uid", Value::Null)]); // NULL key: must never join
        };
        let mut indexed = MemGraph::new();
        seed(&mut indexed);
        let mut plain = MemGraph::new();
        seed(&mut plain);

        let with_index = IndexCatalog::builder()
            .with_label_property("Person", "uid")
            .build();
        let no_index = IndexCatalog::empty();

        let src = "MATCH (a:Person), (b:Person) WHERE a.uid = b.uid RETURN a, b";
        let seek = pairs(src, &mut indexed, &with_index);
        let scan = pairs(src, &mut plain, &no_index);
        assert_eq!(
            seek, scan,
            "the index nested-loop join must return exactly the cartesian+filter result"
        );
        // uid 1 -> (1 a) x (1 b) = 1 pair; uid 2 -> (2 a) x (2 b) = 4 pairs; NULL -> 0. Total 5.
        assert_eq!(seek.len(), 5, "expected 5 joined pairs (NULL never joins)");
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

    #[test]
    fn text_index_seek_returns_exactly_the_scan_result() {
        // `rmp` task #662: the TEXT (trigram) index must NEVER change results — only speed. For each of
        // CONTAINS / ENDS WITH / STARTS WITH (plus unicode, empty needle, mixed-type property, and a
        // no-match needle), the indexed seek path and the plain scan+filter path must return the
        // IDENTICAL node set.
        use crate::catalog::IndexCatalog;

        fn ids(src: &str, graph: &mut MemGraph, catalog: &IndexCatalog) -> Vec<u64> {
            let mut out: Vec<u64> = run_with_catalog(src, graph, catalog)
                .iter()
                .filter_map(|r| r.get("n").and_then(RowValue::as_node))
                .map(|id| id.0)
                .collect();
            out.sort_unstable();
            out
        }

        // Two identically-seeded graphs: one with a declared text index, one without. A mixed-type row
        // (`name` is an integer) and a non-string node exercise the "non-string value is not indexed and
        // not matched" path in BOTH the seek and the residual re-check.
        let seed = |g: &mut MemGraph| {
            g.add_node(["Person"], [("name", Value::String("Robert".to_owned()))]);
            g.add_node(["Person"], [("name", Value::String("roberta".to_owned()))]);
            g.add_node(["Person"], [("name", Value::String("Bobby".to_owned()))]);
            g.add_node(["Person"], [("name", Value::String("Álvaro".to_owned()))]); // unicode
            g.add_node(["Person"], [("name", Value::Integer(42))]); // mixed-type property
            g.add_node(["Person"], [("age", Value::Integer(30))]); // property absent
        };
        let mut indexed = MemGraph::new();
        seed(&mut indexed);
        indexed.create_text_index("Person", "name");
        let mut plain = MemGraph::new();
        seed(&mut plain);

        let with_index = IndexCatalog::builder()
            .with_label_text("Person", "name")
            .build();
        let no_index = IndexCatalog::empty();

        // A spread of needles across the three predicates + edge cases. Every one must agree.
        let queries = [
            "MATCH (n:Person) WHERE n.name CONTAINS 'obe' RETURN n", // Robert, roberta
            "MATCH (n:Person) WHERE n.name CONTAINS 'bb' RETURN n",  // Bobby
            "MATCH (n:Person) WHERE n.name ENDS WITH 'ert' RETURN n", // Robert (not roberta)
            "MATCH (n:Person) WHERE n.name ENDS WITH 'ta' RETURN n", // roberta
            "MATCH (n:Person) WHERE n.name STARTS WITH 'Rob' RETURN n", // Robert
            "MATCH (n:Person) WHERE n.name STARTS WITH 'rob' RETURN n", // roberta (case-sensitive)
            "MATCH (n:Person) WHERE n.name CONTAINS 'lvar' RETURN n", // Álvaro (unicode)
            "MATCH (n:Person) WHERE n.name CONTAINS 'zzz' RETURN n", // no match
            "MATCH (n:Person) WHERE n.name CONTAINS '' RETURN n", // empty needle (short → all strings)
            "MATCH (n:Person) WHERE n.name CONTAINS 'o' RETURN n", // short needle (< 3 chars)
            "MATCH (n:Person) WHERE n.name STARTS WITH 'R' RETURN n", // short prefix (< 2 chars)
        ];
        for q in queries {
            let seek = ids(q, &mut indexed, &with_index);
            let scan = ids(q, &mut plain, &no_index);
            assert_eq!(seek, scan, "text index must not change results for: {q}");
        }

        // Sanity: the indexed plan really does route through the text seek.
        let q = "MATCH (n:Person) WHERE n.name CONTAINS 'obe' RETURN n";
        let plan = {
            let toks = tokenize(q).expect("lex");
            let ast = parse_tokens(&toks, q).expect("parse");
            plan_physical(&lower(&analyze(&ast).expect("analyze")), &with_index)
        };
        assert!(
            plan.to_string().contains("NodeTextIndexSeek"),
            "the indexed plan must route through the text seek:\n{plan}"
        );
    }

    // ---- rmp #665: existence (IS NOT NULL) index scan + ORDER BY served by the index ----------

    #[test]
    fn existence_index_scan_returns_exactly_the_scan_filter_result() {
        // `rmp` task #665 (A): the existence `NodeIndexScan` must NEVER change results — only speed.
        // Seed a *sparse* property (some nodes lack it, one is explicitly null), then assert the indexed
        // (NodeIndexScan) and the plain (scan + filter) paths return the IDENTICAL node set.
        use crate::catalog::IndexCatalog;

        fn ids(src: &str, graph: &mut MemGraph, catalog: &IndexCatalog) -> Vec<u64> {
            let mut out: Vec<u64> = run_with_catalog(src, graph, catalog)
                .iter()
                .filter_map(|r| r.get("n").and_then(RowValue::as_node))
                .map(|id| id.0)
                .collect();
            out.sort_unstable();
            out
        }

        let seed = |g: &mut MemGraph| {
            g.add_node(["Person"], [("email", Value::String("a@x".to_owned()))]); // id 0: present
            g.add_node(["Person"], [("name", Value::String("no-email".to_owned()))]); // id 1: absent
            g.add_node(["Person"], [("email", Value::Null)]); // id 2: explicit null → excluded
            g.add_node(["Person"], [("email", Value::String("b@x".to_owned()))]); // id 3: present
        };
        let mut indexed = MemGraph::new();
        seed(&mut indexed);
        let mut plain = MemGraph::new();
        seed(&mut plain);

        let with_index = IndexCatalog::builder()
            .with_label_property("Person", "email")
            .build();
        let no_index = IndexCatalog::empty();

        let q = "MATCH (n:Person) WHERE n.email IS NOT NULL RETURN n";
        let scan_ids = ids(q, &mut indexed, &with_index);
        let plain_ids = ids(q, &mut plain, &no_index);
        assert_eq!(
            scan_ids, plain_ids,
            "the index scan must not change results"
        );
        assert_eq!(
            scan_ids,
            vec![0, 3],
            "only the two email-bearing nodes; the absent and the explicit-null node are excluded"
        );

        // Sanity: the indexed plan really does route through the NodeIndexScan with a retained residual.
        let plan = {
            let toks = tokenize(q).expect("lex");
            let ast = parse_tokens(&toks, q).expect("parse");
            plan_physical(&lower(&analyze(&ast).expect("analyze")), &with_index)
        };
        let rendered = plan.to_string();
        assert!(
            rendered.contains("NodeIndexScan") && rendered.contains("IS NOT NULL"),
            "the indexed plan must route through NodeIndexScan with a residual IS NOT NULL:\n{rendered}"
        );
    }

    #[test]
    fn order_by_index_elision_matches_the_sort_including_duplicates() {
        // `rmp` task #665 (B): eliding the `Sort` over an ordered index access must produce the SAME
        // ordered rows as keeping the `Sort`. Seed duplicate ages in non-sorted insertion order so the
        // ordering is non-trivial, then compare the indexed (Sort elided) path against the plain (Sort
        // kept) path row-for-row.
        use crate::catalog::IndexCatalog;

        fn ages(src: &str, graph: &mut MemGraph, catalog: &IndexCatalog) -> Vec<i64> {
            run_with_catalog(src, graph, catalog)
                .iter()
                .filter_map(|r| match r.get("age") {
                    Some(RowValue::Value(Value::Integer(a))) => Some(*a),
                    _ => None,
                })
                .collect()
        }

        let seed = |g: &mut MemGraph| {
            g.add_node(["P"], [("age", Value::Integer(30))]); // id 0
            g.add_node(["P"], [("age", Value::Integer(10))]); // id 1
            g.add_node(["P"], [("age", Value::Integer(20))]); // id 2
            g.add_node(["P"], [("age", Value::Integer(10))]); // id 3 (duplicate value)
            g.add_node(["P"], [("age", Value::Integer(30))]); // id 4 (duplicate value)
        };
        let mut indexed = MemGraph::new();
        seed(&mut indexed);
        let mut plain = MemGraph::new();
        seed(&mut plain);

        let with_index = IndexCatalog::builder()
            .with_label_property("P", "age")
            .build();
        let no_index = IndexCatalog::empty();

        let q = "MATCH (n:P) WHERE n.age > 0 RETURN n.age AS age ORDER BY n.age";
        let elided = ages(q, &mut indexed, &with_index); // Sort elided (ordered range seek)
        let sorted = ages(q, &mut plain, &no_index); // Sort kept
        assert_eq!(
            elided, sorted,
            "eliding the Sort must yield the identical ordered rows"
        );
        assert_eq!(
            elided,
            vec![10, 10, 20, 30, 30],
            "ascending by age, duplicates preserved"
        );

        // Sanity: the indexed plan elides the Sort (and marks the seek ordered); the plain plan keeps it.
        let plan_of = |catalog: &IndexCatalog| {
            let toks = tokenize(q).expect("lex");
            let ast = parse_tokens(&toks, q).expect("parse");
            plan_physical(&lower(&analyze(&ast).expect("analyze")), catalog).to_string()
        };
        let indexed_plan = plan_of(&with_index);
        assert!(
            !indexed_plan.contains("Sort") && indexed_plan.contains("ordered asc"),
            "the indexed plan must elide the Sort onto an ordered seek:\n{indexed_plan}"
        );
        assert!(
            plan_of(&no_index).contains("Sort"),
            "the unindexed plan keeps its Sort"
        );
    }

    #[test]
    fn order_by_index_elision_reflects_a_value_updated_mid_life() {
        // `rmp` task #665 (B): the ordered emission must sort by the node's CURRENT property value
        // (`node_property`), not any earlier value — so a value changed after seeding reorders the
        // result exactly as the `Sort` would. Guards the "stale entry" concern at the executor level:
        // the ordered access re-reads the live value, so an out-of-date ordering can never leak.
        use crate::catalog::IndexCatalog;

        fn ages(src: &str, graph: &mut MemGraph, catalog: &IndexCatalog) -> Vec<i64> {
            run_with_catalog(src, graph, catalog)
                .iter()
                .filter_map(|r| match r.get("age") {
                    Some(RowValue::Value(Value::Integer(a))) => Some(*a),
                    _ => None,
                })
                .collect()
        }

        let with_index = IndexCatalog::builder()
            .with_label_property("P", "age")
            .build();
        let no_index = IndexCatalog::empty();

        let build = |g: &mut MemGraph| {
            g.add_node(["P"], [("age", Value::Integer(30))]); // id 0
            g.add_node(["P"], [("age", Value::Integer(10))]); // id 1
            g.add_node(["P"], [("age", Value::Integer(20))]); // id 2
        };
        let mut indexed = MemGraph::new();
        build(&mut indexed);
        let mut plain = MemGraph::new();
        build(&mut plain);

        // Move node 0 from age 30 to age 5 (now the smallest) in both graphs.
        let bump = "MATCH (n:P) WHERE n.age = 30 SET n.age = 5";
        run_with_catalog(bump, &mut indexed, &with_index);
        run_with_catalog(bump, &mut plain, &no_index);

        let q = "MATCH (n:P) WHERE n.age > 0 RETURN n.age AS age ORDER BY n.age";
        let elided = ages(q, &mut indexed, &with_index);
        let sorted = ages(q, &mut plain, &no_index);
        assert_eq!(
            elided, sorted,
            "the elided order must track the updated value like the Sort"
        );
        assert_eq!(
            elided,
            vec![5, 10, 20],
            "the updated node sorts first by its NEW value"
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

    // ---- SEC-190 / rmp #589: stack-overflow hardening for a self-referential clause chain ---------
    //
    // A self-referential chain such as `WITH [a] AS a` repeated has TWO coupled stack-overflow
    // vectors, both reachable from a single shallow authenticated query and both an *uncatchable*
    // process abort (SIGABRT) — which defeats panic isolation and takes down every database the
    // server hosts:
    //
    //   (1) OPERATOR-TREE recursion: each clause is one more nested `Operator::Project`, and the
    //       Volcano executor pulls a row by recursing `input.next()` one frame per level. This
    //       overflows *first* (the descent reaches the leaf before any per-value guard runs) and even
    //       with a constant shallow value. Bounded by the parser's `MAX_QUERY_CLAUSES` clause budget,
    //       which rejects the chain as a recoverable `SyntaxError` before any tree is built/executed.
    //   (2) VALUE-NESTING recursion: the rebound value nests one level deeper per clause and later
    //       overflows a depth-recursive consumer (`to_value`, the wire encoders, the recursive
    //       `Drop`). Bounded by `MAX_VALUE_DEPTH` at every runtime materialisation point (projection,
    //       `collect`, `SET` write). Reachable independently of (1) via a near-cap PARAMETER (allowed
    //       at the bind boundary at exactly the cap) wrapped once by a single shallow clause.

    /// Runs the full pipeline with `params`, returning the first recoverable error stage (or the rows).
    /// Every stage's error is a recoverable [`graphus_core::GraphusError`]; a stack overflow would be an
    /// abort, so reaching `Ok`/`Err` here at all is itself the survival assertion.
    fn run_full(
        src: &str,
        graph: &mut MemGraph,
        params: &crate::binding::Parameters,
    ) -> Result<Vec<Row>, graphus_core::GraphusError> {
        let toks = tokenize(src).map_err(graphus_core::GraphusError::from)?;
        let ast = parse_tokens(&toks, src).map_err(graphus_core::GraphusError::from)?;
        let validated = analyze(&ast).map_err(graphus_core::GraphusError::from)?;
        let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
        let bound = crate::binding::bind_parameters(&plan, params)
            .map_err(graphus_core::GraphusError::from)?;
        let mut cursor = execute(&plan, &bound, graph).map_err(graphus_core::GraphusError::from)?;
        cursor
            .collect_all()
            .map_err(graphus_core::GraphusError::from)
    }

    /// A pure-property value nested exactly `depth` levels (`[[…[0]…]]`), built iteratively.
    fn nested_value(depth: usize) -> Value {
        let mut v = Value::Integer(0);
        for _ in 0..depth {
            v = Value::List(vec![v]);
        }
        v
    }

    /// Vector (1): the operator-tree recursion. A `WITH [a] AS a` chain well past the clause budget is
    /// rejected as a recoverable compile error **before** any deep operator tree is built or executed,
    /// and the engine keeps serving. Proves the SIGABRT is converted to a clean, isolated failure.
    #[test]
    fn deep_self_referential_chain_is_rejected_not_aborted() {
        let mut src = String::from("WITH [1] AS a ");
        for _ in 0..(MAX_QUERY_CLAUSES + 200) {
            src.push_str("WITH [a] AS a ");
        }
        src.push_str("RETURN a");

        let mut g = MemGraph::new();
        let err = run_full(&src, &mut g, &crate::binding::Parameters::new())
            .expect_err("an over-long clause chain must be a recoverable error, not an abort");
        assert!(
            matches!(err, graphus_core::GraphusError::Compile(_)),
            "the chain must be rejected at compile time (clause budget), got {err:?}"
        );

        // The engine survived: a subsequent statement still runs to completion.
        let rows = run("RETURN 1 AS ok", &mut g);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value("ok"), Value::Integer(1));
    }

    /// The `collect`-based self-referential chain (`WITH collect(a) AS a`) is the same operator-tree
    /// vector and is likewise rejected at the clause budget — recoverable, not an abort.
    #[test]
    fn deep_self_referential_collect_chain_is_rejected_not_aborted() {
        let mut src = String::from("WITH [1] AS a ");
        for _ in 0..(MAX_QUERY_CLAUSES + 200) {
            src.push_str("WITH collect(a) AS a ");
        }
        src.push_str("RETURN a");

        let mut g = MemGraph::new();
        let err = run_full(&src, &mut g, &crate::binding::Parameters::new())
            .expect_err("an over-long collect chain must be a recoverable error, not an abort");
        assert!(
            matches!(err, graphus_core::GraphusError::Compile(_)),
            "got {err:?}"
        );
    }

    /// The clause budget is a boundary, not a cliff: a statement with exactly `MAX_QUERY_CLAUSES`
    /// clauses parses; one more is a recoverable `SyntaxError`. (Parse-only — executing a chain this
    /// long on the small default test stack is a separate matter; the budget's job is to reject the
    /// *over*-limit case before execution.)
    #[test]
    fn clause_budget_boundary_is_exact() {
        // A single query is a chain of clauses; build exactly `MAX_QUERY_CLAUSES` of them.
        let at_limit = {
            let mut s = String::from("WITH 1 AS a ");
            for _ in 0..(MAX_QUERY_CLAUSES - 2) {
                s.push_str("WITH 1 AS a ");
            }
            s.push_str("RETURN a"); // total = 1 + (LIMIT-2) + 1 = LIMIT clauses
            s
        };
        let toks = tokenize(&at_limit).expect("lex");
        assert!(
            parse_tokens(&toks, &at_limit).is_ok(),
            "a statement with exactly MAX_QUERY_CLAUSES clauses must parse"
        );

        let over_limit = format!("{at_limit} UNION RETURN 2 AS a"); // pushes past the budget
        let toks = tokenize(&over_limit).expect("lex");
        let err = parse_tokens(&toks, &over_limit).expect_err("over-limit must be rejected");
        assert!(
            matches!(err.kind, crate::parser::SyntaxErrorKind::TooManyClauses),
            "got {:?}",
            err.kind
        );
    }

    /// Vector (2), reachable within the clause budget: a **parameter** nested at exactly the depth cap
    /// (allowed at the bind boundary) is wrapped once by a single shallow projection, so the projected
    /// value exceeds `MAX_VALUE_DEPTH`. The projection guard must reject it as a recoverable
    /// `ResourceLimit`, not let it flow to a depth-recursive `to_value`/encoder/`Drop`.
    #[test]
    fn over_deep_value_from_parameter_projection_is_recoverable() {
        let deep = nested_value(crate::value_depth::MAX_VALUE_DEPTH); // exactly at the cap: bind allows it
        let params = crate::binding::Parameters::new().with("p", deep);
        let mut g = MemGraph::new();
        let err = run_full("RETURN [$p] AS r", &mut g, &params)
            .expect_err("wrapping a cap-depth parameter must exceed the value budget");
        assert!(
            matches!(err, graphus_core::GraphusError::Runtime(_)),
            "must be a recoverable runtime error (ResourceLimit), got {err:?}"
        );
        // Engine survived.
        let rows = run("RETURN 1 AS ok", &mut g);
        assert_eq!(rows[0].value("ok"), Value::Integer(1));
    }

    /// Vector (2) via `collect`: collecting a cap-depth parameter would build a list one level past the
    /// cap; the `push_collected` gather guard rejects it (recoverable), before the deep value is bound.
    #[test]
    fn over_deep_value_from_parameter_collect_is_recoverable() {
        let deep = nested_value(crate::value_depth::MAX_VALUE_DEPTH);
        let params = crate::binding::Parameters::new().with("p", deep);
        let mut g = MemGraph::new();
        let err = run_full("WITH $p AS a RETURN collect(a) AS c", &mut g, &params)
            .expect_err("collecting a cap-depth value must exceed the value budget");
        assert!(
            matches!(err, graphus_core::GraphusError::Runtime(_)),
            "got {err:?}"
        );
    }

    /// Vector (2) via `SET`: persisting an over-deep property is rejected (recoverable), so the storage
    /// accumulation loop `SET n.p = [n.p]` can never poison a later read/encode with an abort.
    #[test]
    fn over_deep_value_set_is_recoverable() {
        let deep = nested_value(crate::value_depth::MAX_VALUE_DEPTH);
        let params = crate::binding::Parameters::new().with("p", deep);
        let mut g = MemGraph::new();
        let _ = g.add_node(["N"], NO_PROPS);
        let err = run_full("MATCH (n:N) SET n.p = [$p]", &mut g, &params)
            .expect_err("persisting an over-deep property must be rejected");
        assert!(
            matches!(err, graphus_core::GraphusError::Runtime(_)),
            "got {err:?}"
        );
    }

    /// Legitimate nesting (a handful of levels, the realistic case) must be **entirely unaffected** by
    /// the depth budget — the guards only ever reject the pathological deep value, never a real one.
    #[test]
    fn legitimate_moderate_nesting_still_projects() {
        let mut g = MemGraph::new();
        // Depth 4 list, and a nested map/list mix — both far under the cap.
        let rows = run("WITH [[[[1]]]] AS a RETURN a AS r", &mut g);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].value("r"),
            Value::List(vec![Value::List(vec![Value::List(vec![Value::List(
                vec![Value::Integer(1)]
            )])])])
        );

        let rows = run(
            "WITH [1] AS a WITH [a] AS a WITH [a, [a]] AS a RETURN a AS r",
            &mut g,
        );
        assert_eq!(rows.len(), 1);
        // a = [1] -> [[1]] -> [[[1]], [[[1]]]]
        let inner = Value::List(vec![Value::List(vec![Value::Integer(1)])]); // [[1]]
        assert_eq!(
            rows[0].value("r"),
            Value::List(vec![inner.clone(), Value::List(vec![inner])])
        );
    }

    /// A `collect` over legitimately shallow values keeps working (the depth guard is depth-only and
    /// never trips on width): `collect` of many depth-1 elements is a depth-2 list, far under the cap.
    #[test]
    fn wide_shallow_collect_is_unaffected() {
        let mut g = MemGraph::new();
        for i in 0..50 {
            let _ = g.add_node(["N"], [("v", Value::Integer(i))]);
        }
        let rows = run("MATCH (n) RETURN collect([n.v]) AS r", &mut g);
        assert_eq!(rows.len(), 1);
        match rows[0].value("r") {
            Value::List(items) => assert_eq!(items.len(), 50),
            other => panic!("expected a 50-element list, got {other:?}"),
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

    // ---------------------------------------------------------------------------------------------
    // CALL { ... } subquery clause (rmp #633)
    // ---------------------------------------------------------------------------------------------

    /// A sorted `(x, y)` pair projection of the result rows (both integer columns).
    fn int_pairs(rows: &[Row], a: &str, b: &str) -> Vec<(i64, i64)> {
        let mut out: Vec<(i64, i64)> = rows
            .iter()
            .filter_map(|r| match (r.value(a), r.value(b)) {
                (Value::Integer(x), Value::Integer(y)) => Some((x, y)),
                _ => None,
            })
            .collect();
        out.sort_unstable();
        out
    }

    #[test]
    fn call_subquery_importing_with_correlated() {
        // Neo4j manual example: `UNWIND [1,2] AS x CALL { WITH x RETURN x*10 AS y } RETURN x, y`
        // → (1,10),(2,20). The importing WITH is the ONLY way `x` enters the subquery.
        let mut g = MemGraph::new();
        let rows = run(
            "UNWIND [1, 2] AS x CALL { WITH x RETURN x * 10 AS y } RETURN x, y",
            &mut g,
        );
        assert_eq!(int_pairs(&rows, "x", "y"), vec![(1, 10), (2, 20)]);
    }

    #[test]
    fn call_subquery_returns_aggregate() {
        // `CALL { MATCH (n) RETURN count(n) AS c } RETURN c` — a leading (uncorrelated) subquery.
        let mut g = exists_tck_graph(); // 4 nodes
        let rows = run("CALL { MATCH (n) RETURN count(n) AS c } RETURN c", &mut g);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value("c"), Value::Integer(4));
    }

    #[test]
    fn call_subquery_cardinality_multiplies() {
        // A returning subquery multiplies cardinality: 2 outer rows × 2 inner rows = 4.
        let mut g = MemGraph::new();
        let rows = run(
            "UNWIND [1, 2] AS x CALL { UNWIND [10, 20] AS y RETURN y } RETURN x, y",
            &mut g,
        );
        assert_eq!(
            int_pairs(&rows, "x", "y"),
            vec![(1, 10), (1, 20), (2, 10), (2, 20)]
        );
    }

    #[test]
    fn call_subquery_empty_result_drops_outer_row() {
        // A returning subquery that yields nothing for a driving row drops that row (inner-apply).
        let mut g = MemGraph::new();
        let rows = run(
            "UNWIND [1, 2, 3] AS x CALL { WITH x UNWIND (CASE WHEN x = 2 THEN [] ELSE [x] END) AS y RETURN y } RETURN x",
            &mut g,
        );
        let mut xs: Vec<i64> = rows
            .iter()
            .filter_map(|r| match r.value("x") {
                Value::Integer(k) => Some(k),
                _ => None,
            })
            .collect();
        xs.sort_unstable();
        assert_eq!(
            xs,
            vec![1, 3],
            "x=2 produced no inner row, so it is dropped"
        );
    }

    #[test]
    fn call_subquery_unit_side_effect_preserves_cardinality() {
        // A UNIT subquery (no RETURN) runs for side effects and passes each driving row through
        // unchanged: 3 driving rows → 3 output rows AND 3 created nodes.
        let mut g = MemGraph::new();
        let rows = run(
            "UNWIND [1, 2, 3] AS x CALL { CREATE (:N) } RETURN x",
            &mut g,
        );
        assert_eq!(
            rows.len(),
            3,
            "unit subquery preserves the driving row count"
        );
        assert_eq!(
            g.scan_nodes_by_label("N").len(),
            3,
            "one node created per driving row"
        );
    }

    #[test]
    fn call_subquery_returning_write_reexecutes_per_row() {
        // A RETURNING subquery with a write must re-execute per driving row (NestedLoop rebuilds the
        // right branch), creating one node per row — never buffering a single result set.
        let mut g = MemGraph::new();
        let rows = run(
            "UNWIND [1, 2] AS x CALL { CREATE (n:M) RETURN n } RETURN x",
            &mut g,
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(g.scan_nodes_by_label("M").len(), 2, "one M per driving row");
    }

    #[test]
    fn call_subquery_union_inside() {
        // UNION inside the subquery: both branches contribute rows.
        let mut g = MemGraph::new();
        let rows = run(
            "CALL { RETURN 1 AS v UNION RETURN 2 AS v } RETURN v",
            &mut g,
        );
        let mut vs: Vec<i64> = rows
            .iter()
            .filter_map(|r| match r.value("v") {
                Value::Integer(k) => Some(k),
                _ => None,
            })
            .collect();
        vs.sort_unstable();
        assert_eq!(vs, vec![1, 2]);
    }

    #[test]
    fn call_subquery_in_transactions_of_rows() {
        // `IN TRANSACTIONS OF n ROWS` parses, plans and executes (batched within the outer txn — a
        // documented engine limitation): 3 driving rows → 3 created nodes, cardinality preserved.
        let mut g = MemGraph::new();
        let rows = run(
            "UNWIND [1, 2, 3] AS x CALL { CREATE (:T) } IN TRANSACTIONS OF 2 ROWS RETURN x",
            &mut g,
        );
        assert_eq!(rows.len(), 3);
        assert_eq!(g.scan_nodes_by_label("T").len(), 3);
    }

    #[test]
    fn call_subquery_correlated_match() {
        // The subquery is correlated by the imported `n`; it must count only n's own neighbours.
        // A(prop 1) has 3 outgoing rels; the others have none.
        let mut g = exists_tck_graph();
        let rows = run(
            "MATCH (n) CALL { WITH n MATCH (n)-->(m) RETURN count(m) AS deg } RETURN n.prop AS p, deg",
            &mut g,
        );
        let mut pairs: Vec<(i64, i64)> = rows
            .iter()
            .filter_map(|r| match (r.value("p"), r.value("deg")) {
                (Value::Integer(p), Value::Integer(d)) => Some((p, d)),
                _ => None,
            })
            .collect();
        pairs.sort_unstable();
        // A has 3; B/C/D have 0, but with an INNER count subquery each still returns one row (count
        // over zero matches = 0), so all four appear.
        assert_eq!(
            pairs,
            vec![(1, 3), (1, 0), (2, 0), (3, 0)]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn call_subquery_trailing_returning_no_outer_return() {
        // A query whose LAST clause is a returning CALL subquery (no trailing outer RETURN) is a
        // valid statement whose result columns are the subquery's returned columns.
        let mut g = MemGraph::new();
        let rows = run("CALL { RETURN 1 AS x }", &mut g);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value("x"), Value::Integer(1));
        assert_eq!(rows[0].columns(), &["x".to_owned()]);
    }

    #[test]
    fn call_subquery_nested() {
        // A CALL subquery nested inside another CALL subquery.
        let mut g = MemGraph::new();
        let rows = run(
            "CALL { CALL { RETURN 1 AS a } RETURN a * 2 AS b } RETURN b",
            &mut g,
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value("b"), Value::Integer(2));
    }

    // ---------------------------------------------------------------------------------------------
    // COUNT { ... } / COLLECT { ... } subquery expressions (rmp #634)
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn count_subquery_top_level_uncorrelated() {
        // `RETURN COUNT { ... }` with no driving MATCH — evaluated over the single implicit row.
        let mut g = exists_tck_graph(); // 4 nodes, 3 rels
        let rows = run("RETURN COUNT { MATCH (n) RETURN n } AS c", &mut g);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value("c"), Value::Integer(4));
    }

    #[test]
    fn count_subquery_pattern_form() {
        // `COUNT { (n)-->() }` — degree of each node. A has 3; others 0.
        let mut g = exists_tck_graph();
        let rows = run(
            "MATCH (n) RETURN n.prop AS p, COUNT { (n)-->() } AS deg",
            &mut g,
        );
        let mut pairs: Vec<(i64, i64)> = rows
            .iter()
            .filter_map(|r| match (r.value("p"), r.value("deg")) {
                (Value::Integer(p), Value::Integer(d)) => Some((p, d)),
                _ => None,
            })
            .collect();
        pairs.sort_unstable();
        assert_eq!(
            pairs,
            vec![(1, 3), (1, 0), (2, 0), (3, 0)]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn count_subquery_full_query_form() {
        // `COUNT { MATCH (n)-->(m) RETURN m }` — same degree, via the full-query form.
        let mut g = exists_tck_graph();
        let rows = run(
            "MATCH (n) WHERE COUNT { MATCH (n)-->(m) RETURN m } > 1 RETURN n.prop AS p",
            &mut g,
        );
        let ps: Vec<i64> = rows
            .iter()
            .filter_map(|r| match r.value("p") {
                Value::Integer(k) => Some(k),
                _ => None,
            })
            .collect();
        assert_eq!(ps, vec![1], "only A has >1 outgoing relationship");
    }

    #[test]
    fn collect_subquery_full_query() {
        // `COLLECT { MATCH (n) RETURN n.prop ORDER BY n.prop }` gathers the single column into a list.
        let mut g = exists_tck_graph();
        let rows = run(
            "RETURN COLLECT { MATCH (n) RETURN n.prop AS p ORDER BY p } AS props",
            &mut g,
        );
        assert_eq!(rows.len(), 1);
        // A list of scalars collapses to a pure `RowValue::Value(Value::List(..))`; `as_list_elems`
        // reads either representation.
        let items = rows[0]
            .get("props")
            .and_then(RowValue::as_list_elems)
            .expect("props is a list");
        let vals: Vec<Value> = items
            .iter()
            .map(|it| match it {
                RowValue::Value(v) => v.clone(),
                _ => Value::Null,
            })
            .collect();
        assert_eq!(
            vals,
            vec![
                Value::Integer(1),
                Value::Integer(1),
                Value::Integer(2),
                Value::Integer(3)
            ]
        );
    }

    #[test]
    fn collect_subquery_correlated() {
        // Correlated COLLECT: the neighbours' props of each node.
        let mut g = exists_tck_graph();
        let rows = run(
            "MATCH (n) RETURN n.prop AS p, COLLECT { MATCH (n)-->(m) RETURN m.prop AS mp ORDER BY mp } AS neighbours",
            &mut g,
        );
        // A (prop 1) collects [1,2,3]; the rest collect []. Find the row whose neighbour list is
        // non-empty and assert it has 3 elements.
        let non_empty: Vec<usize> = rows
            .iter()
            .filter_map(|r| r.get("neighbours").and_then(RowValue::as_list_elems))
            .map(|l| l.len())
            .filter(|&n| n > 0)
            .collect();
        assert_eq!(
            non_empty,
            vec![3],
            "only A has 3 neighbours; the rest collect []"
        );
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

    // ---- string-prefix successor (STARTS WITH bounded range seek, `rmp` task #658) --------------

    /// The exclusive upper bound is the shortest string strictly greater than every string with the
    /// prefix: increment the last scalar, carrying over trailing `U+10FFFF`.
    #[test]
    fn prefix_successor_basic_and_unicode() {
        assert_eq!(string_prefix_successor("ab").as_deref(), Some("ac"));
        assert_eq!(string_prefix_successor("az").as_deref(), Some("a{")); // 'z' (0x7A) -> '{' (0x7B)
        // Multi-byte last scalar: 'é' (U+00E9) -> 'ê' (U+00EA).
        assert_eq!(
            string_prefix_successor("caf\u{00E9}").as_deref(),
            Some("caf\u{00EA}")
        );
    }

    /// An empty prefix (and an all-`U+10FFFF` prefix) has no finite successor -> open upper bound.
    #[test]
    fn prefix_successor_open_upper_cases() {
        assert_eq!(string_prefix_successor(""), None);
        assert_eq!(string_prefix_successor("\u{10FFFF}"), None);
        assert_eq!(string_prefix_successor("\u{10FFFF}\u{10FFFF}"), None);
    }

    /// A trailing max scalar carries: drop it and increment the preceding scalar (a shorter string).
    #[test]
    fn prefix_successor_carries_over_max_scalar() {
        assert_eq!(string_prefix_successor("a\u{10FFFF}").as_deref(), Some("b"));
        assert_eq!(
            string_prefix_successor("ab\u{10FFFF}\u{10FFFF}").as_deref(),
            Some("ac")
        );
    }

    /// The successor must skip the UTF-16 surrogate gap (`U+D800..=U+DFFF` are not scalar values):
    /// incrementing `U+D7FF` yields `U+E000`.
    #[test]
    fn prefix_successor_skips_surrogate_gap() {
        assert_eq!(next_scalar('\u{D7FF}'), Some('\u{E000}'));
        assert_eq!(next_scalar('\u{10FFFF}'), None);
        assert_eq!(
            string_prefix_successor("x\u{D7FF}").as_deref(),
            Some("x\u{E000}")
        );
    }

    /// Property: the successor is strictly greater than the prefix and than `prefix + any suffix`,
    /// under `cmp_values` (the byte-lexicographic order the seam re-check and the keycodec use). This
    /// is the soundness invariant of the seek's upper bound — no matching string is ever excluded.
    #[test]
    fn prefix_successor_bounds_every_prefixed_string() {
        use crate::ordering::cmp_values;
        use std::cmp::Ordering;
        let prefixes = ["a", "ab", "caf\u{00E9}", "z", "\u{0080}", "hello"];
        let suffixes = ["", "x", "\u{10FFFF}", "zzz", "\u{00E9}"];
        for p in prefixes {
            let Some(succ) = string_prefix_successor(p) else {
                continue;
            };
            let succ_v = Value::String(succ);
            for s in suffixes {
                let candidate = Value::String(format!("{p}{s}"));
                assert_eq!(
                    cmp_values(&candidate, &succ_v),
                    Ordering::Less,
                    "`{p}{s}` must sort below the exclusive upper bound"
                );
            }
        }
    }
}
