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

use crate::ast::{Expr, ExprKind, Label, RelDirection, RelType, SortDirection};
use crate::binding::BoundParameters;
use crate::eval::{EvalError, eval, eval_value};
use crate::graph_access::{ExpandDirection, GraphAccess, NodeId};
use crate::loadcsv::LoadCsvState;
use crate::logical::{CreatePart, ProjectionColumn, RemoveOp, SetOp, SortKey, Var, YieldColumn};
use crate::ordering::cmp_values;
use crate::physical::{PhysicalOp, PhysicalPlan, RangeBound};
use crate::runtime::{NodeRef, RelRef, Row, RowValue, cmp_row_values, row_values_equivalent};
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
    /// A `LOAD CSV` source could not be read: the URL was not a string, named a non-`file` scheme
    /// (rejected by the Neo4j `LOAD CSV` security model), the file was missing/unreadable, or a
    /// record failed to parse.
    LoadCsv {
        /// A human description of the failure (path / scheme / I/O / parse detail).
        reason: String,
    },
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
            Self::LoadCsv { reason } => write!(f, "LOAD CSV failed: {reason}"),
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
/// the cancellation token, and the live graph seam.
///
/// The graph is a `&mut dyn GraphAccess` so write operators can mutate it; read operators take it
/// by shared reborrow. Bundling it keeps the operator `next` signature small.
struct Ctx<'a> {
    params: &'a BoundParameters,
    token: &'a CancellationToken,
    graph: &'a mut dyn GraphAccess,
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
        current: Option<(Row, VecDeque<Value>)>,
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

    /// `ExpandAll`/`ExpandInto`: for each input row, enumerate incident relationships.
    Expand {
        input: Box<Operator>,
        from: Var,
        relationship: Var,
        to: Var,
        direction: RelDirection,
        types: Vec<RelType>,
        into: bool,
        pending: VecDeque<Row>,
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
    Write {
        input: Box<Operator>,
        kind: WriteKind,
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
                        return Ok(Some(base.with(variable.name.clone(), RowValue::Value(v))));
                    }
                    *current = None;
                }
                let Some(base) = input.next(ctx)? else {
                    return Ok(None);
                };
                let listv = eval_value(list, &base, ctx.params, ctx.graph)?;
                let elems = match listv {
                    Value::List(items) => VecDeque::from(items),
                    // UNWIND null produces no rows for that input row (Cypher).
                    Value::Null => VecDeque::new(),
                    // UNWIND of a scalar yields a single row (Cypher treats it as a one-element list).
                    other => VecDeque::from(vec![other]),
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
                let url_value = eval_value(url, &base, ctx.params, ctx.graph)?;
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
                pending,
            } => loop {
                if let Some(row) = pending.pop_front() {
                    return Ok(Some(row));
                }
                let Some(base) = input.next(ctx)? else {
                    return Ok(None);
                };
                expand_into_pending(
                    &base,
                    from,
                    relationship,
                    to,
                    *direction,
                    types,
                    *into,
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

            Operator::Write { input, kind } => {
                if let Some(row) = input.next(ctx)? {
                    let out = apply_write(kind, row, ctx)?;
                    Ok(Some(out))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

/// Evaluates a `SKIP`/`LIMIT`/`TopN` count expression to a non-negative `i64` (binding validated it).
fn eval_count(expr: &Expr, ctx: &mut Ctx<'_>) -> Result<i64, ExecError> {
    match eval_value(expr, &Row::empty(), ctx.params, ctx.graph)? {
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
    match eval(expr, row, ctx.params, ctx.graph)? {
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
        let v = eval(&col.expr, row, ctx.params, ctx.graph)?;
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
#[allow(clippy::too_many_arguments)]
fn expand_into_pending(
    base: &Row,
    from: &Var,
    relationship: &Var,
    to: &Var,
    direction: RelDirection,
    types: &[RelType],
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
            let seek = eval_value(value, &Row::empty(), ctx.params, ctx.graph)?;
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
            let bound_val = eval_value(value, &Row::empty(), ctx.params, ctx.graph)?;
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
            ..
        } => Ok(Operator::Expand {
            input: Box::new(build_operator(input, arg, ctx)?),
            from: from.clone(),
            relationship: relationship.clone(),
            to: to.clone(),
            direction: *direction,
            types: types.clone(),
            into: false,
            pending: VecDeque::new(),
        }),
        PhysicalOp::ExpandInto {
            input,
            from,
            relationship,
            to,
            direction,
            types,
            ..
        } => Ok(Operator::Expand {
            input: Box::new(build_operator(input, arg, ctx)?),
            from: from.clone(),
            relationship: relationship.clone(),
            to: to.clone(),
            direction: *direction,
            types: types.clone(),
            into: true,
            pending: VecDeque::new(),
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
        }),
        PhysicalOp::SetClause { input, ops } => Ok(Operator::Write {
            input: Box::new(build_operator(input, arg, ctx)?),
            kind: WriteKind::Set { ops: ops.clone() },
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
        }),
        PhysicalOp::Remove { input, ops } => Ok(Operator::Write {
            input: Box::new(build_operator(input, arg, ctx)?),
            kind: WriteKind::Remove { ops: ops.clone() },
        }),

        // ---- procedure (deferred, named) ------------------------------------------------------
        PhysicalOp::ProcedureCall { .. } => Err(ExecError::Eval(EvalError::UnsupportedFunction {
            name: "CALL <procedure>".to_owned(),
        })),
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
            kvs.push(eval(&k.expr, &row, ctx.params, ctx.graph)?);
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
fn aggregate_rows(
    mut inner: Operator,
    group_keys: &[ProjectionColumn],
    aggregates: &[ProjectionColumn],
    ctx: &mut Ctx<'_>,
) -> Result<VecDeque<Row>, ExecError> {
    // Each group: its key row-values (in group_keys order) + per-aggregate accumulators.
    struct Group {
        keys: Vec<RowValue>,
        accs: Vec<Accumulator>,
    }
    let mut groups: Vec<Group> = Vec::new();

    while let Some(row) = inner.next(ctx)? {
        ctx.check_cancelled()?;
        // Compute the group key.
        let mut key_vals = Vec::with_capacity(group_keys.len());
        for col in group_keys {
            key_vals.push(eval(&col.expr, &row, ctx.params, ctx.graph)?);
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
                let accs = aggregates
                    .iter()
                    .map(|c| Accumulator::new(&c.expr))
                    .collect();
                groups.push(Group {
                    keys: key_vals.clone(),
                    accs,
                });
                groups.len() - 1
            }
        };
        // Update each accumulator from this row.
        for (col, acc) in aggregates.iter().zip(groups[idx].accs.iter_mut()) {
            acc.update(&col.expr, &row, ctx)?;
        }
    }

    // With no input rows and no grouping keys, Cypher still emits one row (the empty group) — e.g.
    // `count(*)` over an empty match is 0. Materialise that single empty group.
    if groups.is_empty() && group_keys.is_empty() {
        let accs = aggregates
            .iter()
            .map(|c| Accumulator::new(&c.expr))
            .collect();
        groups.push(Group {
            keys: Vec::new(),
            accs,
        });
    }

    let mut out = VecDeque::new();
    for g in groups {
        let mut row = Row::empty();
        for (col, kv) in group_keys.iter().zip(g.keys) {
            row.set(col.alias.clone(), kv);
        }
        for (col, acc) in aggregates.iter().zip(g.accs) {
            row.set(col.alias.clone(), RowValue::Value(acc.finish()));
        }
        out.push_back(row);
    }
    Ok(out)
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
    collected: Vec<Value>,
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
                eval(&args[0], row, ctx.params, ctx.graph)?
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
        // The collapsed property value for the numeric / extreme / collect arms. An entity collapses
        // to `Value::Null` here (it is not a property value): `count` and `collect` keep the
        // RowValue-aware semantics above, while `sum`/`avg`/`min`/`max` over an entity argument are
        // a type error / no-op exactly as before this fix.
        let argv = match &rv {
            RowValue::Value(v) => v.clone(),
            RowValue::Node(_) | RowValue::Rel(_) => Value::Null,
        };
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
            AggKind::Collect => self.collected.push(argv),
            AggKind::Other => self.extreme = Some(argv),
            AggKind::CountStar => unreachable!(),
        }
        Ok(())
    }

    /// Produces the group's aggregate value.
    fn finish(self) -> Value {
        match self.kind {
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
            AggKind::Collect => Value::List(self.collected),
        }
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

/// Applies a write to the graph for one driving row, returning the row extended with any new
/// bindings (created entities).
fn apply_write(kind: &WriteKind, row: Row, ctx: &mut Ctx<'_>) -> Result<Row, ExecError> {
    match kind {
        WriteKind::Create { pattern } => create_pattern(pattern, row, ctx),
        WriteKind::Merge {
            pattern,
            on_create,
            on_match,
        } => merge_pattern(pattern, on_create, on_match, row, ctx),
        WriteKind::Set { ops } => {
            apply_set_ops(ops, &row, ctx)?;
            Ok(row)
        }
        WriteKind::Delete { detach, exprs } => {
            apply_delete(*detach, exprs, &row, ctx)?;
            Ok(row)
        }
        WriteKind::Remove { ops } => {
            apply_remove_ops(ops, &row, ctx)?;
            Ok(row)
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

/// `MERGE`: try to match the pattern against the current row; create it if absent. Runs the
/// `ON MATCH` / `ON CREATE` side-effects accordingly.
fn merge_pattern(
    pattern: &[CreatePart],
    on_create: &[SetOp],
    on_match: &[SetOp],
    row: Row,
    ctx: &mut Ctx<'_>,
) -> Result<Row, ExecError> {
    if let Some(matched) = try_match_pattern(pattern, &row, ctx)? {
        apply_set_ops(on_match, &matched, ctx)?;
        Ok(matched)
    } else {
        let created = create_pattern(pattern, row, ctx)?;
        apply_set_ops(on_create, &created, ctx)?;
        Ok(created)
    }
}

/// Attempts to find an existing binding satisfying the MERGE pattern, given the already-bound row.
///
/// v1 supports the common shapes: a single node `MERGE (n:Label {props})`, and a relationship
/// `MERGE (a)-[r:T {props}]->(b)` whose endpoints are already bound. Returns the row extended with
/// the matched bindings, or `None` if no match exists.
fn try_match_pattern(
    pattern: &[CreatePart],
    row: &Row,
    ctx: &mut Ctx<'_>,
) -> Result<Option<Row>, ExecError> {
    // We only handle a single-part pattern's primary entity for matching (the planner enforces
    // MERGE's single pattern). A node part matches by label set + the inline property map; a
    // relationship part matches by type + endpoints + inline properties.
    let mut working = row.clone();
    for part in pattern {
        match part {
            CreatePart::Node {
                variable,
                labels,
                properties,
            } => {
                // If the variable is already bound to a node (from prior MATCH), reuse it.
                if working
                    .get(&variable.name)
                    .and_then(RowValue::as_node)
                    .is_some()
                {
                    continue;
                }
                let props = eval_properties(properties.as_ref(), &working, ctx)?;
                let label_names: Vec<String> = labels.iter().map(|l| l.name.clone()).collect();
                let candidates = match label_names.first() {
                    Some(first) => ctx.graph.scan_nodes_by_label(first),
                    None => ctx.graph.scan_nodes(),
                };
                let found = candidates.into_iter().find(|id| {
                    node_has_labels(*id, &label_names, ctx) && node_has_props(*id, &props, ctx)
                });
                match found {
                    Some(id) => working.set(variable.name.clone(), RowValue::Node(NodeRef { id })),
                    None => return Ok(None),
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
                let props = eval_properties(properties.as_ref(), &working, ctx)?;
                let (start, end) = rel_endpoints(from, to, *direction, &working)?;
                let type_names = [rel_type.name.clone()];
                let found = ctx
                    .graph
                    .expand(start, ExpandDirection::Outgoing, &type_names)
                    .into_iter()
                    .filter(|inc| inc.neighbour == end)
                    .find(|inc| rel_has_props(inc.rel, &props, ctx));
                match found {
                    Some(inc) => {
                        working.set(variable.name.clone(), RowValue::Rel(RelRef { id: inc.rel }))
                    }
                    None => return Ok(None),
                }
            }
        }
    }
    Ok(Some(working))
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
    match eval_value(expr, row, ctx.params, ctx.graph)? {
        Value::Map(entries) => Ok(entries),
        Value::Null => Ok(Vec::new()),
        _ => Err(ExecError::PropertiesNotAMap),
    }
}

/// Applies a list of `SET` ops to the current row's bound entities.
fn apply_set_ops(ops: &[SetOp], row: &Row, ctx: &mut Ctx<'_>) -> Result<(), ExecError> {
    for op in ops {
        match op {
            SetOp::Property { target, value } => {
                let (entity, key) = resolve_property_target(target, row)?;
                let v = eval_value(value, row, ctx.params, ctx.graph)?;
                set_entity_property(entity, &key, v, ctx);
            }
            SetOp::ReplaceProperties { target, value } => {
                let id = entity_node(target, row)?;
                let props = match eval_value(value, row, ctx.params, ctx.graph)? {
                    Value::Map(entries) => entries,
                    Value::Null => Vec::new(),
                    _ => return Err(ExecError::PropertiesNotAMap),
                };
                ctx.graph.replace_node_properties(id, &props);
            }
            SetOp::MergeProperties { target, value } => {
                let id = entity_node(target, row)?;
                let props = match eval_value(value, row, ctx.params, ctx.graph)? {
                    Value::Map(entries) => entries,
                    Value::Null => Vec::new(),
                    _ => return Err(ExecError::PropertiesNotAMap),
                };
                ctx.graph.merge_node_properties(id, &props);
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

/// Resolves a variable expression to a bound node id (for label/replace ops, which apply to nodes).
fn entity_node(target: &Var, row: &Row) -> Result<NodeId, ExecError> {
    row.get(&target.name)
        .and_then(RowValue::as_node)
        .ok_or_else(|| ExecError::NotAnEntity {
            context: format!("`{}` is not a bound node", target.name),
        })
}

/// Applies a `[DETACH] DELETE` to the entities the expressions resolve to.
fn apply_delete(
    detach: bool,
    exprs: &[Expr],
    row: &Row,
    ctx: &mut Ctx<'_>,
) -> Result<(), ExecError> {
    for expr in exprs {
        match eval(expr, row, ctx.params, ctx.graph)? {
            RowValue::Rel(r) => ctx.graph.delete_rel(r.id),
            RowValue::Node(n) => {
                let incident = ctx.graph.incident_rels(n.id);
                if !incident.is_empty() {
                    if detach {
                        for r in incident {
                            ctx.graph.delete_rel(r);
                        }
                    } else {
                        return Err(ExecError::DeleteConnectedNode);
                    }
                }
                ctx.graph.delete_node(n.id);
            }
            // Deleting null / a non-entity is a no-op (Cypher ignores null DELETE).
            RowValue::Value(_) => {}
        }
    }
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
    columns: Vec<String>,
    finished: bool,
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
        };
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

    /// The result column names this plan produces (the root projection's output schema).
    #[must_use]
    pub fn columns(&self) -> Vec<String> {
        result_columns(&self.plan.root)
    }

    /// Opens a [`Cursor`] over `graph` with cancellation token `token` (`04 §7.7`).
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
        let columns = result_columns(&self.plan.root);
        let root = {
            let mut ctx = Ctx {
                params: &self.params,
                token: &token,
                graph,
            };
            build_operator(&self.plan.root, None, &mut ctx)?
        };
        Ok(Cursor {
            root,
            params: self.params.clone(),
            token,
            graph,
            columns,
            finished: false,
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

/// The result column names a plan produces, derived from its root operator's output schema.
///
/// A `Projection`/`Aggregation` root names its columns explicitly; a write/`Optional`/`Skip`/`Limit`
/// root delegates to its input's columns. Leaves name their introduced variable(s).
fn result_columns(op: &PhysicalOp) -> Vec<String> {
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
        | PhysicalOp::Sort { input, .. }
        | PhysicalOp::Optional { input, .. }
        | PhysicalOp::Create { input, .. }
        | PhysicalOp::Merge { input, .. }
        | PhysicalOp::SetClause { input, .. }
        | PhysicalOp::Delete { input, .. }
        | PhysicalOp::Remove { input, .. } => result_columns(input),
        PhysicalOp::TopN { input, .. } => result_columns(input),
        PhysicalOp::Unwind {
            input, variable, ..
        }
        | PhysicalOp::LoadCsv {
            input, variable, ..
        } => {
            let mut cols = result_columns(input);
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
            let mut cols = result_columns(input);
            for v in [relationship, to] {
                if !cols.contains(&v.name) {
                    cols.push(v.name.clone());
                }
            }
            cols
        }
        PhysicalOp::NestedLoopJoin { left, right } | PhysicalOp::HashJoin { left, right, .. } => {
            let mut cols = result_columns(left);
            for c in result_columns(right) {
                if !cols.contains(&c) {
                    cols.push(c);
                }
            }
            cols
        }
        PhysicalOp::Union { left, .. } => result_columns(left),
        PhysicalOp::AllNodesScan { variable }
        | PhysicalOp::NodeByLabelScan { variable, .. }
        | PhysicalOp::TokenLookupScan { variable, .. }
        | PhysicalOp::NodeIndexSeek { variable, .. }
        | PhysicalOp::NodeIndexRangeSeek { variable, .. } => vec![variable.name.clone()],
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
        PhysicalOp::ProcedureCall { yields, .. } => yields
            .as_ref()
            .map(|ys| {
                ys.iter()
                    .map(|y: &YieldColumn| y.variable.name.clone())
                    .collect()
            })
            .unwrap_or_default(),
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
}
