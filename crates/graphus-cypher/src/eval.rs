//! **Expression evaluation** — the executor's scalar engine (`04-technical-design.md` §7.4, §7.6).
//!
//! [`eval`] evaluates an AST [`Expr`] against a [`Row`], the [`BoundParameters`] of the execution,
//! and the graph seam ([`GraphAccess`]), producing a [`RowValue`]. It is the per-row workhorse every
//! relational operator calls (filters evaluate a predicate, projections evaluate each column, …).
//!
//! # Reuse of the value-model semantics (`04 §7.6`)
//!
//! The notorious TCK edge cases are **not** re-implemented here. Comparisons go through
//! [`crate::equality`] (`=`/`<>`/`IN`) and [`crate::ordering`] (`<`/`>`/…); boolean connectives go
//! through [`crate::ternary`] (Kleene 3VL); `WHERE` keeps a row only on [`Ternary::True`]. A
//! predicate that yields `NULL` (3VL unknown) therefore drops the row, exactly as `04 §7.6` requires.
//!
//! # Runtime errors (`04 §7.3`)
//!
//! Evaluation raises **runtime** Cypher errors ([`EvalError`]) — never compile-time ones (those were
//! all settled by semantic analysis before execution began). Division by zero, type mismatches on
//! actual values, and wrong argument types to a function are the runtime classes the executor owns.
//!
//! # Function library
//!
//! A representative **core** of the openCypher scalar/list functions is implemented (in the
//! `call_function` worker); the rest are a documented, mechanically-extensible registry. The aggregating
//! functions (`count`/`sum`/`avg`/`min`/`max`/`collect`) are **not** evaluated here — they are
//! folded by the [`Aggregation`](crate::physical::PhysicalOp::Aggregation) operator over a whole
//! group, not per row (`04 §7.6`).

use std::cell::Cell;
use std::fmt;

use graphus_core::Value;

use crate::ast::{
    BinaryOp, CaseExpr, Expr, ExprKind, LabelExpr, Literal, MapKey, MapProjectionSelector,
    NormalForm, PredefinedType, PredicateOp, TypeExpr, UnaryOp,
};
use crate::binding::BoundParameters;
use crate::equality::{equals, is_in};
use crate::function_registry::FunctionRegistry;
use crate::graph_access::{DeletedEntity, GraphAccess};
use crate::ordering::compare_values;
use crate::runtime::{NodeRef, PathStep, PathValue, RelRef, Row, RowValue};
use crate::statement_clock::StatementClock;
use crate::ternary::Ternary;

/// A **runtime** Cypher evaluation error (`04 §7.3`).
///
/// A concrete error type (a library crate exposes concrete errors, `04 §1.2`). Every variant is a
/// runtime class — division by zero, a type error on actual data, an out-of-range integer literal,
/// or a function misuse — never a compile-time class.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvalError {
    /// Arithmetic divided (or mod-ed) by zero.
    DivisionByZero,
    /// An operator/function received an operand of the wrong type for the actual value.
    TypeError {
        /// A human description of what was expected and where.
        context: String,
    },
    /// An integer literal did not fit in `i64`.
    IntegerOverflow,
    /// A function was called in a way evaluation cannot satisfy (e.g. a non-existent built-in that
    /// passed compile-time arity but has no runtime implementation yet).
    UnsupportedFunction {
        /// The dotted function name.
        name: String,
    },
    /// A numeric argument fell outside the range a built-in accepts — e.g. the `percentile`
    /// argument of `percentileCont`/`percentileDisc`, which must lie in `[0.0, 1.0]`, or a zero
    /// `step` for `range()` (the step must be a non-zero integer). Maps to the Bolt/TCK
    /// `ArgumentError` class with the `NumberOutOfRange` detail (the same class an invalid-argument
    /// runtime failure takes).
    NumberOutOfRange {
        /// A pre-formatted description of the offending value / range violation (kept as a `String`
        /// so the error type stays `Eq`).
        value: String,
    },
    /// A **user-defined function** (`rmp` task #75) — registered as an extension — failed at
    /// runtime: its body returned a
    /// [`FunctionFailure`](crate::function_registry::FunctionFailure), typically because an argument
    /// had the wrong type (function argument *types* are checked at runtime, like the built-ins) or
    /// the computation itself failed. This maps (via `From<EvalError>`) to
    /// [`GraphusError::Runtime`](graphus_core::GraphusError::Runtime) and thus the Bolt
    /// `ArgumentError` class — the same class a built-in's runtime type error takes.
    ExtensionFunction {
        /// The dotted function name.
        name: String,
        /// The handler's failure message.
        message: String,
    },
    /// The inner read-only query of an `EXISTS { <full query> }` subquery failed at runtime
    /// (`rmp` #123) with a non-[`Eval`](Self::TypeError)-class executor error (e.g. a `LOAD CSV` I/O
    /// failure, or a procedure failure inside the subquery). An inner *expression* error surfaces
    /// directly as its own [`EvalError`] variant; this wraps the residual executor classes so the
    /// subquery never panics on them.
    Subquery {
        /// The inner failure's message.
        message: String,
    },
    /// A property or label of an entity DELETED earlier in the same transaction was accessed.
    /// openCypher raises this at runtime: TCK type `EntityNotFound`, detail `DeletedEntityAccess`
    /// (`clauses/return/Return2.feature`). `id`/`type` remain accessible after delete; only
    /// property/label reads fail.
    DeletedEntityAccess,
    /// A built-in tried to materialise a collection larger than the server will allow (e.g.
    /// `range(1, 9_000_000_000_000_000_000)`), which would exhaust memory. Surfaced as a runtime
    /// failure rather than letting the allocation OOM the process.
    ResourceLimit {
        /// A pre-formatted description of the limit that was exceeded (kept as a `String` so the
        /// error type stays `Eq`).
        detail: String,
    },
    /// A built-in was dispatched with fewer arguments than it indexes. The semantic analyzer's
    /// arity check normally guarantees this never happens, but the dispatcher stays defensive so a
    /// gap in that check can never turn into an out-of-bounds panic on user input. Maps to the
    /// `ArgumentError` class at the Bolt boundary.
    ArgumentCount {
        /// The dotted function name.
        name: String,
    },
    /// The right operand of the `=~` regular-expression operator (`rmp` task #446) was not a valid
    /// regular expression, so it could not be compiled. The pattern is only known at runtime (it is an
    /// ordinary expression, e.g. a parameter or a property), so an unparseable / unsupported pattern is
    /// a **runtime** failure, not a compile-time one. This covers a malformed pattern (e.g. an
    /// unbalanced `(`) and a pattern using a `java.util.regex` feature absent from the linear-time RE2
    /// engine (backreferences `\1`, lookaround `(?=…)`) — see [`regex_full_match`]. It is a classified,
    /// non-panicking error that maps (via `From<EvalError>`) to
    /// [`GraphusError::Runtime`](graphus_core::GraphusError::Runtime), and thus the Bolt `ArgumentError`
    /// class — the same class Neo4j raises for an invalid regular expression.
    InvalidRegex {
        /// The offending pattern (truncated for the message so a multi-megabyte pattern cannot bloat
        /// the error), kept as an owned `String` so the error type stays `Eq`.
        pattern: String,
        /// The regex engine's parse-error description.
        reason: String,
    },
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DivisionByZero => write!(f, "/ by zero"),
            Self::TypeError { context } => write!(f, "type mismatch: {context}"),
            Self::IntegerOverflow => write!(f, "integer overflow"),
            Self::UnsupportedFunction { name } => {
                write!(
                    f,
                    "function `{name}` is not implemented in the executor yet"
                )
            }
            Self::NumberOutOfRange { value } => {
                write!(f, "number out of range: {value}")
            }
            Self::ExtensionFunction { name, message } => {
                write!(f, "function `{name}` failed: {message}")
            }
            Self::Subquery { message } => write!(f, "EXISTS subquery failed: {message}"),
            Self::DeletedEntityAccess => {
                write!(f, "cannot access properties or labels of a deleted entity")
            }
            Self::ResourceLimit { detail } => {
                write!(f, "resource limit exceeded: {detail}")
            }
            Self::ArgumentCount { name } => {
                write!(f, "function `{name}` was called with too few arguments")
            }
            Self::InvalidRegex { pattern, reason } => {
                write!(f, "invalid regular expression `{pattern}`: {reason}")
            }
        }
    }
}

impl std::error::Error for EvalError {}

impl From<EvalError> for graphus_core::GraphusError {
    fn from(e: EvalError) -> Self {
        graphus_core::GraphusError::Runtime(e.to_string())
    }
}

/// The result of evaluating an expression: a [`RowValue`] or a runtime [`EvalError`].
pub type EvalResult = Result<RowValue, EvalError>;

/// Evaluates `expr` against `row`, `params` and the graph `graph`, yielding a [`RowValue`]
/// (`04 §7.4`).
///
/// # Errors
///
/// Returns an [`EvalError`] for any **runtime** failure (division by zero, type error on actual
/// data, integer-literal overflow, or an unimplemented function). Compile-time error classes are
/// never produced here (`04 §7.3`).
pub fn eval(
    expr: &Expr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    match &expr.kind {
        ExprKind::Literal(lit) => literal_value(lit).map(RowValue::Value),
        ExprKind::Parameter(name) => Ok(RowValue::Value(
            params.get(name).cloned().unwrap_or(Value::Null),
        )),
        ExprKind::Variable(name) => Ok(row.get(name).cloned().unwrap_or(RowValue::NULL)),

        ExprKind::Binary { op, lhs, rhs } => {
            eval_binary(*op, lhs, rhs, row, params, graph, functions, clock)
        }
        ExprKind::Unary { op, operand } => {
            eval_unary(*op, operand, row, params, graph, functions, clock)
        }
        ExprKind::Predicate { op, operand, rhs } => eval_predicate(
            *op,
            operand,
            rhs.as_deref(),
            row,
            params,
            graph,
            functions,
            clock,
        ),

        ExprKind::Property { base, key } => {
            eval_property(base, key, row, params, graph, functions, clock)
        }
        ExprKind::Index { base, index } => {
            eval_index(base, index, row, params, graph, functions, clock)
        }
        ExprKind::Slice { base, low, high } => eval_slice(
            base,
            low.as_deref(),
            high.as_deref(),
            row,
            params,
            graph,
            functions,
            clock,
        ),
        ExprKind::HasLabels { operand, expr } => {
            let base = eval(operand, row, params, graph, functions, clock)?;
            Ok(ternary_value(eval_label_expr(&base, expr, graph)))
        }

        // A type predicate `expr IS [NOT] :: <type>` (`rmp` #636) is a *total* boolean: even a null
        // operand yields `true`/`false` (a null satisfies every nullable type), never `null`.
        ExprKind::TypePredicate {
            operand,
            negated,
            type_expr,
        } => {
            let value = eval(operand, row, params, graph, functions, clock)?;
            let conforms = value_conforms_to_type(&value, type_expr);
            Ok(RowValue::Value(Value::Boolean(conforms != *negated)))
        }
        // A normalization predicate `expr IS [NOT] [<form>] NORMALIZED` (`rmp` #636) is defined only
        // on strings: a null or non-`STRING` operand yields `null` (per Neo4j), otherwise the boolean
        // (negated for the `IS NOT` form).
        ExprKind::NormalizedPredicate {
            operand,
            negated,
            form,
        } => {
            let value = eval(operand, row, params, graph, functions, clock)?;
            match value.as_value() {
                Some(Value::String(s)) => {
                    let normalized = is_string_normalized(s, *form);
                    Ok(RowValue::Value(Value::Boolean(normalized != *negated)))
                }
                _ => Ok(RowValue::NULL),
            }
        }

        ExprKind::FunctionCall {
            name,
            distinct: _,
            args,
        } => {
            // `rmp` #371: a single-segment name (the overwhelmingly common case) needs no `String` —
            // borrow the segment directly. Only a genuinely namespaced (`a.b.c`) name pays the join.
            match name.as_slice() {
                [single] => call_function(single, args, row, params, graph, functions, clock),
                _ => call_function(&name.join("."), args, row, params, graph, functions, clock),
            }
        }
        // `count(*)` only appears as an aggregate (handled by the Aggregation operator); reaching
        // here as a scalar would be a planner bug, so produce a typed runtime error rather than panic.
        ExprKind::CountStar => Err(EvalError::TypeError {
            context: "count(*) is an aggregate and cannot be evaluated per row".to_owned(),
        }),

        ExprKind::List(items) => {
            // Bound the materialised list against the per-value budget as it is built (`SEC-191`,
            // CWE-770 / CWE-789), exactly like a list comprehension. Cap the pre-allocation at the
            // budget's element ceiling so a huge list literal in the (≤ 64 MiB) query text cannot force
            // a multi-GB `Vec::with_capacity` *before* the per-element budget check even runs.
            let cap = items
                .len()
                .min(crate::value_size::max_list_elements().saturating_add(1));
            let mut out = Vec::with_capacity(cap);
            let mut out_bytes: usize = 0;
            for it in items {
                let elem = eval(it, row, params, graph, functions, clock)?;
                accumulate_list_bytes(&mut out_bytes, &elem, "list literal")?;
                out.push(elem);
            }
            // Canonical list construction: stays structural iff any element is (node/rel/path).
            Ok(RowValue::list(out))
        }
        ExprKind::Map(entries) => {
            // Bound the materialised map against the per-value budget as it is built (`SEC-191`,
            // CWE-770 / CWE-789), like the list literal: a map literal `{k0:$s, …, kN:$s}` with many
            // keys each bound to a large value would otherwise materialise an unbounded single value.
            // Cap the pre-allocation at the budget element ceiling so a huge literal in the (≤ 64 MiB)
            // query text cannot force a multi-GB `Vec::with_capacity` before the per-entry check runs.
            let cap = entries
                .len()
                .min(crate::value_size::max_list_elements().saturating_add(1));
            let mut out = Vec::with_capacity(cap);
            let mut out_bytes: usize = 0;
            for (MapKey { name, .. }, v) in entries {
                let val = eval(v, row, params, graph, functions, clock)?;
                out_bytes = out_bytes.saturating_add(name.len());
                accumulate_list_bytes(&mut out_bytes, &val, "map literal")?;
                out.push((name.clone(), val));
            }
            // Canonical map construction: stays structural iff any value is (node/rel/path/structural
            // collection), so `{key: u}.key` recovers the node for `DELETE` (Delete5.feature).
            Ok(RowValue::map(out))
        }

        ExprKind::Case(case) => eval_case(case, row, params, graph, functions, clock),

        ExprKind::ListComprehension(lc) => {
            eval_list_comprehension(lc, row, params, graph, functions, clock)
        }
        ExprKind::PatternComprehension(pc) => {
            eval_pattern_comprehension(pc, row, params, graph, functions, clock)
        }
        ExprKind::Quantifier(q) => eval_quantifier(q, row, params, graph, functions, clock),
        ExprKind::Reduce(r) => eval_reduce(r, row, params, graph, functions, clock),
        ExprKind::MapProjection(mp) => {
            eval_map_projection(mp, row, params, graph, functions, clock)
        }
        ExprKind::ExistsSubquery(ex) => {
            eval_exists_subquery(ex, row, params, graph, functions, clock)
        }
        ExprKind::CountSubquery(sq) => {
            eval_count_subquery(sq, row, params, graph, functions, clock)
        }
        ExprKind::CollectSubquery(sq) => {
            eval_collect_subquery(sq, row, params, graph, functions, clock)
        }
    }
}

/// Evaluates `expr` and collapses the result to a property [`Value`], resolving an entity reference
/// (which is not itself a comparable property value) to `Null` for value-typed contexts.
///
/// This is the form comparisons/ordering consume: the value-model operations (`04 §7.6`) are defined
/// over [`Value`], so an expression feeding `=`/`<`/… is reduced here.
pub fn eval_value(
    expr: &Expr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> Result<Value, EvalError> {
    Ok(to_value(eval(expr, row, params, graph, functions, clock)?))
}

/// Collapses a [`RowValue`] to a property [`Value`]. An entity reference has **no** property value,
/// so it becomes `Null` in a value context (it is only meaningful as a structural row binding).
pub(crate) fn to_value(rv: RowValue) -> Value {
    match rv {
        RowValue::Value(v) => v,
        // An entity/path in a pure value context is not a property value; collapse to null.
        // (Structural comparison/ordering uses RowValue directly via the runtime helpers, not this
        // path.)
        RowValue::Node(_) | RowValue::Rel(_) | RowValue::Path(_) => Value::Null,
        // A structural list collapses elementwise, so size/shape-sensitive value consumers (e.g.
        // `size()`, UNWIND fallbacks) still observe the right cardinality.
        RowValue::List(items) => Value::List(items.into_iter().map(to_value).collect()),
        // A structural map collapses value-wise, keeping its keys (so `keys(m)`, `size(m)` and map
        // projection still see the right shape; the structural values become null in a pure-value
        // context, matching the entity collapse above).
        RowValue::Map(entries) => {
            Value::Map(entries.into_iter().map(|(k, v)| (k, to_value(v))).collect())
        }
    }
}

/// Decodes an AST [`Literal`] into a property [`Value`], range-checking integers into `i64`
/// (`04 §7.3` defers the range check to here, the runtime phase).
fn literal_value(lit: &Literal) -> Result<Value, EvalError> {
    match lit {
        // The parser already range-checked the literal into `i64` at compile time (`04 §7.3`,
        // openCypher `IntegerOverflow`), so decoding here is total.
        Literal::Integer(i) => Ok(Value::Integer(*i)),
        Literal::Float(x) => Ok(Value::Float(*x)),
        Literal::String(s) => Ok(Value::String(s.clone())),
        Literal::Boolean(b) => Ok(Value::Boolean(*b)),
        Literal::Null => Ok(Value::Null),
    }
}

/// Lifts a [`Ternary`] into a Cypher boolean [`RowValue`]: `True`/`False` → boolean, `Null` → null.
fn ternary_value(t: Ternary) -> RowValue {
    match t {
        Ternary::True => RowValue::Value(Value::Boolean(true)),
        Ternary::False => RowValue::Value(Value::Boolean(false)),
        Ternary::Null => RowValue::NULL,
    }
}

/// Evaluates a value expression to a [`Ternary`] for predicate contexts (3VL): `TRUE`/`FALSE` from a
/// boolean, `NULL` from null, and a **runtime type error** for a non-boolean non-null.
fn eval_to_ternary(
    expr: &Expr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> Result<Ternary, EvalError> {
    match eval(expr, row, params, graph, functions, clock)? {
        RowValue::Value(Value::Boolean(b)) => Ok(Ternary::from_bool(b)),
        RowValue::Value(Value::Null) => Ok(Ternary::Null),
        other => Err(EvalError::TypeError {
            context: format!("expected a boolean predicate, got {}", describe(&other)),
        }),
    }
}

/// Evaluates a binary operator (`04 §7.6` for comparisons/logic; arithmetic by Cypher numeric rules).
#[allow(clippy::too_many_arguments)] // an internal evaluator worker; the seams are positional
fn eval_binary(
    op: BinaryOp,
    lhs: &Expr,
    rhs: &Expr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    match op {
        // ---- boolean connectives (Kleene 3VL via Ternary) ------------------------------------
        BinaryOp::And => {
            let a = eval_to_ternary(lhs, row, params, graph, functions, clock)?;
            // Short-circuit FALSE without evaluating rhs is sound; but to surface a rhs type error
            // consistently we evaluate rhs too unless `a` already settles it to FALSE.
            if a == Ternary::False {
                return Ok(ternary_value(Ternary::False));
            }
            let b = eval_to_ternary(rhs, row, params, graph, functions, clock)?;
            Ok(ternary_value(a.and(b)))
        }
        BinaryOp::Or => {
            let a = eval_to_ternary(lhs, row, params, graph, functions, clock)?;
            if a == Ternary::True {
                return Ok(ternary_value(Ternary::True));
            }
            let b = eval_to_ternary(rhs, row, params, graph, functions, clock)?;
            Ok(ternary_value(a.or(b)))
        }
        BinaryOp::Xor => {
            let a = eval_to_ternary(lhs, row, params, graph, functions, clock)?;
            let b = eval_to_ternary(rhs, row, params, graph, functions, clock)?;
            Ok(ternary_value(a.xor(b)))
        }

        // ---- equality / comparison (reuse the value-model semantics) -------------------------
        BinaryOp::Eq => {
            let a = eval(lhs, row, params, graph, functions, clock)?;
            let b = eval(rhs, row, params, graph, functions, clock)?;
            Ok(ternary_value(row_values_equal(&a, &b)))
        }
        BinaryOp::Neq => {
            let a = eval(lhs, row, params, graph, functions, clock)?;
            let b = eval(rhs, row, params, graph, functions, clock)?;
            Ok(ternary_value(!row_values_equal(&a, &b)))
        }
        BinaryOp::Lt | BinaryOp::Gt | BinaryOp::Lte | BinaryOp::Gte => {
            let (a, b) = eval_pair(lhs, rhs, row, params, graph, functions, clock)?;
            Ok(ternary_value(compare(op, &a, &b)))
        }
        BinaryOp::RegexMatch => {
            // `string =~ pattern` (`rmp` task #446). Evaluate both operands to values, then apply the
            // Cypher 3VL regex-match rules in `regex_match` (null → null; non-string → TypeError;
            // whole-string `java.util.regex`-style match otherwise).
            let (a, b) = eval_pair(lhs, rhs, row, params, graph, functions, clock)?;
            regex_match(&a, &b)
        }

        // ---- arithmetic ----------------------------------------------------------------------
        BinaryOp::Add => {
            // Evaluate **structurally** first: `+` is also list concatenation, and a list of nodes /
            // relationships / paths must keep its structural elements (collapsing through a property
            // `Value` would turn each entity into `Null` — `[a] + collect(n) + [b]`). When either
            // operand is a structural list we concatenate at the `RowValue` level; otherwise we defer
            // to the scalar/property `+` (numeric add, string concat, property-list concat).
            let a = eval(lhs, row, params, graph, functions, clock)?;
            let b = eval(rhs, row, params, graph, functions, clock)?;
            if let Some(out) = structural_list_add(&a, &b) {
                return out;
            }
            arithmetic_add(&to_value(a), &to_value(b))
        }
        BinaryOp::Sub => {
            let (a, b) = eval_pair(lhs, rhs, row, params, graph, functions, clock)?;
            if a.is_null() || b.is_null() {
                return Ok(RowValue::NULL);
            }
            // Temporal `-`: temporal - duration and duration - duration (rmp #53).
            if let Some(r) = crate::temporal_fns::sub(&a, &b) {
                return r.map(RowValue::Value);
            }
            numeric_binop_values(&a, &b, |x, y| x - y, i64::checked_sub)
        }
        BinaryOp::Mul => {
            let (a, b) = eval_pair(lhs, rhs, row, params, graph, functions, clock)?;
            if a.is_null() || b.is_null() {
                return Ok(RowValue::NULL);
            }
            // Temporal `*`: duration * number (commutative) (rmp #53).
            if let Some(r) = crate::temporal_fns::mul(&a, &b) {
                return r.map(RowValue::Value);
            }
            numeric_binop_values(&a, &b, |x, y| x * y, i64::checked_mul)
        }
        BinaryOp::Div => eval_div(lhs, rhs, row, params, graph, functions, clock),
        BinaryOp::Mod => eval_mod(lhs, rhs, row, params, graph, functions, clock),
        BinaryOp::Pow => {
            let (a, b) = eval_pair(lhs, rhs, row, params, graph, functions, clock)?;
            match (numeric_f64(&a), numeric_f64(&b)) {
                (Some(x), Some(y)) => Ok(RowValue::Value(Value::Float(x.powf(y)))),
                _ if a.is_null() || b.is_null() => Ok(RowValue::NULL),
                _ => Err(EvalError::TypeError {
                    context: "^ requires numeric operands".to_owned(),
                }),
            }
        }
    }
}

/// Evaluates both operands to property values (entities collapse to null in value context).
fn eval_pair(
    lhs: &Expr,
    rhs: &Expr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> Result<(Value, Value), EvalError> {
    Ok((
        eval_value(lhs, row, params, graph, functions, clock)?,
        eval_value(rhs, row, params, graph, functions, clock)?,
    ))
}

/// Cypher `=` over the full runtime value space, including the structural classes (`04 §7.6`).
///
/// Property values defer to [`equals`] (the CIP equality semantics — `NaN`, nested null
/// propagation, …). Entities are equal iff they denote the same graph element; paths iff they
/// traverse the same elements in the same order and orientation. Lists of either representation
/// compare elementwise with three-valued propagation (a length mismatch is decisively `FALSE`).
/// Mixed value classes are `FALSE`; a `null` on either side is `NULL`.
fn row_values_equal(a: &RowValue, b: &RowValue) -> Ternary {
    if a.is_null() || b.is_null() {
        return Ternary::Null;
    }
    match (a, b) {
        (RowValue::Value(x), RowValue::Value(y)) => equals(x, y),
        (RowValue::Node(x), RowValue::Node(y)) => Ternary::from_bool(x.id == y.id),
        (RowValue::Rel(x), RowValue::Rel(y)) => Ternary::from_bool(x.id == y.id),
        (RowValue::Path(x), RowValue::Path(y)) => Ternary::from_bool(x == y),
        // Lists (structural and/or pure) compare elementwise. The pure/pure case was already
        // settled by `equals` above, so at least one side here is structural.
        _ => match (a.as_list_elems(), b.as_list_elems()) {
            (Some(xs), Some(ys)) => {
                if xs.len() != ys.len() {
                    return Ternary::False;
                }
                let mut acc = Ternary::True;
                for (x, y) in xs.iter().zip(ys.iter()) {
                    acc = acc.and(row_values_equal(x, y));
                    if acc == Ternary::False {
                        return Ternary::False;
                    }
                }
                acc
            }
            // Different value classes (entity vs scalar, path vs list, …) are never equal.
            _ => Ternary::False,
        },
    }
}

/// The 3VL result of a `<`/`>`/`<=`/`>=` comparison, driven by the Cypher **comparability** relation
/// ([`compare_values`], the *partial* order — CIP §Comparability), **not** the total orderability
/// ([`crate::ordering::cmp_values`], which `ORDER BY`/`min`/`max`/`DISTINCT`/indexes keep).
///
/// - A `null` operand makes the result `NULL` (incomparability via null propagation).
/// - Incomparable operands (cross-type — string vs number, a map operand, a `null` reached inside a
///   list, mismatched temporal classes / CRS, …) make the result `NULL`.
/// - A `NaN` operand against a **numeric** operand makes every inequality `FALSE` (the TCK
///   `Comparison2 [5]` rule); a `NaN` against a **non-numeric** operand is a cross-type comparison
///   and is therefore `NULL`.
fn compare(op: BinaryOp, a: &Value, b: &Value) -> Ternary {
    use std::cmp::Ordering;
    if a.is_null() || b.is_null() {
        return Ternary::Null;
    }
    // NaN against a numeric operand: every inequality is FALSE (openCypher; TCK `Comparison2 [5]`,
    // e.g. `(0.0/0.0) > 1` → false). NaN against a *non-numeric* operand is a cross-type comparison,
    // which `compare_values` already reports as incomparable → NULL below.
    if (is_nan(a) && is_numeric(b)) || (is_nan(b) && is_numeric(a)) {
        return Ternary::False;
    }
    match compare_values(a, b) {
        None => Ternary::Null, // incomparable operands → NULL
        Some(ord) => {
            let truth = match op {
                BinaryOp::Lt => ord == Ordering::Less,
                BinaryOp::Gt => ord == Ordering::Greater,
                BinaryOp::Lte => ord != Ordering::Greater,
                BinaryOp::Gte => ord != Ordering::Less,
                _ => unreachable!("compare on a non-comparison operator"),
            };
            Ternary::from_bool(truth)
        }
    }
}

/// Evaluates the `=~` regular-expression match `subject =~ pattern` under Cypher 3VL semantics
/// (`rmp` task #446, `04 §7.6`), reproducing Neo4j's `java.util.regex` behaviour.
///
/// # Semantics
///
/// - **Null / non-string propagation.** If *either* operand is `NULL`, **or** a non-null operand is
///   not a `STRING`, the result is `NULL`. This is the Cypher string-operator rule (Neo4j: "attempting
///   to use [string operators] on values which are not `STRING` values will return `null`"), and it is
///   exactly how `STARTS WITH` / `ENDS WITH` / `CONTAINS` behave here — pinned for that family by the
///   TCK `precedence/Precedence4 [4]` scenario, where `'abc' STARTS WITH true` must be `null` (so an
///   enclosing operator stays `null` rather than raising a runtime `TypeError`). `=~` is a member of the
///   same family, so it follows the same rule: `123 =~ '.*'` and `'x' =~ 7` are `NULL`, not errors.
/// - **Whole-string match.** The pattern must match the **entire** subject, not a substring: Neo4j
///   compiles `=~` to `java.util.regex.Pattern.matcher(value).matches()`, which is fully anchored.
///   [`regex_full_match`] reproduces this by anchoring with `\A(?:…)\z`. So `'abc' =~ 'a.*'` is `true`
///   (`a.*` describes the whole string) but `'abc' =~ 'b.*'` is `false` (a substring match would have
///   been `true`).
///
/// # Errors
///
/// Returns [`EvalError::InvalidRegex`] for a (string) pattern the engine cannot compile — a malformed
/// pattern, or one using a `java.util.regex` feature absent from the linear-time engine (see
/// [`regex_full_match`]). It never panics on user input. A non-string *operand* is **not** an error
/// (it yields `NULL`, per the rule above); only a malformed *pattern string* is.
fn regex_match(subject: &Value, pattern: &Value) -> EvalResult {
    // A null or non-string subject yields NULL (the Cypher string-operator rule — see the fn docs).
    let Value::String(subject) = subject else {
        return Ok(RowValue::NULL);
    };
    // A null or non-string pattern likewise yields NULL: `'x' =~ null` and `'x' =~ 7` are both NULL.
    // The pattern is only validated as a *regex* once we know it is a string.
    let Value::String(pattern) = pattern else {
        return Ok(RowValue::NULL);
    };
    let re = regex_full_match(pattern)?;
    Ok(ternary_value(Ternary::from_bool(re.is_match(subject))))
}

/// Compiles `pattern` into a [`Regex`](regex::Regex) that matches **only** when the entire haystack
/// matches — Java's `Matcher.matches()` semantics, which Neo4j's `=~` inherits (`rmp` task #446).
///
/// The user pattern is wrapped as `\A(?:<pattern>)\z`:
/// - `\A` / `\z` anchor to the absolute start / end of the haystack (unlike `^` / `$`, they ignore
///   multiline mode, so a `(?m)` flag inside the user pattern cannot accidentally un-anchor the
///   whole-string match — matching Java, where `matches()` is whole-input regardless of `MULTILINE`).
/// - The non-capturing group `(?:…)` preserves the user pattern's operator precedence, so a top-level
///   alternation like `a|b` still means `\A(?:a|b)\z` (either whole-string `a` or whole-string `b`),
///   not `(\Aa)|(b\z)`. An inline flag the user puts at the start (`(?i)foo`) sits inside the group and
///   so scopes to the whole user pattern, exactly as the leading flag does in Java.
///
/// # Deliberate divergence from `java.util.regex` (documented per `rmp` #446)
///
/// The `regex` crate is a finite-automaton (RE2-style) engine with a **linear-time** matching
/// guarantee, so no pattern/input pair can trigger catastrophic backtracking (ReDoS, CWE-1333) — the
/// property the task mandates for an operator that takes untrusted patterns. The price is that the two
/// `java.util.regex` features that *require* backtracking are unsupported: **backreferences** (`\1`)
/// and **lookaround** (`(?=…)`, `(?<=…)`). A pattern using them fails to compile and surfaces as a
/// classified [`EvalError::InvalidRegex`] rather than executing — never a silent wrong answer and
/// never a panic. The common pattern syntax (literals, classes `[…]`, Perl classes `\d`/`\w`/`\s`,
/// quantifiers, anchors, alternation, groups, and the `(?i)`/`(?s)`/`(?m)`/`(?x)` inline flags) is
/// shared with Java and behaves identically.
///
/// # Errors
///
/// Returns [`EvalError::InvalidRegex`] if the wrapped pattern does not compile.
fn regex_full_match(pattern: &str) -> Result<regex::Regex, EvalError> {
    // `\A(?:…)\z` ⇒ whole-haystack anchored, precedence-preserving (see the fn docs).
    let anchored = format!(r"\A(?:{pattern})\z");
    regex::Regex::new(&anchored).map_err(|e| EvalError::InvalidRegex {
        // Truncate the echoed pattern so a multi-megabyte pattern cannot bloat the error string; the
        // engine's own message already pinpoints the offending span.
        pattern: truncate_for_error(pattern),
        reason: e.to_string(),
    })
}

/// Truncates `s` to a bounded, char-boundary-safe prefix for embedding in an error message, appending
/// an ellipsis when it was shortened (so an attacker-sized pattern cannot bloat the error string).
fn truncate_for_error(s: &str) -> String {
    /// The longest pattern prefix echoed in an `InvalidRegex` message.
    const MAX: usize = 120;
    if s.len() <= MAX {
        return s.to_owned();
    }
    let mut end = MAX;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Whether a value is a Cypher number (`INTEGER` or `FLOAT`, including `NaN`).
fn is_numeric(v: &Value) -> bool {
    matches!(v, Value::Integer(_) | Value::Float(_))
}

fn is_nan(v: &Value) -> bool {
    matches!(v, Value::Float(f) if f.is_nan())
}

/// Rejects a string-concatenation result whose byte length would exceed
/// [`MAX_VALUE_BYTES`](crate::value_size::MAX_VALUE_BYTES) — the per-value budget every materialised
/// value shares (`SEC-191`, CWE-770 / CWE-789). The check is `O(1)` (the operand lengths are known)
/// and runs **before** the `format!` allocates, so a runaway `+` / coercion chain
/// (`s + s + s + …`, each step feeding the next) is rejected the instant a single result crosses the
/// budget rather than growing until it OOMs the engine thread.
///
/// # Errors
/// [`EvalError::ResourceLimit`] if `a_len + b_len` exceeds the budget.
fn check_concat_string_len(a_len: usize, b_len: usize) -> Result<(), EvalError> {
    let total = a_len.saturating_add(b_len);
    let limit = crate::value_size::max_value_bytes();
    if total > limit {
        return Err(EvalError::ResourceLimit {
            detail: format!(
                "string concatenation would produce {total} bytes (limit {limit} bytes per value)"
            ),
        });
    }
    Ok(())
}

/// Rejects a list-concatenation result whose element count would exceed the per-value budget
/// ([`max_list_elements`](crate::value_size::max_list_elements), derived from
/// [`MAX_VALUE_BYTES`](crate::value_size::MAX_VALUE_BYTES) exactly as `range()` derives its element
/// ceiling). The check is `O(1)` (only the operand element counts are read) and runs **before** the
/// result `Vec` grows, so a runaway list `+` is rejected the instant a single result crosses the
/// budget — the `Vec` backbone alone (`count * size_of::<Value>()`) is what the budget bounds.
///
/// # Errors
/// [`EvalError::ResourceLimit`] if `a_len + b_len` exceeds the element ceiling.
fn check_concat_list_len(a_len: usize, b_len: usize) -> Result<(), EvalError> {
    let total = a_len.saturating_add(b_len);
    let limit = crate::value_size::max_list_elements();
    if total > limit {
        return Err(EvalError::ResourceLimit {
            detail: format!(
                "list concatenation would produce {total} elements (limit {limit}, a {}-byte \
                 materialisation budget)",
                crate::value_size::max_value_bytes()
            ),
        });
    }
    Ok(())
}

/// Bounds the **byte** size of a list-concatenation result against the per-value budget (`SEC-191`,
/// CWE-770 / CWE-789). [`check_concat_list_len`] bounds the element COUNT, but a concatenation of FEW
/// large-valued elements — `[$s] + [$s] + …` with `$s` a big string — keeps the count trivially under
/// the ceiling while the byte footprint grows without bound, so the bytes must be bounded too (exactly
/// as [`check_concat_string_len`] does for `+` on strings). The caller passes
/// [`estimate_value_bytes`](crate::value_size::estimate_value_bytes)-derived sizes, which short-circuit
/// at the budget, so once an operand alone exceeds it the check is `O(budget)`, not `O(value)`; a
/// chained `+` stays bounded because each step re-checks the growing accumulator and rejects the first
/// time the running result crosses the ceiling.
fn check_concat_value_bytes(a_bytes: usize, b_bytes: usize) -> Result<(), EvalError> {
    let total = a_bytes.saturating_add(b_bytes);
    let limit = crate::value_size::max_value_bytes();
    if total > limit {
        return Err(EvalError::ResourceLimit {
            detail: format!(
                "list concatenation would produce {total} bytes (limit {limit} bytes per value)"
            ),
        });
    }
    Ok(())
}

/// Structural list concatenation for `+` when a **structural** list (one holding a node /
/// relationship / path) is involved. Returns `Some(result)` when at least one operand is a
/// structural [`RowValue::List`], handling `list + list`, `list + element` and `element + list` while
/// preserving entity references; returns `None` to defer to the scalar/property `+` (numeric add,
/// string concat, pure-property list concat) when no structural list participates.
///
/// `null + x` / `x + null` is **not** handled here (it is value-level null propagation), so a null
/// operand makes this return `None` and the property path produces null.
///
/// # Errors
/// [`EvalError::ResourceLimit`] (carried as `Some(Err(..))`) if the concatenated list would exceed
/// the per-value element budget ([`check_concat_list_len`]). Checked on the operand element counts
/// **before** the result `Vec` is grown.
fn structural_list_add(a: &RowValue, b: &RowValue) -> Option<EvalResult> {
    let a_struct_list = matches!(a, RowValue::List(_));
    let b_struct_list = matches!(b, RowValue::List(_));
    if !a_struct_list && !b_struct_list {
        return None;
    }
    // The element count each operand contributes: a list-shaped operand (structural or property)
    // contributes its length, anything else a single element (Cypher's `list + element`).
    fn elem_count(v: &RowValue) -> usize {
        match v {
            RowValue::List(items) => items.len(),
            RowValue::Value(Value::List(items)) => items.len(),
            _ => 1,
        }
    }
    if let Err(e) = check_concat_list_len(elem_count(a), elem_count(b)).and_then(|()| {
        // Also bound the BYTE footprint, not just the element count (`SEC-191`): `[$big] + [$big]` has
        // few elements but a large materialised size.
        check_concat_value_bytes(
            crate::value_size::estimate_rowvalue_bytes(a),
            crate::value_size::estimate_rowvalue_bytes(b),
        )
    }) {
        return Some(Err(e));
    }
    // Borrow each operand as list elements when it is list-shaped (structural or property), else
    // treat it as a single element to append/prepend (Cypher's `list + element`).
    fn elems_or_single(v: &RowValue) -> Vec<RowValue> {
        v.as_list_elems().unwrap_or_else(|| vec![v.clone()])
    }
    let mut out = elems_or_single(a);
    out.extend(elems_or_single(b));
    Some(Ok(RowValue::list(out)))
}

/// Cypher `+`: numeric addition, **or** string concatenation, **or** list concatenation, with null
/// propagation.
fn arithmetic_add(a: &Value, b: &Value) -> EvalResult {
    if a.is_null() || b.is_null() {
        return Ok(RowValue::NULL);
    }
    // Temporal `+`: temporal + duration (commutative) and duration + duration (rmp #53).
    if let Some(r) = crate::temporal_fns::add(a, b) {
        return r.map(RowValue::Value);
    }
    match (a, b) {
        (Value::Integer(x), Value::Integer(y)) => x
            .checked_add(*y)
            .map(Value::Integer)
            .map(RowValue::Value)
            .ok_or(EvalError::IntegerOverflow),
        (Value::String(x), Value::String(y)) => {
            check_concat_string_len(x.len(), y.len())?;
            Ok(RowValue::Value(Value::String(format!("{x}{y}"))))
        }
        (Value::List(x), Value::List(y)) => {
            check_concat_list_len(x.len(), y.len())?;
            check_concat_value_bytes(
                crate::value_size::estimate_value_bytes(a),
                crate::value_size::estimate_value_bytes(b),
            )?;
            let mut out = x.clone();
            out.extend(y.iter().cloned());
            Ok(RowValue::Value(Value::List(out)))
        }
        // List + element / element + list (Cypher appends/prepends scalars).
        (Value::List(x), other) => {
            check_concat_list_len(x.len(), 1)?;
            check_concat_value_bytes(
                crate::value_size::estimate_value_bytes(a),
                crate::value_size::estimate_value_bytes(other),
            )?;
            let mut out = x.clone();
            out.push(other.clone());
            Ok(RowValue::Value(Value::List(out)))
        }
        (other, Value::List(y)) => {
            check_concat_list_len(1, y.len())?;
            check_concat_value_bytes(
                crate::value_size::estimate_value_bytes(other),
                crate::value_size::estimate_value_bytes(b),
            )?;
            let mut out = Vec::with_capacity(y.len() + 1);
            out.push(other.clone());
            out.extend(y.iter().cloned());
            Ok(RowValue::Value(Value::List(out)))
        }
        // String + number and number + string concatenate the string form (Cypher coercion).
        (Value::String(x), other) => {
            let suffix = stringify_scalar(other);
            check_concat_string_len(x.len(), suffix.len())?;
            Ok(RowValue::Value(Value::String(format!("{x}{suffix}"))))
        }
        (other, Value::String(y)) => {
            let prefix = stringify_scalar(other);
            check_concat_string_len(prefix.len(), y.len())?;
            Ok(RowValue::Value(Value::String(format!("{prefix}{y}"))))
        }
        _ => match (numeric_f64(a), numeric_f64(b)) {
            (Some(x), Some(y)) => Ok(RowValue::Value(Value::Float(x + y))),
            _ => Err(EvalError::TypeError {
                context: "+ requires numeric, string or list operands".to_owned(),
            }),
        },
    }
}

/// A numeric binary op (`-`, `*`) over already-evaluated non-null values, with an integer-exact
/// path (checked) and a float fallback.
fn numeric_binop_values(
    a: &Value,
    b: &Value,
    float_op: impl Fn(f64, f64) -> f64,
    int_op: impl Fn(i64, i64) -> Option<i64>,
) -> EvalResult {
    if let (Value::Integer(x), Value::Integer(y)) = (a, b) {
        return int_op(*x, *y)
            .map(Value::Integer)
            .map(RowValue::Value)
            .ok_or(EvalError::IntegerOverflow);
    }
    match (numeric_f64(a), numeric_f64(b)) {
        (Some(x), Some(y)) => Ok(RowValue::Value(Value::Float(float_op(x, y)))),
        _ => Err(EvalError::TypeError {
            context: "arithmetic requires numeric operands".to_owned(),
        }),
    }
}

/// Cypher `/`: integer division stays integer (truncating toward zero); any float operand promotes
/// to float; division by zero is a **runtime** error for integers and yields ±inf/NaN for floats
/// (IEEE), matching openCypher.
fn eval_div(
    lhs: &Expr,
    rhs: &Expr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    let (a, b) = eval_pair(lhs, rhs, row, params, graph, functions, clock)?;
    if a.is_null() || b.is_null() {
        return Ok(RowValue::NULL);
    }
    // Temporal `/`: duration / number (rmp #53).
    if let Some(r) = crate::temporal_fns::div(&a, &b) {
        return r.map(RowValue::Value);
    }
    if let (Value::Integer(x), Value::Integer(y)) = (&a, &b) {
        if *y == 0 {
            return Err(EvalError::DivisionByZero);
        }
        // `checked_div` also rejects `i64::MIN / -1`, which overflows the magnitude of `i64`
        // (a hard panic even in release otherwise); surface it as the integer-overflow class.
        return x
            .checked_div(*y)
            .map(Value::Integer)
            .map(RowValue::Value)
            .ok_or(EvalError::IntegerOverflow);
    }
    match (numeric_f64(&a), numeric_f64(&b)) {
        (Some(x), Some(y)) => Ok(RowValue::Value(Value::Float(x / y))),
        _ => Err(EvalError::TypeError {
            context: "/ requires numeric operands".to_owned(),
        }),
    }
}

/// Cypher `%`: integer modulo (runtime error on zero divisor), float remainder otherwise.
fn eval_mod(
    lhs: &Expr,
    rhs: &Expr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    let (a, b) = eval_pair(lhs, rhs, row, params, graph, functions, clock)?;
    if a.is_null() || b.is_null() {
        return Ok(RowValue::NULL);
    }
    if let (Value::Integer(x), Value::Integer(y)) = (&a, &b) {
        if *y == 0 {
            return Err(EvalError::DivisionByZero);
        }
        // `checked_rem` also rejects `i64::MIN % -1` (which panics on overflow even in release);
        // surface it as the integer-overflow class, mirroring `eval_div`.
        return x
            .checked_rem(*y)
            .map(Value::Integer)
            .map(RowValue::Value)
            .ok_or(EvalError::IntegerOverflow);
    }
    match (numeric_f64(&a), numeric_f64(&b)) {
        (Some(x), Some(y)) => Ok(RowValue::Value(Value::Float(x % y))),
        _ => Err(EvalError::TypeError {
            context: "% requires numeric operands".to_owned(),
        }),
    }
}

/// Evaluates a unary operator (`NOT` via 3VL, unary `+`/`-` numeric with null propagation).
fn eval_unary(
    op: UnaryOp,
    operand: &Expr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    match op {
        UnaryOp::Not => {
            let t = eval_to_ternary(operand, row, params, graph, functions, clock)?;
            Ok(ternary_value(!t))
        }
        UnaryOp::Plus => {
            let v = eval_value(operand, row, params, graph, functions, clock)?;
            if v.is_null() {
                return Ok(RowValue::NULL);
            }
            match v {
                Value::Integer(_) | Value::Float(_) => Ok(RowValue::Value(v)),
                _ => Err(EvalError::TypeError {
                    context: "unary + requires a number".to_owned(),
                }),
            }
        }
        UnaryOp::Minus => {
            let v = eval_value(operand, row, params, graph, functions, clock)?;
            if v.is_null() {
                return Ok(RowValue::NULL);
            }
            match v {
                Value::Integer(i) => i
                    .checked_neg()
                    .map(Value::Integer)
                    .map(RowValue::Value)
                    .ok_or(EvalError::IntegerOverflow),
                Value::Float(f) => Ok(RowValue::Value(Value::Float(-f))),
                _ => Err(EvalError::TypeError {
                    context: "unary - requires a number".to_owned(),
                }),
            }
        }
    }
}

/// Evaluates a string/list/null postfix predicate (`STARTS WITH`/`ENDS WITH`/`CONTAINS`/`IN`/`IS
/// [NOT] NULL`), 3VL.
#[allow(clippy::too_many_arguments)] // an internal evaluator worker; the seams are positional
fn eval_predicate(
    op: PredicateOp,
    operand: &Expr,
    rhs: Option<&Expr>,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    match op {
        PredicateOp::IsNull => {
            let v = eval(operand, row, params, graph, functions, clock)?;
            Ok(RowValue::Value(Value::Boolean(v.is_null())))
        }
        PredicateOp::IsNotNull => {
            let v = eval(operand, row, params, graph, functions, clock)?;
            Ok(RowValue::Value(Value::Boolean(!v.is_null())))
        }
        PredicateOp::In => {
            let value = eval_value(operand, row, params, graph, functions, clock)?;
            let list = match rhs {
                Some(r) => eval_value(r, row, params, graph, functions, clock)?,
                None => Value::Null,
            };
            Ok(ternary_value(is_in(&value, &list)))
        }
        PredicateOp::StartsWith | PredicateOp::EndsWith | PredicateOp::Contains => {
            let a = eval_value(operand, row, params, graph, functions, clock)?;
            let b = match rhs {
                Some(r) => eval_value(r, row, params, graph, functions, clock)?,
                None => Value::Null,
            };
            if a.is_null() || b.is_null() {
                return Ok(RowValue::NULL);
            }
            match (&a, &b) {
                (Value::String(s), Value::String(sub)) => {
                    let truth = match op {
                        PredicateOp::StartsWith => s.starts_with(sub.as_str()),
                        PredicateOp::EndsWith => s.ends_with(sub.as_str()),
                        PredicateOp::Contains => s.contains(sub.as_str()),
                        _ => unreachable!(),
                    };
                    Ok(RowValue::Value(Value::Boolean(truth)))
                }
                // A non-null, non-string operand yields `null`, not an error: openCypher / Neo4j
                // specify that `STARTS WITH`/`ENDS WITH`/`CONTAINS` applied to non-`STRING` values
                // return `null` (pinned by `tck/.../precedence/Precedence4` [4], where
                // `'abc' STARTS WITH true` must be `null` so the enclosing `<>` is `null`, not a
                // runtime `TypeError`).
                _ => Ok(RowValue::NULL),
            }
        }
    }
}

/// Whether a fully-evaluated [`RowValue`] conforms to a declared [`TypeExpr`] (`rmp` #636, the
/// `IS :: <type>` predicate).
///
/// Every Cypher type is **nullable** by default, so a `null` value conforms to any type unless it
/// carries a trailing `NOT NULL` (or is the empty [`Nothing`](TypeExpr::Nothing) type). A non-null
/// value conforms iff its runtime shape matches the type's nominal part: structural values (nodes,
/// relationships, paths, and structural lists/maps that carry them) match only the corresponding
/// structural type, and every property value is dispatched to [`value_conforms`].
fn value_conforms_to_type(rv: &RowValue, ty: &TypeExpr) -> bool {
    match rv {
        RowValue::Value(v) => value_conforms(v, ty),
        RowValue::Node(_) => structural_conforms(ty, PredefinedType::Node),
        RowValue::Rel(_) => structural_conforms(ty, PredefinedType::Relationship),
        RowValue::Path(_) => structural_conforms(ty, PredefinedType::Path),
        RowValue::Map(_) => structural_conforms(ty, PredefinedType::Map),
        RowValue::List(items) => structural_list_conforms(items, ty),
    }
}

/// Type conformance of a **non-null structural scalar** (node / relationship / path / structural
/// map) against `ty`: it matches `ANY`, a union with a matching member, or exactly the predefined
/// `kind`. It is never `null`, and never conforms to `NOTHING`, `NULL`, or a list type.
fn structural_conforms(ty: &TypeExpr, kind: PredefinedType) -> bool {
    match ty {
        TypeExpr::Any { .. } => true,
        TypeExpr::Union(members) => members.iter().any(|m| structural_conforms(m, kind)),
        TypeExpr::Predefined { name, .. } => *name == kind,
        TypeExpr::List { .. } | TypeExpr::Nothing | TypeExpr::Null => false,
    }
}

/// Type conformance of a **non-null structural list** (one carrying nodes/relationships/paths)
/// against `ty`: it matches `ANY`, a union with a matching member, or a `LIST<inner>` whose every
/// element conforms to `inner`. A `MAP`, `PROPERTY VALUE`, or scalar predefined type never matches a
/// list. An empty list trivially conforms to any `LIST<inner>` (including `LIST<NOTHING>`).
fn structural_list_conforms(items: &[RowValue], ty: &TypeExpr) -> bool {
    match ty {
        TypeExpr::Any { .. } => true,
        TypeExpr::Union(members) => members.iter().any(|m| structural_list_conforms(items, m)),
        TypeExpr::List { inner, .. } => items.iter().all(|it| value_conforms_to_type(it, inner)),
        TypeExpr::Predefined { .. } | TypeExpr::Nothing | TypeExpr::Null => false,
    }
}

/// Type conformance of a property [`Value`] against `ty` (`rmp` #636). This is where nullability is
/// resolved: [`Value::Null`] conforms iff the type admits null (nullable, or the `NULL` type).
fn value_conforms(v: &Value, ty: &TypeExpr) -> bool {
    match ty {
        TypeExpr::Union(members) => members.iter().any(|m| value_conforms(v, m)),
        TypeExpr::Any { not_null } => !*not_null || !v.is_null(),
        TypeExpr::Nothing => false,
        TypeExpr::Null => v.is_null(),
        TypeExpr::List { inner, not_null } => {
            if v.is_null() {
                return !*not_null;
            }
            match v {
                Value::List(items) => items.iter().all(|it| value_conforms(it, inner)),
                // Graphus models a byte string as a `LIST<INTEGER NOT NULL>` of its byte values; the
                // stack-allocated `Value::Integer` per byte carries no heap allocation.
                Value::Bytes(bytes) => bytes
                    .iter()
                    .all(|&b| value_conforms(&Value::Integer(i64::from(b)), inner)),
                _ => false,
            }
        }
        TypeExpr::Predefined { name, not_null } => {
            if v.is_null() {
                return !*not_null;
            }
            value_predefined_admits(v, *name)
        }
    }
}

/// Whether a **non-null** property [`Value`] matches the predefined nominal type `name` (`rmp` #636).
fn value_predefined_admits(v: &Value, name: PredefinedType) -> bool {
    use PredefinedType as P;
    match name {
        P::Boolean => matches!(v, Value::Boolean(_)),
        P::Integer => matches!(v, Value::Integer(_)),
        P::Float => matches!(v, Value::Float(_)),
        P::String => matches!(v, Value::String(_)),
        P::Date => matches!(v, Value::Date(_)),
        P::LocalTime => matches!(v, Value::LocalTime(_)),
        P::ZonedTime => matches!(v, Value::ZonedTime(_)),
        P::LocalDateTime => matches!(v, Value::LocalDateTime(_)),
        P::ZonedDateTime => matches!(v, Value::ZonedDateTime(_)),
        P::Duration => matches!(v, Value::Duration(_)),
        P::Point => matches!(v, Value::Point(_)),
        P::Map => matches!(v, Value::Map(_)),
        // `PROPERTY VALUE` is any storable property value — every non-null value except a map (maps
        // are not a storable property type in the LPG model). A byte string is storable.
        P::PropertyValue => !matches!(v, Value::Null | Value::Map(_)),
        // A property value is never a graph entity or path (those are structural `RowValue`s handled
        // in `value_conforms_to_type`, never a `Value`).
        P::Node | P::Relationship | P::Path => false,
    }
}

/// Whether `s` is already in the Unicode normalization `form` (`rmp` #636, the `IS NORMALIZED`
/// predicate). Uses the `unicode-normalization` quick-check functions, which run without allocating
/// when the string is already normalized.
fn is_string_normalized(s: &str, form: NormalForm) -> bool {
    use unicode_normalization::{is_nfc, is_nfd, is_nfkc, is_nfkd};
    match form {
        NormalForm::Nfc => is_nfc(s),
        NormalForm::Nfd => is_nfd(s),
        NormalForm::Nfkc => is_nfkc(s),
        NormalForm::Nfkd => is_nfkd(s),
    }
}

/// Evaluates `base.key`: a property access on an entity reference (lazy lookup through the seam) or
/// a map key access; anything else (incl. null) yields null.
fn eval_property(
    base: &Expr,
    key: &str,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    let base = eval(base, row, params, graph, functions, clock)?;
    property_of(&base, key, graph)
}

/// Reads property `key` from an already-evaluated `base` value, applying Cypher's value model:
/// node/relationship property reads (raising [`EvalError::DeletedEntityAccess`] for an entity deleted
/// earlier in this query), map key lookup (property or structural), point/temporal component access,
/// and the missing-property `null` rule everywhere else. This is the shared core of `n.key` static
/// property access and the [map projection](eval_map_projection) `.key` selector, so both agree
/// exactly on the property semantics.
///
/// # Errors
/// [`EvalError::DeletedEntityAccess`] when `base` is a node/relationship deleted earlier in the query.
fn property_of(base: &RowValue, key: &str, graph: &dyn GraphAccess) -> EvalResult {
    match base {
        RowValue::Node(NodeRef { id }) => {
            // Reading a property of an entity deleted earlier in this same query raises at runtime
            // (`clauses/return/Return2.feature` [15]); `id`/`type` stay accessible, only properties
            // and labels fail.
            if graph.entity_deleted_by_txn(DeletedEntity::Node(*id)) {
                return Err(EvalError::DeletedEntityAccess);
            }
            Ok(RowValue::Value(
                graph.node_property(*id, key).unwrap_or(Value::Null),
            ))
        }
        RowValue::Rel(RelRef { id }) => {
            if graph.entity_deleted_by_txn(DeletedEntity::Rel(*id)) {
                return Err(EvalError::DeletedEntityAccess); // Return2.feature [17]
            }
            Ok(RowValue::Value(
                graph.rel_property(*id, key).unwrap_or(Value::Null),
            ))
        }
        RowValue::Value(Value::Map(entries)) => Ok(RowValue::Value(
            entries
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Null),
        )),
        // A structural map keeps its values at the `RowValue` level, so `m.key` recovers the
        // node/relationship/path reference (or nested structural collection) the map holds — the
        // property-map arm above only handles pure-property maps (Delete5.feature).
        RowValue::Map(entries) => Ok(entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or(RowValue::NULL)),
        // Point component access: `p.x`, `p.longitude`, `p.crs`, `p.srid`, … (rmp #73).
        RowValue::Value(Value::Point(p)) => Ok(RowValue::Value(
            crate::spatial_fns::component(p, key).unwrap_or(Value::Null),
        )),
        // Temporal component access: `d.year`, `t.hour`, `dur.minutesOfHour`, … (rmp #53).
        // A non-temporal (incl. null) base yields null, Cypher's missing-property rule.
        RowValue::Value(v) => Ok(RowValue::Value(
            crate::temporal_fns::component(v, key).unwrap_or(Value::Null),
        )),
        // Paths and lists have no properties; the missing-property rule yields null.
        RowValue::Path(_) | RowValue::List(_) => Ok(RowValue::NULL),
    }
}

/// Evaluates `base[index]`: list element by integer index (negative indexes from the end) or map
/// value by string key; out-of-range / wrong-type yields null (Cypher).
///
/// The base is evaluated at the [`RowValue`] level so that indexing a **structural** list — one that
/// holds node/relationship/path references (e.g. `[a, 1]` with `a` a node) — returns the structural
/// element unchanged. This is what lets `labels(list[0])`, `type(list[0])` and `(list[1]).prop`
/// recover the graph element the TCK's "accept type Any" scenarios feed through a list
/// (`expressions/graph/Graph{3,4,6}.feature`). A pure-property list keeps its former `Value`-level
/// behaviour exactly.
fn eval_index(
    base: &Expr,
    index: &Expr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    let base = eval(base, row, params, graph, functions, clock)?;
    let idx = eval_value(index, row, params, graph, functions, clock)?;
    if base.is_null() || idx.is_null() {
        return Ok(RowValue::NULL);
    }
    // Dynamic property access: a node/relationship indexed by a string key reads that property
    // (`n['name']`; `expressions/graph/Graph7.feature`), exactly like the static `n.name` form.
    match (&base, &idx) {
        (RowValue::Node(NodeRef { id }), Value::String(k)) => {
            // `n['key']` on an entity self-deleted earlier in the query fails exactly like `n.key`
            // (`clauses/return/Return2.feature`).
            if graph.entity_deleted_by_txn(DeletedEntity::Node(*id)) {
                return Err(EvalError::DeletedEntityAccess);
            }
            return Ok(RowValue::Value(
                graph.node_property(*id, k).unwrap_or(Value::Null),
            ));
        }
        (RowValue::Rel(RelRef { id }), Value::String(k)) => {
            if graph.entity_deleted_by_txn(DeletedEntity::Rel(*id)) {
                return Err(EvalError::DeletedEntityAccess);
            }
            return Ok(RowValue::Value(
                graph.rel_property(*id, k).unwrap_or(Value::Null),
            ));
        }
        _ => {}
    }
    // A structural list indexed by an integer returns the element as a `RowValue`, preserving any
    // node/relationship/path reference it carries.
    if let (Some(items), Value::Integer(i)) = (base.as_list_elems(), &idx) {
        let len = items.len() as i64;
        let pos = if *i < 0 { len + *i } else { *i };
        return if pos < 0 || pos >= len {
            Ok(RowValue::NULL)
        } else {
            Ok(items[pos as usize].clone())
        };
    }
    // A structural map indexed by a string key returns the value as a `RowValue`, preserving any
    // node/relationship/path reference it carries (`m['key']`, the dynamic analogue of `m.key`).
    if let (Some(entries), Value::String(k)) = (base.as_map_entries(), &idx) {
        return Ok(entries
            .into_iter()
            .find(|(ek, _)| ek == k)
            .map(|(_, v)| v)
            .unwrap_or(RowValue::NULL));
    }
    match (to_value(base), &idx) {
        (Value::Map(entries), Value::String(k)) => Ok(RowValue::Value(
            entries
                .into_iter()
                .find(|(ek, _)| ek == k)
                .map(|(_, v)| v)
                .unwrap_or(Value::Null),
        )),
        _ => Err(EvalError::TypeError {
            context: "index requires a list[int] or map[string]".to_owned(),
        }),
    }
}

/// Evaluates `base[low..high]` list slicing with optional, clamped bounds (Cypher semantics).
#[allow(clippy::too_many_arguments)] // an internal evaluator worker; the seams are positional
fn eval_slice(
    base: &Expr,
    low: Option<&Expr>,
    high: Option<&Expr>,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    let base = eval_value(base, row, params, graph, functions, clock)?;
    if base.is_null() {
        return Ok(RowValue::NULL);
    }
    let Value::List(items) = &base else {
        return Err(EvalError::TypeError {
            context: "slice requires a list".to_owned(),
        });
    };
    let len = items.len() as i64;
    let resolve = |bound: Option<&Expr>, default: i64| -> Result<Option<i64>, EvalError> {
        match bound {
            None => Ok(Some(default)),
            Some(e) => match eval_value(e, row, params, graph, functions, clock)? {
                Value::Null => Ok(None),
                Value::Integer(i) => Ok(Some(if i < 0 { len + i } else { i })),
                _ => Err(EvalError::TypeError {
                    context: "slice bound must be an integer".to_owned(),
                }),
            },
        }
    };
    let (Some(lo), Some(hi)) = (resolve(low, 0)?, resolve(high, len)?) else {
        // A null bound makes the whole slice null (Cypher).
        return Ok(RowValue::NULL);
    };
    let lo = lo.clamp(0, len) as usize;
    let hi = hi.clamp(0, len) as usize;
    if lo >= hi {
        return Ok(RowValue::Value(Value::List(Vec::new())));
    }
    Ok(RowValue::Value(Value::List(items[lo..hi].to_vec())))
}

/// Evaluates a `CASE` expression (simple or searched), 3VL-aware for the searched form.
fn eval_case(
    case: &CaseExpr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    match &case.subject {
        // Simple CASE: compare the subject against each WHEN value with Cypher `=`.
        Some(subject) => {
            let subj = eval_value(subject, row, params, graph, functions, clock)?;
            for alt in &case.alternatives {
                let when = eval_value(&alt.when, row, params, graph, functions, clock)?;
                if equals(&subj, &when).is_true() {
                    return eval(&alt.then, row, params, graph, functions, clock);
                }
            }
        }
        // Searched CASE: each WHEN is a predicate; the first TRUE wins.
        None => {
            for alt in &case.alternatives {
                if eval_to_ternary(&alt.when, row, params, graph, functions, clock)?.is_true() {
                    return eval(&alt.then, row, params, graph, functions, clock);
                }
            }
        }
    }
    match &case.else_expr {
        Some(e) => eval(e, row, params, graph, functions, clock),
        None => Ok(RowValue::NULL),
    }
}

/// Tests whether `base` (a node/rel reference) carries **all** of `labels` (3VL: null → NULL).
/// Evaluates a [`LabelExpr`] label-expression predicate against a value (Neo4j 5.x semantics).
///
/// - **Node**: the expression is evaluated against the node's label set; `%` is true iff the node
///   carries at least one label, so a node with no labels gives `%` = false and `!A` = true
///   (`expressions/graph/Graph5.feature`).
/// - **Relationship**: a relationship always has exactly one type, so the "set" is that single type
///   and `%` is always true. `A&B` can therefore never match a relationship.
/// - **`null`**: the predicate is `null` (three-valued), matching `Graph5` [5].
/// - **Any other value** (has no labels/type): false.
fn eval_label_expr(base: &RowValue, expr: &LabelExpr, graph: &dyn GraphAccess) -> Ternary {
    match base {
        RowValue::Node(NodeRef { id }) => {
            let node_labels = graph.node_labels(*id).unwrap_or_default();
            let has_any = !node_labels.is_empty();
            Ternary::from_bool(expr.evaluate(
                &|name| node_labels.iter().any(|nl| nl.as_str() == name),
                has_any,
            ))
        }
        RowValue::Rel(RelRef { id }) => match graph.rel_data(*id) {
            Some(data) => Ternary::from_bool(expr.evaluate(&|name| data.rel_type == *name, true)),
            // A dangling relationship reference carries no type: evaluate against the empty set.
            None => Ternary::from_bool(expr.evaluate(&|_| false, false)),
        },
        RowValue::Value(Value::Null) => Ternary::Null,
        // Label predicate on any other non-null, non-entity value is FALSE (it has no labels/type).
        _ => Ternary::False,
    }
}

// =================================================================================================
// Numeric / string helpers
// =================================================================================================

/// The `f64` view of a number value, or `None` for a non-number.
fn numeric_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Integer(i) => Some(*i as f64),
        Value::Float(f) => Some(*f),
        _ => None,
    }
}

/// A compact string rendering of a scalar for `+` string coercion and `toString`.
fn stringify_scalar(v: &Value) -> String {
    match v {
        Value::Null => "null".to_owned(),
        Value::Boolean(b) => b.to_string(),
        Value::Integer(i) => i.to_string(),
        Value::Float(f) => f.to_string(),
        Value::String(s) => s.clone(),
        other => describe(&RowValue::Value(other.clone())).to_owned(),
    }
}

/// A short type description for diagnostics.
///
/// PERF/B7: returns `&'static str` — every arm is a constant type name, so there is no need to
/// heap-allocate a `String` per diagnostic. Callers embed it in `format!`/`stringify_scalar`.
fn describe(v: &RowValue) -> &'static str {
    match v {
        RowValue::Node(_) => "Node",
        RowValue::Rel(_) => "Relationship",
        RowValue::Path(_) => "Path",
        RowValue::List(_) => "List",
        RowValue::Map(_) => "Map",
        RowValue::Value(v) => match v {
            Value::Null => "null",
            Value::Boolean(_) => "Boolean",
            Value::Integer(_) => "Integer",
            Value::Float(_) => "Float",
            Value::String(_) => "String",
            Value::Bytes(_) => "Bytes",
            Value::List(_) => "List",
            Value::Map(_) => "Map",
            _ => "Temporal",
        },
    }
}

// =================================================================================================
// Function library (the implemented core; the rest are a documented registry)
// =================================================================================================

/// Evaluates a scalar/list function call by (lower-cased) dotted name (`04 §7.4`).
///
/// The **implemented core** covers the openCypher functions the executor's tests and common queries
/// lean on:
///
/// - **type/coercion:** `tostring`, `tointeger`, `tofloat`, `toboolean`, `tobooleanornull`,
///   `coalesce`.
/// - **collection/size:** `size`, `length`, `head`, `last`, `tail`, `reverse`, `range`, `keys`.
/// - **entity:** `id`, `labels`, `type`, `properties`, `startnode`, `endnode`.
/// - **path:** `nodes`, `relationships` (plus `length` over a path).
/// - **math:** `abs`, `ceil`, `floor`, `round`, `sign`, `sqrt`, `rand`.
/// - **string:** `toupper`, `tolower`, `trim`, `ltrim`, `rtrim`, `substring`, `replace`, `split`,
///   `left`, `right`.
///
/// Any other name that passed the compile-time arity check but has **no** runtime implementation
/// yet (e.g. `percentilecont`) returns an
/// [`EvalError::UnsupportedFunction`] — a documented, mechanically-extensible registry boundary, not
/// a silent wrong answer (`CLAUDE.md`: never guess; scope and document). Aggregating functions
/// (`count`/`sum`/`avg`/`min`/`max`/`collect`) are folded by the
/// [`Aggregation`](crate::physical::PhysicalOp::Aggregation) operator, not here.
fn call_function(
    name: &str,
    args: &[Expr],
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    // PERF/B5: function dispatch runs once per call per row. Avoid heap-allocating a lowercased
    // copy of `name` for the common case (Cypher function names are short ASCII) by lowercasing
    // into a stack buffer; only an unusually long name falls back to a heap `String`. The selected
    // function is identical to the previous `to_ascii_lowercase()` path (pure ASCII fold).
    let mut lower_buf = [0u8; 64];
    // Lowercase into a stack buffer for the common short-name case; `from_utf8` re-validates the
    // ASCII-lowercased bytes cheaply (it cannot fail — ASCII folding preserves UTF-8 validity and
    // length) and keeps this crate `#![forbid(unsafe_code)]`-clean. An over-long name (or the
    // impossible validation error) falls back to an owned heap lowercase.
    let lower_cow: std::borrow::Cow<'_, str> = if name.len() <= lower_buf.len() {
        let buf = &mut lower_buf[..name.len()];
        buf.copy_from_slice(name.as_bytes());
        buf.make_ascii_lowercase();
        match std::str::from_utf8(buf) {
            Ok(s) => std::borrow::Cow::Borrowed(s),
            Err(_) => std::borrow::Cow::Owned(name.to_ascii_lowercase()),
        }
    } else {
        std::borrow::Cow::Owned(name.to_ascii_lowercase())
    };
    let lower: &str = &lower_cow;

    // `coalesce` is special: it returns its first non-null argument, evaluated left to right.
    if lower == "coalesce" {
        for a in args {
            let v = eval(a, row, params, graph, functions, clock)?;
            if !v.is_null() {
                return Ok(v);
            }
        }
        return Ok(RowValue::NULL);
    }

    // Entity functions take the un-collapsed RowValue (they need the reference).
    match lower {
        "id" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            return Ok(match v {
                RowValue::Node(NodeRef { id }) => RowValue::Value(Value::Integer(id.0 as i64)),
                RowValue::Rel(RelRef { id }) => RowValue::Value(Value::Integer(id.0 as i64)),
                _ => RowValue::NULL,
            });
        }
        "labels" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            return match v {
                RowValue::Node(NodeRef { id }) => {
                    // `labels(n)` on a node self-deleted earlier in this query raises at runtime
                    // (`clauses/return/Return2.feature` [16]); only `id`/`type` survive a delete.
                    if graph.entity_deleted_by_txn(DeletedEntity::Node(id)) {
                        return Err(EvalError::DeletedEntityAccess);
                    }
                    Ok(RowValue::Value(Value::List(
                        graph
                            .node_labels(id)
                            .unwrap_or_default()
                            .into_iter()
                            .map(Value::String)
                            .collect(),
                    )))
                }
                // `labels(null)` is null (a missing optional match, `labels(null)` literally).
                RowValue::Value(Value::Null) => Ok(RowValue::NULL),
                // Any non-null, non-node argument is a runtime `TypeError` the TCK details as
                // `InvalidArgumentValue` (`expressions/graph/Graph3.feature` [9]). The statically
                // decidable cases (a node literal / a path) are already rejected at compile time.
                other => Err(EvalError::TypeError {
                    context: format!("labels() requires a node, got {}", describe(&other)),
                }),
            };
        }
        "type" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            return match v {
                // `type(r)` STILL works after a same-query `DELETE r` (the relationship keeps its
                // identity; only property/label reads fail — `clauses/return/Return2.feature` [14]).
                // `rel_data_including_deleted` reads the type through a self-delete tombstone that the
                // visibility-filtered `rel_data` would otherwise hide.
                RowValue::Rel(RelRef { id }) => Ok(graph
                    .rel_data_including_deleted(id)
                    .map(|d| RowValue::Value(Value::String(d.rel_type)))
                    .unwrap_or(RowValue::NULL)),
                // `type(null)` is null (an unmatched optional relationship, `type(null)` literally).
                RowValue::Value(Value::Null) => Ok(RowValue::NULL),
                // Any non-null, non-relationship argument is a runtime `TypeError`
                // (`expressions/graph/Graph4.feature` [6]); a node argument is rejected at compile
                // time (statically decidable).
                other => Err(EvalError::TypeError {
                    context: format!("type() requires a relationship, got {}", describe(&other)),
                }),
            };
        }
        "properties" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            return match v {
                RowValue::Node(NodeRef { id }) => map_from_props(graph.node_properties(id)),
                RowValue::Rel(RelRef { id }) => map_from_props(graph.rel_properties(id)),
                RowValue::Value(m @ Value::Map(_)) => Ok(RowValue::Value(m)),
                _ => Ok(RowValue::NULL),
            };
        }
        "keys" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            return match v {
                RowValue::Node(NodeRef { id }) => keys_list(graph.node_properties(id)),
                RowValue::Rel(RelRef { id }) => keys_list(graph.rel_properties(id)),
                // `keys($map)` materialises one `Value::String` per key — bound the key list against the
                // per-value budget (a wide map parameter is the amplifier) before collecting (`SEC-191`).
                RowValue::Value(Value::Map(entries)) => {
                    check_list_len_budget(entries.len(), "keys()")?;
                    Ok(RowValue::Value(Value::List(
                        entries.into_iter().map(|(k, _)| Value::String(k)).collect(),
                    )))
                }
                _ => Ok(RowValue::NULL),
            };
        }
        "startnode" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            return Ok(match v {
                RowValue::Rel(RelRef { id }) => graph
                    .rel_data(id)
                    .map(|d| RowValue::Node(NodeRef { id: d.start }))
                    .unwrap_or(RowValue::NULL),
                _ => RowValue::NULL,
            });
        }
        "endnode" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            return Ok(match v {
                RowValue::Rel(RelRef { id }) => graph
                    .rel_data(id)
                    .map(|d| RowValue::Node(NodeRef { id: d.end }))
                    .unwrap_or(RowValue::NULL),
                _ => RowValue::NULL,
            });
        }
        // Path accessors (openCypher `expressions/path/**`): ordered projections of a path value.
        "nodes" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            return match v {
                RowValue::Path(p) => Ok(RowValue::list(
                    p.nodes()
                        .into_iter()
                        .map(|id| RowValue::Node(NodeRef { id }))
                        .collect(),
                )),
                RowValue::Value(Value::Null) => Ok(RowValue::NULL),
                other => Err(EvalError::TypeError {
                    context: format!("nodes() requires a path, got {}", describe(&other)),
                }),
            };
        }
        "relationships" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            return match v {
                RowValue::Path(p) => Ok(RowValue::list(
                    p.rels()
                        .into_iter()
                        .map(|id| RowValue::Rel(RelRef { id }))
                        .collect(),
                )),
                RowValue::Value(Value::Null) => Ok(RowValue::NULL),
                other => Err(EvalError::TypeError {
                    context: format!("relationships() requires a path, got {}", describe(&other)),
                }),
            };
        }
        // Collection-shape functions, evaluated at the RowValue level so structural lists
        // (`nodes(p)`, `collect(n)`, …) and paths keep their elements; the pure-property cases
        // behave exactly as the former `Value`-level implementations.
        // `char_length` / `character_length` are Neo4j 5.x aliases of `size()` (Unicode character
        // count over a string; the same list length over a list). They share this arm so their
        // behaviour is identical to `size` by construction. Only `length` keeps the path-specific
        // relationship-count semantics (gated on `lower == "length"`).
        "size" | "length" | "char_length" | "character_length" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            return match v {
                // `length(p)` is the path's relationship count (openCypher).
                RowValue::Path(p) if lower == "length" => {
                    Ok(RowValue::Value(Value::Integer(p.len() as i64)))
                }
                RowValue::List(items) => Ok(RowValue::Value(Value::Integer(items.len() as i64))),
                RowValue::Value(Value::Null) => Ok(RowValue::NULL),
                RowValue::Value(Value::List(items)) => {
                    Ok(RowValue::Value(Value::Integer(items.len() as i64)))
                }
                RowValue::Value(Value::String(s)) => {
                    Ok(RowValue::Value(Value::Integer(s.chars().count() as i64)))
                }
                _ => Err(EvalError::TypeError {
                    context: format!("{lower}() requires a list or string"),
                }),
            };
        }
        "head" | "last" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            let Some(mut items) = v.as_list_elems() else {
                return match v {
                    RowValue::Value(Value::Null) => Ok(RowValue::NULL),
                    _ => Err(EvalError::TypeError {
                        context: "expected a list argument".to_owned(),
                    }),
                };
            };
            return Ok(match lower {
                "head" => {
                    if items.is_empty() {
                        RowValue::NULL
                    } else {
                        items.remove(0)
                    }
                }
                _ => items.pop().unwrap_or(RowValue::NULL),
            });
        }
        "tail" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            let items = match v {
                // `tail(null)` is the empty list (the pre-existing `list_arg` behaviour).
                RowValue::Value(Value::Null) => Vec::new(),
                other => other.as_list_elems().ok_or_else(|| EvalError::TypeError {
                    context: "expected a list argument".to_owned(),
                })?,
            };
            return Ok(RowValue::list(items.into_iter().skip(1).collect()));
        }
        "reverse" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            return match v {
                RowValue::List(items) => Ok(RowValue::list(items.into_iter().rev().collect())),
                RowValue::Value(Value::List(items)) => Ok(RowValue::Value(Value::List(
                    items.into_iter().rev().collect(),
                ))),
                RowValue::Value(Value::String(s)) => {
                    Ok(RowValue::Value(Value::String(s.chars().rev().collect())))
                }
                RowValue::Value(Value::Null) => Ok(RowValue::NULL),
                _ => Err(EvalError::TypeError {
                    context: "reverse() requires a list or string".to_owned(),
                }),
            };
        }
        // Scalar type-conversion functions (openCypher `expressions/typeConversion/**`). These are
        // evaluated at the `RowValue` level so that a structural/entity argument — node,
        // relationship, path, list, or map — is rejected with the runtime `TypeError` the TCK
        // details as `InvalidArgumentValue` (`TypeConversion2/3/4` scenario "Fail … on invalid
        // types"). Were they to fall through to the generic `argv` collapse below, an entity would
        // silently become `null` (via `to_value`) and the invalid-type scenarios would wrongly
        // succeed. The accepted property values delegate to the value-level helpers, which encode
        // each function's exact conversion table.
        "tointeger" | "tofloat" | "tostring" | "toboolean" | "tobooleanornull"
        | "tointegerornull" | "tofloatornull" | "tostringornull" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            return convert_scalar(lower, v).map(RowValue::Value);
        }
        // `toIntegerList` / `toFloatList` / `toBooleanList` / `toStringList` (Neo4j 5.x): apply the
        // matching `*OrNull` conversion to every element, so a non-convertible (or null) element
        // becomes `null`. A null input list is `null`; a non-list argument is a runtime `TypeError`.
        "tointegerlist" | "tofloatlist" | "tobooleanlist" | "tostringlist" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            return to_typed_list(lower, v).map(RowValue::Value);
        }
        // `elementId(n | r)` — the STRING element identifier of a node/relationship. Graphus is a
        // single instance, so the element id is the decimal of the entity's integer id, matching the
        // Bolt/REST wire `element_id` byte-for-byte (`graphus_bolt::packstream::element_id`). A null
        // argument is null; any non-entity argument is null (mirroring `id()`).
        "elementid" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            return Ok(match v {
                RowValue::Node(NodeRef { id }) => {
                    RowValue::Value(Value::String(wire_element_id(id.0)))
                }
                RowValue::Rel(RelRef { id }) => {
                    RowValue::Value(Value::String(wire_element_id(id.0)))
                }
                _ => RowValue::NULL,
            });
        }
        // `valueType(v)` — the STRING name of the most precise Cypher type (Neo4j 5.x normalized form).
        "valuetype" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            return Ok(RowValue::Value(Value::String(value_type_string(&v))));
        }
        // `isEmpty(list | map | string)` — whether the collection / string has no elements; `null` on
        // a null argument; a runtime `TypeError` on any other type (Neo4j 5.x).
        "isempty" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            return is_empty_value(&v).map(RowValue::Value);
        }
        // `nullIf(a, b)` — `null` when the two arguments are equivalent (Cypher value equality, plus
        // node/relationship identity), otherwise the first argument unchanged (Neo4j 5.x / SQL NULLIF).
        "nullif" => {
            let a = eval(&args[0], row, params, graph, functions, clock)?;
            let b = eval(&args[1], row, params, graph, functions, clock)?;
            return Ok(if row_values_equivalent_for_nullif(&a, &b) {
                RowValue::NULL
            } else {
                a
            });
        }
        // `exists(<property access>)` — the **function** form of property existence (the `EXISTS {…}`
        // *subquery* form is a separate `ExprKind::ExistsSubquery`, handled in `eval`). Returns `true`
        // when the argument evaluates to a **non-null** value (i.e. the property exists and is not
        // null), else `false` — the long-standing boolean-total property-existence semantics, which is
        // equivalent to `<property access> IS NOT NULL`. A null base (`exists(null.prop)`) yields
        // `false` because the property access itself evaluates to null. Evaluated at the `RowValue`
        // level so a structural/entity argument is treated as present (non-null) rather than collapsed.
        "exists" => {
            let v = eval(&args[0], row, params, graph, functions, clock)?;
            return Ok(RowValue::Value(Value::Boolean(!v.is_null())));
        }
        _ => {}
    }

    // The remaining functions operate on collapsed property values.
    let argv: Vec<Value> = args
        .iter()
        .map(|a| eval_value(a, row, params, graph, functions, clock))
        .collect::<Result<_, _>>()?;

    let result = match lower {
        // Temporal constructors (rmp #53): string / component-map / projection forms, plus the
        // clock variants (`date.transaction`, `localtime.realtime`, … — `Temporal4.feature` [13]).
        // The clock variants route to the same base constructor; their zero-argument "current
        // instant" form is a named deferral (needs the clock seam), handled in `construct`.
        "date"
        | "time"
        | "datetime"
        | "localtime"
        | "localdatetime"
        | "duration"
        | "date.transaction"
        | "date.statement"
        | "date.realtime"
        | "datetime.transaction"
        | "datetime.statement"
        | "datetime.realtime"
        | "localdatetime.transaction"
        | "localdatetime.statement"
        | "localdatetime.realtime"
        | "localtime.transaction"
        | "localtime.statement"
        | "localtime.realtime"
        | "time.transaction"
        | "time.statement"
        | "time.realtime" => crate::temporal_fns::construct(lower, argv.first(), clock)?,
        // Spatial point constructor and distance (rmp #73). `distance` and `point.distance` are
        // the two openCypher spellings of the same two-point distance.
        "point" => crate::spatial_fns::construct_point(arg(&argv, 0, lower)?)?,
        "distance" | "point.distance" => {
            crate::spatial_fns::distance(arg(&argv, 0, lower)?, arg(&argv, 1, lower)?)?
        }
        // `point.withinBBox(point, lowerLeft, upperRight)` — whether the point lies inside the
        // bounding box (with geographic longitude antimeridian wraparound); `null` on any null
        // argument or a CRS mismatch (Neo4j 5.x).
        "point.withinbbox" => crate::spatial_fns::within_bbox(
            arg(&argv, 0, lower)?,
            arg(&argv, 1, lower)?,
            arg(&argv, 2, lower)?,
        )?,
        // Temporal difference and truncation functions (rmp #53).
        "duration.between" | "duration.inmonths" | "duration.indays" | "duration.inseconds" => {
            crate::temporal_fns::duration_between(
                lower,
                arg(&argv, 0, lower)?,
                arg(&argv, 1, lower)?,
            )?
        }
        // `datetime.fromepoch(seconds, nanos)` / `datetime.fromepochmillis(ms)`:
        // a UTC instant from a POSIX-epoch count (`Temporal1.feature` [11]).
        "datetime.fromepoch" => {
            crate::temporal_fns::from_epoch_seconds(arg(&argv, 0, lower)?, arg(&argv, 1, lower)?)?
        }
        "datetime.fromepochmillis" => {
            crate::temporal_fns::from_epoch_millis(arg(&argv, 0, lower)?)?
        }
        "date.truncate"
        | "time.truncate"
        | "localtime.truncate"
        | "datetime.truncate"
        | "localdatetime.truncate" => crate::temporal_fns::truncate(
            lower,
            arg(&argv, 0, lower)?,
            arg(&argv, 1, lower)?,
            argv.get(2),
        )?,
        "range" => range_fn(&argv)?,
        "abs" => match arg(&argv, 0, "abs")? {
            Value::Integer(i) => i
                .checked_abs()
                .map(Value::Integer)
                .ok_or(EvalError::IntegerOverflow)?,
            Value::Float(f) => Value::Float(f.abs()),
            Value::Null => Value::Null,
            _ => return Err(num_type_error("abs")),
        },
        "ceil" => float_unary(arg(&argv, 0, "ceil")?, f64::ceil, "ceil")?,
        "floor" => float_unary(arg(&argv, 0, "floor")?, f64::floor, "floor")?,
        // `round(value)`, `round(value, precision)`, `round(value, precision, mode)` (Neo4j 5.x).
        "round" => round_fn(&argv)?,
        // `sqrt()` of a negative number is NaN (IEEE 754, which the openCypher Float is).
        "sqrt" => float_unary(arg(&argv, 0, "sqrt")?, f64::sqrt, "sqrt")?,
        "rand" => Value::Float(next_rand_f64()),
        "sign" => match arg(&argv, 0, "sign")? {
            Value::Integer(i) => Value::Integer(i.signum()),
            Value::Float(f) => Value::Integer(if *f > 0.0 {
                1
            } else if *f < 0.0 {
                -1
            } else {
                0
            }),
            Value::Null => Value::Null,
            _ => return Err(num_type_error("sign")),
        },
        // ---- mathematical constants (rmp #629) ----------------------------------------------
        // `pi()` and `e()` take no arguments; their exact `f64` constants match Neo4j 5.x
        // (π = 3.141592653589793, e = 2.718281828459045).
        "pi" => Value::Float(std::f64::consts::PI),
        "e" => Value::Float(std::f64::consts::E),
        // ---- trigonometric functions (rmp #629) ---------------------------------------------
        // Each accepts a number (radians) and returns a Float; a non-numeric argument is a runtime
        // `TypeError` and `null` maps to `null` (all via `float_unary`, exactly like `ceil`/`floor`).
        "sin" => float_unary(arg(&argv, 0, "sin")?, f64::sin, "sin")?,
        "cos" => float_unary(arg(&argv, 0, "cos")?, f64::cos, "cos")?,
        "tan" => float_unary(arg(&argv, 0, "tan")?, f64::tan, "tan")?,
        // `cot(x) = 1/tan(x)`; `cot(0)` is `+Infinity` (IEEE 754 `1.0 / 0.0`), matching Neo4j.
        "cot" => float_unary(arg(&argv, 0, "cot")?, |x| 1.0 / x.tan(), "cot")?,
        // `asin`/`acos` return NaN for arguments outside `[-1, 1]` (IEEE 754), matching Neo4j.
        "asin" => float_unary(arg(&argv, 0, "asin")?, f64::asin, "asin")?,
        "acos" => float_unary(arg(&argv, 0, "acos")?, f64::acos, "acos")?,
        "atan" => float_unary(arg(&argv, 0, "atan")?, f64::atan, "atan")?,
        // `atan2(y, x)` — the two-argument arctangent; argument order matches Neo4j (`y` then `x`).
        "atan2" => atan2_fn(&argv)?,
        // `degrees(radians)` / `radians(degrees)` — the standard π-based conversions.
        "degrees" => float_unary(arg(&argv, 0, "degrees")?, f64::to_degrees, "degrees")?,
        "radians" => float_unary(arg(&argv, 0, "radians")?, f64::to_radians, "radians")?,
        // `haversin(x) = (1 - cos(x)) / 2` (the haversine of an angle in radians).
        "haversin" => float_unary(
            arg(&argv, 0, "haversin")?,
            |x| (1.0 - x.cos()) / 2.0,
            "haversin",
        )?,
        // ---- logarithmic / exponential functions (rmp #629) ---------------------------------
        // `exp(x) = eˣ`; `log(x)` is the natural logarithm (base e); `log10(x)` is base 10.
        // `log(0)`/`log10(0)` are `-Infinity` and a negative argument is NaN (IEEE 754), per Neo4j.
        "exp" => float_unary(arg(&argv, 0, "exp")?, f64::exp, "exp")?,
        "log" => float_unary(arg(&argv, 0, "log")?, f64::ln, "log")?,
        "log10" => float_unary(arg(&argv, 0, "log10")?, f64::log10, "log10")?,
        // `isNaN(number)` — whether a FLOAT is NaN. An INTEGER is never NaN; `null` maps to `null`.
        "isnan" => match arg(&argv, 0, "isNaN")? {
            Value::Float(f) => Value::Boolean(f.is_nan()),
            Value::Integer(_) => Value::Boolean(false),
            Value::Null => Value::Null,
            _ => return Err(num_type_error("isNaN")),
        },
        // `timestamp()` — milliseconds since the Unix epoch, constant for the whole statement (read
        // off the captured statement clock, never a fresh wall-clock sample).
        "timestamp" => Value::Integer(clock.epoch_millis()),
        // `randomUUID()` — a fresh random (version-4) UUID string on every call.
        "randomuuid" => Value::String(random_uuid_string()),
        "toupper" => string_case(arg(&argv, 0, "toUpper")?, true, "toUpper")?,
        "tolower" => string_case(arg(&argv, 0, "toLower")?, false, "toLower")?,
        "trim" => string_unary(arg(&argv, 0, "trim")?, |s| s.trim().to_owned(), "trim")?,
        "ltrim" => string_unary(
            arg(&argv, 0, "ltrim")?,
            |s| s.trim_start().to_owned(),
            "ltrim",
        )?,
        "rtrim" => string_unary(
            arg(&argv, 0, "rtrim")?,
            |s| s.trim_end().to_owned(),
            "rtrim",
        )?,
        // `btrim(input [, trimCharacterString])` — trim from **both** ends (Neo4j 5.x). Without the
        // second argument all leading/trailing whitespace is removed; with it, the trailing/leading
        // run of characters **in the set** `trimCharacterString` is removed. `null` in either
        // position yields `null`.
        "btrim" => btrim_fn(&argv)?,
        // `normalize(input [, normalForm])` — Unicode normalization (NFC/NFD/NFKC/NFKD; default NFC).
        // `null` input (or a null form) yields `null`. See `normalize_fn` for the form-argument note.
        "normalize" => normalize_fn(&argv)?,
        "substring" => substring_fn(&argv)?,
        "replace" => replace_fn(&argv)?,
        "split" => split_fn(&argv)?,
        "left" => left_right_fn(&argv, true)?,
        "right" => left_right_fn(&argv, false)?,
        other => {
            // Not a built-in (every built-in is matched above, including the entity functions that
            // returned early). Consult the **extension** function registry (`rmp` task #75): a
            // registered scalar UDF is invoked over the already-collapsed `argv`. A built-in can
            // never reach here, so a UDF can never shadow a built-in at runtime — consistent with
            // registration-time rejection of built-in-colliding names. A handler failure (including
            // its own argument-type rejection) becomes the runtime
            // [`EvalError::ExtensionFunction`], which maps to `GraphusError::Runtime` →
            // `ArgumentError` at the Bolt boundary (the same class a built-in's runtime type error
            // takes). Only when no UDF is registered do we return the documented
            // `UnsupportedFunction` (an un-implemented built-in like `percentileCont`).
            if functions.signature(other).is_some() {
                return functions
                    .invoke(other, &argv)
                    .map(RowValue::Value)
                    .map_err(|failure| EvalError::ExtensionFunction {
                        name: failure.name,
                        message: failure.message,
                    });
            }
            return Err(EvalError::UnsupportedFunction {
                name: other.to_owned(),
            });
        }
    };
    Ok(RowValue::Value(result))
}

fn map_from_props(props: Option<Vec<(String, Value)>>) -> Result<RowValue, EvalError> {
    match props {
        Some(p) => {
            // Sibling of keys(): bound the property map against the per-value budget (`SEC-191`,
            // CWE-770 / CWE-789). Lower-severity than the parameter-driven amplifiers (bounded by
            // already-stored data, not a cheap 1→N blow-up), guarded for consistency with keys().
            check_list_len_budget(p.len(), "properties()")?;
            Ok(RowValue::Value(Value::Map(p)))
        }
        None => Ok(RowValue::NULL),
    }
}

fn keys_list(props: Option<Vec<(String, Value)>>) -> Result<RowValue, EvalError> {
    match props {
        Some(p) => {
            // A node/relationship can carry an adversarially large (write-amplified) property set;
            // bound the key list against the per-value budget before collecting (`SEC-191`).
            check_list_len_budget(p.len(), "keys()")?;
            Ok(RowValue::Value(Value::List(
                p.into_iter().map(|(k, _)| Value::String(k)).collect(),
            )))
        }
        None => Ok(RowValue::NULL),
    }
}

fn num_type_error(fname: &str) -> EvalError {
    EvalError::TypeError {
        context: format!("{fname}() requires a number"),
    }
}

/// Borrows the `n`-th positional argument of a built-in defensively. The semantic analyzer's arity
/// check should make this infallible, but if it ever misses a case we return an
/// [`EvalError::ArgumentCount`] instead of panicking on out-of-bounds user input.
fn arg<'a>(argv: &'a [Value], n: usize, fname: &str) -> Result<&'a Value, EvalError> {
    argv.get(n).ok_or_else(|| EvalError::ArgumentCount {
        name: fname.to_owned(),
    })
}

/// Dispatches the scalar type-conversion functions (`toInteger`/`toFloat`/`toString`/`toBoolean`/
/// `toBooleanOrNull`) on an **un-collapsed** [`RowValue`] argument.
///
/// A structural or entity argument — node, relationship, path, structural list, or map — is not a
/// convertible scalar and raises the runtime `TypeError` the openCypher TCK details as
/// `InvalidArgumentValue` (`expressions/typeConversion/TypeConversion{2,3,4}.feature`, the
/// "Fail … on invalid types" outlines). `null` is the identity for every conversion. Property
/// scalars (`Value`) delegate to the per-function helpers, which encode each conversion table.
///
/// `lower` is the already-lowercased function name; it is one of the five conversion spellings (the
/// caller dispatches only those here).
fn convert_scalar(lower: &str, rv: RowValue) -> Result<Value, EvalError> {
    // The `…OrNull` companions never raise: any non-convertible argument (structural or otherwise)
    // is `null` rather than a `TypeError` (Neo4j's `toBooleanOrNull`/`toIntegerOrNull`/… contract).
    // For the strict spellings, a structural/entity argument is the runtime `TypeError`.
    let null_on_invalid = lower.ends_with("ornull");

    // Structural/entity arguments are non-convertible for every conversion function. (A `null`
    // RowValue is `RowValue::Value(Value::Null)` and so flows through to the value-level helpers,
    // each of which maps `null` → `null`.)
    let v = match rv {
        RowValue::Value(v) => v,
        RowValue::Node(_)
        | RowValue::Rel(_)
        | RowValue::Path(_)
        | RowValue::List(_)
        | RowValue::Map(_) => {
            if null_on_invalid {
                return Ok(Value::Null);
            }
            return Err(invalid_conversion_argument(lower));
        }
    };
    // A structural value that survived collapse as `Value::List`/`Value::Map` (e.g. a literal `[]`
    // or `{}`) is equally non-convertible.
    if matches!(v, Value::List(_) | Value::Map(_)) {
        if null_on_invalid {
            return Ok(Value::Null);
        }
        return Err(invalid_conversion_argument(lower));
    }
    match lower {
        "tointeger" => to_integer(&v),
        "tofloat" => to_float(&v),
        "tostring" => to_string_value(&v),
        "toboolean" => to_boolean(&v, false),
        "tobooleanornull" => to_boolean(&v, true),
        // The `*OrNull` companions of the numeric/string conversions: they never raise, so a scalar
        // that the strict form would reject (e.g. `toFloat(true)`) becomes `null` instead
        // (`toInteger`/`toString` already never raise on a scalar, so they share their bodies).
        "tointegerornull" => to_integer(&v),
        "tofloatornull" => to_float_or_null(&v),
        "tostringornull" => to_string_value(&v),
        // Unreachable: the caller dispatches only the conversion spellings above.
        _ => Err(EvalError::TypeError {
            context: format!("{lower}() is not a scalar conversion"),
        }),
    }
}

/// `toFloatOrNull(v)` over an already-validated scalar: identical to [`to_float`] except a boolean —
/// which the strict `toFloat` rejects as an invalid type — yields `null` rather than an error. Every
/// other scalar delegates to `to_float`, which cannot error for a non-boolean.
fn to_float_or_null(v: &Value) -> Result<Value, EvalError> {
    match v {
        Value::Boolean(_) => Ok(Value::Null),
        other => to_float(other),
    }
}

/// The runtime `TypeError` raised when a conversion function receives a non-convertible
/// (structural/entity) argument. The TCK gates the invalid-type scenarios on the error TYPE
/// (`TypeError`) and PHASE (`runtime`); the `InvalidArgumentValue` detail is a soft match.
fn invalid_conversion_argument(lower: &str) -> EvalError {
    EvalError::TypeError {
        context: format!("{lower}() does not accept a node, relationship, path, list or map"),
    }
}

/// `toInteger(v)` over an already-validated scalar (`convert_scalar` has rejected entities/lists/
/// maps). An integer is itself; a float truncates toward zero; a numeric string parses (integer
/// first, then float-with-truncation) or yields `null`; a boolean and `null` yield `null`.
fn to_integer(v: &Value) -> Result<Value, EvalError> {
    Ok(match v {
        Value::Integer(i) => Value::Integer(*i),
        Value::Float(f) => float_to_integer(*f),
        Value::String(s) => {
            let t = s.trim();
            // Try an exact integer first (preserves full `i64` range that an `f64` round-trip would
            // lose); fall back to a float parse and truncate (`toInteger('1.7') = 1`,
            // `toInteger('2.9') = 2`). A non-numeric string (`'foo'`, `''`) is `null`.
            t.parse::<i64>()
                .map(Value::Integer)
                .unwrap_or_else(|_| t.parse::<f64>().map_or(Value::Null, float_to_integer))
        }
        Value::Boolean(_) | Value::Null => Value::Null,
        // `convert_scalar` has already rejected the structural cases; any residual is `null`.
        _ => Value::Null,
    })
}

/// Truncates a float toward zero into an `i64`, yielding `null` for values openCypher cannot
/// represent as an integer: NaN, ±infinity, and magnitudes outside the `i64` range. A plain
/// `f as i64` cast would instead *saturate* (`1e30 as i64 == i64::MAX`), silently fabricating a
/// value openCypher requires to be `null`.
fn float_to_integer(f: f64) -> Value {
    // The exact boundary: `i64::MAX` is not representable as `f64`, so compare against the next
    // representable power of two (`2^63`) and the inclusive lower bound `i64::MIN` (which *is*
    // representable exactly). Truncation toward zero happens via the `as` cast once in range.
    if f.is_finite() && f >= -(2.0_f64.powi(63)) && f < 2.0_f64.powi(63) {
        Value::Integer(f.trunc() as i64)
    } else {
        Value::Null
    }
}

/// `toFloat(v)` over an already-validated scalar. A float is itself; an integer widens; a numeric
/// string parses or yields `null`; `null` yields `null`. A boolean is **not** convertible
/// (`TypeConversion3.feature` [6] lists `true` among the invalid types).
fn to_float(v: &Value) -> Result<Value, EvalError> {
    Ok(match v {
        Value::Float(f) => Value::Float(*f),
        Value::Integer(i) => Value::Float(*i as f64),
        Value::String(s) => s
            .trim()
            .parse::<f64>()
            .map(Value::Float)
            .unwrap_or(Value::Null),
        Value::Null => Value::Null,
        Value::Boolean(_) => return Err(invalid_conversion_argument("tofloat")),
        // `convert_scalar` has already rejected the structural cases; any residual is `null`.
        _ => Value::Null,
    })
}

/// `toString(v)` over an already-validated scalar. Integers, floats, booleans, strings, and
/// temporal/spatial values render to their canonical string; `null` yields `null`.
fn to_string_value(v: &Value) -> Result<Value, EvalError> {
    Ok(match v {
        Value::Null => Value::Null,
        v => match crate::temporal_fns::to_iso(v) {
            Some(iso) => Value::String(iso),
            None => Value::String(stringify_scalar(v)),
        },
    })
}

/// `toBoolean(v)` / `toBooleanOrNull(v)` (openCypher TCK `expressions/typeConversion/
/// TypeConversion1.feature`): a boolean is itself; a string converts from `'true'`/`'false'`
/// (case-insensitively, after trimming — mirroring [`to_integer`]'s string handling) and any other
/// string is null; an integer converts as zero → `false`, non-zero → `true` (the TCK's
/// invalid-type table — `TypeConversion1` scenario [5] — lists float/list/map/node/relationship/
/// path but deliberately *not* integer); null is null. Every other type is non-convertible:
/// `toBoolean` raises the runtime `TypeError` the TCK details as `InvalidArgumentValue`, while the
/// `…OrNull` companion yields null instead (that single difference is the whole contract).
fn to_boolean(v: &Value, null_on_invalid: bool) -> Result<Value, EvalError> {
    Ok(match v {
        Value::Boolean(b) => Value::Boolean(*b),
        Value::Integer(i) => Value::Boolean(*i != 0),
        Value::String(s) => {
            let t = s.trim();
            if t.eq_ignore_ascii_case("true") {
                Value::Boolean(true)
            } else if t.eq_ignore_ascii_case("false") {
                Value::Boolean(false)
            } else {
                Value::Null
            }
        }
        Value::Null => Value::Null,
        _ if null_on_invalid => Value::Null,
        _ => {
            return Err(EvalError::TypeError {
                context: "toBoolean() requires a boolean, string or integer".to_owned(),
            });
        }
    })
}

thread_local! {
    /// Per-thread `rand()` generator state, seeded lazily on the thread's first draw by
    /// [`rand_seed`]. A `thread_local` keeps the production evaluator free of locks and `unsafe`
    /// while staying correct under the executor's thread-per-scenario/-session usage.
    static RAND_STATE: Cell<u64> = Cell::new(rand_seed());
}

/// A non-zero, non-deterministic 64-bit seed for [`RAND_STATE`], drawn from the standard library's
/// own entropy: each [`RandomState`](std::collections::hash_map::RandomState) mixes OS-provided
/// per-process randomness with a per-instance counter, so this needs no new dependency and no
/// direct OS call. Zero is the `xorshift64*` fixed point, so it is remapped to a fixed odd
/// constant (the same guard `graphus_sim::SimRng` applies to its seed).
fn rand_seed() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let seed = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    if seed == 0 {
        0x9E37_79B9_7F4A_7C15
    } else {
        seed
    }
}

/// The next `rand()` draw: a Float uniform in `[0.0, 1.0)` (the openCypher `rand()` contract; the
/// TCK scenarios that use it — `expressions/quantifier/Quantifier9–12` — only rely on the type and
/// range, never the sequence). One `xorshift64*` step — the same generator as
/// `graphus_sim::SimRng`, restated here because the production cypher crate must not depend on the
/// simulation harness — then the top 53 bits are scaled by 2⁻⁵³, which is exact in an `f64` and
/// strictly below 1.0.
fn next_rand_f64() -> f64 {
    RAND_STATE.with(|cell| {
        let mut x = cell.get();
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        cell.set(x);
        let bits = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        (bits >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    })
}

fn float_unary(v: &Value, f: impl Fn(f64) -> f64, fname: &str) -> Result<Value, EvalError> {
    match v {
        Value::Integer(i) => Ok(Value::Float(f(*i as f64))),
        Value::Float(x) => Ok(Value::Float(f(*x))),
        Value::Null => Ok(Value::Null),
        _ => Err(num_type_error(fname)),
    }
}

/// `atan2(y, x)` — the two-argument arctangent (Neo4j 5.x argument order: `y` then `x`). A null
/// argument propagates to `null`; a non-numeric argument is a runtime `TypeError`.
fn atan2_fn(argv: &[Value]) -> Result<Value, EvalError> {
    let y = arg(argv, 0, "atan2")?;
    let x = arg(argv, 1, "atan2")?;
    if matches!(y, Value::Null) || matches!(x, Value::Null) {
        return Ok(Value::Null);
    }
    let (Some(yf), Some(xf)) = (numeric_f64(y), numeric_f64(x)) else {
        return Err(num_type_error("atan2"));
    };
    Ok(Value::Float(yf.atan2(xf)))
}

// =================================================================================================
// `round(value[, precision[, mode]])` — Neo4j 5.x numeric rounding (rmp #629)
// =================================================================================================

/// A Neo4j 5.x rounding mode for the three-argument `round(value, precision, mode)` form.
#[derive(Clone, Copy)]
enum RoundMode {
    /// Round away from zero.
    Up,
    /// Round toward zero (truncate).
    Down,
    /// Round toward positive infinity.
    Ceiling,
    /// Round toward negative infinity.
    Floor,
    /// Round to nearest; ties away from zero.
    HalfUp,
    /// Round to nearest; ties toward zero.
    HalfDown,
    /// Round to nearest; ties to the even neighbour (banker's rounding).
    HalfEven,
}

impl RoundMode {
    /// Parses a Neo4j rounding-mode string. Neo4j's modes are upper-case; parsing is
    /// case-insensitive for robustness. An unrecognised mode is a runtime error (`ArgumentError`).
    fn parse(s: &str) -> Result<Self, EvalError> {
        match s.to_ascii_uppercase().as_str() {
            "UP" => Ok(Self::Up),
            "DOWN" => Ok(Self::Down),
            "CEILING" => Ok(Self::Ceiling),
            "FLOOR" => Ok(Self::Floor),
            "HALF_UP" => Ok(Self::HalfUp),
            "HALF_DOWN" => Ok(Self::HalfDown),
            "HALF_EVEN" => Ok(Self::HalfEven),
            _ => Err(EvalError::TypeError {
                context: format!(
                    "round(): unknown rounding mode '{s}' (expected UP, DOWN, CEILING, FLOOR, \
                     HALF_UP, HALF_DOWN or HALF_EVEN)"
                ),
            }),
        }
    }
}

/// The `10^precision` scale factor for rounding to `precision` decimal places, or `None` when the
/// scale is not a usable finite non-zero `f64` (an absurd precision) — in which case rounding is the
/// identity (the value already carries at least that much / that little precision in an `f64`).
fn round_scale(precision: i64) -> Option<f64> {
    let p = i32::try_from(precision.clamp(-308, 308)).unwrap_or(0);
    let scale = 10f64.powi(p);
    (scale.is_finite() && scale != 0.0).then_some(scale)
}

/// `round(value)` and `round(value, precision)` — Neo4j's **default** rounding: HALF_UP (ties away
/// from zero) at the requested precision, **except at precision 0**, where ties round toward positive
/// infinity so that `round(value, 0)` aligns with the single-argument `round(value)` (Neo4j 5.x, the
/// documented exception). Non-finite inputs round to themselves.
fn default_round(x: f64, precision: i64) -> f64 {
    if !x.is_finite() {
        return x;
    }
    let Some(scale) = round_scale(precision) else {
        return x;
    };
    let scaled = x * scale;
    if !scaled.is_finite() {
        return x;
    }
    let rounded = if precision == 0 {
        // Ties toward +∞ (Java `Math.round` semantics): floor(x + 0.5).
        (scaled + 0.5).floor()
    } else {
        // HALF_UP (ties away from zero) is exactly Rust's `f64::round`.
        scaled.round()
    };
    rounded / scale
}

/// `round(value, precision, mode)` — rounding to `precision` decimal places with an explicit mode
/// (applied uniformly, with no precision-0 special case — that is only the default's behaviour).
/// Non-finite inputs round to themselves.
fn mode_round(x: f64, precision: i64, mode: RoundMode) -> f64 {
    if !x.is_finite() {
        return x;
    }
    let Some(scale) = round_scale(precision) else {
        return x;
    };
    let scaled = x * scale;
    if !scaled.is_finite() {
        return x;
    }
    let rounded = match mode {
        RoundMode::Up => {
            if scaled >= 0.0 {
                scaled.ceil()
            } else {
                scaled.floor()
            }
        }
        RoundMode::Down => scaled.trunc(),
        RoundMode::Ceiling => scaled.ceil(),
        RoundMode::Floor => scaled.floor(),
        RoundMode::HalfUp => scaled.round(),
        RoundMode::HalfDown => round_half_down(scaled),
        RoundMode::HalfEven => round_half_even(scaled),
    };
    rounded / scale
}

/// Round to nearest with ties toward zero (`HALF_DOWN`).
fn round_half_down(scaled: f64) -> f64 {
    let magnitude = scaled.abs();
    let floor = magnitude.floor();
    let rounded = if magnitude - floor > 0.5 {
        floor + 1.0
    } else {
        floor
    };
    rounded.copysign(scaled)
}

/// Round to nearest with ties to the even neighbour (`HALF_EVEN`, banker's rounding).
fn round_half_even(scaled: f64) -> f64 {
    let floor = scaled.floor();
    let frac = scaled - floor;
    if frac < 0.5 {
        floor
    } else if frac > 0.5 {
        floor + 1.0
    } else if floor % 2.0 == 0.0 {
        floor
    } else {
        floor + 1.0
    }
}

/// `round(value[, precision[, mode]])` (Neo4j 5.x). A null value / precision / mode propagates to
/// `null`; a non-numeric value or precision, or an unknown mode string, is a runtime error.
fn round_fn(argv: &[Value]) -> Result<Value, EvalError> {
    let x = match arg(argv, 0, "round")? {
        Value::Integer(i) => *i as f64,
        Value::Float(f) => *f,
        Value::Null => return Ok(Value::Null),
        _ => return Err(num_type_error("round")),
    };
    if argv.len() < 2 {
        return Ok(Value::Float(default_round(x, 0)));
    }
    let precision = match arg(argv, 1, "round")? {
        Value::Integer(i) => *i,
        // Neo4j accepts a FLOAT precision; truncate it toward zero to a whole number of places.
        Value::Float(f) => *f as i64,
        Value::Null => return Ok(Value::Null),
        _ => {
            return Err(EvalError::TypeError {
                context: "round() precision must be a number".to_owned(),
            });
        }
    };
    if argv.len() < 3 {
        return Ok(Value::Float(default_round(x, precision)));
    }
    let mode = match arg(argv, 2, "round")? {
        Value::String(s) => RoundMode::parse(s)?,
        Value::Null => return Ok(Value::Null),
        _ => {
            return Err(EvalError::TypeError {
                context: "round() rounding mode must be a string".to_owned(),
            });
        }
    };
    Ok(Value::Float(mode_round(x, precision, mode)))
}

// =================================================================================================
// Additional scalar / list functions (Neo4j 5.x; rmp #630)
// =================================================================================================

/// The STRING element id for an entity whose internal handle is `id` — the decimal of the handle
/// cast to `i64`, byte-for-byte identical to the Bolt/REST wire element id
/// (`graphus_bolt::packstream::element_id`, which stringifies the same `i64::try_from`ed handle). A
/// single-instance convention (`04 §8.3`): a driver treats it as an opaque string.
fn wire_element_id(id: u64) -> String {
    i64::try_from(id).unwrap_or(i64::MAX).to_string()
}

/// `isEmpty(list | map | string)` (Neo4j 5.x): whether a collection or string has no elements. A
/// null argument yields `null`; any other type is a runtime `TypeError`.
fn is_empty_value(rv: &RowValue) -> Result<Value, EvalError> {
    let empty = match rv {
        RowValue::Value(Value::Null) => return Ok(Value::Null),
        RowValue::List(items) => items.is_empty(),
        RowValue::Map(entries) => entries.is_empty(),
        RowValue::Value(Value::List(items)) => items.is_empty(),
        RowValue::Value(Value::Map(entries)) => entries.is_empty(),
        RowValue::Value(Value::String(s)) => s.is_empty(),
        _ => {
            return Err(EvalError::TypeError {
                context: "isEmpty() requires a list, map or string".to_owned(),
            });
        }
    };
    Ok(Value::Boolean(empty))
}

/// Whether two arguments of `nullIf(a, b)` are **equivalent** (Neo4j 5.x / SQL `NULLIF`): a
/// node/relationship pair by identity, everything else by Cypher value equality (only a definite
/// `TRUE` equality counts — an unknown/`null` comparison is *not* equivalent, so `nullIf` returns
/// `a`). Entities compared against non-entities are never equivalent.
fn row_values_equivalent_for_nullif(a: &RowValue, b: &RowValue) -> bool {
    match (a, b) {
        (RowValue::Node(x), RowValue::Node(y)) => x.id == y.id,
        (RowValue::Rel(x), RowValue::Rel(y)) => x.id == y.id,
        (RowValue::Node(_) | RowValue::Rel(_), _) | (_, RowValue::Node(_) | RowValue::Rel(_)) => {
            false
        }
        _ => equals(&to_value(a.clone()), &to_value(b.clone())).is_true(),
    }
}

/// `toIntegerList` / `toFloatList` / `toBooleanList` / `toStringList` (Neo4j 5.x): apply the matching
/// `*OrNull` conversion to every element (a non-convertible or null element becomes `null`). A null
/// input list yields `null`; a non-list argument is a runtime `TypeError`.
fn to_typed_list(lower: &str, rv: RowValue) -> Result<Value, EvalError> {
    let elem_conv = match lower {
        "tointegerlist" => "tointegerornull",
        "tofloatlist" => "tofloatornull",
        "tobooleanlist" => "tobooleanornull",
        "tostringlist" => "tostringornull",
        // Unreachable: the caller dispatches only the four list-conversion spellings.
        _ => {
            return Err(EvalError::TypeError {
                context: format!("{lower}() is not a list conversion"),
            });
        }
    };
    if rv.is_null() {
        return Ok(Value::Null);
    }
    let Some(elems) = rv.as_list_elems() else {
        return Err(EvalError::TypeError {
            context: format!("{lower}() requires a list"),
        });
    };
    check_list_len_budget(elems.len(), lower)?;
    let mut out = Vec::with_capacity(elems.len());
    for e in elems {
        // The `*OrNull` conversions never raise, so this collects one `Value` per input element.
        out.push(convert_scalar(elem_conv, e)?);
    }
    Ok(Value::List(out))
}

/// `valueType(v)` (Neo4j 5.x): the STRING name of the most precise Cypher type of `v`. A concrete
/// value is `"<TYPE> NOT NULL"` (the value is non-null); the null value is the lower-case `"null"`.
///
/// # Fidelity note
/// The scalar, temporal, spatial, node/relationship/path/map and **homogeneous** / nested /
/// nullable-element / empty list forms match Neo4j 5.13+ exactly (including the `NOT NULL` suffixes,
/// the space-separated temporal names, `LIST<NOTHING>` for `[]`, and a nullable element type when a
/// `null` is present). For a **heterogeneous** list Neo4j emits a normalized union whose exact member
/// ordering is not publicly specified; this implementation emits a deterministic (lexicographically
/// ordered) union — a documented best-effort for that rare case.
fn value_type_string(rv: &RowValue) -> String {
    if rv.is_null() {
        return "null".to_owned();
    }
    format!("{} NOT NULL", value_type_body(rv))
}

/// The type name of a **non-null** value without a trailing nullability marker — the reusable body of
/// [`value_type_string`], also used as a union member when describing list element types.
fn value_type_body(rv: &RowValue) -> String {
    match rv {
        RowValue::Node(_) => "NODE".to_owned(),
        RowValue::Rel(_) => "RELATIONSHIP".to_owned(),
        RowValue::Path(_) => "PATH".to_owned(),
        RowValue::Map(_) => "MAP".to_owned(),
        RowValue::List(items) => format!("LIST<{}>", list_element_type(items)),
        RowValue::Value(v) => value_type_body_value(v),
    }
}

/// The type-name body for a property [`Value`] (see [`value_type_body`]).
fn value_type_body_value(v: &Value) -> String {
    match v {
        // `NULL` only reaches here as a list element (a top-level null is handled by
        // `value_type_string`); as a union member it marks the element type nullable.
        Value::Null => "NULL".to_owned(),
        Value::Boolean(_) => "BOOLEAN".to_owned(),
        Value::Integer(_) => "INTEGER".to_owned(),
        Value::Float(_) => "FLOAT".to_owned(),
        Value::String(_) => "STRING".to_owned(),
        // Graphus models a byte string as a list of byte-valued integers; Neo4j has no distinct
        // `valueType` name for raw byte arrays, so this reports the equivalent list type.
        Value::Bytes(_) => "LIST<INTEGER NOT NULL>".to_owned(),
        Value::List(items) => {
            let elems: Vec<RowValue> = items.iter().cloned().map(RowValue::Value).collect();
            format!("LIST<{}>", list_element_type(&elems))
        }
        Value::Map(_) => "MAP".to_owned(),
        Value::Date(_) => "DATE".to_owned(),
        Value::LocalTime(_) => "LOCAL TIME".to_owned(),
        Value::ZonedTime(_) => "ZONED TIME".to_owned(),
        Value::LocalDateTime(_) => "LOCAL DATETIME".to_owned(),
        Value::ZonedDateTime(_) => "ZONED DATETIME".to_owned(),
        Value::Duration(_) => "DURATION".to_owned(),
        Value::Point(_) => "POINT".to_owned(),
    }
}

/// The normalized element type of a list for [`value_type_string`]: `NOTHING` for the empty list, a
/// single `T NOT NULL` (or nullable `T` when a `null` element is present), or a deterministic union
/// of the distinct member types when the list is heterogeneous.
fn list_element_type(elems: &[RowValue]) -> String {
    if elems.is_empty() {
        return "NOTHING".to_owned();
    }
    let mut members: Vec<String> = Vec::new();
    let mut has_null = false;
    for e in elems {
        if e.is_null() {
            has_null = true;
        } else {
            let body = value_type_body(e);
            if !members.contains(&body) {
                members.push(body);
            }
        }
    }
    members.sort();
    match (members.len(), has_null) {
        // Every element was null: the element type is `NULL`.
        (0, _) => "NULL".to_owned(),
        // A single concrete type: `NOT NULL` unless a null element made it nullable.
        (1, false) => format!("{} NOT NULL", members[0]),
        (1, true) => members.into_iter().next().unwrap_or_default(),
        // A union of distinct types; each member carries its own nullability marker.
        (_, false) => members
            .iter()
            .map(|m| format!("{m} NOT NULL"))
            .collect::<Vec<_>>()
            .join(" | "),
        (_, true) => members.join(" | "),
    }
}

/// One `xorshift64*` step of the thread-local `rand()` state, returning the full 64-bit mixed draw.
/// Shares the exact generator [`next_rand_f64`] scales, so `rand()` and `randomUUID()` advance the
/// same per-thread stream (no extra state, no lock, no `unsafe`).
fn next_rand_u64() -> u64 {
    RAND_STATE.with(|cell| {
        let mut x = cell.get();
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        cell.set(x);
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    })
}

/// `randomUUID()` (Neo4j 5.x): a random version-4 UUID (RFC 4122) as the canonical 36-character
/// lower-case `8-4-4-4-12` hex string. Two 64-bit draws supply the 128 bits; the version nibble
/// (`4`) and the two variant bits (`10`) are set per the spec, so the output is a well-formed v4 UUID.
fn random_uuid_string() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&next_rand_u64().to_le_bytes());
    bytes[8..].copy_from_slice(&next_rand_u64().to_le_bytes());
    // Version 4 (random) in the high nibble of byte 6; RFC 4122 variant (10xx) in byte 8.
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    let mut s = String::with_capacity(36);
    for (i, b) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

fn string_unary(v: &Value, f: impl Fn(&str) -> String, fname: &str) -> Result<Value, EvalError> {
    match v {
        Value::String(s) => Ok(Value::String(f(s))),
        Value::Null => Ok(Value::Null),
        _ => Err(EvalError::TypeError {
            context: format!("{fname}() requires a string"),
        }),
    }
}

/// `btrim(input [, trimCharacterString])` (Neo4j 5.x): trims from **both** ends. Without the second
/// argument all leading/trailing whitespace is removed (like `trim`); with it, any leading/trailing
/// run of characters drawn from the **set** `trimCharacterString` is removed (PostgreSQL/Neo4j
/// `btrim` semantics — a character set, not a substring). A `null` in either argument position
/// yields `null`; a non-string argument is a runtime [`EvalError::TypeError`]. `btrim` can only
/// shrink the string, so no per-value budget guard is needed.
fn btrim_fn(argv: &[Value]) -> Result<Value, EvalError> {
    let s = match arg(argv, 0, "btrim")? {
        Value::Null => return Ok(Value::Null),
        Value::String(s) => s,
        _ => {
            return Err(EvalError::TypeError {
                context: "btrim() requires a string".to_owned(),
            });
        }
    };
    match argv.get(1) {
        None => Ok(Value::String(s.trim().to_owned())),
        // A null trim set propagates null.
        Some(Value::Null) => Ok(Value::Null),
        Some(Value::String(set)) => {
            if set.is_empty() {
                // An empty character set trims nothing.
                return Ok(Value::String(s.clone()));
            }
            // `str::contains(char)` tests membership of `c` in the trim-character set.
            Ok(Value::String(
                s.trim_matches(|c: char| set.contains(c)).to_owned(),
            ))
        }
        Some(_) => Err(EvalError::TypeError {
            context: "btrim() trimCharacterString must be a string".to_owned(),
        }),
    }
}

/// `normalize(input [, normalForm])` (Neo4j 5.x): Unicode normalization to NFC/NFD/NFKC/NFKD
/// (default NFC). `null` input — or an explicit null form — yields `null`; a non-string input is a
/// runtime [`EvalError::TypeError`].
///
/// # The form argument
///
/// In Neo4j the second argument is a bare *keyword* (`NFC`/`NFD`/`NFKC`/`NFKD`). Graphus accepts it
/// as a **case-insensitive string** (`normalize(s, 'NFKC')`): the keyword spelling would need parser
/// support (a separate concern), while the single-argument default-`NFC` form matches Neo4j exactly.
/// An unrecognised form string is a runtime type error.
fn normalize_fn(argv: &[Value]) -> Result<Value, EvalError> {
    let s = match arg(argv, 0, "normalize")? {
        Value::Null => return Ok(Value::Null),
        Value::String(s) => s,
        _ => {
            return Err(EvalError::TypeError {
                context: "normalize() requires a string".to_owned(),
            });
        }
    };
    let form = match argv.get(1) {
        None => NormalForm::Nfc,
        Some(Value::Null) => return Ok(Value::Null),
        Some(Value::String(f)) => parse_normal_form(f)?,
        Some(_) => {
            return Err(EvalError::TypeError {
                context: "normalize() normalization form must be a string".to_owned(),
            });
        }
    };
    normalized_string(s, form).map(Value::String)
}

/// Maps a case-insensitive form name (`"NFC"`/`"NFD"`/`"NFKC"`/`"NFKD"`) to a [`NormalForm`].
fn parse_normal_form(name: &str) -> Result<NormalForm, EvalError> {
    match name.to_ascii_uppercase().as_str() {
        "NFC" => Ok(NormalForm::Nfc),
        "NFD" => Ok(NormalForm::Nfd),
        "NFKC" => Ok(NormalForm::Nfkc),
        "NFKD" => Ok(NormalForm::Nfkd),
        other => Err(EvalError::TypeError {
            context: format!(
                "normalize() unknown normalization form {other:?}; expected NFC, NFD, NFKC or NFKD"
            ),
        }),
    }
}

/// Normalizes `s` to `form`, guarding the output against the per-value byte budget (`SEC-191`,
/// CWE-770 / CWE-789): compatibility decomposition (NFKD/NFKC) can **expand** the byte length (a
/// ligature or compatibility character maps to several code points), so an attacker could amplify a
/// near-budget string. The output byte length is computed exactly by walking the normalization
/// iterator (no result allocation), rejected if over budget, and only then collected.
fn normalized_string(s: &str, form: NormalForm) -> Result<String, EvalError> {
    use unicode_normalization::UnicodeNormalization;
    let out_len: usize = match form {
        NormalForm::Nfc => s.nfc().map(char::len_utf8).sum(),
        NormalForm::Nfd => s.nfd().map(char::len_utf8).sum(),
        NormalForm::Nfkc => s.nfkc().map(char::len_utf8).sum(),
        NormalForm::Nfkd => s.nfkd().map(char::len_utf8).sum(),
    };
    let limit = crate::value_size::max_value_bytes();
    if out_len > limit {
        return Err(EvalError::ResourceLimit {
            detail: format!(
                "normalize() would produce a {out_len}-byte string (limit {limit} bytes per value)"
            ),
        });
    }
    Ok(match form {
        NormalForm::Nfc => s.nfc().collect(),
        NormalForm::Nfd => s.nfd().collect(),
        NormalForm::Nfkc => s.nfkc().collect(),
        NormalForm::Nfkd => s.nfkd().collect(),
    })
}

/// `toUpper`/`toLower` with a per-value budget guard (`SEC-191`, CWE-770 / CWE-789). Unlike
/// trim/ltrim/rtrim (which can only shrink), Unicode case mapping can **expand** the byte length —
/// e.g. `U+0390` (2 B) uppercases to three code points (6 B). An attacker can therefore amplify a
/// near-budget string past the budget. We compute the mapped output byte length **exactly** by walking
/// the case-mapping iterator (no allocation of the result), reject with [`EvalError::ResourceLimit`] if
/// it would exceed the budget, and only then build the `String`. The exact walk (rather than a
/// conservative `×3` factor) is future-proof against Unicode case-mapping changes and never
/// false-rejects a non-expanding input.
fn string_case(v: &Value, upper: bool, fname: &str) -> Result<Value, EvalError> {
    match v {
        Value::String(s) => {
            let out_len: usize = if upper {
                s.chars()
                    .flat_map(char::to_uppercase)
                    .map(char::len_utf8)
                    .sum()
            } else {
                s.chars()
                    .flat_map(char::to_lowercase)
                    .map(char::len_utf8)
                    .sum()
            };
            let limit = crate::value_size::max_value_bytes();
            if out_len > limit {
                return Err(EvalError::ResourceLimit {
                    detail: format!(
                        "{fname}() would produce a {out_len}-byte string (limit {limit} bytes per value)"
                    ),
                });
            }
            Ok(Value::String(if upper {
                s.to_uppercase()
            } else {
                s.to_lowercase()
            }))
        }
        Value::Null => Ok(Value::Null),
        _ => Err(EvalError::TypeError {
            context: format!("{fname}() requires a string"),
        }),
    }
}

/// `range(start, end[, step])` — an inclusive integer range (openCypher).
///
/// The byte budget a single materialised `range()` list may occupy (`SEC-191`, CWE-770/789). The
/// previous element ceiling (`1 << 30`) capped the element *count* but not the *memory*: at
/// `size_of::<Value>()` (~40 bytes) per element it admitted a ~40 GiB single allocation, an OOM
/// vector on any normal host. We instead cap the **memory**: 256 MiB is a generous list yet stays
/// far below any sane RAM budget, and the element ceiling is derived from it so the count guard and
/// the memory it implies can never diverge again.
const MAX_RANGE_BYTES: i128 = 256 * 1024 * 1024;

/// The largest number of elements `range()` may materialise, derived from [`MAX_RANGE_BYTES`] and
/// the in-memory size of one element. Computed at runtime (not as an associated const) because
/// `size_of` in a `const` context with `i128` arithmetic is awkward; the division is trivial.
fn max_range_elements() -> i128 {
    let elem = core::mem::size_of::<Value>() as i128;
    // `elem` is always > 0 (a `Value` is never zero-sized); guard anyway so the division is total.
    MAX_RANGE_BYTES / elem.max(1)
}

fn range_fn(argv: &[Value]) -> Result<Value, EvalError> {
    let int = |v: &Value| match v {
        Value::Integer(i) => Ok(*i),
        _ => Err(EvalError::TypeError {
            context: "range() requires integer arguments".to_owned(),
        }),
    };
    let start = int(arg(argv, 0, "range")?)?;
    let end = int(arg(argv, 1, "range")?)?;
    let step = if argv.len() > 2 { int(&argv[2])? } else { 1 };
    if step == 0 {
        // A zero step is a runtime `ArgumentError`/`NumberOutOfRange` (the step is out of its valid
        // range of non-zero integers), not a `TypeError`
        // (`expressions/list/List11.feature` [4]: `range(<start>, <end>, 0)`).
        return Err(EvalError::NumberOutOfRange {
            value: "range() step 0".to_owned(),
        });
    }
    // Reject ranges that would materialise more elements than the server will hold, before
    // allocating anything: `range(1, 9_000_000_000_000_000_000)` would otherwise OOM the process.
    // The count is computed with `i128` so the span itself never overflows.
    let count: i128 = if (step > 0 && start <= end) || (step < 0 && start >= end) {
        let span = (i128::from(end) - i128::from(start)).abs();
        span / i128::from(step).abs() + 1
    } else {
        0
    };
    let limit = max_range_elements();
    if count > limit {
        return Err(EvalError::ResourceLimit {
            detail: format!(
                "range() would produce {count} elements (limit {limit}, a {MAX_RANGE_BYTES}-byte \
                 materialisation budget)"
            ),
        });
    }
    let mut out = Vec::with_capacity(count as usize);
    let mut cur = start;
    if step > 0 {
        while cur <= end {
            out.push(Value::Integer(cur));
            match cur.checked_add(step) {
                Some(n) => cur = n,
                None => break,
            }
        }
    } else {
        while cur >= end {
            out.push(Value::Integer(cur));
            match cur.checked_add(step) {
                Some(n) => cur = n,
                None => break,
            }
        }
    }
    Ok(Value::List(out))
}

/// `substring(s, start[, length])` over Unicode scalar values (chars), clamped (openCypher).
fn substring_fn(argv: &[Value]) -> Result<Value, EvalError> {
    let a0 = arg(argv, 0, "substring")?;
    let Value::String(s) = a0 else {
        return match a0 {
            Value::Null => Ok(Value::Null),
            _ => Err(EvalError::TypeError {
                context: "substring() requires a string".to_owned(),
            }),
        };
    };
    let chars: Vec<char> = s.chars().collect();
    let start = match arg(argv, 1, "substring")? {
        Value::Integer(i) => (*i).max(0) as usize,
        _ => {
            return Err(EvalError::TypeError {
                context: "substring() start must be an integer".to_owned(),
            });
        }
    };
    let start = start.min(chars.len());
    let end = if argv.len() > 2 {
        match &argv[2] {
            Value::Integer(len) => start
                .saturating_add((*len).max(0) as usize)
                .min(chars.len()),
            _ => {
                return Err(EvalError::TypeError {
                    context: "substring() length must be an integer".to_owned(),
                });
            }
        }
    } else {
        chars.len()
    };
    Ok(Value::String(chars[start..end].iter().collect()))
}

/// `replace(s, search, replacement)` (openCypher).
fn replace_fn(argv: &[Value]) -> Result<Value, EvalError> {
    match (
        arg(argv, 0, "replace")?,
        arg(argv, 1, "replace")?,
        arg(argv, 2, "replace")?,
    ) {
        (Value::String(s), Value::String(search), Value::String(rep)) => {
            // `replace` is an **expanding** builder: replacing a short pattern with a long replacement
            // grows the result without bound (e.g. `replace(s, "a", <huge>)`). Reject a result that
            // would exceed the per-value budget BEFORE `String::replace` allocates it (`SEC-191`).
            let bound = replace_result_len_bound(s, search, rep);
            let limit = crate::value_size::max_value_bytes();
            if bound > limit {
                return Err(EvalError::ResourceLimit {
                    detail: format!(
                        "replace() would produce up to {bound} bytes (limit {limit} bytes per value)"
                    ),
                });
            }
            Ok(Value::String(s.replace(search.as_str(), rep)))
        }
        (Value::Null, _, _) | (_, Value::Null, _) | (_, _, Value::Null) => Ok(Value::Null),
        _ => Err(EvalError::TypeError {
            context: "replace() requires string arguments".to_owned(),
        }),
    }
}

/// An `O(1)` upper bound (in bytes) on the length of `s.replace(search, rep)`, computed **without**
/// scanning `s`, so `replace` can be rejected before it allocates an over-budget result.
///
/// When `rep` is no longer than `search` the result can never grow past `s.len()`. Otherwise each
/// non-overlapping occurrence adds `rep.len() - search.len()` bytes; the count of occurrences is at
/// most `s.len() / search.len()` (each consumes at least `search.len()` bytes), or `s.len() + 1`
/// insertion points for the empty pattern (`"abc".replace("", x)` == `"xaxbxcx"`). Using these upper
/// bounds keeps the estimate conservative (it can only over-count, which only tightens the budget —
/// the safe direction) and `O(1)`.
fn replace_result_len_bound(s: &str, search: &str, rep: &str) -> usize {
    if rep.len() <= search.len() {
        return s.len();
    }
    let per_occurrence = rep.len() - search.len();
    let occurrences = if search.is_empty() {
        s.len().saturating_add(1)
    } else {
        s.len() / search.len()
    };
    s.len()
        .saturating_add(occurrences.saturating_mul(per_occurrence))
}

/// `split(s, delimiter)` (openCypher).
fn split_fn(argv: &[Value]) -> Result<Value, EvalError> {
    match (arg(argv, 0, "split")?, arg(argv, 1, "split")?) {
        (Value::String(s), Value::String(delim)) => {
            // `split` is a list-producing builder: it materialises one `Value::String` per part, so a
            // char-wise split (empty delimiter) or a dense single-byte delimiter amplifies a bounded
            // input string into one `Value` slot per character — bypassing the per-value budget unless
            // guarded (`SEC-191`, CWE-770 / CWE-789; the exact gap #481's neighbour `replace` already
            // closes). Count the parts EXACTLY (one cheap O(|s|) pass, no allocation) and reject before
            // `.collect()` if the result list would exceed the budget. The exact count (not a loose
            // `|s|/|delim|` upper bound) avoids falsely rejecting a split whose delimiter is sparse or
            // absent — that legitimately yields few parts.
            let part_count = if delim.is_empty() {
                s.chars().count()
            } else {
                s.matches(delim.as_str()).count() + 1
            };
            check_list_len_budget(part_count, "split()")?;
            let parts: Vec<Value> = if delim.is_empty() {
                s.chars().map(|c| Value::String(c.to_string())).collect()
            } else {
                s.split(delim.as_str())
                    .map(|p| Value::String(p.to_owned()))
                    .collect()
            };
            Ok(Value::List(parts))
        }
        (Value::Null, _) | (_, Value::Null) => Ok(Value::Null),
        _ => Err(EvalError::TypeError {
            context: "split() requires string arguments".to_owned(),
        }),
    }
}

/// `left(s, n)` / `right(s, n)` (openCypher).
fn left_right_fn(argv: &[Value], left: bool) -> Result<Value, EvalError> {
    let fname = if left { "left" } else { "right" };
    match (arg(argv, 0, fname)?, arg(argv, 1, fname)?) {
        (Value::String(s), Value::Integer(n)) => {
            let chars: Vec<char> = s.chars().collect();
            let n = (*n).max(0) as usize;
            let take = n.min(chars.len());
            let slice: String = if left {
                chars[..take].iter().collect()
            } else {
                chars[chars.len() - take..].iter().collect()
            };
            Ok(Value::String(slice))
        }
        (Value::Null, _) => Ok(Value::Null),
        _ => Err(EvalError::TypeError {
            context: "left()/right() require (string, integer)".to_owned(),
        }),
    }
}

// =================================================================================================
// Comprehensions, quantifiers and existential subqueries (expression-level sub-scopes)
// =================================================================================================

/// Evaluates a list comprehension `[x IN list WHERE p | e]`: iterate the list with `x` bound,
/// keep elements whose predicate is `TRUE` (3VL — `NULL` excludes, like `WHERE`), and project each
/// kept element (or the element itself in the filter-only form). A `null` list yields `null`.
fn eval_list_comprehension(
    lc: &crate::ast::ListComprehension,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    let items = eval_to_list_items(
        &lc.list,
        "list comprehension",
        row,
        params,
        graph,
        functions,
        clock,
    )?;
    let Some(items) = items else {
        return Ok(RowValue::NULL);
    };
    let mut out = Vec::new();
    let mut out_bytes: usize = 0;
    for item in items {
        let inner = row.with(lc.variable.name.clone(), item.clone());
        if let Some(pred) = &lc.predicate {
            if !eval_to_ternary(pred, &inner, params, graph, functions, clock)?.is_true() {
                continue;
            }
        }
        let elem = match &lc.projection {
            Some(proj) => eval(proj, &inner, params, graph, functions, clock)?,
            None => item,
        };
        accumulate_list_bytes(&mut out_bytes, &elem, "list comprehension")?;
        out.push(elem);
    }
    Ok(RowValue::list(out))
}

/// Adds the estimated byte cost of `elem` to a streaming list builder's running `bytes` total and
/// rejects once the accumulated list would exceed the per-value budget
/// ([`MAX_VALUE_BYTES`](crate::value_size::MAX_VALUE_BYTES)) — the guard a list / pattern
/// comprehension applies as it appends each projected element (`SEC-191`, CWE-770 / CWE-789). Walks
/// only the **new** element (amortised `O(1)`), never re-walking the accumulated list, and rejects
/// before the over-budget element is retained.
///
/// # Errors
/// [`EvalError::ResourceLimit`] once the running total exceeds the budget.
fn accumulate_list_bytes(bytes: &mut usize, elem: &RowValue, what: &str) -> Result<(), EvalError> {
    *bytes = bytes.saturating_add(crate::value_size::estimate_rowvalue_bytes(elem));
    let limit = crate::value_size::max_value_bytes();
    if *bytes > limit {
        return Err(EvalError::ResourceLimit {
            detail: format!("{what} exceeds the {limit}-byte value limit"),
        });
    }
    Ok(())
}

/// Rejects a list-producing builtin whose element **count** alone would exceed the per-value budget
/// (`SEC-191`, CWE-770 / CWE-789) — the `O(1)` guard the one-shot `.collect()` builders (`split`,
/// `keys`, `LOAD CSV` records) apply *before* allocating. The backing `Vec<Value>` owns `count` slots
/// of `size_of::<Value>()` bytes each, so a build of more than
/// [`max_list_elements`](crate::value_size::max_list_elements) elements exceeds the budget regardless
/// of element content. This mirrors `range()`'s element ceiling and `replace`'s pre-allocation bound:
/// the budget the streaming builders enforce per element is enforced here on the known final count, so
/// an amplifying builtin can no longer turn a bounded input into an unbounded materialised value.
///
/// # Errors
/// [`EvalError::ResourceLimit`] when `count` exceeds the per-value element ceiling.
fn check_list_len_budget(count: usize, what: &str) -> Result<(), EvalError> {
    let limit = crate::value_size::max_list_elements();
    if count > limit {
        return Err(EvalError::ResourceLimit {
            detail: format!("{what} would produce {count} elements (limit {limit} per value)"),
        });
    }
    Ok(())
}

/// Evaluates a comprehension/quantifier **source list** to its elements at the [`RowValue`] level,
/// so structural lists (`nodes(p)`, `collect(n)`, …) iterate with their entities intact. `None`
/// stands for a `null` source (the comprehension/quantifier is then `null` overall).
fn eval_to_list_items(
    list: &Expr,
    what: &str,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> Result<Option<Vec<RowValue>>, EvalError> {
    let v = eval(list, row, params, graph, functions, clock)?;
    if v.is_null() {
        return Ok(None);
    }
    match v.as_list_elems() {
        Some(items) => Ok(Some(items)),
        None => Err(EvalError::TypeError {
            context: format!("{what} requires a list, got {}", describe(&v)),
        }),
    }
}

/// Evaluates a quantifier `all/any/none/single(x IN list WHERE p)` under Kleene 3VL with
/// short-circuiting. A `null` list yields `null`; a `null` predicate outcome leaves the overall
/// result unknown unless a definite element already decided it.
fn eval_quantifier(
    q: &crate::ast::QuantifierExpr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    use crate::ast::QuantifierKind;
    let items = eval_to_list_items(&q.list, "quantifier", row, params, graph, functions, clock)?;
    let Some(items) = items else {
        return Ok(RowValue::NULL);
    };
    let yes = || Ok(RowValue::Value(Value::Boolean(true)));
    let no = || Ok(RowValue::Value(Value::Boolean(false)));
    let mut trues = 0usize;
    let mut nulls = 0usize;
    for item in items {
        let inner = row.with(q.variable.name.clone(), item);
        match eval_to_ternary(&q.predicate, &inner, params, graph, functions, clock)? {
            Ternary::True => match q.kind {
                // One satisfied element decides ANY (true) and NONE (false) outright.
                QuantifierKind::Any => return yes(),
                QuantifierKind::None => return no(),
                QuantifierKind::All => {}
                QuantifierKind::Single => {
                    trues += 1;
                    if trues > 1 {
                        return no();
                    }
                }
            },
            // One failed element decides ALL outright.
            Ternary::False => {
                if q.kind == QuantifierKind::All {
                    return no();
                }
            }
            Ternary::Null => nulls += 1,
        }
    }
    // End of list: any unknown element leaves the undecided quantifiers unknown.
    match q.kind {
        QuantifierKind::All | QuantifierKind::None => {
            if nulls > 0 {
                Ok(RowValue::NULL)
            } else {
                yes()
            }
        }
        QuantifierKind::Any => {
            if nulls > 0 {
                Ok(RowValue::NULL)
            } else {
                no()
            }
        }
        QuantifierKind::Single => {
            // An unknown element could be the (second) satisfying one, so any null leaves the
            // result unknown; otherwise exactly-one decides.
            if nulls > 0 {
                Ok(RowValue::NULL)
            } else {
                Ok(RowValue::Value(Value::Boolean(trues == 1)))
            }
        }
    }
}

/// Evaluates a `reduce(acc = init, x IN list | body)` list fold. The list is evaluated first so a
/// `null` list short-circuits to `null` (Cypher null-propagation) without evaluating `init`; an empty
/// list returns `init`. Otherwise it is a left fold: `acc` starts at `init` and, for each element,
/// `body` is re-evaluated with `acc` and `x` bound, its result becoming the new `acc`; the final
/// `acc` is returned. `acc` and `x` are local to `body` (they never leak into the outer row).
fn eval_reduce(
    r: &crate::ast::ReduceExpr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    // A `null` source yields `null`; a non-list, non-null source is a type error (mirrors the
    // comprehension / quantifier source rule). Evaluated before `init` so a `null` list never forces
    // `init` evaluation.
    let items = eval_to_list_items(&r.list, "reduce", row, params, graph, functions, clock)?;
    let Some(items) = items else {
        return Ok(RowValue::NULL);
    };
    // `init` is evaluated in the enclosing scope (the accumulator / element are not yet bound); for an
    // empty list this value is the result.
    let mut acc = eval(&r.init, row, params, graph, functions, clock)?;
    for item in items {
        let inner = row
            .with(r.accumulator.name.clone(), acc)
            .with(r.variable.name.clone(), item);
        acc = eval(&r.body, &inner, params, graph, functions, clock)?;
    }
    Ok(acc)
}

/// Evaluates a map projection `entity { .prop, .*, key: expr, var }` into a map. A `null` entity
/// makes the whole projection `null`. The `.*` all-properties selector is applied **first**
/// (mirroring Neo4j's `includeAllProps` flag), then the property / literal / variable selectors in
/// source order — a later selector with a key already present **overrides** it (so an explicit
/// `key: …` wins over a `.*` property of the same name). Works over nodes, relationships and maps.
fn eval_map_projection(
    mp: &crate::ast::MapProjection,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    let entity = eval(&mp.entity, row, params, graph, functions, clock)?;
    if entity.is_null() {
        return Ok(RowValue::NULL);
    }
    let mut out: Vec<(String, RowValue)> = Vec::new();
    let mut out_bytes: usize = 0;
    // Pass 1 — the all-properties selector `.*`, applied first regardless of its textual position,
    // exactly as Neo4j applies `includeAllProps` before the individual entries.
    if mp
        .selectors
        .iter()
        .any(|s| matches!(s, MapProjectionSelector::AllProperties))
    {
        for (k, v) in all_properties_entries(&entity, graph)? {
            upsert_projection(&mut out, &mut out_bytes, k, v)?;
        }
    }
    // Pass 2 — the property / literal / variable selectors, in source order (last write wins on a key
    // already produced, including one added by `.*`).
    for sel in &mp.selectors {
        match sel {
            MapProjectionSelector::AllProperties => {}
            MapProjectionSelector::Property(key) => {
                let value = property_of(&entity, key, graph)?;
                upsert_projection(&mut out, &mut out_bytes, key.clone(), value)?;
            }
            MapProjectionSelector::Entry { key, value } => {
                let v = eval(value, row, params, graph, functions, clock)?;
                upsert_projection(&mut out, &mut out_bytes, key.name.clone(), v)?;
            }
        }
    }
    Ok(RowValue::map(out))
}

/// All properties of an evaluated `base` (node / relationship / map) as `(key, value)` entries, for
/// the `.*` map-projection selector. A non-entity, non-map `base` contributes nothing (Neo4j only
/// permits node/relationship/map here; `null` is already short-circuited by the caller). The entry
/// count is bounded against the per-value budget (`SEC-191`, CWE-770 / CWE-789), like `properties()`.
///
/// # Errors
/// [`EvalError::ResourceLimit`] when the property count exceeds the per-value element ceiling.
fn all_properties_entries(
    base: &RowValue,
    graph: &dyn GraphAccess,
) -> Result<Vec<(String, RowValue)>, EvalError> {
    let entries = match base {
        RowValue::Node(NodeRef { id }) => graph
            .node_properties(*id)
            .map(props_to_rowvalues)
            .unwrap_or_default(),
        RowValue::Rel(RelRef { id }) => graph
            .rel_properties(*id)
            .map(props_to_rowvalues)
            .unwrap_or_default(),
        RowValue::Value(Value::Map(entries)) => props_to_rowvalues(entries.clone()),
        RowValue::Map(entries) => entries.clone(),
        _ => Vec::new(),
    };
    check_list_len_budget(entries.len(), "map projection '.*'")?;
    Ok(entries)
}

/// Lifts a property list into `RowValue` entries (each value wrapped as [`RowValue::Value`]).
fn props_to_rowvalues(props: Vec<(String, Value)>) -> Vec<(String, RowValue)> {
    props
        .into_iter()
        .map(|(k, v)| (k, RowValue::Value(v)))
        .collect()
}

/// Inserts `(key, value)` into a map-projection builder with **last-wins** semantics (replacing the
/// value of a key already present, otherwise appending), and charges the key + value against the
/// per-value budget as it grows (`SEC-191`). The budget total is a monotonic upper bound: an override
/// re-charges the key, which only ever rejects earlier — the safe direction.
///
/// # Errors
/// [`EvalError::ResourceLimit`] once the running total exceeds the per-value budget.
fn upsert_projection(
    out: &mut Vec<(String, RowValue)>,
    bytes: &mut usize,
    key: String,
    value: RowValue,
) -> Result<(), EvalError> {
    *bytes = bytes.saturating_add(key.len());
    accumulate_list_bytes(bytes, &value, "map projection")?;
    if let Some(slot) = out.iter_mut().find(|(k, _)| *k == key) {
        slot.1 = value;
    } else {
        out.push((key, value));
    }
    Ok(())
}

/// Evaluates a pattern comprehension `[(a)-[r]->(b) WHERE p | e]`: match the pattern seeded by the
/// outer row's bindings, filter by the predicate (3VL), and project each match into the list.
fn eval_pattern_comprehension(
    pc: &crate::ast::PatternComprehension,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    // A named path (`[p = (a)-->(b) | p]`) binds the path variable for the predicate/projection.
    let path_var = pc.var.as_ref().map(|v| v.name.as_str());
    let matches = pattern_element_rows(
        &pc.element,
        row,
        params,
        graph,
        functions,
        clock,
        false,
        path_var,
    )?;
    let mut out = Vec::new();
    let mut out_bytes: usize = 0;
    for m in matches {
        if let Some(pred) = &pc.predicate {
            if !eval_to_ternary(pred, &m, params, graph, functions, clock)?.is_true() {
                continue;
            }
        }
        let elem = eval(&pc.projection, &m, params, graph, functions, clock)?;
        accumulate_list_bytes(&mut out_bytes, &elem, "pattern comprehension")?;
        out.push(elem);
    }
    Ok(RowValue::list(out))
}

/// Evaluates an existential subquery `EXISTS { [MATCH] pattern [WHERE p] }`: true iff the pattern
/// (all comma-separated parts jointly, constrained by the outer bindings) matches at least once
/// with the predicate `TRUE`. Always boolean, never null.
fn eval_exists_subquery(
    ex: &crate::ast::ExistsSubquery,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    // Full-query form (`EXISTS { MATCH ... RETURN ... }`): execute the inner read-only query as a
    // correlated subquery seeded by the outer row.
    if let Some(inner_query) = &ex.full_query {
        return eval_exists_full_query(inner_query, row, params, graph, functions, clock);
    }
    // Comma-separated parts join through their shared variables: each part's matches seed the next.
    let mut rows = vec![row.clone()];
    for part in &ex.pattern {
        // A named path binds the path variable for the (joint) predicate.
        let path_var = part.var.as_ref().map(|v| v.name.as_str());
        let mut next = Vec::new();
        for r in &rows {
            next.extend(pattern_element_rows(
                &part.element,
                r,
                params,
                graph,
                functions,
                clock,
                false,
                path_var,
            )?);
        }
        if next.is_empty() {
            return Ok(RowValue::Value(Value::Boolean(false)));
        }
        rows = next;
    }
    match &ex.predicate {
        None => Ok(RowValue::Value(Value::Boolean(true))),
        Some(pred) => {
            for r in &rows {
                if eval_to_ternary(pred, r, params, graph, functions, clock)?.is_true() {
                    return Ok(RowValue::Value(Value::Boolean(true)));
                }
            }
            Ok(RowValue::Value(Value::Boolean(false)))
        }
    }
}

// =================================================================================================
// Full-query EXISTS subquery execution (rmp #123)
// =================================================================================================

/// A **read-only** view of a [`GraphAccess`] seam.
///
/// The full-query form of an `EXISTS { ... }` subquery runs a real sub-pipeline, but
/// [`Executor::open_seeded`](crate::executor::Executor::open_seeded) needs `&mut dyn GraphAccess`
/// while the evaluator only holds `&dyn GraphAccess`. The subquery is guaranteed read-only — any
/// writing clause inside it is rejected at compile time (`InvalidClauseComposition`, see
/// `semantics::reject_writing_clauses`) — so this adapter forwards every **read** to the underlying
/// seam and makes every **write** `unreachable!`: the read-only inner plan never calls a write.
struct ReadOnlyGraph<'g>(&'g dyn GraphAccess);

impl GraphAccess for ReadOnlyGraph<'_> {
    // ---- reads: forwarded verbatim to the underlying seam -------------------------------------
    fn scan_nodes(&self) -> Vec<crate::graph_access::NodeId> {
        self.0.scan_nodes()
    }
    fn scan_nodes_by_label(&self, label: &str) -> Vec<crate::graph_access::NodeId> {
        self.0.scan_nodes_by_label(label)
    }
    fn expand(
        &self,
        node: crate::graph_access::NodeId,
        direction: crate::graph_access::ExpandDirection,
        types: &[String],
    ) -> Vec<crate::graph_access::Incident> {
        self.0.expand(node, direction, types)
    }
    fn node_exists(&self, node: crate::graph_access::NodeId) -> bool {
        self.0.node_exists(node)
    }
    fn rel_exists(&self, rel: crate::graph_access::RelId) -> bool {
        self.0.rel_exists(rel)
    }
    fn node_labels(&self, node: crate::graph_access::NodeId) -> Option<Vec<String>> {
        self.0.node_labels(node)
    }
    fn rel_data(&self, rel: crate::graph_access::RelId) -> Option<crate::graph_access::RelData> {
        self.0.rel_data(rel)
    }
    fn node_property(&self, node: crate::graph_access::NodeId, key: &str) -> Option<Value> {
        self.0.node_property(node, key)
    }
    fn rel_property(&self, rel: crate::graph_access::RelId, key: &str) -> Option<Value> {
        self.0.rel_property(rel, key)
    }
    fn node_properties(&self, node: crate::graph_access::NodeId) -> Option<Vec<(String, Value)>> {
        self.0.node_properties(node)
    }
    fn rel_properties(&self, rel: crate::graph_access::RelId) -> Option<Vec<(String, Value)>> {
        self.0.rel_properties(rel)
    }
    fn incident_rels(&self, node: crate::graph_access::NodeId) -> Vec<crate::graph_access::RelId> {
        self.0.incident_rels(node)
    }
    fn index_seek_eq(
        &self,
        label: &str,
        property: &str,
        value: &Value,
    ) -> Option<Vec<crate::graph_access::NodeId>> {
        self.0.index_seek_eq(label, property, value)
    }
    fn scan_filter_eq(
        &self,
        label: &str,
        property: &str,
        value: &Value,
    ) -> Vec<crate::graph_access::NodeId> {
        // Forward to the inner seam (`rmp` task #325) so the precise equality-scan SIREAD footprint is
        // preserved through this read-only decorator, exactly as `index_seek_eq` is forwarded.
        self.0.scan_filter_eq(label, property, value)
    }
    fn index_seek_range(
        &self,
        label: &str,
        property: &str,
        lower: Option<(&Value, bool)>,
        upper: Option<(&Value, bool)>,
    ) -> Option<Vec<crate::graph_access::NodeId>> {
        self.0.index_seek_range(label, property, lower, upper)
    }
    fn index_seek_spatial(
        &self,
        label: &str,
        property: &str,
        center_x: f64,
        center_y: f64,
        radius: f64,
    ) -> Option<Vec<crate::graph_access::NodeId>> {
        self.0
            .index_seek_spatial(label, property, center_x, center_y, radius)
    }
    fn fulltext_query(&self, name: &str, search: &str) -> Option<Vec<crate::graph_access::NodeId>> {
        self.0.fulltext_query(name, search)
    }
    fn fulltext_score(
        &self,
        name: &str,
        node: crate::graph_access::NodeId,
        search: &str,
    ) -> Option<u64> {
        self.0.fulltext_score(name, node, search)
    }
    fn fulltext_query_rel(
        &self,
        name: &str,
        search: &str,
    ) -> Option<Vec<crate::graph_access::RelId>> {
        self.0.fulltext_query_rel(name, search)
    }
    fn fulltext_score_rel(
        &self,
        name: &str,
        rel: crate::graph_access::RelId,
        search: &str,
    ) -> Option<u64> {
        self.0.fulltext_score_rel(name, rel, search)
    }
    fn statistics(&self) -> Option<&dyn crate::statistics::Statistics> {
        self.0.statistics()
    }

    // ---- writes: never reached (the read-only inner plan emits no write operator) -------------
    fn create_node(
        &mut self,
        _labels: &[String],
        _properties: &[(String, Value)],
    ) -> crate::graph_access::NodeId {
        unreachable!("EXISTS subquery is read-only; writing clauses are rejected at compile time")
    }
    fn create_rel(
        &mut self,
        _rel_type: &str,
        _start: crate::graph_access::NodeId,
        _end: crate::graph_access::NodeId,
        _properties: &[(String, Value)],
    ) -> crate::graph_access::RelId {
        unreachable!("EXISTS subquery is read-only; writing clauses are rejected at compile time")
    }
    fn set_node_property(&mut self, _node: crate::graph_access::NodeId, _key: &str, _value: Value) {
        unreachable!("EXISTS subquery is read-only; writing clauses are rejected at compile time")
    }
    fn set_rel_property(&mut self, _rel: crate::graph_access::RelId, _key: &str, _value: Value) {
        unreachable!("EXISTS subquery is read-only; writing clauses are rejected at compile time")
    }
    fn add_labels(&mut self, _node: crate::graph_access::NodeId, _labels: &[String]) {
        unreachable!("EXISTS subquery is read-only; writing clauses are rejected at compile time")
    }
    fn remove_labels(&mut self, _node: crate::graph_access::NodeId, _labels: &[String]) {
        unreachable!("EXISTS subquery is read-only; writing clauses are rejected at compile time")
    }
    fn remove_node_property(&mut self, _node: crate::graph_access::NodeId, _key: &str) {
        unreachable!("EXISTS subquery is read-only; writing clauses are rejected at compile time")
    }
    fn remove_rel_property(&mut self, _rel: crate::graph_access::RelId, _key: &str) {
        unreachable!("EXISTS subquery is read-only; writing clauses are rejected at compile time")
    }
    fn replace_node_properties(
        &mut self,
        _node: crate::graph_access::NodeId,
        _properties: &[(String, Value)],
    ) {
        unreachable!("EXISTS subquery is read-only; writing clauses are rejected at compile time")
    }
    fn merge_node_properties(
        &mut self,
        _node: crate::graph_access::NodeId,
        _properties: &[(String, Value)],
    ) {
        unreachable!("EXISTS subquery is read-only; writing clauses are rejected at compile time")
    }
    fn replace_rel_properties(
        &mut self,
        _rel: crate::graph_access::RelId,
        _properties: &[(String, Value)],
    ) {
        unreachable!("EXISTS subquery is read-only; writing clauses are rejected at compile time")
    }
    fn merge_rel_properties(
        &mut self,
        _rel: crate::graph_access::RelId,
        _properties: &[(String, Value)],
    ) {
        unreachable!("EXISTS subquery is read-only; writing clauses are rejected at compile time")
    }
    fn delete_rel(&mut self, _rel: crate::graph_access::RelId) {
        unreachable!("EXISTS subquery is read-only; writing clauses are rejected at compile time")
    }
    fn delete_node(&mut self, _node: crate::graph_access::NodeId) {
        unreachable!("EXISTS subquery is read-only; writing clauses are rejected at compile time")
    }
}

thread_local! {
    /// Per-thread memo of compiled inner **subquery** subplans (the full-query forms of `EXISTS`,
    /// `COUNT` and `COLLECT`), keyed by a normalised fingerprint of `(inner query AST, outer
    /// variable names)`.
    ///
    /// The inner physical plan is parameter-independent and does **not** depend on the outer *row*
    /// (correlation is by the [`Argument`](crate::physical::PhysicalOp::Argument) seed), only on the
    /// inner query AST and the set of outer variables. A subquery is re-entered once per outer row
    /// with the same node, so compiling per row would be quadratic; this memo compiles once and
    /// reuses. Thread-local because the evaluator is a free function with no per-execution handle to
    /// hang a cache on, and because [`std::cell::RefCell`] keeps it `!Sync`-safe without locking
    /// (each executor thread owns its own).
    static SUBQUERY_PLAN_CACHE: std::cell::RefCell<
        std::collections::HashMap<String, std::rc::Rc<CompiledSubplan>>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

/// A compiled inner subplan: the physical plan wrapped in a ready-to-open [`Executor`].
///
/// [`Executor`]: crate::executor::Executor
struct CompiledSubplan {
    executor: crate::executor::Executor,
}

/// Compiles (once, memoised per thread) the inner query of a full-query subquery form, correlated
/// with the outer `row`'s columns.
///
/// The subplan lowers the inner query with the outer variables as correlated
/// [`Argument`](crate::physical::PhysicalOp::Argument) inputs, plans it physically (an empty index
/// catalogue is correct — the [`ReadOnlyGraph`] still serves any real index seek through the seam),
/// and binds the inner parameters from the outer (already-bound) parameter set. The result is keyed
/// by a span-normalised fingerprint of the inner AST plus the driving row's column set, so two outer
/// rows with the same shape (the steady state) reuse the same compiled plan.
fn compile_correlated_subplan(
    inner_query: &crate::ast::Query,
    row: &Row,
    params: &BoundParameters,
) -> Result<std::rc::Rc<CompiledSubplan>, EvalError> {
    use crate::catalog::IndexCatalog;
    use crate::logical::Var;

    let outer_vars: Vec<Var> = row.columns().iter().map(Var::named).collect();
    let mut normalized = inner_query.clone();
    normalized.zero_expr_spans_in_place();
    let fingerprint = format!("{:?}|{:?}", normalized, row.columns());

    SUBQUERY_PLAN_CACHE.with(|cache| {
        if let Some(existing) = cache.borrow().get(&fingerprint) {
            return Ok(std::rc::Rc::clone(existing));
        }
        let logical = crate::lower::lower_correlated(inner_query, &outer_vars);
        let physical = crate::physical::plan_physical(&logical, &IndexCatalog::empty());
        let bound =
            crate::binding::bind_parameters(&physical, &params.as_parameters()).map_err(|e| {
                EvalError::Subquery {
                    message: e.to_string(),
                }
            })?;
        let compiled = std::rc::Rc::new(CompiledSubplan {
            executor: crate::executor::Executor::new(physical, bound),
        });
        cache
            .borrow_mut()
            .insert(fingerprint.clone(), std::rc::Rc::clone(&compiled));
        Ok(compiled)
    })
}

/// Executes the full-query form of an `EXISTS { ... }` subquery: run the inner read-only query
/// correlated by the outer `row`, returning `Boolean(true)` iff it yields at least one row (never
/// `Null`).
fn eval_exists_full_query(
    inner_query: &crate::ast::Query,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    // NOTE (`rmp` task #140): a full-query subplan opens its own cursor via `open_seeded`, which
    // captures a fresh statement clock. The outer `clock` is therefore not forwarded here; the two
    // captures are microseconds apart, and the bare/`.statement` instant is still fixed *within* the
    // inner subplan. Threading the outer clock into the subplan would require widening the public
    // `open_*` signatures, which is out of scope for this seam.
    _clock: &StatementClock,
) -> EvalResult {
    let plan = compile_correlated_subplan(inner_query, row, params)?;
    // Run the inner plan over a read-only view, seeded with the outer row, and pull a single row.
    let mut ro = ReadOnlyGraph(graph);
    let token = crate::executor::CancellationToken::new();
    let mut cursor = plan
        .executor
        .open_seeded(
            &mut ro,
            token,
            functions,
            crate::procedure_registry::builtins(),
            row,
        )
        .map_err(|e| EvalError::Subquery {
            message: e.to_string(),
        })?;
    let any = cursor.next().map_err(exec_error_to_eval)?.is_some();
    Ok(RowValue::Value(Value::Boolean(any)))
}

/// Drains the full-query form of a `COUNT`/`COLLECT` subquery, applying `fold` to every row the
/// correlated inner query produces (seeded by the outer `row`). Shared by
/// [`eval_count_subquery`] and [`eval_collect_subquery`].
fn drive_correlated_subquery(
    inner_query: &crate::ast::Query,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    mut fold: impl FnMut(Row),
) -> Result<(), EvalError> {
    let plan = compile_correlated_subplan(inner_query, row, params)?;
    let mut ro = ReadOnlyGraph(graph);
    let token = crate::executor::CancellationToken::new();
    let mut cursor = plan
        .executor
        .open_seeded(
            &mut ro,
            token,
            functions,
            crate::procedure_registry::builtins(),
            row,
        )
        .map_err(|e| EvalError::Subquery {
            message: e.to_string(),
        })?;
    while let Some(inner_row) = cursor.next().map_err(exec_error_to_eval)? {
        fold(inner_row);
    }
    Ok(())
}

/// Evaluates a `COUNT { ... }` subquery to the [`Integer`](Value::Integer) number of rows the
/// correlated subquery matches (never `Null`).
fn eval_count_subquery(
    sq: &crate::ast::SubqueryExpr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> EvalResult {
    // Full-query form: run the inner query correlated and count its rows.
    if let Some(inner_query) = &sq.full_query {
        let mut n: i64 = 0;
        drive_correlated_subquery(inner_query, row, params, graph, functions, |_| n += 1)?;
        return Ok(RowValue::Value(Value::Integer(n)));
    }
    // Pattern form: count the pattern's matches (the comma-separated parts join through shared
    // variables), filtered by the optional `WHERE`.
    let n = count_pattern_matches(
        &sq.pattern,
        sq.predicate.as_deref(),
        row,
        params,
        graph,
        functions,
        clock,
    )?;
    Ok(RowValue::Value(Value::Integer(n)))
}

/// Counts the matches of a correlated bare pattern (the `COUNT { (a)-->(b) [WHERE p] }` form),
/// mirroring the pattern-join semantics of [`eval_exists_subquery`] but tallying every surviving
/// row instead of short-circuiting on the first.
fn count_pattern_matches(
    pattern: &[crate::ast::PatternPart],
    predicate: Option<&Expr>,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> Result<i64, EvalError> {
    let mut rows = vec![row.clone()];
    for part in pattern {
        let path_var = part.var.as_ref().map(|v| v.name.as_str());
        let mut next = Vec::new();
        for r in &rows {
            next.extend(pattern_element_rows(
                &part.element,
                r,
                params,
                graph,
                functions,
                clock,
                false,
                path_var,
            )?);
        }
        rows = next;
    }
    let count = match predicate {
        None => rows.len(),
        Some(pred) => {
            let mut c = 0usize;
            for r in &rows {
                if eval_to_ternary(pred, r, params, graph, functions, clock)?.is_true() {
                    c += 1;
                }
            }
            c
        }
    };
    Ok(count as i64)
}

/// Evaluates a `COLLECT { ... }` subquery to a [`List`](RowValue::list) of the single returned
/// column's value across every row the correlated subquery produces. `COLLECT` is always the
/// full-query form and its inner query returns exactly one column (both enforced by the semantic
/// pass); an empty result yields the empty list.
fn eval_collect_subquery(
    sq: &crate::ast::SubqueryExpr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    _clock: &StatementClock,
) -> EvalResult {
    let inner_query = sq
        .full_query
        .as_ref()
        .expect("COLLECT subquery is always the full-query form");
    let mut items: Vec<RowValue> = Vec::new();
    drive_correlated_subquery(inner_query, row, params, graph, functions, |inner_row| {
        // The inner query returns exactly one column (semantic invariant); collect its value,
        // preserving structural values (nodes/relationships/paths) via `RowValue`.
        if let Some(v) = inner_row.values().first() {
            items.push(v.clone());
        }
    })?;
    Ok(RowValue::list(items))
}

/// Maps an inner-subquery [`ExecError`](crate::executor::ExecError) to an [`EvalError`]: an inner
/// expression error surfaces as its own class; every other class is wrapped in
/// [`EvalError::Subquery`].
fn exec_error_to_eval(e: crate::executor::ExecError) -> EvalError {
    match e {
        crate::executor::ExecError::Eval(inner) => inner,
        other => EvalError::Subquery {
            message: other.to_string(),
        },
    }
}

// =================================================================================================
// Expression-level pattern matching (pattern comprehensions / EXISTS subqueries)
// =================================================================================================

/// All binding rows produced by matching `element` against the graph, seeded by `row`: variables
/// already bound in `row` constrain the match (an outer `n` in `[(n)-->(b) | b]` anchors the
/// start), unbound pattern variables bind into the produced rows. Relationship uniqueness (trail
/// semantics) holds within the element — one relationship is traversed at most once per match.
///
/// `first_only` stops at the first complete match (the `EXISTS` fast path when no joint
/// constraints follow).
#[allow(clippy::too_many_arguments)] // an internal evaluator worker; the seams are positional
fn pattern_element_rows(
    element: &crate::ast::PatternElement,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
    first_only: bool,
    path_var: Option<&str>,
) -> Result<Vec<Row>, EvalError> {
    let mut results = Vec::new();
    for start in node_candidates(&element.start, row, params, graph, functions, clock)? {
        let mut seeded = row.clone();
        if let Some(v) = &element.start.variable {
            seeded.set(v.name.clone(), RowValue::Node(NodeRef { id: start }));
        }
        let cctx = ChainCtx {
            params,
            graph,
            functions,
            clock,
            first_only,
            path_var,
            start,
        };
        match_chain(
            &element.chain,
            0,
            start,
            seeded,
            &mut Vec::new(),
            &mut Vec::new(),
            &mut results,
            &cctx,
        )?;
        if first_only && !results.is_empty() {
            break;
        }
    }
    Ok(results)
}

/// The per-element invariants of one [`match_chain`] DFS: the evaluation seams, the `EXISTS`
/// fast-path flag, and the named-path recording target (`path_var` + the element's start node).
struct ChainCtx<'a> {
    params: &'a BoundParameters,
    graph: &'a dyn GraphAccess,
    functions: &'a dyn FunctionRegistry,
    clock: &'a StatementClock,
    first_only: bool,
    path_var: Option<&'a str>,
    start: crate::graph_access::NodeId,
}

/// Depth-first chain matcher: extend the partial match at `chain[idx]` from `current`, pushing
/// every complete match into `out`. `used_rels` enforces per-match relationship uniqueness (trail
/// semantics); `steps` records the traversed hops so a named path can be bound on completion.
#[allow(clippy::too_many_arguments)] // an internal DFS worker; bundling these adds no clarity
fn match_chain(
    chain: &[crate::ast::PatternChainLink],
    idx: usize,
    current: crate::graph_access::NodeId,
    row: Row,
    used_rels: &mut Vec<crate::graph_access::RelId>,
    steps: &mut Vec<PathStep>,
    out: &mut Vec<Row>,
    cctx: &ChainCtx<'_>,
) -> Result<(), EvalError> {
    let (params, graph, functions, clock) = (cctx.params, cctx.graph, cctx.functions, cctx.clock);
    let Some(link) = chain.get(idx) else {
        let mut row = row;
        if let Some(pv) = cctx.path_var {
            row.set(
                pv.to_owned(),
                RowValue::Path(PathValue {
                    start: cctx.start,
                    steps: steps.clone(),
                }),
            );
        }
        out.push(row);
        return Ok(());
    };
    if let Some(range) = link.relationship.range {
        return match_var_length_link(
            chain, idx, &range, 0, current, row, used_rels, steps, out, cctx,
        );
    }
    let types: Vec<String> = link
        .relationship
        .types
        .iter()
        .map(|t| t.name.clone())
        .collect();
    let direction = crate::graph_access::ExpandDirection::from_pattern(link.relationship.direction);
    for inc in graph.expand(current, direction, &types) {
        if used_rels.contains(&inc.rel) {
            continue;
        }
        let mut next_row = row.clone();
        // Relationship variable: an already-bound one is an identity constraint; otherwise bind.
        if let Some(v) = &link.relationship.variable {
            match next_row.get(&v.name) {
                Some(RowValue::Rel(r)) if r.id == inc.rel => {}
                Some(_) => continue,
                None => next_row.set(v.name.clone(), RowValue::Rel(RelRef { id: inc.rel })),
            }
        }
        if let Some(props) = &link.relationship.properties {
            if !rel_props_match(inc.rel, props, &row, params, graph, functions, clock)? {
                continue;
            }
        }
        // Target node: label/property filters plus the identity constraint when already bound.
        if !node_matches(
            inc.neighbour,
            &link.node,
            &row,
            params,
            graph,
            functions,
            clock,
        )? {
            continue;
        }
        if let Some(v) = &link.node.variable {
            match next_row.get(&v.name) {
                Some(RowValue::Node(n)) if n.id == inc.neighbour => {}
                Some(_) => continue,
                None => next_row.set(
                    v.name.clone(),
                    RowValue::Node(NodeRef { id: inc.neighbour }),
                ),
            }
        }
        used_rels.push(inc.rel);
        steps.push(hop_step(inc.rel, current, inc.neighbour, graph));
        match_chain(
            chain,
            idx + 1,
            inc.neighbour,
            next_row,
            used_rels,
            steps,
            out,
            cctx,
        )?;
        steps.pop();
        used_rels.pop();
        if cctx.first_only && !out.is_empty() {
            return Ok(());
        }
    }
    Ok(())
}

/// The recorded [`PathStep`] for traversing `rel` from `from` to `to`: forward iff the
/// relationship's stored start is the node we left (a self-loop is always forward).
fn hop_step(
    rel: crate::graph_access::RelId,
    from: crate::graph_access::NodeId,
    to: crate::graph_access::NodeId,
    graph: &dyn GraphAccess,
) -> PathStep {
    let forward = graph.rel_data(rel).is_none_or(|d| d.start == from);
    PathStep {
        forward,
        rel,
        node: to,
    }
}

/// The variable-length case of one chain link (`-[r:T*m..n]->`): depth-first trail enumeration.
///
/// At every depth within `[min, max]` whose current node satisfies the link's target node pattern,
/// the link completes — the relationship variable (if named) binds the **list** of traversed
/// relationships (openCypher var-length binding) and the chain continues at `idx + 1`. Trail
/// semantics (`used_rels`) bound the recursion, so an unbounded `*` terminates on any graph.
#[allow(clippy::too_many_arguments)] // an internal DFS worker; bundling these adds no clarity
fn match_var_length_link(
    chain: &[crate::ast::PatternChainLink],
    idx: usize,
    range: &crate::ast::VarLengthRange,
    depth: u64,
    current: crate::graph_access::NodeId,
    row: Row,
    used_rels: &mut Vec<crate::graph_access::RelId>,
    steps: &mut Vec<PathStep>,
    out: &mut Vec<Row>,
    cctx: &ChainCtx<'_>,
) -> Result<(), EvalError> {
    let (params, graph, functions, clock) = (cctx.params, cctx.graph, cctx.functions, cctx.clock);
    let link = &chain[idx];
    let min = range.min.unwrap_or(1);
    // Complete the link at this depth if allowed and the far node satisfies the target pattern.
    if depth >= min && node_matches(current, &link.node, &row, params, graph, functions, clock)? {
        let mut next_row = row.clone();
        let mut ok = true;
        if let Some(v) = &link.relationship.variable {
            // A var-length relationship variable is always freshly bound (semantic analysis
            // rejects re-use), to the list of traversed relationships in order.
            let rels: Vec<RowValue> = steps[steps.len() - depth as usize..]
                .iter()
                .map(|s| RowValue::Rel(RelRef { id: s.rel }))
                .collect();
            next_row.set(v.name.clone(), RowValue::list(rels));
        }
        if let Some(v) = &link.node.variable {
            match next_row.get(&v.name) {
                Some(RowValue::Node(n)) if n.id == current => {}
                Some(_) => ok = false,
                None => next_row.set(v.name.clone(), RowValue::Node(NodeRef { id: current })),
            }
        }
        if ok {
            match_chain(
                chain,
                idx + 1,
                current,
                next_row,
                used_rels,
                steps,
                out,
                cctx,
            )?;
            if cctx.first_only && !out.is_empty() {
                return Ok(());
            }
        }
    }
    // Deepen while under the upper bound.
    if range.max.is_some_and(|max| depth >= max) {
        return Ok(());
    }
    let types: Vec<String> = link
        .relationship
        .types
        .iter()
        .map(|t| t.name.clone())
        .collect();
    let direction = crate::graph_access::ExpandDirection::from_pattern(link.relationship.direction);
    for inc in graph.expand(current, direction, &types) {
        if used_rels.contains(&inc.rel) {
            continue;
        }
        if let Some(props) = &link.relationship.properties {
            if !rel_props_match(inc.rel, props, &row, params, graph, functions, clock)? {
                continue;
            }
        }
        used_rels.push(inc.rel);
        steps.push(hop_step(inc.rel, current, inc.neighbour, graph));
        match_var_length_link(
            chain,
            idx,
            range,
            depth + 1,
            inc.neighbour,
            row.clone(),
            used_rels,
            steps,
            out,
            cctx,
        )?;
        steps.pop();
        used_rels.pop();
        if cctx.first_only && !out.is_empty() {
            return Ok(());
        }
    }
    Ok(())
}

/// The candidate start nodes for `np` under `row`: a bound outer variable anchors to that node
/// (re-checked against the pattern's labels/properties); otherwise a label scan (or full scan)
/// filtered by the pattern.
fn node_candidates(
    np: &crate::ast::NodePattern,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> Result<Vec<crate::graph_access::NodeId>, EvalError> {
    if let Some(v) = &np.variable {
        if let Some(rv) = row.get(&v.name) {
            return match rv {
                RowValue::Node(n)
                    if node_matches(n.id, np, row, params, graph, functions, clock)? =>
                {
                    Ok(vec![n.id])
                }
                _ => Ok(Vec::new()),
            };
        }
    }
    let ids = match np.labels.first() {
        Some(l) => graph.scan_nodes_by_label(&l.name),
        None => graph.scan_nodes(),
    };
    let mut out = Vec::new();
    for id in ids {
        if node_matches(id, np, row, params, graph, functions, clock)? {
            out.push(id);
        }
    }
    Ok(out)
}

/// Whether node `id` satisfies `np`'s labels (all of them) and inline property map (every entry
/// equal under Cypher `=` semantics).
fn node_matches(
    id: crate::graph_access::NodeId,
    np: &crate::ast::NodePattern,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> Result<bool, EvalError> {
    if !np.labels.is_empty() {
        let Some(labels) = graph.node_labels(id) else {
            return Ok(false);
        };
        if !np
            .labels
            .iter()
            .all(|l| labels.iter().any(|have| have == &l.name))
        {
            return Ok(false);
        }
    }
    if let Some(props) = &np.properties {
        let entries = eval_props_map(props, row, params, graph, functions, clock)?;
        for (k, want) in entries {
            let actual = graph.node_property(id, &k).unwrap_or(Value::Null);
            if !equals(&actual, &want).is_true() {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Whether relationship `id` satisfies the inline property map `props`.
fn rel_props_match(
    id: crate::graph_access::RelId,
    props: &Expr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> Result<bool, EvalError> {
    let entries = eval_props_map(props, row, params, graph, functions, clock)?;
    for (k, want) in entries {
        let actual = graph.rel_property(id, &k).unwrap_or(Value::Null);
        if !equals(&actual, &want).is_true() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Evaluates an inline pattern property expression (`{k: v, ...}` or a map parameter) to its
/// key/value pairs.
fn eval_props_map(
    props: &Expr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    clock: &StatementClock,
) -> Result<Vec<(String, Value)>, EvalError> {
    match eval_value(props, row, params, graph, functions, clock)? {
        Value::Map(entries) => Ok(entries),
        other => Err(EvalError::TypeError {
            context: format!("pattern properties must be a map, got {other:?}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::Parameters;
    use crate::function_registry::{Arity, FunctionFailure, FunctionSet, no_functions};
    use crate::graph_access::MemGraph;
    use crate::lexer::tokenize;
    use crate::parser::parse_tokens;

    /// A captured statement clock for the evaluation tests. Most tests evaluate expressions that
    /// never read the clock; the few that exercise current-instant constructors only require that
    /// the same clock be observed across the expression, which a single capture guarantees.
    fn test_clock() -> StatementClock {
        StatementClock::capture()
    }

    /// Parses a single expression by wrapping it in `RETURN <expr>` and extracting the projected
    /// item's expression from the AST.
    fn parse_expr(src: &str) -> Expr {
        let full = format!("RETURN {src} AS x");
        let toks = tokenize(&full).expect("lex");
        let ast = parse_tokens(&toks, &full).expect("parse");
        let crate::ast::QueryBody::Regular { head, .. } = &ast.body else {
            panic!("expected regular query");
        };
        let crate::ast::Clause::Return(ret) = &head.clauses[0] else {
            panic!("expected RETURN");
        };
        ret.body.items[0].expr.clone()
    }

    fn evaluate(src: &str) -> Value {
        let expr = parse_expr(src);
        let g = MemGraph::new();
        let bound = BoundParameters::empty();
        to_value(
            eval(
                &expr,
                &Row::empty(),
                &bound,
                &g,
                no_functions(),
                &test_clock(),
            )
            .unwrap(),
        )
    }

    /// Evaluates `src` against `graph` with `row` in scope, returning the raw [`EvalResult`] so a
    /// test can assert on the `RowValue` structure or a runtime error.
    fn eval_in(graph: &dyn GraphAccess, row: &Row, src: &str) -> EvalResult {
        let expr = parse_expr(src);
        eval(
            &expr,
            row,
            &BoundParameters::empty(),
            graph,
            no_functions(),
            &test_clock(),
        )
    }

    /// A graph with one `:Foo:Bar` node bound to `n` and one `:T {k:7}` relationship bound to `r`,
    /// plus the row binding both — the fixture for the accessor rules (`rmp` task #132).
    fn graph_with_node_and_rel() -> (MemGraph, Row) {
        let mut g = MemGraph::new();
        let n = g.add_node(
            ["Foo", "Bar"],
            [("name", Value::String("Mattias".to_owned()))],
        );
        let a = g.add_node(Vec::<String>::new(), Vec::<(String, Value)>::new());
        let b = g.add_node(Vec::<String>::new(), Vec::<(String, Value)>::new());
        let r = g.add_rel("T", a, b, [("k", Value::Integer(7))]);
        let mut row = Row::empty();
        row.set("n", RowValue::Node(NodeRef { id: n }));
        row.set("r", RowValue::Rel(RelRef { id: r }));
        (g, row)
    }

    #[test]
    fn labels_on_node_rel_null_and_invalid() {
        let (g, row) = graph_with_node_and_rel();
        // A node yields its label list (order is unspecified, so compare as a set).
        let RowValue::Value(Value::List(labels)) = eval_in(&g, &row, "labels(n)").unwrap() else {
            panic!("labels(n) should be a list");
        };
        let set: std::collections::BTreeSet<_> = labels
            .iter()
            .map(|v| match v {
                Value::String(s) => s.clone(),
                _ => panic!("label not a string"),
            })
            .collect();
        assert_eq!(
            set,
            ["Bar".to_owned(), "Foo".to_owned()].into_iter().collect()
        );
        // `labels(null)` is null, not an error.
        assert_eq!(eval_in(&g, &row, "labels(null)").unwrap(), RowValue::NULL);
        // A non-null, non-node argument (a relationship reaches the runtime path; a scalar literal is
        // already rejected at compile time) is a runtime TypeError.
        assert!(matches!(
            eval_in(&g, &row, "labels(r)"),
            Err(EvalError::TypeError { .. })
        ));
    }

    #[test]
    fn type_on_rel_node_null_and_invalid() {
        let (g, row) = graph_with_node_and_rel();
        assert_eq!(
            eval_in(&g, &row, "type(r)").unwrap(),
            RowValue::Value(Value::String("T".to_owned()))
        );
        // `type(null)` is null, not an error.
        assert_eq!(eval_in(&g, &row, "type(null)").unwrap(), RowValue::NULL);
        // A non-null, non-relationship argument is a runtime TypeError.
        assert!(matches!(
            eval_in(&g, &row, "type(n)"),
            Err(EvalError::TypeError { .. })
        ));
    }

    // ---- Theme 3: label predicate on a relationship (`Graph5.feature` [2]) ---------------------

    #[test]
    fn label_predicate_on_relationship_checks_type() {
        let (g, row) = graph_with_node_and_rel(); // `r` is a `:T` relationship
        // `r:T` is true (type matches), case-sensitively; `r:t` is false; never null for a non-null rel.
        assert_eq!(
            eval_in(&g, &row, "r:T").unwrap(),
            RowValue::Value(Value::Boolean(true))
        );
        assert_eq!(
            eval_in(&g, &row, "r:t").unwrap(),
            RowValue::Value(Value::Boolean(false))
        );
        assert_eq!(
            eval_in(&g, &row, "r:Other").unwrap(),
            RowValue::Value(Value::Boolean(false))
        );
    }

    // ---- Theme 1: access to an entity deleted by the current transaction -----------------------

    /// A `GraphAccess` decorator that reports **every** entity as self-deleted, to exercise the
    /// executor's `DeletedEntityAccess` paths over the in-memory reference graph (which itself never
    /// tombstones). The authoritative coverage is the TCK through the record-backed graph; this proves
    /// the eval wiring (property/label/index raise, `id`/`type` survive).
    struct AllDeleted<'a>(&'a dyn GraphAccess);

    impl GraphAccess for AllDeleted<'_> {
        fn scan_nodes(&self) -> Vec<crate::graph_access::NodeId> {
            self.0.scan_nodes()
        }
        fn scan_nodes_by_label(&self, label: &str) -> Vec<crate::graph_access::NodeId> {
            self.0.scan_nodes_by_label(label)
        }
        fn expand(
            &self,
            node: crate::graph_access::NodeId,
            direction: crate::graph_access::ExpandDirection,
            types: &[String],
        ) -> Vec<crate::graph_access::Incident> {
            self.0.expand(node, direction, types)
        }
        fn node_exists(&self, node: crate::graph_access::NodeId) -> bool {
            self.0.node_exists(node)
        }
        fn rel_exists(&self, rel: crate::graph_access::RelId) -> bool {
            self.0.rel_exists(rel)
        }
        fn node_labels(&self, node: crate::graph_access::NodeId) -> Option<Vec<String>> {
            self.0.node_labels(node)
        }
        fn rel_data(
            &self,
            rel: crate::graph_access::RelId,
        ) -> Option<crate::graph_access::RelData> {
            self.0.rel_data(rel)
        }
        fn node_property(&self, node: crate::graph_access::NodeId, key: &str) -> Option<Value> {
            self.0.node_property(node, key)
        }
        fn rel_property(&self, rel: crate::graph_access::RelId, key: &str) -> Option<Value> {
            self.0.rel_property(rel, key)
        }
        fn node_properties(
            &self,
            node: crate::graph_access::NodeId,
        ) -> Option<Vec<(String, Value)>> {
            self.0.node_properties(node)
        }
        fn rel_properties(&self, rel: crate::graph_access::RelId) -> Option<Vec<(String, Value)>> {
            self.0.rel_properties(rel)
        }
        // The whole point of the decorator: report every entity as self-deleted.
        fn entity_deleted_by_txn(&self, _entity: DeletedEntity) -> bool {
            true
        }
        // Writes are never exercised here; forward them so the impl is complete.
        fn create_node(
            &mut self,
            _labels: &[String],
            _properties: &[(String, Value)],
        ) -> crate::graph_access::NodeId {
            unreachable!("AllDeleted is read-only in tests")
        }
        fn create_rel(
            &mut self,
            _rel_type: &str,
            _start: crate::graph_access::NodeId,
            _end: crate::graph_access::NodeId,
            _properties: &[(String, Value)],
        ) -> crate::graph_access::RelId {
            unreachable!("AllDeleted is read-only in tests")
        }
        fn set_node_property(
            &mut self,
            _node: crate::graph_access::NodeId,
            _key: &str,
            _value: Value,
        ) {
        }
        fn set_rel_property(
            &mut self,
            _rel: crate::graph_access::RelId,
            _key: &str,
            _value: Value,
        ) {
        }
        fn add_labels(&mut self, _node: crate::graph_access::NodeId, _labels: &[String]) {}
        fn remove_labels(&mut self, _node: crate::graph_access::NodeId, _labels: &[String]) {}
        fn remove_node_property(&mut self, _node: crate::graph_access::NodeId, _key: &str) {}
        fn remove_rel_property(&mut self, _rel: crate::graph_access::RelId, _key: &str) {}
        fn replace_node_properties(
            &mut self,
            _node: crate::graph_access::NodeId,
            _properties: &[(String, Value)],
        ) {
        }
        fn merge_node_properties(
            &mut self,
            _node: crate::graph_access::NodeId,
            _properties: &[(String, Value)],
        ) {
        }
        fn replace_rel_properties(
            &mut self,
            _rel: crate::graph_access::RelId,
            _properties: &[(String, Value)],
        ) {
        }
        fn merge_rel_properties(
            &mut self,
            _rel: crate::graph_access::RelId,
            _properties: &[(String, Value)],
        ) {
        }
        fn incident_rels(
            &self,
            _node: crate::graph_access::NodeId,
        ) -> Vec<crate::graph_access::RelId> {
            Vec::new()
        }
        fn delete_rel(&mut self, _rel: crate::graph_access::RelId) {}
        fn delete_node(&mut self, _node: crate::graph_access::NodeId) {}
    }

    #[test]
    fn deleted_entity_property_and_label_access_raises_but_id_type_survive() {
        let (g, row) = graph_with_node_and_rel();
        let del = AllDeleted(&g);

        // Property reads (static and dynamic) of a self-deleted node/rel raise DeletedEntityAccess.
        assert_eq!(
            eval_in(&del, &row, "n.name"),
            Err(EvalError::DeletedEntityAccess)
        );
        assert_eq!(
            eval_in(&del, &row, "r.k"),
            Err(EvalError::DeletedEntityAccess)
        );
        assert_eq!(
            eval_in(&del, &row, "n['name']"),
            Err(EvalError::DeletedEntityAccess)
        );
        assert_eq!(
            eval_in(&del, &row, "r['k']"),
            Err(EvalError::DeletedEntityAccess)
        );
        // labels(n) of a self-deleted node raises.
        assert_eq!(
            eval_in(&del, &row, "labels(n)"),
            Err(EvalError::DeletedEntityAccess)
        );

        // id() and type() STILL work after delete (identity survives).
        assert!(matches!(
            eval_in(&del, &row, "id(n)").unwrap(),
            RowValue::Value(Value::Integer(_))
        ));
        assert!(matches!(
            eval_in(&del, &row, "id(r)").unwrap(),
            RowValue::Value(Value::Integer(_))
        ));
        assert_eq!(
            eval_in(&del, &row, "type(r)").unwrap(),
            RowValue::Value(Value::String("T".to_owned()))
        );
    }

    #[test]
    fn dynamic_property_access_reads_entity_property() {
        let (g, row) = graph_with_node_and_rel();
        // `n['name']` is dynamic property access, equivalent to `n.name`.
        assert_eq!(
            eval_in(&g, &row, "n['nam' + 'e']").unwrap(),
            RowValue::Value(Value::String("Mattias".to_owned()))
        );
        assert_eq!(
            eval_in(&g, &row, "r['k']").unwrap(),
            RowValue::Value(Value::Integer(7))
        );
        // A missing key is null (the missing-property rule).
        assert_eq!(eval_in(&g, &row, "n['missing']").unwrap(), RowValue::NULL);
    }

    #[test]
    fn indexing_a_structural_list_preserves_the_element_reference() {
        let (g, row) = graph_with_node_and_rel();
        // `[n, 1][0]` must recover the *node* (not a collapsed null), so `labels([n,1][0])` works —
        // the "accept type Any" path (`expressions/graph/Graph3.feature` [6]).
        let labels = eval_in(&g, &row, "labels([n, 1][0])").unwrap();
        assert!(
            matches!(&labels, RowValue::Value(Value::List(l)) if l.len() == 2),
            "labels([n,1][0]) should be the node's 2-label list, got {labels:?}"
        );
        // The same list indexed past the node returns the integer (a pure value).
        assert_eq!(
            eval_in(&g, &row, "[n, 1][1]").unwrap(),
            RowValue::Value(Value::Integer(1))
        );
        // `type([r, 1][0])` recovers the relationship.
        assert_eq!(
            eval_in(&g, &row, "type([r, 1][0])").unwrap(),
            RowValue::Value(Value::String("T".to_owned()))
        );
    }

    #[test]
    fn static_property_access_on_null_entity_is_null() {
        let g = MemGraph::new();
        let mut row = Row::empty();
        row.set("n", RowValue::NULL);
        // `n.prop` where `n IS NULL` is null, not an error (`expressions/graph/Graph6.feature` [3]).
        assert_eq!(eval_in(&g, &row, "n.prop").unwrap(), RowValue::NULL);
        // Dynamic access on null is likewise null.
        assert_eq!(eval_in(&g, &row, "n['prop']").unwrap(), RowValue::NULL);
    }

    #[test]
    fn arithmetic_and_precedence() {
        assert_eq!(evaluate("1 + 2 * 3"), Value::Integer(7));
        assert_eq!(evaluate("(1 + 2) * 3"), Value::Integer(9));
        assert_eq!(evaluate("7 / 2"), Value::Integer(3)); // integer division
        assert_eq!(evaluate("7.0 / 2"), Value::Float(3.5));
        assert_eq!(evaluate("7 % 3"), Value::Integer(1));
        assert_eq!(evaluate("2 ^ 10"), Value::Float(1024.0));
    }

    #[test]
    fn division_by_zero_is_runtime_error() {
        let expr = parse_expr("1 / 0");
        let g = MemGraph::new();
        let err = eval(
            &expr,
            &Row::empty(),
            &BoundParameters::empty(),
            &g,
            no_functions(),
            &test_clock(),
        )
        .unwrap_err();
        assert_eq!(err, EvalError::DivisionByZero);
    }

    #[test]
    fn three_valued_logic_and_null() {
        assert_eq!(evaluate("true AND false"), Value::Boolean(false));
        assert_eq!(evaluate("true OR null"), Value::Boolean(true));
        assert_eq!(evaluate("false AND null"), Value::Boolean(false));
        assert_eq!(evaluate("null AND true"), Value::Null);
        assert_eq!(evaluate("NOT null"), Value::Null);
    }

    #[test]
    fn comparisons_and_in() {
        assert_eq!(evaluate("1 < 2"), Value::Boolean(true));
        assert_eq!(evaluate("1 = 1.0"), Value::Boolean(true));
        assert_eq!(evaluate("1 = null"), Value::Null);
        assert_eq!(evaluate("3 IN [1, 2, 3]"), Value::Boolean(true));
        assert_eq!(evaluate("4 IN [1, null, 3]"), Value::Null);
    }

    #[test]
    fn string_predicates_and_functions() {
        assert_eq!(evaluate("'hello' STARTS WITH 'he'"), Value::Boolean(true));
        assert_eq!(evaluate("'hello' CONTAINS 'ell'"), Value::Boolean(true));
        assert_eq!(evaluate("toUpper('abc')"), Value::String("ABC".to_owned()));
        assert_eq!(evaluate("size([1, 2, 3])"), Value::Integer(3));
        assert_eq!(
            evaluate("substring('hello', 1, 3)"),
            Value::String("ell".to_owned())
        );
        assert_eq!(evaluate("toString(42)"), Value::String("42".to_owned()));
        assert_eq!(evaluate("coalesce(null, null, 5)"), Value::Integer(5));
    }

    #[test]
    fn exponentiation_precedence_and_left_associativity() {
        // `^` yields a float and is left-associative: `2 ^ 3 ^ 2 == (2 ^ 3) ^ 2 == 8 ^ 2 == 64`.
        assert_eq!(evaluate("2 ^ 3 ^ 2"), Value::Float(64.0));
        // `^` binds tighter than `*`/`+`: `2 * 3 ^ 2 == 2 * 9 == 18`; `2 + 3 ^ 2 == 2 + 9 == 11`.
        assert_eq!(evaluate("2 * 3 ^ 2"), Value::Float(18.0));
        assert_eq!(evaluate("2 + 3 ^ 2"), Value::Float(11.0));
        // Unary minus binds tighter than `^` (`tck/.../Precedence2` [4]): `-2 ^ 2 == (-2) ^ 2 == 4`,
        // and `-3 ^ 2 == (-3) ^ 2 == 9`, while `-(3 ^ 2) == -9`.
        assert_eq!(evaluate("-2 ^ 2"), Value::Float(4.0));
        assert_eq!(evaluate("-3 ^ 2"), Value::Float(9.0));
        assert_eq!(evaluate("-(3 ^ 2)"), Value::Float(-9.0));
        // The full Precedence2 [2] `c` column: `4 ^ (3 * 2) ^ 3 == (4 ^ 6) ^ 3 == 4 ^ 18`.
        assert_eq!(evaluate("4 ^ (3 * 2) ^ 3"), Value::Float(68_719_476_736.0));
    }

    #[test]
    fn smallest_integer_literal_evaluates_to_i64_min() {
        // `-9223372036854775808` (i64::MIN) is a folded, in-range literal — no runtime overflow.
        assert_eq!(evaluate("-9223372036854775808"), Value::Integer(i64::MIN));
        assert_eq!(evaluate("9223372036854775807"), Value::Integer(i64::MAX));
    }

    #[test]
    fn string_predicate_on_non_string_returns_null() {
        // openCypher / Neo4j: a string predicate over a non-`STRING` operand yields `null`, not a
        // type error (`tck/.../precedence/Precedence4` [4]).
        assert_eq!(evaluate("'abc' STARTS WITH true"), Value::Null);
        assert_eq!(evaluate("'abc' CONTAINS 1"), Value::Null);
        assert_eq!(evaluate("'abc' ENDS WITH [1]"), Value::Null);
        // A null operand likewise yields null (existing 3VL behaviour, kept).
        assert_eq!(evaluate("'abc' STARTS WITH null"), Value::Null);
        // And the precedence interaction: `'abc' STARTS WITH null OR true == null OR true == true`.
        assert_eq!(
            evaluate("'abc' STARTS WITH null OR true"),
            Value::Boolean(true)
        );
    }

    #[test]
    fn regex_match_operator_basic_gate() {
        // The `rmp` #446 acceptance gate (the four mandated cases):
        // `'abc' =~ 'a.*'` → true (the whole string matches `a.*`).
        assert_eq!(evaluate("'abc' =~ 'a.*'"), Value::Boolean(true));
        // `'abc' =~ 'b.*'` → false: `=~` is a WHOLE-STRING (Java `matches()`) match, so a pattern that
        // would only match a *substring* (`b.*` matches `bc` inside `abc`) does NOT match the whole.
        assert_eq!(evaluate("'abc' =~ 'b.*'"), Value::Boolean(false));
        // `null =~ '.*'` → null (3VL null propagation on the subject).
        assert_eq!(evaluate("null =~ '.*'"), Value::Null);
    }

    #[test]
    fn regex_match_invalid_pattern_is_classified_error_not_panic() {
        // The fourth gate case: an invalid pattern is a classified `InvalidRegex` runtime error — NOT
        // a panic, and NOT a silent wrong answer. `'('` is an unbalanced group.
        let g = MemGraph::new();
        let row = Row::empty();
        let err = eval_in(&g, &row, "'abc' =~ '('").expect_err("an unbalanced group must error");
        assert!(
            matches!(err, EvalError::InvalidRegex { .. }),
            "expected InvalidRegex, got {err:?}"
        );
        // And it maps to the runtime error class at the boundary (Bolt `ArgumentError`), never a panic.
        let mapped: graphus_core::GraphusError = err.into();
        assert!(matches!(mapped, graphus_core::GraphusError::Runtime(_)));
    }

    #[test]
    fn regex_match_whole_string_anchoring() {
        // Whole-string semantics (Java `Matcher.matches()`): the pattern must describe the ENTIRE
        // subject. A bare literal that equals a prefix/suffix/substring does not match the whole.
        assert_eq!(evaluate("'abc' =~ 'abc'"), Value::Boolean(true));
        assert_eq!(evaluate("'abc' =~ 'ab'"), Value::Boolean(false)); // prefix only
        assert_eq!(evaluate("'abc' =~ 'bc'"), Value::Boolean(false)); // suffix only
        assert_eq!(evaluate("'abc' =~ 'b'"), Value::Boolean(false)); // substring only
        // `.*` on both ends spans the whole string (this is why Neo4j's own examples use `.*`).
        assert_eq!(evaluate("'a-b-c' =~ '.*-.*'"), Value::Boolean(true));
        // The empty pattern matches only the empty string (whole-string anchoring).
        assert_eq!(evaluate("'' =~ ''"), Value::Boolean(true));
        assert_eq!(evaluate("'x' =~ ''"), Value::Boolean(false));
    }

    #[test]
    fn regex_match_top_level_alternation_is_anchored_per_branch() {
        // The `(?:…)` wrapper preserves alternation precedence: `a|b` means whole-string `a` OR
        // whole-string `b`, NOT `(\Aa)|(b\z)`. So `'ab'` matches neither branch.
        assert_eq!(evaluate("'a' =~ 'a|b'"), Value::Boolean(true));
        assert_eq!(evaluate("'b' =~ 'a|b'"), Value::Boolean(true));
        assert_eq!(evaluate("'ab' =~ 'a|b'"), Value::Boolean(false));
    }

    #[test]
    fn regex_match_inline_case_insensitive_flag() {
        // The `(?i)` leading flag (a `java.util.regex` feature shared with RE2) makes the whole
        // pattern case-insensitive — Neo4j's documented `=~ '(?i)…'` idiom.
        assert_eq!(evaluate("'HELLO' =~ '(?i)hello'"), Value::Boolean(true));
        assert_eq!(evaluate("'Hello' =~ '(?i)h.*o'"), Value::Boolean(true));
        // Without the flag, case matters.
        assert_eq!(evaluate("'HELLO' =~ 'hello'"), Value::Boolean(false));
    }

    #[test]
    fn regex_match_non_string_operands_yield_null() {
        // `=~` is a member of the string-operator family: a non-null, non-`STRING` operand on either
        // side yields `null`, consistent with `STARTS WITH`/`CONTAINS`/`ENDS WITH` and Neo4j's rule.
        assert_eq!(evaluate("123 =~ '.*'"), Value::Null); // non-string subject
        assert_eq!(evaluate("true =~ '.*'"), Value::Null);
        assert_eq!(evaluate("'abc' =~ 7"), Value::Null); // non-string pattern
        assert_eq!(evaluate("'abc' =~ null"), Value::Null); // null pattern
        assert_eq!(evaluate("[1] =~ '.*'"), Value::Null);
        // The precedence interaction (mirrors the STARTS-WITH test): a `null` result OR true is true.
        assert_eq!(evaluate("(123 =~ '.*') OR true"), Value::Boolean(true));
    }

    #[test]
    fn regex_full_match_helper_anchors_and_rejects_backtracking_features() {
        // Anchoring: the helper-built regex matches only the whole haystack.
        let re = regex_full_match("a.*").expect("valid pattern compiles");
        assert!(re.is_match("abc"));
        assert!(!re.is_match("xabc")); // would match unanchored, must not here

        // The deliberate `java.util.regex` divergence (documented per `rmp` #446): backreferences and
        // lookaround force super-linear matching and are absent from the linear-time RE2 engine, so a
        // pattern using them is a classified `InvalidRegex`, never a panic and never a wrong answer.
        // Backreference `\1` (written with a real backslash here, not a Cypher escape):
        assert!(matches!(
            regex_full_match(r"(a)\1"),
            Err(EvalError::InvalidRegex { .. })
        ));
        // Lookahead `(?=…)`:
        assert!(matches!(
            regex_full_match("a(?=b)"),
            Err(EvalError::InvalidRegex { .. })
        ));
        // A valid, shared-syntax pattern still compiles (Perl class `\d`, quantifiers, classes).
        let digits = regex_full_match(r"\d+").expect("\\d+ is shared with Java and compiles");
        assert!(digits.is_match("2026"));
        assert!(!digits.is_match("20a6"));
    }

    #[test]
    fn case_expression() {
        assert_eq!(
            evaluate("CASE 2 WHEN 1 THEN 'a' WHEN 2 THEN 'b' ELSE 'c' END"),
            Value::String("b".to_owned())
        );
        assert_eq!(
            evaluate("CASE WHEN 1 > 2 THEN 'x' ELSE 'y' END"),
            Value::String("y".to_owned())
        );
    }

    #[test]
    fn list_and_map_literals_and_indexing() {
        assert_eq!(evaluate("[1, 2, 3][1]"), Value::Integer(2));
        assert_eq!(evaluate("[1, 2, 3][-1]"), Value::Integer(3));
        assert_eq!(
            evaluate("[1, 2, 3, 4][1..3]"),
            Value::List(vec![Value::Integer(2), Value::Integer(3)])
        );
        assert_eq!(evaluate("{a: 1, b: 2}.b"), Value::Integer(2));
        assert_eq!(
            evaluate("range(1, 3)"),
            Value::List(vec![
                Value::Integer(1),
                Value::Integer(2),
                Value::Integer(3)
            ])
        );
    }

    /// FIX 8 (`list/List11` [4]): `range()` with a zero step is a runtime
    /// `ArgumentError`/`NumberOutOfRange`, not a `TypeError`; a non-zero step evaluates normally.
    #[test]
    fn range_with_zero_step_is_number_out_of_range() {
        let g = MemGraph::new();
        let err = eval_in(&g, &Row::empty(), "range(1, 10, 0)").expect_err("zero step");
        assert!(
            matches!(err, EvalError::NumberOutOfRange { .. }),
            "expected NumberOutOfRange, got {err:?}"
        );
        // No-regression: a non-zero step evaluates to the expected list.
        assert_eq!(
            evaluate("range(1, 5, 2)"),
            Value::List(vec![
                Value::Integer(1),
                Value::Integer(3),
                Value::Integer(5)
            ])
        );
        // No-regression: a negative step evaluates correctly.
        assert_eq!(
            evaluate("range(3, 1, -1)"),
            Value::List(vec![
                Value::Integer(3),
                Value::Integer(2),
                Value::Integer(1)
            ])
        );
    }

    #[test]
    fn parameter_lookup() {
        let expr = parse_expr("$p + 1");
        let g = MemGraph::new();
        let bound = bind(&Parameters::new().with("p", Value::Integer(10)), &expr);
        assert_eq!(
            to_value(
                eval(
                    &expr,
                    &Row::empty(),
                    &bound,
                    &g,
                    no_functions(),
                    &test_clock()
                )
                .unwrap()
            ),
            Value::Integer(11)
        );
    }

    /// Test helper: builds `BoundParameters` directly from a `Parameters` set by binding against a
    /// throwaway plan that references the parameter. We bypass the full pipeline by constructing a
    /// `BoundParameters` through the public binding path.
    fn bind(params: &Parameters, _expr: &Expr) -> BoundParameters {
        use crate::catalog::IndexCatalog;
        use crate::lower::lower;
        use crate::physical::plan_physical;
        use crate::semantics::analyze;
        let src = "RETURN $p + 1 AS x";
        let toks = tokenize(src).unwrap();
        let ast = parse_tokens(&toks, src).unwrap();
        let plan = plan_physical(&lower(&analyze(&ast).unwrap()), &IndexCatalog::empty());
        crate::binding::bind_parameters(&plan, params).unwrap()
    }

    #[test]
    fn rand_is_a_float_in_the_unit_interval() {
        // The openCypher contract (and all the TCK relies on): a Float in [0.0, 1.0). Draw enough
        // times to also catch a stuck (fixed-point) generator state.
        let mut distinct = std::collections::BTreeSet::new();
        for _ in 0..1_000 {
            match evaluate("rand()") {
                Value::Float(f) => {
                    assert!((0.0..1.0).contains(&f), "rand() out of [0, 1): {f}");
                    distinct.insert(f.to_bits());
                }
                other => panic!("rand() must be a Float, got {other:?}"),
            }
        }
        assert!(distinct.len() > 1, "rand() returned a constant");
    }

    #[test]
    fn to_boolean_truth_table() {
        // TCK `TypeConversion1` scenarios [1]–[4].
        assert_eq!(evaluate("toBoolean(true)"), Value::Boolean(true));
        assert_eq!(evaluate("toBoolean(false)"), Value::Boolean(false));
        assert_eq!(evaluate("toBoolean('true')"), Value::Boolean(true));
        assert_eq!(evaluate("toBoolean('FaLsE')"), Value::Boolean(false));
        assert_eq!(evaluate("toBoolean(' true ')"), Value::Boolean(true));
        assert_eq!(evaluate("toBoolean('')"), Value::Null);
        assert_eq!(evaluate("toBoolean(' tru ')"), Value::Null);
        assert_eq!(evaluate("toBoolean('f alse')"), Value::Null);
        assert_eq!(evaluate("toBoolean(null)"), Value::Null);
        // Integers are convertible (deliberately absent from the TCK's invalid-type table).
        assert_eq!(evaluate("toBoolean(0)"), Value::Boolean(false));
        assert_eq!(evaluate("toBoolean(42)"), Value::Boolean(true));
    }

    #[test]
    fn to_boolean_invalid_type_errors_but_or_null_yields_null() {
        // TCK `TypeConversion1` scenario [5]: a non-convertible type is a runtime TypeError for
        // `toBoolean` — and null for the `OrNull` companion (its single behavioural difference).
        let g = MemGraph::new();
        for src in ["toBoolean(1.0)", "toBoolean([])", "toBoolean({})"] {
            let expr = parse_expr(src);
            let err = eval(
                &expr,
                &Row::empty(),
                &BoundParameters::empty(),
                &g,
                no_functions(),
                &test_clock(),
            )
            .unwrap_err();
            assert!(matches!(err, EvalError::TypeError { .. }), "{src}: {err:?}");
        }
        assert_eq!(evaluate("toBooleanOrNull(1.0)"), Value::Null);
        assert_eq!(evaluate("toBooleanOrNull([])"), Value::Null);
        assert_eq!(evaluate("toBooleanOrNull({})"), Value::Null);
        assert_eq!(evaluate("toBooleanOrNull('true')"), Value::Boolean(true));
        assert_eq!(evaluate("toBooleanOrNull(null)"), Value::Null);
    }

    /// Asserts that evaluating `src` raises a runtime [`EvalError::TypeError`] (the class the harness
    /// maps to the TCK `TypeError` at `runtime`, detail `InvalidArgumentValue`).
    fn assert_type_error(src: &str) {
        let g = MemGraph::new();
        let expr = parse_expr(src);
        let err = eval(
            &expr,
            &Row::empty(),
            &BoundParameters::empty(),
            &g,
            no_functions(),
            &test_clock(),
        )
        .unwrap_err();
        assert!(matches!(err, EvalError::TypeError { .. }), "{src}: {err:?}");
    }

    #[test]
    fn to_integer_conversion_table() {
        // TCK `TypeConversion2` [1], [3], [4], [6], [7]: integer/float/numeric-string conversions.
        assert_eq!(evaluate("toInteger(82.9)"), Value::Integer(82));
        assert_eq!(evaluate("toInteger(7)"), Value::Integer(7));
        assert_eq!(evaluate("toInteger('42')"), Value::Integer(42));
        // [4] handling Any type: a float-shaped string truncates (`'1.7'` → 1, `'2.9'` → 2).
        assert_eq!(evaluate("toInteger('1.7')"), Value::Integer(1));
        assert_eq!(evaluate("toInteger('2.9')"), Value::Integer(2));
        // [2]/[5] non-numeric and empty strings are null.
        assert_eq!(evaluate("toInteger('foo')"), Value::Null);
        assert_eq!(evaluate("toInteger('')"), Value::Null);
        // null is the identity; a boolean is non-numeric → null (absent from the invalid table).
        assert_eq!(evaluate("toInteger(null)"), Value::Null);
        assert_eq!(evaluate("toInteger(true)"), Value::Null);
        // A large integer-shaped string keeps full `i64` precision (no `f64` round-trip).
        assert_eq!(
            evaluate("toInteger('9007199254740993')"),
            Value::Integer(9_007_199_254_740_993)
        );
    }

    #[test]
    fn to_integer_rejects_invalid_types() {
        // TCK `TypeConversion2` [8]: list/map/node/relationship/path are runtime TypeErrors. The
        // list/map cases are reachable here; node/rel/path are covered by the TCK feature run (they
        // require a graph binding).
        assert_type_error("toInteger([])");
        assert_type_error("toInteger({})");
        // Inside a list comprehension the element is still rejected (the [8] query shape).
        assert_type_error("[x IN [1, []] | toInteger(x)]");
    }

    #[test]
    fn to_float_conversion_table() {
        // TCK `TypeConversion3` [1], [3], [4], [5].
        assert_eq!(evaluate("toFloat(3.4)"), Value::Float(3.4));
        assert_eq!(evaluate("toFloat(3)"), Value::Float(3.0));
        assert_eq!(evaluate("toFloat('5')"), Value::Float(5.0));
        assert_eq!(evaluate("toFloat('2.5')"), Value::Float(2.5));
        // [2]/[4] non-numeric and empty strings are null; null is the identity.
        assert_eq!(evaluate("toFloat('foo')"), Value::Null);
        assert_eq!(evaluate("toFloat('')"), Value::Null);
        assert_eq!(evaluate("toFloat(null)"), Value::Null);
    }

    #[test]
    fn to_float_rejects_invalid_types_including_boolean() {
        // TCK `TypeConversion3` [6]: boolean/list/map/node/relationship/path are runtime TypeErrors.
        // Note that — unlike `toInteger`/`toBoolean` — a boolean is invalid for `toFloat`.
        assert_type_error("toFloat(true)");
        assert_type_error("toFloat([])");
        assert_type_error("toFloat({})");
        assert_type_error("[x IN [1.0, true] | toFloat(x)]");
    }

    #[test]
    fn to_string_conversion_table() {
        // TCK `TypeConversion4` [1], [2], [3], [5], [6].
        assert_eq!(evaluate("toString(42)"), Value::String("42".to_owned()));
        assert_eq!(evaluate("toString(2.3)"), Value::String("2.3".to_owned()));
        assert_eq!(evaluate("toString(true)"), Value::String("true".to_owned()));
        assert_eq!(
            evaluate("toString(1 < 0)"),
            Value::String("false".to_owned())
        );
        assert_eq!(evaluate("toString('apa')"), Value::String("apa".to_owned()));
        assert_eq!(evaluate("toString(null)"), Value::Null);
    }

    #[test]
    fn to_string_rejects_invalid_types() {
        // TCK `TypeConversion4` [10]: list/map/node/relationship/path are runtime TypeErrors.
        assert_type_error("toString([])");
        assert_type_error("toString({})");
        assert_type_error("[x IN [1, '', []] | toString(x)]");
    }

    #[test]
    fn sqrt_returns_float_nan_for_negative_and_null_for_null() {
        // TCK `Mathematical13` scenario [1] (the exact corpus value), plus the IEEE edges.
        assert_eq!(evaluate("sqrt(12.96)"), Value::Float(3.6));
        assert_eq!(evaluate("sqrt(4)"), Value::Float(2.0));
        assert_eq!(evaluate("sqrt(null)"), Value::Null);
        match evaluate("sqrt(-1.0)") {
            Value::Float(f) => assert!(f.is_nan(), "sqrt(-1.0) must be NaN, got {f}"),
            other => panic!("sqrt(-1.0) must be a Float, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_function_is_named_error() {
        // `percentileCont` is a registered function (compile passes) with no runtime evaluator yet
        // — the documented, mechanically-extensible registry boundary. (`nodes`/`relationships`
        // are now implemented, so this exercises a still-open gap.)
        let expr = parse_expr("percentileCont(1, 0.5)");
        let g = MemGraph::new();
        let err = eval(
            &expr,
            &Row::empty(),
            &BoundParameters::empty(),
            &g,
            no_functions(),
            &test_clock(),
        )
        .unwrap_err();
        assert!(matches!(err, EvalError::UnsupportedFunction { .. }));
    }

    // ---- user-defined function dispatch in `call_function` (`rmp` task #75) ------------------

    /// A `FunctionSet` with `ext.double` (doubles a number, rejects other types) and `ext.boom`
    /// (always fails).
    fn udf_set() -> FunctionSet {
        let mut set = FunctionSet::new();
        set.register(
            "ext.double",
            Arity::Exact(1),
            false,
            Box::new(|args| match args.first() {
                Some(Value::Integer(i)) => Ok(Value::Integer(i * 2)),
                Some(Value::Float(f)) => Ok(Value::Float(f * 2.0)),
                Some(Value::Null) | None => Ok(Value::Null),
                Some(other) => Err(FunctionFailure::new(
                    "ext.double",
                    format!("expected a number, got {other:?}"),
                )),
            }),
        )
        .expect("register ext.double");
        set.register(
            "ext.boom",
            Arity::Exact(0),
            false,
            Box::new(|_args| Err(FunctionFailure::new("ext.boom", "always fails"))),
        )
        .expect("register ext.boom");
        set
    }

    /// Evaluates `src` against a UDF registry, returning the runtime result.
    fn eval_with_udfs(src: &str, set: &FunctionSet) -> EvalResult {
        let expr = parse_expr(src);
        let g = MemGraph::new();
        eval(
            &expr,
            &Row::empty(),
            &BoundParameters::empty(),
            &g,
            set,
            &test_clock(),
        )
    }

    #[test]
    fn scalar_udf_is_invoked_by_call_function() {
        let set = udf_set();
        assert_eq!(
            to_value(eval_with_udfs("ext.double(21)", &set).unwrap()),
            Value::Integer(42)
        );
        // Case-insensitive at runtime.
        assert_eq!(
            to_value(eval_with_udfs("EXT.Double(2.5)", &set).unwrap()),
            Value::Float(5.0)
        );
        assert_eq!(
            to_value(eval_with_udfs("ext.double(null)", &set).unwrap()),
            Value::Null
        );
    }

    #[test]
    fn udf_body_failure_is_extension_function_error() {
        let set = udf_set();
        let err = eval_with_udfs("ext.boom()", &set).unwrap_err();
        match err {
            EvalError::ExtensionFunction { name, message } => {
                assert_eq!(name, "ext.boom");
                assert!(message.contains("always fails"));
            }
            other => panic!("expected ExtensionFunction, got {other:?}"),
        }
        // Wrong-type argument: a runtime ExtensionFunction error (function arg types are runtime).
        let err = eval_with_udfs("ext.double('x')", &set).unwrap_err();
        assert!(matches!(err, EvalError::ExtensionFunction { .. }));
    }

    #[test]
    fn unknown_function_with_no_udf_is_unsupported() {
        // With no UDF registered, a non-built-in falls through to UnsupportedFunction (the
        // documented boundary), not ExtensionFunction.
        let set = FunctionSet::new();
        let err = eval_with_udfs("percentileCont(1, 0.5)", &set).unwrap_err();
        assert!(matches!(err, EvalError::UnsupportedFunction { .. }));
    }

    #[test]
    fn builtins_are_not_shadowed_by_runtime_udf_lookup() {
        // A built-in is matched before the UDF fallthrough, so even with UDFs present `abs` is the
        // built-in. (Registration also rejects built-in-colliding names, so this is belt-and-braces.)
        let set = udf_set();
        assert_eq!(
            to_value(eval_with_udfs("abs(-7)", &set).unwrap()),
            Value::Integer(7)
        );
    }

    // --- regression tests for the audited reachable panics / wrong results ------------------------

    /// Regression (audit SEV 9): `i64::MIN / -1` overflows the magnitude of `i64` and panics even in
    /// release. It must surface as the integer-overflow error class, not abort the process.
    #[test]
    fn integer_division_min_by_neg_one_is_overflow_not_panic() {
        let g = MemGraph::new();
        let err = eval_in(&g, &Row::empty(), "-9223372036854775808 / -1").unwrap_err();
        assert_eq!(err, EvalError::IntegerOverflow);
    }

    /// Regression (audit SEV 9): `i64::MIN % -1` panics on overflow the same way; it must surface as
    /// the integer-overflow class.
    #[test]
    fn integer_modulo_min_by_neg_one_is_overflow_not_panic() {
        let g = MemGraph::new();
        let err = eval_in(&g, &Row::empty(), "-9223372036854775808 % -1").unwrap_err();
        assert_eq!(err, EvalError::IntegerOverflow);
        // A normal modulo still works.
        assert_eq!(evaluate("7 % 3"), Value::Integer(1));
    }

    /// Regression (audit SEV 7): an enormous `range()` must be rejected as a resource limit rather
    /// than being allowed to allocate a multi-exabyte `Vec` and OOM the process. A reasonable range
    /// still materialises.
    #[test]
    fn range_rejects_oversized_materialisation() {
        let g = MemGraph::new();
        let err = eval_in(&g, &Row::empty(), "range(1, 9000000000000000000)").unwrap_err();
        assert!(
            matches!(err, EvalError::ResourceLimit { .. }),
            "expected ResourceLimit, got {err:?}"
        );
        assert_eq!(
            to_value(eval_in(&g, &Row::empty(), "range(1, 5)").unwrap()),
            Value::List((1..=5).map(Value::Integer).collect())
        );
    }

    /// Regression (audit SEV 8): `toInteger` of a value outside the `i64` range must yield `null`
    /// (openCypher), not saturate to `i64::MAX`. NaN and ±infinity are likewise `null`.
    #[test]
    fn to_integer_returns_null_for_non_representable() {
        assert_eq!(evaluate("toInteger(1e30)"), Value::Null);
        assert_eq!(evaluate("toInteger(-1e30)"), Value::Null);
        assert_eq!(evaluate("toInteger('1e30')"), Value::Null);
        assert_eq!(evaluate("toInteger(1.0/0.0)"), Value::Null);
        // In-range conversions still truncate toward zero as before.
        assert_eq!(evaluate("toInteger(2.9)"), Value::Integer(2));
        assert_eq!(evaluate("toInteger('1.7')"), Value::Integer(1));
        assert_eq!(evaluate("toInteger(42)"), Value::Integer(42));
    }

    /// Regression (audit SEV 3): the built-in dispatcher must not index its argument vector blindly.
    /// `range_fn` is reachable from dispatch; calling it with too few arguments returns an
    /// `ArgumentCount` error instead of panicking on an out-of-bounds index.
    #[test]
    fn builtin_with_missing_argument_does_not_panic() {
        assert_eq!(
            range_fn(&[]).unwrap_err(),
            EvalError::ArgumentCount {
                name: "range".to_owned()
            }
        );
        assert_eq!(
            split_fn(&[Value::String("a,b".to_owned())]).unwrap_err(),
            EvalError::ArgumentCount {
                name: "split".to_owned()
            }
        );
    }

    // =============================================================================================
    // Mathematical functions (rmp #629)
    // =============================================================================================

    /// Evaluates `src` and asserts the result is a `Float` within `1e-12` of `want`.
    fn assert_float_close(src: &str, want: f64) {
        match evaluate(src) {
            Value::Float(got) => assert!(
                (got - want).abs() < 1e-12,
                "{src} = {got}, expected ≈ {want}"
            ),
            other => panic!("{src} = {other:?}, expected a Float"),
        }
    }

    #[test]
    fn math_constants_pi_and_e() {
        assert_eq!(evaluate("pi()"), Value::Float(std::f64::consts::PI));
        assert_eq!(evaluate("e()"), Value::Float(std::f64::consts::E));
    }

    #[test]
    fn trigonometric_functions() {
        assert_float_close("sin(0)", 0.0);
        assert_float_close("cos(0)", 1.0);
        assert_float_close("tan(0)", 0.0);
        assert_float_close("sin(pi() / 2)", 1.0);
        assert_float_close("atan(1) * 4", std::f64::consts::PI);
        assert_float_close("atan2(1, 1)", std::f64::consts::FRAC_PI_4);
        assert_float_close("haversin(0)", 0.0);
        assert_float_close("haversin(pi())", 1.0);
        assert_float_close("degrees(pi())", 180.0);
        assert_float_close("radians(180)", std::f64::consts::PI);
        // `cot(0)` is +Infinity (1/tan(0)); `asin`/`acos` out of [-1,1] are NaN.
        assert_eq!(evaluate("cot(0)"), Value::Float(f64::INFINITY));
        assert!(matches!(evaluate("asin(2)"), Value::Float(f) if f.is_nan()));
        assert!(matches!(evaluate("acos(2)"), Value::Float(f) if f.is_nan()));
        // Integer arguments coerce to Float; null propagates; a non-number is a runtime TypeError.
        assert_float_close("cos(0.0)", 1.0);
        assert_eq!(evaluate("sin(null)"), Value::Null);
        assert!(matches!(
            eval_in(&MemGraph::new(), &Row::empty(), "sin('x')"),
            Err(EvalError::TypeError { .. })
        ));
    }

    #[test]
    fn logarithmic_and_exponential_functions() {
        assert_float_close("exp(0)", 1.0);
        assert_float_close("log(e())", 1.0);
        assert_float_close("log10(1000)", 3.0);
        assert_float_close("sqrt(16)", 4.0);
        // Documented IEEE-754 edge cases (Neo4j 5.x): log(0) = -Inf, sqrt(-1) = NaN.
        assert_eq!(evaluate("log(0)"), Value::Float(f64::NEG_INFINITY));
        assert!(matches!(evaluate("sqrt(-1)"), Value::Float(f) if f.is_nan()));
        assert_eq!(evaluate("log(null)"), Value::Null);
    }

    #[test]
    fn isnan_over_number_kinds() {
        // NaN only for a NaN Float; an Integer is never NaN; null propagates.
        assert_eq!(evaluate("isNaN(sqrt(-1))"), Value::Boolean(true));
        assert_eq!(evaluate("isNaN(1.5)"), Value::Boolean(false));
        assert_eq!(evaluate("isNaN(1)"), Value::Boolean(false));
        assert_eq!(evaluate("isNaN(null)"), Value::Null);
    }

    #[test]
    fn round_default_and_precision() {
        // Single-argument: ties toward +∞ (Neo4j `round(value)` / Java Math.round), so a negative
        // half rounds toward zero-and-up, unlike the away-from-zero `f64::round`.
        assert_eq!(evaluate("round(2.5)"), Value::Float(3.0));
        assert_eq!(evaluate("round(-2.5)"), Value::Float(-2.0));
        assert_eq!(evaluate("round(2.4)"), Value::Float(2.0));
        assert_eq!(evaluate("round(2.49)"), Value::Float(2.0));
        // Two-argument precision (HALF_UP away from zero for precision != 0).
        assert_float_close("round(1.23456, 2)", 1.23);
        assert_float_close("round(3.145, 2)", 3.15);
        assert_float_close("round(-3.145, 2)", -3.15);
        // Precision 0 aligns with the single-argument form (ties toward +∞).
        assert_eq!(evaluate("round(-2.5, 0)"), Value::Float(-2.0));
        // Null propagation.
        assert_eq!(evaluate("round(null)"), Value::Null);
        assert_eq!(evaluate("round(1.5, null)"), Value::Null);
    }

    #[test]
    fn round_with_explicit_modes() {
        // Each mode applied at precision 0 to the tie value 2.5 (and -2.5 where the sign matters).
        assert_eq!(evaluate("round(2.5, 0, 'UP')"), Value::Float(3.0));
        assert_eq!(evaluate("round(2.1, 0, 'UP')"), Value::Float(3.0));
        assert_eq!(evaluate("round(2.9, 0, 'DOWN')"), Value::Float(2.0));
        assert_eq!(evaluate("round(-2.1, 0, 'CEILING')"), Value::Float(-2.0));
        assert_eq!(evaluate("round(2.1, 0, 'FLOOR')"), Value::Float(2.0));
        assert_eq!(evaluate("round(2.5, 0, 'HALF_UP')"), Value::Float(3.0));
        assert_eq!(evaluate("round(2.5, 0, 'HALF_DOWN')"), Value::Float(2.0));
        assert_eq!(evaluate("round(-2.5, 0, 'HALF_DOWN')"), Value::Float(-2.0));
        // HALF_EVEN (banker's): 2.5 → 2 (even), 3.5 → 4 (even), 2.05 at 1 dp → 2.0.
        assert_eq!(evaluate("round(2.5, 0, 'HALF_EVEN')"), Value::Float(2.0));
        assert_eq!(evaluate("round(3.5, 0, 'HALF_EVEN')"), Value::Float(4.0));
        // An unknown mode is a runtime error; a null mode propagates to null.
        assert!(matches!(
            eval_in(&MemGraph::new(), &Row::empty(), "round(2.5, 0, 'SIDEWAYS')"),
            Err(EvalError::TypeError { .. })
        ));
        assert_eq!(evaluate("round(2.5, 0, null)"), Value::Null);
    }

    // =============================================================================================
    // Additional scalar / list functions (rmp #630)
    // =============================================================================================

    #[test]
    fn element_id_matches_the_integer_id_string() {
        let (g, row) = graph_with_node_and_rel();
        // `elementId(n)` is the decimal string of the same integer id `id(n)` returns (and that the
        // Bolt/REST wire packs as `element_id`).
        let RowValue::Value(Value::Integer(node_id)) = eval_in(&g, &row, "id(n)").unwrap() else {
            panic!("id(n) must be an Integer");
        };
        assert_eq!(
            eval_in(&g, &row, "elementId(n)").unwrap(),
            RowValue::Value(Value::String(node_id.to_string()))
        );
        let RowValue::Value(Value::Integer(rel_id)) = eval_in(&g, &row, "id(r)").unwrap() else {
            panic!("id(r) must be an Integer");
        };
        assert_eq!(
            eval_in(&g, &row, "elementId(r)").unwrap(),
            RowValue::Value(Value::String(rel_id.to_string()))
        );
        // A null argument is null.
        assert_eq!(
            eval_in(&g, &row, "elementId(null)").unwrap(),
            RowValue::NULL
        );
    }

    #[test]
    fn timestamp_is_a_positive_integer() {
        // A statement-fixed millisecond epoch; only its type and positivity are contract.
        match evaluate("timestamp()") {
            Value::Integer(ms) => assert!(ms > 0, "timestamp() = {ms}"),
            other => panic!("timestamp() = {other:?}, expected an Integer"),
        }
    }

    #[test]
    fn random_uuid_is_a_well_formed_v4() {
        let Value::String(uuid) = evaluate("randomUUID()") else {
            panic!("randomUUID() must be a String");
        };
        assert_eq!(uuid.len(), 36, "uuid = {uuid}");
        let bytes = uuid.as_bytes();
        // Dashes at the canonical 8-4-4-4-12 positions.
        for pos in [8, 13, 18, 23] {
            assert_eq!(bytes[pos], b'-', "expected '-' at {pos} in {uuid}");
        }
        // Version 4 nibble and the RFC-4122 variant nibble (8, 9, a or b).
        assert_eq!(bytes[14], b'4', "version nibble in {uuid}");
        assert!(
            matches!(bytes[19], b'8' | b'9' | b'a' | b'b'),
            "variant nibble in {uuid}"
        );
        // All non-dash characters are lower-case hex.
        assert!(
            uuid.chars()
                .all(|c| c == '-' || c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn is_empty_over_lists_maps_and_strings() {
        assert_eq!(evaluate("isEmpty([])"), Value::Boolean(true));
        assert_eq!(evaluate("isEmpty([1])"), Value::Boolean(false));
        assert_eq!(evaluate("isEmpty('')"), Value::Boolean(true));
        assert_eq!(evaluate("isEmpty('a')"), Value::Boolean(false));
        assert_eq!(evaluate("isEmpty({})"), Value::Boolean(true));
        assert_eq!(evaluate("isEmpty({a: 1})"), Value::Boolean(false));
        // Null propagates; a non-collection non-string is a runtime TypeError.
        assert_eq!(evaluate("isEmpty(null)"), Value::Null);
        assert!(matches!(
            eval_in(&MemGraph::new(), &Row::empty(), "isEmpty(1)"),
            Err(EvalError::TypeError { .. })
        ));
    }

    #[test]
    fn value_type_names_match_neo4j() {
        assert_eq!(evaluate("valueType(1)"), s("INTEGER NOT NULL"));
        assert_eq!(evaluate("valueType(1.5)"), s("FLOAT NOT NULL"));
        assert_eq!(evaluate("valueType('a')"), s("STRING NOT NULL"));
        assert_eq!(evaluate("valueType(true)"), s("BOOLEAN NOT NULL"));
        assert_eq!(evaluate("valueType(null)"), s("null"));
        assert_eq!(
            evaluate("valueType([1, 2, 3])"),
            s("LIST<INTEGER NOT NULL> NOT NULL")
        );
        assert_eq!(evaluate("valueType([])"), s("LIST<NOTHING> NOT NULL"));
        // A null element makes the element type nullable (no inner NOT NULL).
        assert_eq!(
            evaluate("valueType([1, null])"),
            s("LIST<INTEGER> NOT NULL")
        );
        assert_eq!(evaluate("valueType({a: 1})"), s("MAP NOT NULL"));
        // Temporal / spatial names (space-separated, Neo4j 5.x).
        assert_eq!(
            evaluate("valueType(date('2020-01-01'))"),
            s("DATE NOT NULL")
        );
        assert_eq!(
            evaluate("valueType(duration({days: 1}))"),
            s("DURATION NOT NULL")
        );
        assert_eq!(
            evaluate("valueType(point({x: 1, y: 2}))"),
            s("POINT NOT NULL")
        );
    }

    #[test]
    fn value_type_over_entities() {
        let (g, row) = graph_with_node_and_rel();
        assert_eq!(
            eval_in(&g, &row, "valueType(n)").unwrap(),
            RowValue::Value(s("NODE NOT NULL"))
        );
        assert_eq!(
            eval_in(&g, &row, "valueType(r)").unwrap(),
            RowValue::Value(s("RELATIONSHIP NOT NULL"))
        );
    }

    #[test]
    fn null_if_returns_null_only_when_equivalent() {
        assert_eq!(evaluate("nullIf(1, 1)"), Value::Null);
        assert_eq!(evaluate("nullIf(1, 2)"), Value::Integer(1));
        assert_eq!(evaluate("nullIf('a', 'a')"), Value::Null);
        assert_eq!(evaluate("nullIf('a', 'b')"), s("a"));
        // A null first argument is null; differing types are never equivalent.
        assert_eq!(evaluate("nullIf(null, 1)"), Value::Null);
        assert_eq!(evaluate("nullIf(1, '1')"), Value::Integer(1));
        // Same node is equivalent (identity); node vs its relationship is not.
        let (g, row) = graph_with_node_and_rel();
        assert_eq!(eval_in(&g, &row, "nullIf(n, n)").unwrap(), RowValue::NULL);
        assert!(matches!(
            eval_in(&g, &row, "nullIf(n, r)").unwrap(),
            RowValue::Node(_)
        ));
    }

    #[test]
    fn char_length_is_a_size_alias() {
        assert_eq!(evaluate("char_length('hello')"), Value::Integer(5));
        assert_eq!(evaluate("character_length('héllo')"), Value::Integer(5));
        assert_eq!(evaluate("char_length('')"), Value::Integer(0));
        assert_eq!(evaluate("char_length(null)"), Value::Null);
    }

    #[test]
    fn to_scalar_or_null_never_raises() {
        assert_eq!(evaluate("toIntegerOrNull('42')"), Value::Integer(42));
        assert_eq!(evaluate("toIntegerOrNull('abc')"), Value::Null);
        assert_eq!(evaluate("toIntegerOrNull([1])"), Value::Null);
        assert_eq!(evaluate("toFloatOrNull('1.5')"), Value::Float(1.5));
        assert_eq!(evaluate("toFloatOrNull(true)"), Value::Null);
        assert_eq!(evaluate("toStringOrNull(42)"), s("42"));
        assert_eq!(evaluate("toStringOrNull([1, 2])"), Value::Null);
    }

    #[test]
    fn to_typed_lists_convert_element_wise() {
        assert_eq!(
            evaluate("toIntegerList(['1', '2', 'x'])"),
            Value::List(vec![Value::Integer(1), Value::Integer(2), Value::Null])
        );
        assert_eq!(
            evaluate("toFloatList([1, 2, 'y'])"),
            Value::List(vec![Value::Float(1.0), Value::Float(2.0), Value::Null])
        );
        assert_eq!(
            evaluate("toBooleanList(['true', 'nope', false])"),
            Value::List(vec![
                Value::Boolean(true),
                Value::Null,
                Value::Boolean(false)
            ])
        );
        assert_eq!(
            evaluate("toStringList([1, 2.5, true])"),
            Value::List(vec![s("1"), s("2.5"), s("true")])
        );
        // A null input list is null; a non-list argument is a runtime TypeError.
        assert_eq!(evaluate("toIntegerList(null)"), Value::Null);
        assert!(matches!(
            eval_in(&MemGraph::new(), &Row::empty(), "toIntegerList(5)"),
            Err(EvalError::TypeError { .. })
        ));
    }

    // =============================================================================================
    // reduce (list fold) — rmp #631
    // =============================================================================================

    #[test]
    fn reduce_sums_a_list() {
        assert_eq!(
            evaluate("reduce(s = 0, x IN [1, 2, 3] | s + x)"),
            Value::Integer(6)
        );
        // A non-trivial body: sum of squares 1 + 4 + 9.
        assert_eq!(
            evaluate("reduce(total = 0, x IN [1, 2, 3] | total + x * x)"),
            Value::Integer(14)
        );
    }

    #[test]
    fn reduce_empty_list_returns_the_initial_value() {
        assert_eq!(
            evaluate("reduce(s = 10, x IN [] | s + x)"),
            Value::Integer(10)
        );
    }

    #[test]
    fn reduce_null_list_is_null() {
        assert_eq!(evaluate("reduce(s = 0, x IN null | s + x)"), Value::Null);
    }

    #[test]
    fn reduce_folds_strings_left_to_right() {
        assert_eq!(
            evaluate("reduce(acc = '', x IN ['a', 'b', 'c'] | acc + x)"),
            s("abc")
        );
    }

    #[test]
    fn reduce_nests() {
        // For each of the two outer elements the inner fold contributes 10 + 20 = 30, so 60 total.
        assert_eq!(
            evaluate("reduce(a = 0, x IN [1, 2] | a + reduce(b = 0, y IN [10, 20] | b + y))"),
            Value::Integer(60)
        );
    }

    #[test]
    fn reduce_element_does_not_leak_into_outer_scope() {
        // Bind `x` in the outer row; the fold's element variable `x` must shadow it only *inside*
        // the body. The inner fold sees x = 1,2,3 (sum 6); the trailing `+ x` must see the OUTER
        // x = 100 → 106 (if the element binding leaked it would read the last element, 3 → 9).
        let mut row = Row::empty();
        row.set("x", RowValue::Value(Value::Integer(100)));
        assert_eq!(
            to_value(
                eval_in(
                    &MemGraph::new(),
                    &row,
                    "reduce(s = 0, x IN [1, 2, 3] | s + x) + x"
                )
                .unwrap()
            ),
            Value::Integer(106)
        );
    }

    #[test]
    fn reduce_over_a_non_list_is_a_type_error() {
        assert!(matches!(
            eval_in(
                &MemGraph::new(),
                &Row::empty(),
                "reduce(s = 0, x IN 5 | s + x)"
            ),
            Err(EvalError::TypeError { .. })
        ));
    }

    // =============================================================================================
    // Map projection — rmp #632
    // =============================================================================================

    /// A `:Person {name: 'Bob', age: 30}` node bound to `p`, a `tag` string value and a `nothing`
    /// null binding in the row — the fixture for the map-projection tests.
    fn graph_with_person() -> (MemGraph, Row) {
        let mut g = MemGraph::new();
        let p = g.add_node(
            ["Person"],
            [
                ("name", Value::String("Bob".to_owned())),
                ("age", Value::Integer(30)),
            ],
        );
        let mut row = Row::empty();
        row.set("p", RowValue::Node(NodeRef { id: p }));
        row.set("tag", RowValue::Value(Value::String("vip".to_owned())));
        row.set("nothing", RowValue::NULL);
        (g, row)
    }

    /// Evaluates `src` and asserts it produced a (pure-property) map, returned as key/value pairs.
    fn eval_map(g: &dyn GraphAccess, row: &Row, src: &str) -> Vec<(String, Value)> {
        match to_value(eval_in(g, row, src).unwrap()) {
            Value::Map(m) => m,
            other => panic!("expected a map from `{src}`, got {other:?}"),
        }
    }

    /// Order-independent view of a projected map (for `.*`, whose property order is unspecified).
    fn as_btree(m: Vec<(String, Value)>) -> std::collections::BTreeMap<String, Value> {
        m.into_iter().collect()
    }

    #[test]
    fn map_projection_property_selector() {
        let (g, row) = graph_with_person();
        assert_eq!(
            eval_map(&g, &row, "p{.name}"),
            vec![("name".to_owned(), s("Bob"))]
        );
        // Two properties, in written order.
        assert_eq!(
            eval_map(&g, &row, "p{.name, .age}"),
            vec![
                ("name".to_owned(), s("Bob")),
                ("age".to_owned(), Value::Integer(30))
            ]
        );
        // A missing property projects as null (the missing-property rule).
        assert_eq!(
            eval_map(&g, &row, "p{.name, .missing}"),
            vec![
                ("name".to_owned(), s("Bob")),
                ("missing".to_owned(), Value::Null)
            ]
        );
    }

    #[test]
    fn map_projection_all_properties() {
        let (g, row) = graph_with_person();
        assert_eq!(
            as_btree(eval_map(&g, &row, "p{.*}")),
            as_btree(vec![
                ("name".to_owned(), s("Bob")),
                ("age".to_owned(), Value::Integer(30))
            ])
        );
    }

    #[test]
    fn map_projection_literal_and_variable_selectors() {
        let (g, row) = graph_with_person();
        // Literal entry with a computed value.
        assert_eq!(
            eval_map(&g, &row, "p{.name, extra: p.age * 2}"),
            vec![
                ("name".to_owned(), s("Bob")),
                ("extra".to_owned(), Value::Integer(60))
            ]
        );
        // A bare-variable selector projects the value of that row variable under its own name.
        assert_eq!(
            eval_map(&g, &row, "p{.name, tag}"),
            vec![("name".to_owned(), s("Bob")), ("tag".to_owned(), s("vip"))]
        );
    }

    #[test]
    fn map_projection_all_properties_then_override() {
        let (g, row) = graph_with_person();
        // `.*` is applied first; an explicit entry with the same key overrides the `.*` property.
        let projected = as_btree(eval_map(&g, &row, "p{.*, name: 'Override'}"));
        assert_eq!(projected.get("name"), Some(&s("Override")));
        assert_eq!(projected.get("age"), Some(&Value::Integer(30)));
        assert_eq!(projected.len(), 2, "override must not add a duplicate key");
    }

    #[test]
    fn map_projection_over_relationship_and_map_literal() {
        let (g, row) = graph_with_node_and_rel();
        // A relationship projects like a node.
        assert_eq!(
            eval_map(&g, &row, "r{.k}"),
            vec![("k".to_owned(), Value::Integer(7))]
        );
        // A projection applies to any map, including a map literal.
        assert_eq!(
            eval_map(&g, &Row::empty(), "{a: 1, b: 2}{.a, tag: 'x'}"),
            vec![
                ("a".to_owned(), Value::Integer(1)),
                ("tag".to_owned(), s("x"))
            ]
        );
        assert_eq!(
            as_btree(eval_map(&g, &Row::empty(), "{a: 1, b: 2}{.*}")),
            as_btree(vec![
                ("a".to_owned(), Value::Integer(1)),
                ("b".to_owned(), Value::Integer(2))
            ])
        );
    }

    #[test]
    fn map_projection_of_null_entity_is_null() {
        let (g, row) = graph_with_person();
        // A null projected entity makes the whole projection null, regardless of the selectors.
        assert_eq!(
            to_value(eval_in(&g, &row, "nothing{.name}").unwrap()),
            Value::Null
        );
        assert_eq!(
            to_value(eval_in(&g, &row, "nothing{.*, tag: 'x'}").unwrap()),
            Value::Null
        );
    }

    /// A `Value::String` shorthand for the assertions above.
    fn s(v: &str) -> Value {
        Value::String(v.to_owned())
    }

    // --- `rmp` #636: type predicate (`IS :: <type>`) evaluation ---------------------------------

    fn b(v: bool) -> Value {
        Value::Boolean(v)
    }

    #[test]
    fn type_predicate_scalar_matches_and_mismatches() {
        assert_eq!(evaluate("1 IS :: INTEGER"), b(true));
        assert_eq!(evaluate("1 IS :: STRING"), b(false));
        assert_eq!(evaluate("1 IS NOT :: STRING"), b(true));
        assert_eq!(evaluate("1 IS NOT :: INTEGER"), b(false));
        assert_eq!(evaluate("1.5 IS :: FLOAT"), b(true));
        // No integer -> float widening: `1 IS :: FLOAT` is exact and false.
        assert_eq!(evaluate("1 IS :: FLOAT"), b(false));
        assert_eq!(evaluate("'x' IS :: STRING"), b(true));
        assert_eq!(evaluate("true IS :: BOOLEAN"), b(true));
        assert_eq!(evaluate("true IS :: INTEGER"), b(false));
    }

    #[test]
    fn type_predicate_bare_and_typed_syntaxes_agree() {
        // The bare `expr :: TYPE` and the `IS TYPED` alias behave like `IS ::`.
        assert_eq!(evaluate("1 :: INTEGER"), b(true));
        assert_eq!(evaluate("1 IS TYPED INTEGER"), b(true));
        assert_eq!(evaluate("1 IS NOT TYPED STRING"), b(true));
    }

    #[test]
    fn type_predicate_null_and_nullability() {
        // Every type is nullable by default: a null satisfies it.
        assert_eq!(evaluate("null IS :: INTEGER"), b(true));
        assert_eq!(evaluate("null IS :: BOOLEAN"), b(true));
        // `NOT NULL` excludes null.
        assert_eq!(evaluate("null IS :: INTEGER NOT NULL"), b(false));
        assert_eq!(evaluate("null IS :: BOOLEAN NOT NULL"), b(false));
        assert_eq!(evaluate("1 IS :: INTEGER NOT NULL"), b(true));
        // The negation is a pure boolean flip, including for null.
        assert_eq!(evaluate("null IS NOT :: STRING"), b(false));
        assert_eq!(evaluate("(null + 1) IS NOT :: DATE NOT NULL"), b(true));
    }

    #[test]
    fn type_predicate_special_types() {
        // ANY matches everything (including null); NOTHING matches nothing; NULL matches only null.
        assert_eq!(evaluate("1 IS :: ANY"), b(true));
        assert_eq!(evaluate("null IS :: ANY"), b(true));
        assert_eq!(evaluate("1 IS :: NOTHING"), b(false));
        assert_eq!(evaluate("null IS :: NOTHING"), b(false));
        assert_eq!(evaluate("null IS :: NULL"), b(true));
        assert_eq!(evaluate("1 IS :: NULL"), b(false));
        assert_eq!(evaluate("1 IS :: ANY NOT NULL"), b(true));
        assert_eq!(evaluate("null IS :: ANY NOT NULL"), b(false));
    }

    #[test]
    fn type_predicate_lists() {
        assert_eq!(evaluate("[1, 2] IS :: LIST<INTEGER>"), b(true));
        assert_eq!(evaluate("[1, 2.0] IS :: LIST<INTEGER>"), b(false));
        assert_eq!(evaluate("[1, 2.0] IS :: LIST<INTEGER | FLOAT>"), b(true));
        // An empty list matches every element type, even NOTHING.
        assert_eq!(evaluate("[] IS :: LIST<INTEGER>"), b(true));
        assert_eq!(evaluate("[] IS :: LIST<NOTHING>"), b(true));
        // Element nullability.
        assert_eq!(evaluate("[1, null] IS :: LIST<INTEGER>"), b(true));
        assert_eq!(evaluate("[1, null] IS :: LIST<INTEGER NOT NULL>"), b(false));
        // ARRAY<...> is a synonym for LIST<...>.
        assert_eq!(evaluate("[1, 2] IS :: ARRAY<INTEGER>"), b(true));
        // Nested lists.
        assert_eq!(evaluate("[[1], [2]] IS :: LIST<LIST<INTEGER>>"), b(true));
    }

    #[test]
    fn type_predicate_unions() {
        assert_eq!(evaluate("1 IS :: INTEGER | FLOAT"), b(true));
        assert_eq!(evaluate("1.0 IS :: INTEGER | FLOAT"), b(true));
        assert_eq!(evaluate("'x' IS :: INTEGER | FLOAT"), b(false));
        // ANY<...> closed dynamic union.
        assert_eq!(evaluate("'x' IS :: ANY<INTEGER | STRING>"), b(true));
        // A null satisfies a union whose member is nullable.
        assert_eq!(evaluate("null IS :: INTEGER | STRING"), b(true));
        assert_eq!(
            evaluate("null IS :: INTEGER NOT NULL | STRING NOT NULL"),
            b(false)
        );
    }

    #[test]
    fn type_predicate_synonyms() {
        assert_eq!(evaluate("1 IS :: INT"), b(true));
        assert_eq!(evaluate("1 IS :: SIGNED INTEGER"), b(true));
        assert_eq!(evaluate("true IS :: BOOL"), b(true));
        assert_eq!(evaluate("'x' IS :: VARCHAR"), b(true));
    }

    #[test]
    fn type_predicate_temporal_and_point_and_map() {
        assert_eq!(evaluate("date('2020-01-01') IS :: DATE"), b(true));
        assert_eq!(evaluate("date('2020-01-01') IS :: LOCAL TIME"), b(false));
        assert_eq!(
            evaluate("localdatetime('2020-01-01T00:00') IS :: LOCAL DATETIME"),
            b(true)
        );
        assert_eq!(evaluate("duration('P1D') IS :: DURATION"), b(true));
        assert_eq!(evaluate("point({x: 1, y: 2}) IS :: POINT"), b(true));
        assert_eq!(evaluate("{a: 1} IS :: MAP"), b(true));
        assert_eq!(evaluate("{a: 1} IS :: PROPERTY VALUE"), b(false));
        assert_eq!(evaluate("1 IS :: PROPERTY VALUE"), b(true));
    }

    #[test]
    fn type_predicate_entities() {
        let (g, row) = graph_with_node_and_rel();
        let check = |src: &str| to_value(eval_in(&g, &row, src).unwrap());
        assert_eq!(check("n IS :: NODE"), b(true));
        assert_eq!(check("n IS :: RELATIONSHIP"), b(false));
        assert_eq!(check("r IS :: RELATIONSHIP"), b(true));
        assert_eq!(check("r IS :: EDGE"), b(true));
        assert_eq!(check("n IS :: VERTEX"), b(true));
        assert_eq!(check("n IS :: ANY NODE"), b(true));
        assert_eq!(check("r IS :: ANY RELATIONSHIP"), b(true));
        assert_eq!(check("n IS :: MAP"), b(false));
        assert_eq!(check("n IS :: ANY"), b(true));
        assert_eq!(check("n IS :: PROPERTY VALUE"), b(false));
    }

    // --- `rmp` #636: normalization predicate (`IS NORMALIZED`) evaluation -----------------------

    #[test]
    fn normalized_predicate_basic() {
        // 'ä' as a single precomposed code point (U+00E4) is NFC-normalized.
        assert_eq!(evaluate("'\\u00E4' IS NORMALIZED"), b(true));
        assert_eq!(evaluate("'\\u00E4' IS NFC NORMALIZED"), b(true));
        // The same 'ä' decomposed ('a' + combining diaeresis U+0308) is NOT NFC, but IS NFD.
        assert_eq!(evaluate("'a\\u0308' IS NORMALIZED"), b(false));
        assert_eq!(evaluate("'a\\u0308' IS NOT NORMALIZED"), b(true));
        assert_eq!(evaluate("'a\\u0308' IS NFD NORMALIZED"), b(true));
        assert_eq!(evaluate("'a\\u0308' IS NFC NORMALIZED"), b(false));
        // ASCII is normalized in every form.
        assert_eq!(evaluate("'abc' IS NORMALIZED"), b(true));
        assert_eq!(evaluate("'abc' IS NFKC NORMALIZED"), b(true));
        assert_eq!(evaluate("'abc' IS NFKD NORMALIZED"), b(true));
    }

    #[test]
    fn normalized_predicate_null_and_non_string_yield_null() {
        assert_eq!(evaluate("1 IS NORMALIZED"), Value::Null);
        assert_eq!(evaluate("1 IS NOT NORMALIZED"), Value::Null);
        assert_eq!(evaluate("null IS NORMALIZED"), Value::Null);
        assert_eq!(evaluate("null IS NFD NORMALIZED"), Value::Null);
        assert_eq!(evaluate("[1] IS NORMALIZED"), Value::Null);
    }

    // --- `rmp` #643: residual string / spatial / predicate functions ---------------------------

    #[test]
    fn normalize_function_default_nfc_and_explicit_forms() {
        // Decomposed 'ä' ('a' + U+0308) normalizes (default NFC) to the precomposed U+00E4.
        assert_eq!(evaluate("normalize('a\\u0308')"), s("\u{00E4}"));
        assert_eq!(evaluate("normalize('a\\u0308', 'NFC')"), s("\u{00E4}"));
        // NFD decomposes the precomposed 'ä' back to 'a' + combining diaeresis.
        assert_eq!(evaluate("normalize('\\u00E4', 'NFD')"), s("a\u{0308}"));
        // The form string is case-insensitive.
        assert_eq!(evaluate("normalize('a\\u0308', 'nfc')"), s("\u{00E4}"));
        // NFKC folds the compatibility ligature 'ﬁ' (U+FB01) to 'fi'.
        assert_eq!(evaluate("normalize('\\uFB01', 'NFKC')"), s("fi"));
        assert_eq!(evaluate("normalize('\\uFB01', 'NFKD')"), s("fi"));
        // A plain-ASCII string is unchanged in every form.
        assert_eq!(evaluate("normalize('abc')"), s("abc"));
    }

    #[test]
    fn normalize_function_null_and_errors() {
        assert_eq!(evaluate("normalize(null)"), Value::Null);
        // A null form propagates null.
        assert_eq!(evaluate("normalize('x', null)"), Value::Null);
        // A non-string input is a type error; an unknown form is a type error.
        assert!(eval_in(&MemGraph::new(), &Row::empty(), "normalize(1)").is_err());
        assert!(eval_in(&MemGraph::new(), &Row::empty(), "normalize('x', 'NFX')").is_err());
    }

    #[test]
    fn btrim_function_whitespace_and_character_set() {
        // Default: trim leading/trailing whitespace from both ends.
        assert_eq!(evaluate("btrim('  hi  ')"), s("hi"));
        // With a trim-character set: remove any leading/trailing char in the set (order-independent).
        assert_eq!(evaluate("btrim('xxyhelloyxx', 'xy')"), s("hello"));
        assert_eq!(evaluate("btrim('__hi__', '_')"), s("hi"));
        // A set that does not appear at the ends leaves the string unchanged.
        assert_eq!(evaluate("btrim('hello', 'z')"), s("hello"));
        // An empty trim set trims nothing.
        assert_eq!(evaluate("btrim('  hi  ', '')"), s("  hi  "));
    }

    #[test]
    fn btrim_function_null_and_errors() {
        assert_eq!(evaluate("btrim(null)"), Value::Null);
        assert_eq!(evaluate("btrim(null, 'x')"), Value::Null);
        // A null trim-character set propagates null.
        assert_eq!(evaluate("btrim('hi', null)"), Value::Null);
        assert!(eval_in(&MemGraph::new(), &Row::empty(), "btrim(1)").is_err());
    }

    #[test]
    fn exists_function_on_property_access() {
        let (g, row) = graph_with_node_and_rel();
        // The node has `name`; a present, non-null property exists.
        assert_eq!(eval_in(&g, &row, "exists(n.name)").unwrap(), b(true).into());
        // A missing property does not exist (boolean-total: false, not null).
        assert_eq!(
            eval_in(&g, &row, "exists(n.missing)").unwrap(),
            b(false).into()
        );
        // A relationship property likewise.
        assert_eq!(eval_in(&g, &row, "exists(r.k)").unwrap(), b(true).into());
        assert_eq!(
            eval_in(&g, &row, "exists(r.nope)").unwrap(),
            b(false).into()
        );
        // A null base (`exists(<null>.prop)`) is false — the property access is null.
        assert_eq!(evaluate("exists(null)"), b(false));
    }

    #[test]
    fn within_bbox_function_end_to_end() {
        // Cartesian containment through the function-call path (constructor + withinBBox).
        assert_eq!(
            evaluate("point.withinBBox(point({x:5,y:5}), point({x:0,y:0}), point({x:10,y:10}))"),
            b(true)
        );
        assert_eq!(
            evaluate("point.withinBBox(point({x:11,y:5}), point({x:0,y:0}), point({x:10,y:10}))"),
            b(false)
        );
        // Any null argument -> null.
        assert_eq!(
            evaluate("point.withinBBox(null, point({x:0,y:0}), point({x:10,y:10}))"),
            Value::Null
        );
    }
}
