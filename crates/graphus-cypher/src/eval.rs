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

use crate::ast::{BinaryOp, CaseExpr, Expr, ExprKind, Literal, MapKey, PredicateOp, UnaryOp};
use crate::binding::BoundParameters;
use crate::equality::{equals, is_in};
use crate::function_registry::FunctionRegistry;
use crate::graph_access::GraphAccess;
use crate::lexer::IntLiteral;
use crate::ordering::compare_values;
use crate::runtime::{NodeRef, PathStep, PathValue, RelRef, Row, RowValue};
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
    /// argument of `percentileCont`/`percentileDisc`, which must lie in `[0.0, 1.0]`. Maps to the
    /// Bolt/TCK `ArgumentError` class with the `NumberOutOfRange` detail (the same class an
    /// invalid-argument runtime failure takes).
    NumberOutOfRange {
        /// The offending value, pre-formatted for the diagnostic message (kept as a `String` so the
        /// error type stays `Eq`).
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
                write!(f, "number out of range: {value} is not in [0.0, 1.0]")
            }
            Self::ExtensionFunction { name, message } => {
                write!(f, "function `{name}` failed: {message}")
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
) -> EvalResult {
    match &expr.kind {
        ExprKind::Literal(lit) => literal_value(lit).map(RowValue::Value),
        ExprKind::Parameter(name) => Ok(RowValue::Value(
            params.get(name).cloned().unwrap_or(Value::Null),
        )),
        ExprKind::Variable(name) => Ok(row.get(name).cloned().unwrap_or(RowValue::NULL)),

        ExprKind::Binary { op, lhs, rhs } => {
            eval_binary(*op, lhs, rhs, row, params, graph, functions)
        }
        ExprKind::Unary { op, operand } => eval_unary(*op, operand, row, params, graph, functions),
        ExprKind::Predicate { op, operand, rhs } => {
            eval_predicate(*op, operand, rhs.as_deref(), row, params, graph, functions)
        }

        ExprKind::Property { base, key } => eval_property(base, key, row, params, graph, functions),
        ExprKind::Index { base, index } => eval_index(base, index, row, params, graph, functions),
        ExprKind::Slice { base, low, high } => eval_slice(
            base,
            low.as_deref(),
            high.as_deref(),
            row,
            params,
            graph,
            functions,
        ),
        ExprKind::HasLabels { operand, labels } => {
            let base = eval(operand, row, params, graph, functions)?;
            let names: Vec<&str> = labels.iter().map(|l| l.name.as_str()).collect();
            Ok(ternary_value(has_labels(&base, &names, graph)))
        }

        ExprKind::FunctionCall {
            name,
            distinct: _,
            args,
        } => call_function(&name.join("."), args, row, params, graph, functions),
        // `count(*)` only appears as an aggregate (handled by the Aggregation operator); reaching
        // here as a scalar would be a planner bug, so produce a typed runtime error rather than panic.
        ExprKind::CountStar => Err(EvalError::TypeError {
            context: "count(*) is an aggregate and cannot be evaluated per row".to_owned(),
        }),

        ExprKind::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(eval(it, row, params, graph, functions)?);
            }
            // Canonical list construction: stays structural iff any element is (node/rel/path).
            Ok(RowValue::list(out))
        }
        ExprKind::Map(entries) => {
            let mut out = Vec::with_capacity(entries.len());
            for (MapKey { name, .. }, v) in entries {
                out.push((name.clone(), eval(v, row, params, graph, functions)?));
            }
            // Canonical map construction: stays structural iff any value is (node/rel/path/structural
            // collection), so `{key: u}.key` recovers the node for `DELETE` (Delete5.feature).
            Ok(RowValue::map(out))
        }

        ExprKind::Case(case) => eval_case(case, row, params, graph, functions),

        ExprKind::ListComprehension(lc) => {
            eval_list_comprehension(lc, row, params, graph, functions)
        }
        ExprKind::PatternComprehension(pc) => {
            eval_pattern_comprehension(pc, row, params, graph, functions)
        }
        ExprKind::Quantifier(q) => eval_quantifier(q, row, params, graph, functions),
        ExprKind::ExistsSubquery(ex) => eval_exists_subquery(ex, row, params, graph, functions),
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
) -> Result<Value, EvalError> {
    Ok(to_value(eval(expr, row, params, graph, functions)?))
}

/// Collapses a [`RowValue`] to a property [`Value`]. An entity reference has **no** property value,
/// so it becomes `Null` in a value context (it is only meaningful as a structural row binding).
fn to_value(rv: RowValue) -> Value {
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
        Literal::Integer(IntLiteral { value, .. }) => i64::try_from(*value)
            .map(Value::Integer)
            .map_err(|_| EvalError::IntegerOverflow),
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
) -> Result<Ternary, EvalError> {
    match eval(expr, row, params, graph, functions)? {
        RowValue::Value(Value::Boolean(b)) => Ok(Ternary::from_bool(b)),
        RowValue::Value(Value::Null) => Ok(Ternary::Null),
        other => Err(EvalError::TypeError {
            context: format!("expected a boolean predicate, got {}", describe(&other)),
        }),
    }
}

/// Evaluates a binary operator (`04 §7.6` for comparisons/logic; arithmetic by Cypher numeric rules).
fn eval_binary(
    op: BinaryOp,
    lhs: &Expr,
    rhs: &Expr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
) -> EvalResult {
    match op {
        // ---- boolean connectives (Kleene 3VL via Ternary) ------------------------------------
        BinaryOp::And => {
            let a = eval_to_ternary(lhs, row, params, graph, functions)?;
            // Short-circuit FALSE without evaluating rhs is sound; but to surface a rhs type error
            // consistently we evaluate rhs too unless `a` already settles it to FALSE.
            if a == Ternary::False {
                return Ok(ternary_value(Ternary::False));
            }
            let b = eval_to_ternary(rhs, row, params, graph, functions)?;
            Ok(ternary_value(a.and(b)))
        }
        BinaryOp::Or => {
            let a = eval_to_ternary(lhs, row, params, graph, functions)?;
            if a == Ternary::True {
                return Ok(ternary_value(Ternary::True));
            }
            let b = eval_to_ternary(rhs, row, params, graph, functions)?;
            Ok(ternary_value(a.or(b)))
        }
        BinaryOp::Xor => {
            let a = eval_to_ternary(lhs, row, params, graph, functions)?;
            let b = eval_to_ternary(rhs, row, params, graph, functions)?;
            Ok(ternary_value(a.xor(b)))
        }

        // ---- equality / comparison (reuse the value-model semantics) -------------------------
        BinaryOp::Eq => {
            let a = eval(lhs, row, params, graph, functions)?;
            let b = eval(rhs, row, params, graph, functions)?;
            Ok(ternary_value(row_values_equal(&a, &b)))
        }
        BinaryOp::Neq => {
            let a = eval(lhs, row, params, graph, functions)?;
            let b = eval(rhs, row, params, graph, functions)?;
            Ok(ternary_value(!row_values_equal(&a, &b)))
        }
        BinaryOp::Lt | BinaryOp::Gt | BinaryOp::Lte | BinaryOp::Gte => {
            let (a, b) = eval_pair(lhs, rhs, row, params, graph, functions)?;
            Ok(ternary_value(compare(op, &a, &b)))
        }
        BinaryOp::RegexMatch => {
            // Regex is a documented deferral (no regex engine dependency in v1).
            Err(EvalError::UnsupportedFunction {
                name: "=~ (regex match)".to_owned(),
            })
        }

        // ---- arithmetic ----------------------------------------------------------------------
        BinaryOp::Add => {
            // Evaluate **structurally** first: `+` is also list concatenation, and a list of nodes /
            // relationships / paths must keep its structural elements (collapsing through a property
            // `Value` would turn each entity into `Null` — `[a] + collect(n) + [b]`). When either
            // operand is a structural list we concatenate at the `RowValue` level; otherwise we defer
            // to the scalar/property `+` (numeric add, string concat, property-list concat).
            let a = eval(lhs, row, params, graph, functions)?;
            let b = eval(rhs, row, params, graph, functions)?;
            if let Some(out) = structural_list_add(&a, &b) {
                return Ok(out);
            }
            arithmetic_add(&to_value(a), &to_value(b))
        }
        BinaryOp::Sub => {
            let (a, b) = eval_pair(lhs, rhs, row, params, graph, functions)?;
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
            let (a, b) = eval_pair(lhs, rhs, row, params, graph, functions)?;
            if a.is_null() || b.is_null() {
                return Ok(RowValue::NULL);
            }
            // Temporal `*`: duration * number (commutative) (rmp #53).
            if let Some(r) = crate::temporal_fns::mul(&a, &b) {
                return r.map(RowValue::Value);
            }
            numeric_binop_values(&a, &b, |x, y| x * y, i64::checked_mul)
        }
        BinaryOp::Div => eval_div(lhs, rhs, row, params, graph, functions),
        BinaryOp::Mod => eval_mod(lhs, rhs, row, params, graph, functions),
        BinaryOp::Pow => {
            let (a, b) = eval_pair(lhs, rhs, row, params, graph, functions)?;
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
) -> Result<(Value, Value), EvalError> {
    Ok((
        eval_value(lhs, row, params, graph, functions)?,
        eval_value(rhs, row, params, graph, functions)?,
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

/// Whether a value is a Cypher number (`INTEGER` or `FLOAT`, including `NaN`).
fn is_numeric(v: &Value) -> bool {
    matches!(v, Value::Integer(_) | Value::Float(_))
}

fn is_nan(v: &Value) -> bool {
    matches!(v, Value::Float(f) if f.is_nan())
}

/// Structural list concatenation for `+` when a **structural** list (one holding a node /
/// relationship / path) is involved. Returns `Some(result)` when at least one operand is a
/// structural [`RowValue::List`], handling `list + list`, `list + element` and `element + list` while
/// preserving entity references; returns `None` to defer to the scalar/property `+` (numeric add,
/// string concat, pure-property list concat) when no structural list participates.
///
/// `null + x` / `x + null` is **not** handled here (it is value-level null propagation), so a null
/// operand makes this return `None` and the property path produces null.
fn structural_list_add(a: &RowValue, b: &RowValue) -> Option<RowValue> {
    let a_struct_list = matches!(a, RowValue::List(_));
    let b_struct_list = matches!(b, RowValue::List(_));
    if !a_struct_list && !b_struct_list {
        return None;
    }
    // Borrow each operand as list elements when it is list-shaped (structural or property), else
    // treat it as a single element to append/prepend (Cypher's `list + element`).
    fn elems_or_single(v: &RowValue) -> Vec<RowValue> {
        v.as_list_elems().unwrap_or_else(|| vec![v.clone()])
    }
    let mut out = elems_or_single(a);
    out.extend(elems_or_single(b));
    Some(RowValue::list(out))
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
            Ok(RowValue::Value(Value::String(format!("{x}{y}"))))
        }
        (Value::List(x), Value::List(y)) => {
            let mut out = x.clone();
            out.extend(y.iter().cloned());
            Ok(RowValue::Value(Value::List(out)))
        }
        // List + element / element + list (Cypher appends/prepends scalars).
        (Value::List(x), other) => {
            let mut out = x.clone();
            out.push(other.clone());
            Ok(RowValue::Value(Value::List(out)))
        }
        (other, Value::List(y)) => {
            let mut out = Vec::with_capacity(y.len() + 1);
            out.push(other.clone());
            out.extend(y.iter().cloned());
            Ok(RowValue::Value(Value::List(out)))
        }
        // String + number and number + string concatenate the string form (Cypher coercion).
        (Value::String(x), other) => Ok(RowValue::Value(Value::String(format!(
            "{x}{}",
            stringify_scalar(other)
        )))),
        (other, Value::String(y)) => Ok(RowValue::Value(Value::String(format!(
            "{}{y}",
            stringify_scalar(other)
        )))),
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
) -> EvalResult {
    let (a, b) = eval_pair(lhs, rhs, row, params, graph, functions)?;
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
        return Ok(RowValue::Value(Value::Integer(x / y)));
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
) -> EvalResult {
    let (a, b) = eval_pair(lhs, rhs, row, params, graph, functions)?;
    if a.is_null() || b.is_null() {
        return Ok(RowValue::NULL);
    }
    if let (Value::Integer(x), Value::Integer(y)) = (&a, &b) {
        if *y == 0 {
            return Err(EvalError::DivisionByZero);
        }
        return Ok(RowValue::Value(Value::Integer(x % y)));
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
) -> EvalResult {
    match op {
        UnaryOp::Not => {
            let t = eval_to_ternary(operand, row, params, graph, functions)?;
            Ok(ternary_value(!t))
        }
        UnaryOp::Plus => {
            let v = eval_value(operand, row, params, graph, functions)?;
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
            let v = eval_value(operand, row, params, graph, functions)?;
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
fn eval_predicate(
    op: PredicateOp,
    operand: &Expr,
    rhs: Option<&Expr>,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
) -> EvalResult {
    match op {
        PredicateOp::IsNull => {
            let v = eval(operand, row, params, graph, functions)?;
            Ok(RowValue::Value(Value::Boolean(v.is_null())))
        }
        PredicateOp::IsNotNull => {
            let v = eval(operand, row, params, graph, functions)?;
            Ok(RowValue::Value(Value::Boolean(!v.is_null())))
        }
        PredicateOp::In => {
            let value = eval_value(operand, row, params, graph, functions)?;
            let list = match rhs {
                Some(r) => eval_value(r, row, params, graph, functions)?,
                None => Value::Null,
            };
            Ok(ternary_value(is_in(&value, &list)))
        }
        PredicateOp::StartsWith | PredicateOp::EndsWith | PredicateOp::Contains => {
            let a = eval_value(operand, row, params, graph, functions)?;
            let b = match rhs {
                Some(r) => eval_value(r, row, params, graph, functions)?,
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
                _ => Err(EvalError::TypeError {
                    context: "string predicate requires string operands".to_owned(),
                }),
            }
        }
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
) -> EvalResult {
    match eval(base, row, params, graph, functions)? {
        RowValue::Node(NodeRef { id }) => Ok(RowValue::Value(
            graph.node_property(id, key).unwrap_or(Value::Null),
        )),
        RowValue::Rel(RelRef { id }) => Ok(RowValue::Value(
            graph.rel_property(id, key).unwrap_or(Value::Null),
        )),
        RowValue::Value(Value::Map(entries)) => Ok(RowValue::Value(
            entries
                .into_iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .unwrap_or(Value::Null),
        )),
        // A structural map keeps its values at the `RowValue` level, so `m.key` recovers the
        // node/relationship/path reference (or nested structural collection) the map holds — the
        // property-map arm above only handles pure-property maps (Delete5.feature).
        RowValue::Map(entries) => Ok(entries
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .unwrap_or(RowValue::NULL)),
        // Point component access: `p.x`, `p.longitude`, `p.crs`, `p.srid`, … (rmp #73).
        RowValue::Value(Value::Point(p)) => Ok(RowValue::Value(
            crate::spatial_fns::component(&p, key).unwrap_or(Value::Null),
        )),
        // Temporal component access: `d.year`, `t.hour`, `dur.minutesOfHour`, … (rmp #53).
        // A non-temporal (incl. null) base yields null, Cypher's missing-property rule.
        RowValue::Value(v) => Ok(RowValue::Value(
            crate::temporal_fns::component(&v, key).unwrap_or(Value::Null),
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
) -> EvalResult {
    let base = eval(base, row, params, graph, functions)?;
    let idx = eval_value(index, row, params, graph, functions)?;
    if base.is_null() || idx.is_null() {
        return Ok(RowValue::NULL);
    }
    // Dynamic property access: a node/relationship indexed by a string key reads that property
    // (`n['name']`; `expressions/graph/Graph7.feature`), exactly like the static `n.name` form.
    match (&base, &idx) {
        (RowValue::Node(NodeRef { id }), Value::String(k)) => {
            return Ok(RowValue::Value(
                graph.node_property(*id, k).unwrap_or(Value::Null),
            ));
        }
        (RowValue::Rel(RelRef { id }), Value::String(k)) => {
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
fn eval_slice(
    base: &Expr,
    low: Option<&Expr>,
    high: Option<&Expr>,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
) -> EvalResult {
    let base = eval_value(base, row, params, graph, functions)?;
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
            Some(e) => match eval_value(e, row, params, graph, functions)? {
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
) -> EvalResult {
    match &case.subject {
        // Simple CASE: compare the subject against each WHEN value with Cypher `=`.
        Some(subject) => {
            let subj = eval_value(subject, row, params, graph, functions)?;
            for alt in &case.alternatives {
                let when = eval_value(&alt.when, row, params, graph, functions)?;
                if equals(&subj, &when).is_true() {
                    return eval(&alt.then, row, params, graph, functions);
                }
            }
        }
        // Searched CASE: each WHEN is a predicate; the first TRUE wins.
        None => {
            for alt in &case.alternatives {
                if eval_to_ternary(&alt.when, row, params, graph, functions)?.is_true() {
                    return eval(&alt.then, row, params, graph, functions);
                }
            }
        }
    }
    match &case.else_expr {
        Some(e) => eval(e, row, params, graph, functions),
        None => Ok(RowValue::NULL),
    }
}

/// Tests whether `base` (a node/rel reference) carries **all** of `labels` (3VL: null → NULL).
fn has_labels(base: &RowValue, labels: &[&str], graph: &dyn GraphAccess) -> Ternary {
    match base {
        RowValue::Node(NodeRef { id }) => match graph.node_labels(*id) {
            Some(node_labels) => {
                Ternary::from_bool(labels.iter().all(|l| node_labels.iter().any(|nl| nl == l)))
            }
            None => Ternary::False,
        },
        RowValue::Value(Value::Null) => Ternary::Null,
        // Label predicate on a non-node is FALSE (it has no labels).
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
        other => describe(&RowValue::Value(other.clone())),
    }
}

/// A short type description for diagnostics.
fn describe(v: &RowValue) -> String {
    match v {
        RowValue::Node(_) => "Node".to_owned(),
        RowValue::Rel(_) => "Relationship".to_owned(),
        RowValue::Path(_) => "Path".to_owned(),
        RowValue::List(_) => "List".to_owned(),
        RowValue::Map(_) => "Map".to_owned(),
        RowValue::Value(v) => match v {
            Value::Null => "null".to_owned(),
            Value::Boolean(_) => "Boolean".to_owned(),
            Value::Integer(_) => "Integer".to_owned(),
            Value::Float(_) => "Float".to_owned(),
            Value::String(_) => "String".to_owned(),
            Value::Bytes(_) => "Bytes".to_owned(),
            Value::List(_) => "List".to_owned(),
            Value::Map(_) => "Map".to_owned(),
            _ => "Temporal".to_owned(),
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
) -> EvalResult {
    let lower = name.to_ascii_lowercase();

    // `coalesce` is special: it returns its first non-null argument, evaluated left to right.
    if lower == "coalesce" {
        for a in args {
            let v = eval(a, row, params, graph, functions)?;
            if !v.is_null() {
                return Ok(v);
            }
        }
        return Ok(RowValue::NULL);
    }

    // Entity functions take the un-collapsed RowValue (they need the reference).
    match lower.as_str() {
        "id" => {
            let v = eval(&args[0], row, params, graph, functions)?;
            return Ok(match v {
                RowValue::Node(NodeRef { id }) => RowValue::Value(Value::Integer(id.0 as i64)),
                RowValue::Rel(RelRef { id }) => RowValue::Value(Value::Integer(id.0 as i64)),
                _ => RowValue::NULL,
            });
        }
        "labels" => {
            let v = eval(&args[0], row, params, graph, functions)?;
            return match v {
                RowValue::Node(NodeRef { id }) => Ok(RowValue::Value(Value::List(
                    graph
                        .node_labels(id)
                        .unwrap_or_default()
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                ))),
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
            let v = eval(&args[0], row, params, graph, functions)?;
            return match v {
                RowValue::Rel(RelRef { id }) => Ok(graph
                    .rel_data(id)
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
            let v = eval(&args[0], row, params, graph, functions)?;
            return Ok(match v {
                RowValue::Node(NodeRef { id }) => map_from_props(graph.node_properties(id)),
                RowValue::Rel(RelRef { id }) => map_from_props(graph.rel_properties(id)),
                RowValue::Value(m @ Value::Map(_)) => RowValue::Value(m),
                _ => RowValue::NULL,
            });
        }
        "keys" => {
            let v = eval(&args[0], row, params, graph, functions)?;
            return Ok(match v {
                RowValue::Node(NodeRef { id }) => keys_list(graph.node_properties(id)),
                RowValue::Rel(RelRef { id }) => keys_list(graph.rel_properties(id)),
                RowValue::Value(Value::Map(entries)) => RowValue::Value(Value::List(
                    entries.into_iter().map(|(k, _)| Value::String(k)).collect(),
                )),
                _ => RowValue::NULL,
            });
        }
        "startnode" => {
            let v = eval(&args[0], row, params, graph, functions)?;
            return Ok(match v {
                RowValue::Rel(RelRef { id }) => graph
                    .rel_data(id)
                    .map(|d| RowValue::Node(NodeRef { id: d.start }))
                    .unwrap_or(RowValue::NULL),
                _ => RowValue::NULL,
            });
        }
        "endnode" => {
            let v = eval(&args[0], row, params, graph, functions)?;
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
            let v = eval(&args[0], row, params, graph, functions)?;
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
            let v = eval(&args[0], row, params, graph, functions)?;
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
        "size" | "length" => {
            let v = eval(&args[0], row, params, graph, functions)?;
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
            let v = eval(&args[0], row, params, graph, functions)?;
            let Some(mut items) = v.as_list_elems() else {
                return match v {
                    RowValue::Value(Value::Null) => Ok(RowValue::NULL),
                    _ => Err(EvalError::TypeError {
                        context: "expected a list argument".to_owned(),
                    }),
                };
            };
            return Ok(match lower.as_str() {
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
            let v = eval(&args[0], row, params, graph, functions)?;
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
            let v = eval(&args[0], row, params, graph, functions)?;
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
        "tointeger" | "tofloat" | "tostring" | "toboolean" | "tobooleanornull" => {
            let v = eval(&args[0], row, params, graph, functions)?;
            return convert_scalar(&lower, v).map(RowValue::Value);
        }
        _ => {}
    }

    // The remaining functions operate on collapsed property values.
    let argv: Vec<Value> = args
        .iter()
        .map(|a| eval_value(a, row, params, graph, functions))
        .collect::<Result<_, _>>()?;

    let result = match lower.as_str() {
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
        | "time.realtime" => crate::temporal_fns::construct(&lower, argv.first())?,
        // Spatial point constructor and distance (rmp #73). `distance` and `point.distance` are
        // the two openCypher spellings of the same two-point distance.
        "point" => crate::spatial_fns::construct_point(&argv[0])?,
        "distance" | "point.distance" => crate::spatial_fns::distance(&argv[0], &argv[1])?,
        // Temporal difference and truncation functions (rmp #53).
        "duration.between" | "duration.inmonths" | "duration.indays" | "duration.inseconds" => {
            crate::temporal_fns::duration_between(&lower, &argv[0], &argv[1])?
        }
        "date.truncate"
        | "time.truncate"
        | "localtime.truncate"
        | "datetime.truncate"
        | "localdatetime.truncate" => {
            crate::temporal_fns::truncate(&lower, &argv[0], &argv[1], argv.get(2))?
        }
        "range" => range_fn(&argv)?,
        "abs" => match &argv[0] {
            Value::Integer(i) => i
                .checked_abs()
                .map(Value::Integer)
                .ok_or(EvalError::IntegerOverflow)?,
            Value::Float(f) => Value::Float(f.abs()),
            Value::Null => Value::Null,
            _ => return Err(num_type_error("abs")),
        },
        "ceil" => float_unary(&argv[0], f64::ceil, "ceil")?,
        "floor" => float_unary(&argv[0], f64::floor, "floor")?,
        "round" => float_unary(&argv[0], f64::round, "round")?,
        // `sqrt()` of a negative number is NaN (IEEE 754, which the openCypher Float is).
        "sqrt" => float_unary(&argv[0], f64::sqrt, "sqrt")?,
        "rand" => Value::Float(next_rand_f64()),
        "sign" => match &argv[0] {
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
        "toupper" => string_unary(&argv[0], |s| s.to_uppercase(), "toUpper")?,
        "tolower" => string_unary(&argv[0], |s| s.to_lowercase(), "toLower")?,
        "trim" => string_unary(&argv[0], |s| s.trim().to_owned(), "trim")?,
        "ltrim" => string_unary(&argv[0], |s| s.trim_start().to_owned(), "ltrim")?,
        "rtrim" => string_unary(&argv[0], |s| s.trim_end().to_owned(), "rtrim")?,
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

fn map_from_props(props: Option<Vec<(String, Value)>>) -> RowValue {
    match props {
        Some(p) => RowValue::Value(Value::Map(p)),
        None => RowValue::NULL,
    }
}

fn keys_list(props: Option<Vec<(String, Value)>>) -> RowValue {
    match props {
        Some(p) => RowValue::Value(Value::List(
            p.into_iter().map(|(k, _)| Value::String(k)).collect(),
        )),
        None => RowValue::NULL,
    }
}

fn num_type_error(fname: &str) -> EvalError {
    EvalError::TypeError {
        context: format!("{fname}() requires a number"),
    }
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
        // Unreachable: the caller dispatches only the five conversion spellings.
        _ => Err(EvalError::TypeError {
            context: format!("{lower}() is not a scalar conversion"),
        }),
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
        Value::Float(f) => Value::Integer(*f as i64),
        Value::String(s) => {
            let t = s.trim();
            // Try an exact integer first (preserves full `i64` range that an `f64` round-trip would
            // lose); fall back to a float parse and truncate (`toInteger('1.7') = 1`,
            // `toInteger('2.9') = 2`). A non-numeric string (`'foo'`, `''`) is `null`.
            t.parse::<i64>()
                .map(Value::Integer)
                .or_else(|_| t.parse::<f64>().map(|f| Value::Integer(f as i64)))
                .unwrap_or(Value::Null)
        }
        Value::Boolean(_) | Value::Null => Value::Null,
        // `convert_scalar` has already rejected the structural cases; any residual is `null`.
        _ => Value::Null,
    })
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

fn string_unary(v: &Value, f: impl Fn(&str) -> String, fname: &str) -> Result<Value, EvalError> {
    match v {
        Value::String(s) => Ok(Value::String(f(s))),
        Value::Null => Ok(Value::Null),
        _ => Err(EvalError::TypeError {
            context: format!("{fname}() requires a string"),
        }),
    }
}

/// `range(start, end[, step])` — an inclusive integer range (openCypher).
fn range_fn(argv: &[Value]) -> Result<Value, EvalError> {
    let int = |v: &Value| match v {
        Value::Integer(i) => Ok(*i),
        _ => Err(EvalError::TypeError {
            context: "range() requires integer arguments".to_owned(),
        }),
    };
    let start = int(&argv[0])?;
    let end = int(&argv[1])?;
    let step = if argv.len() > 2 { int(&argv[2])? } else { 1 };
    if step == 0 {
        return Err(EvalError::TypeError {
            context: "range() step must be non-zero".to_owned(),
        });
    }
    let mut out = Vec::new();
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
    let Value::String(s) = &argv[0] else {
        return match &argv[0] {
            Value::Null => Ok(Value::Null),
            _ => Err(EvalError::TypeError {
                context: "substring() requires a string".to_owned(),
            }),
        };
    };
    let chars: Vec<char> = s.chars().collect();
    let start = match &argv[1] {
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
    match (&argv[0], &argv[1], &argv[2]) {
        (Value::String(s), Value::String(search), Value::String(rep)) => {
            Ok(Value::String(s.replace(search.as_str(), rep)))
        }
        (Value::Null, _, _) | (_, Value::Null, _) | (_, _, Value::Null) => Ok(Value::Null),
        _ => Err(EvalError::TypeError {
            context: "replace() requires string arguments".to_owned(),
        }),
    }
}

/// `split(s, delimiter)` (openCypher).
fn split_fn(argv: &[Value]) -> Result<Value, EvalError> {
    match (&argv[0], &argv[1]) {
        (Value::String(s), Value::String(delim)) => {
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
    match (&argv[0], &argv[1]) {
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
) -> EvalResult {
    let items = eval_to_list_items(
        &lc.list,
        "list comprehension",
        row,
        params,
        graph,
        functions,
    )?;
    let Some(items) = items else {
        return Ok(RowValue::NULL);
    };
    let mut out = Vec::new();
    for item in items {
        let inner = row.with(lc.variable.name.clone(), item.clone());
        if let Some(pred) = &lc.predicate {
            if !eval_to_ternary(pred, &inner, params, graph, functions)?.is_true() {
                continue;
            }
        }
        match &lc.projection {
            Some(proj) => out.push(eval(proj, &inner, params, graph, functions)?),
            None => out.push(item),
        }
    }
    Ok(RowValue::list(out))
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
) -> Result<Option<Vec<RowValue>>, EvalError> {
    let v = eval(list, row, params, graph, functions)?;
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
) -> EvalResult {
    use crate::ast::QuantifierKind;
    let items = eval_to_list_items(&q.list, "quantifier", row, params, graph, functions)?;
    let Some(items) = items else {
        return Ok(RowValue::NULL);
    };
    let yes = || Ok(RowValue::Value(Value::Boolean(true)));
    let no = || Ok(RowValue::Value(Value::Boolean(false)));
    let mut trues = 0usize;
    let mut nulls = 0usize;
    for item in items {
        let inner = row.with(q.variable.name.clone(), item);
        match eval_to_ternary(&q.predicate, &inner, params, graph, functions)? {
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

/// Evaluates a pattern comprehension `[(a)-[r]->(b) WHERE p | e]`: match the pattern seeded by the
/// outer row's bindings, filter by the predicate (3VL), and project each match into the list.
fn eval_pattern_comprehension(
    pc: &crate::ast::PatternComprehension,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
) -> EvalResult {
    // A named path (`[p = (a)-->(b) | p]`) binds the path variable for the predicate/projection.
    let path_var = pc.var.as_ref().map(|v| v.name.as_str());
    let matches =
        pattern_element_rows(&pc.element, row, params, graph, functions, false, path_var)?;
    let mut out = Vec::new();
    for m in matches {
        if let Some(pred) = &pc.predicate {
            if !eval_to_ternary(pred, &m, params, graph, functions)?.is_true() {
                continue;
            }
        }
        out.push(eval(&pc.projection, &m, params, graph, functions)?);
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
) -> EvalResult {
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
                if eval_to_ternary(pred, r, params, graph, functions)?.is_true() {
                    return Ok(RowValue::Value(Value::Boolean(true)));
                }
            }
            Ok(RowValue::Value(Value::Boolean(false)))
        }
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
fn pattern_element_rows(
    element: &crate::ast::PatternElement,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    functions: &dyn FunctionRegistry,
    first_only: bool,
    path_var: Option<&str>,
) -> Result<Vec<Row>, EvalError> {
    let mut results = Vec::new();
    for start in node_candidates(&element.start, row, params, graph, functions)? {
        let mut seeded = row.clone();
        if let Some(v) = &element.start.variable {
            seeded.set(v.name.clone(), RowValue::Node(NodeRef { id: start }));
        }
        let cctx = ChainCtx {
            params,
            graph,
            functions,
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
    let (params, graph, functions) = (cctx.params, cctx.graph, cctx.functions);
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
            if !rel_props_match(inc.rel, props, &row, params, graph, functions)? {
                continue;
            }
        }
        // Target node: label/property filters plus the identity constraint when already bound.
        if !node_matches(inc.neighbour, &link.node, &row, params, graph, functions)? {
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
    let (params, graph, functions) = (cctx.params, cctx.graph, cctx.functions);
    let link = &chain[idx];
    let min = range.min.unwrap_or(1);
    // Complete the link at this depth if allowed and the far node satisfies the target pattern.
    if depth >= min && node_matches(current, &link.node, &row, params, graph, functions)? {
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
            if !rel_props_match(inc.rel, props, &row, params, graph, functions)? {
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
) -> Result<Vec<crate::graph_access::NodeId>, EvalError> {
    if let Some(v) = &np.variable {
        if let Some(rv) = row.get(&v.name) {
            return match rv {
                RowValue::Node(n) if node_matches(n.id, np, row, params, graph, functions)? => {
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
        if node_matches(id, np, row, params, graph, functions)? {
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
        let entries = eval_props_map(props, row, params, graph, functions)?;
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
) -> Result<bool, EvalError> {
    let entries = eval_props_map(props, row, params, graph, functions)?;
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
) -> Result<Vec<(String, Value)>, EvalError> {
    match eval_value(props, row, params, graph, functions)? {
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
        to_value(eval(&expr, &Row::empty(), &bound, &g, no_functions()).unwrap())
    }

    /// Evaluates `src` against `graph` with `row` in scope, returning the raw [`EvalResult`] so a
    /// test can assert on the `RowValue` structure or a runtime error.
    fn eval_in(graph: &dyn GraphAccess, row: &Row, src: &str) -> EvalResult {
        let expr = parse_expr(src);
        eval(&expr, row, &BoundParameters::empty(), graph, no_functions())
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

    #[test]
    fn parameter_lookup() {
        let expr = parse_expr("$p + 1");
        let g = MemGraph::new();
        let bound = bind(&Parameters::new().with("p", Value::Integer(10)), &expr);
        assert_eq!(
            to_value(eval(&expr, &Row::empty(), &bound, &g, no_functions()).unwrap()),
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
        eval(&expr, &Row::empty(), &BoundParameters::empty(), &g, set)
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
}
