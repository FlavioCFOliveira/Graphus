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

use std::fmt;

use graphus_core::Value;

use crate::ast::{BinaryOp, CaseExpr, Expr, ExprKind, Literal, MapKey, PredicateOp, UnaryOp};
use crate::binding::BoundParameters;
use crate::equality::{equals, is_in, not_equals};
use crate::graph_access::GraphAccess;
use crate::lexer::IntLiteral;
use crate::ordering::cmp_values;
use crate::runtime::{NodeRef, RelRef, Row, RowValue};
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
) -> EvalResult {
    match &expr.kind {
        ExprKind::Literal(lit) => literal_value(lit).map(RowValue::Value),
        ExprKind::Parameter(name) => Ok(RowValue::Value(
            params.get(name).cloned().unwrap_or(Value::Null),
        )),
        ExprKind::Variable(name) => Ok(row.get(name).cloned().unwrap_or(RowValue::NULL)),

        ExprKind::Binary { op, lhs, rhs } => eval_binary(*op, lhs, rhs, row, params, graph),
        ExprKind::Unary { op, operand } => eval_unary(*op, operand, row, params, graph),
        ExprKind::Predicate { op, operand, rhs } => {
            eval_predicate(*op, operand, rhs.as_deref(), row, params, graph)
        }

        ExprKind::Property { base, key } => eval_property(base, key, row, params, graph),
        ExprKind::Index { base, index } => eval_index(base, index, row, params, graph),
        ExprKind::Slice { base, low, high } => {
            eval_slice(base, low.as_deref(), high.as_deref(), row, params, graph)
        }
        ExprKind::HasLabels { operand, labels } => {
            let base = eval(operand, row, params, graph)?;
            let names: Vec<&str> = labels.iter().map(|l| l.name.as_str()).collect();
            Ok(ternary_value(has_labels(&base, &names, graph)))
        }

        ExprKind::FunctionCall {
            name,
            distinct: _,
            args,
        } => call_function(&name.join("."), args, row, params, graph),
        // `count(*)` only appears as an aggregate (handled by the Aggregation operator); reaching
        // here as a scalar would be a planner bug, so produce a typed runtime error rather than panic.
        ExprKind::CountStar => Err(EvalError::TypeError {
            context: "count(*) is an aggregate and cannot be evaluated per row".to_owned(),
        }),

        ExprKind::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(to_value(eval(it, row, params, graph)?, graph));
            }
            Ok(RowValue::Value(Value::List(out)))
        }
        ExprKind::Map(entries) => {
            let mut out = Vec::with_capacity(entries.len());
            for (MapKey { name, .. }, v) in entries {
                out.push((name.clone(), to_value(eval(v, row, params, graph)?, graph)));
            }
            Ok(RowValue::Value(Value::Map(out)))
        }

        ExprKind::Case(case) => eval_case(case, row, params, graph),

        ExprKind::ListComprehension(lc) => eval_list_comprehension(lc, row, params, graph),
        ExprKind::PatternComprehension(pc) => eval_pattern_comprehension(pc, row, params, graph),
        ExprKind::Quantifier(q) => eval_quantifier(q, row, params, graph),
        ExprKind::ExistsSubquery(ex) => eval_exists_subquery(ex, row, params, graph),
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
) -> Result<Value, EvalError> {
    Ok(to_value(eval(expr, row, params, graph)?, graph))
}

/// Collapses a [`RowValue`] to a property [`Value`]. An entity reference has **no** property value,
/// so it becomes `Null` in a value context (it is only meaningful as a structural row binding).
fn to_value(rv: RowValue, _graph: &dyn GraphAccess) -> Value {
    match rv {
        RowValue::Value(v) => v,
        // An entity in a pure value context is not a property value; collapse to null. (Structural
        // comparison/ordering uses RowValue directly via the runtime helpers, not this path.)
        RowValue::Node(_) | RowValue::Rel(_) => Value::Null,
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
) -> Result<Ternary, EvalError> {
    match eval(expr, row, params, graph)? {
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
) -> EvalResult {
    match op {
        // ---- boolean connectives (Kleene 3VL via Ternary) ------------------------------------
        BinaryOp::And => {
            let a = eval_to_ternary(lhs, row, params, graph)?;
            // Short-circuit FALSE without evaluating rhs is sound; but to surface a rhs type error
            // consistently we evaluate rhs too unless `a` already settles it to FALSE.
            if a == Ternary::False {
                return Ok(ternary_value(Ternary::False));
            }
            let b = eval_to_ternary(rhs, row, params, graph)?;
            Ok(ternary_value(a.and(b)))
        }
        BinaryOp::Or => {
            let a = eval_to_ternary(lhs, row, params, graph)?;
            if a == Ternary::True {
                return Ok(ternary_value(Ternary::True));
            }
            let b = eval_to_ternary(rhs, row, params, graph)?;
            Ok(ternary_value(a.or(b)))
        }
        BinaryOp::Xor => {
            let a = eval_to_ternary(lhs, row, params, graph)?;
            let b = eval_to_ternary(rhs, row, params, graph)?;
            Ok(ternary_value(a.xor(b)))
        }

        // ---- equality / comparison (reuse the value-model semantics) -------------------------
        BinaryOp::Eq => {
            let (a, b) = eval_pair(lhs, rhs, row, params, graph)?;
            Ok(ternary_value(equals(&a, &b)))
        }
        BinaryOp::Neq => {
            let (a, b) = eval_pair(lhs, rhs, row, params, graph)?;
            Ok(ternary_value(not_equals(&a, &b)))
        }
        BinaryOp::Lt | BinaryOp::Gt | BinaryOp::Lte | BinaryOp::Gte => {
            let (a, b) = eval_pair(lhs, rhs, row, params, graph)?;
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
            let (a, b) = eval_pair(lhs, rhs, row, params, graph)?;
            arithmetic_add(&a, &b)
        }
        BinaryOp::Sub => {
            numeric_binop(lhs, rhs, row, params, graph, |x, y| x - y, i64::checked_sub)
        }
        BinaryOp::Mul => {
            numeric_binop(lhs, rhs, row, params, graph, |x, y| x * y, i64::checked_mul)
        }
        BinaryOp::Div => eval_div(lhs, rhs, row, params, graph),
        BinaryOp::Mod => eval_mod(lhs, rhs, row, params, graph),
        BinaryOp::Pow => {
            let (a, b) = eval_pair(lhs, rhs, row, params, graph)?;
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
) -> Result<(Value, Value), EvalError> {
    Ok((
        eval_value(lhs, row, params, graph)?,
        eval_value(rhs, row, params, graph)?,
    ))
}

/// The 3VL result of a `<`/`>`/`<=`/`>=` comparison: `NULL` if either side is null, else the
/// orderability ([`cmp_values`]) projected onto the operator.
fn compare(op: BinaryOp, a: &Value, b: &Value) -> Ternary {
    use std::cmp::Ordering;
    if a.is_null() || b.is_null() {
        return Ternary::Null;
    }
    // A NaN operand makes inequalities NULL (it is incomparable in Cypher's `<`/`>`), matching the
    // openCypher rule that NaN is unordered for relational comparisons.
    if is_nan(a) || is_nan(b) {
        return Ternary::Null;
    }
    let ord = cmp_values(a, b);
    let truth = match op {
        BinaryOp::Lt => ord == Ordering::Less,
        BinaryOp::Gt => ord == Ordering::Greater,
        BinaryOp::Lte => ord != Ordering::Greater,
        BinaryOp::Gte => ord != Ordering::Less,
        _ => unreachable!("compare on a non-comparison operator"),
    };
    Ternary::from_bool(truth)
}

fn is_nan(v: &Value) -> bool {
    matches!(v, Value::Float(f) if f.is_nan())
}

/// Cypher `+`: numeric addition, **or** string concatenation, **or** list concatenation, with null
/// propagation.
fn arithmetic_add(a: &Value, b: &Value) -> EvalResult {
    if a.is_null() || b.is_null() {
        return Ok(RowValue::NULL);
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

/// A numeric binary op (`-`, `*`) with integer-exact path (checked) and a float fallback; null
/// propagates.
fn numeric_binop(
    lhs: &Expr,
    rhs: &Expr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    float_op: impl Fn(f64, f64) -> f64,
    int_op: impl Fn(i64, i64) -> Option<i64>,
) -> EvalResult {
    let (a, b) = eval_pair(lhs, rhs, row, params, graph)?;
    if a.is_null() || b.is_null() {
        return Ok(RowValue::NULL);
    }
    if let (Value::Integer(x), Value::Integer(y)) = (&a, &b) {
        return int_op(*x, *y)
            .map(Value::Integer)
            .map(RowValue::Value)
            .ok_or(EvalError::IntegerOverflow);
    }
    match (numeric_f64(&a), numeric_f64(&b)) {
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
) -> EvalResult {
    let (a, b) = eval_pair(lhs, rhs, row, params, graph)?;
    if a.is_null() || b.is_null() {
        return Ok(RowValue::NULL);
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
) -> EvalResult {
    let (a, b) = eval_pair(lhs, rhs, row, params, graph)?;
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
) -> EvalResult {
    match op {
        UnaryOp::Not => {
            let t = eval_to_ternary(operand, row, params, graph)?;
            Ok(ternary_value(!t))
        }
        UnaryOp::Plus => {
            let v = eval_value(operand, row, params, graph)?;
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
            let v = eval_value(operand, row, params, graph)?;
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
) -> EvalResult {
    match op {
        PredicateOp::IsNull => {
            let v = eval(operand, row, params, graph)?;
            Ok(RowValue::Value(Value::Boolean(v.is_null())))
        }
        PredicateOp::IsNotNull => {
            let v = eval(operand, row, params, graph)?;
            Ok(RowValue::Value(Value::Boolean(!v.is_null())))
        }
        PredicateOp::In => {
            let value = eval_value(operand, row, params, graph)?;
            let list = match rhs {
                Some(r) => eval_value(r, row, params, graph)?,
                None => Value::Null,
            };
            Ok(ternary_value(is_in(&value, &list)))
        }
        PredicateOp::StartsWith | PredicateOp::EndsWith | PredicateOp::Contains => {
            let a = eval_value(operand, row, params, graph)?;
            let b = match rhs {
                Some(r) => eval_value(r, row, params, graph)?,
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
) -> EvalResult {
    match eval(base, row, params, graph)? {
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
        // Property of null is null (Cypher); property of any other value is null too.
        _ => Ok(RowValue::NULL),
    }
}

/// Evaluates `base[index]`: list element by integer index (negative indexes from the end) or map
/// value by string key; out-of-range / wrong-type yields null (Cypher).
fn eval_index(
    base: &Expr,
    index: &Expr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
) -> EvalResult {
    let base = eval_value(base, row, params, graph)?;
    let idx = eval_value(index, row, params, graph)?;
    if base.is_null() || idx.is_null() {
        return Ok(RowValue::NULL);
    }
    match (&base, &idx) {
        (Value::List(items), Value::Integer(i)) => {
            let len = items.len() as i64;
            let pos = if *i < 0 { len + *i } else { *i };
            if pos < 0 || pos >= len {
                Ok(RowValue::NULL)
            } else {
                Ok(RowValue::Value(items[pos as usize].clone()))
            }
        }
        (Value::Map(entries), Value::String(k)) => Ok(RowValue::Value(
            entries
                .iter()
                .find(|(ek, _)| ek == k)
                .map(|(_, v)| v.clone())
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
) -> EvalResult {
    let base = eval_value(base, row, params, graph)?;
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
            Some(e) => match eval_value(e, row, params, graph)? {
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
) -> EvalResult {
    match &case.subject {
        // Simple CASE: compare the subject against each WHEN value with Cypher `=`.
        Some(subject) => {
            let subj = eval_value(subject, row, params, graph)?;
            for alt in &case.alternatives {
                let when = eval_value(&alt.when, row, params, graph)?;
                if equals(&subj, &when).is_true() {
                    return eval(&alt.then, row, params, graph);
                }
            }
        }
        // Searched CASE: each WHEN is a predicate; the first TRUE wins.
        None => {
            for alt in &case.alternatives {
                if eval_to_ternary(&alt.when, row, params, graph)?.is_true() {
                    return eval(&alt.then, row, params, graph);
                }
            }
        }
    }
    match &case.else_expr {
        Some(e) => eval(e, row, params, graph),
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
/// - **type/coercion:** `tostring`, `tointeger`, `tofloat`, `coalesce`.
/// - **collection/size:** `size`, `length`, `head`, `last`, `tail`, `reverse`, `range`, `keys`.
/// - **entity:** `id`, `labels`, `type`, `properties`, `startnode`, `endnode`.
/// - **math:** `abs`, `ceil`, `floor`, `round`, `sign`.
/// - **string:** `toupper`, `tolower`, `trim`, `ltrim`, `rtrim`, `substring`, `replace`, `split`,
///   `left`, `right`.
///
/// Any other name that passed the compile-time arity check but has **no** runtime implementation
/// yet (e.g. `nodes`/`relationships` on paths, `percentilecont`, temporal constructors) returns an
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
) -> EvalResult {
    let lower = name.to_ascii_lowercase();

    // `coalesce` is special: it returns its first non-null argument, evaluated left to right.
    if lower == "coalesce" {
        for a in args {
            let v = eval(a, row, params, graph)?;
            if !v.is_null() {
                return Ok(v);
            }
        }
        return Ok(RowValue::NULL);
    }

    // Entity functions take the un-collapsed RowValue (they need the reference).
    match lower.as_str() {
        "id" => {
            let v = eval(&args[0], row, params, graph)?;
            return Ok(match v {
                RowValue::Node(NodeRef { id }) => RowValue::Value(Value::Integer(id.0 as i64)),
                RowValue::Rel(RelRef { id }) => RowValue::Value(Value::Integer(id.0 as i64)),
                _ => RowValue::NULL,
            });
        }
        "labels" => {
            let v = eval(&args[0], row, params, graph)?;
            return Ok(match v {
                RowValue::Node(NodeRef { id }) => RowValue::Value(Value::List(
                    graph
                        .node_labels(id)
                        .unwrap_or_default()
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                )),
                _ => RowValue::NULL,
            });
        }
        "type" => {
            let v = eval(&args[0], row, params, graph)?;
            return Ok(match v {
                RowValue::Rel(RelRef { id }) => graph
                    .rel_data(id)
                    .map(|d| RowValue::Value(Value::String(d.rel_type)))
                    .unwrap_or(RowValue::NULL),
                _ => RowValue::NULL,
            });
        }
        "properties" => {
            let v = eval(&args[0], row, params, graph)?;
            return Ok(match v {
                RowValue::Node(NodeRef { id }) => map_from_props(graph.node_properties(id)),
                RowValue::Rel(RelRef { id }) => map_from_props(graph.rel_properties(id)),
                RowValue::Value(m @ Value::Map(_)) => RowValue::Value(m),
                _ => RowValue::NULL,
            });
        }
        "keys" => {
            let v = eval(&args[0], row, params, graph)?;
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
            let v = eval(&args[0], row, params, graph)?;
            return Ok(match v {
                RowValue::Rel(RelRef { id }) => graph
                    .rel_data(id)
                    .map(|d| RowValue::Node(NodeRef { id: d.start }))
                    .unwrap_or(RowValue::NULL),
                _ => RowValue::NULL,
            });
        }
        "endnode" => {
            let v = eval(&args[0], row, params, graph)?;
            return Ok(match v {
                RowValue::Rel(RelRef { id }) => graph
                    .rel_data(id)
                    .map(|d| RowValue::Node(NodeRef { id: d.end }))
                    .unwrap_or(RowValue::NULL),
                _ => RowValue::NULL,
            });
        }
        _ => {}
    }

    // The remaining functions operate on collapsed property values.
    let argv: Vec<Value> = args
        .iter()
        .map(|a| eval_value(a, row, params, graph))
        .collect::<Result<_, _>>()?;

    let result = match lower.as_str() {
        "tostring" => match &argv[0] {
            Value::Null => Value::Null,
            v => Value::String(stringify_scalar(v)),
        },
        "tointeger" => to_integer(&argv[0]),
        "tofloat" => to_float(&argv[0]),
        "size" | "length" => match &argv[0] {
            Value::Null => Value::Null,
            Value::List(items) => Value::Integer(items.len() as i64),
            Value::String(s) => Value::Integer(s.chars().count() as i64),
            _ => {
                return Err(EvalError::TypeError {
                    context: format!("{lower}() requires a list or string"),
                });
            }
        },
        "head" => list_arg(&argv[0])?.first().cloned().unwrap_or(Value::Null),
        "last" => list_arg(&argv[0])?.last().cloned().unwrap_or(Value::Null),
        "tail" => {
            let items = list_arg(&argv[0])?;
            Value::List(items.iter().skip(1).cloned().collect())
        }
        "reverse" => match &argv[0] {
            Value::List(items) => Value::List(items.iter().rev().cloned().collect()),
            Value::String(s) => Value::String(s.chars().rev().collect()),
            Value::Null => Value::Null,
            _ => {
                return Err(EvalError::TypeError {
                    context: "reverse() requires a list or string".to_owned(),
                });
            }
        },
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

fn list_arg(v: &Value) -> Result<&[Value], EvalError> {
    match v {
        Value::List(items) => Ok(items),
        Value::Null => Ok(&[]),
        _ => Err(EvalError::TypeError {
            context: "expected a list argument".to_owned(),
        }),
    }
}

fn to_integer(v: &Value) -> Value {
    match v {
        Value::Integer(i) => Value::Integer(*i),
        Value::Float(f) => Value::Integer(*f as i64),
        Value::String(s) => s
            .trim()
            .parse::<i64>()
            .map(Value::Integer)
            .unwrap_or(Value::Null),
        Value::Boolean(_) | Value::Null => Value::Null,
        _ => Value::Null,
    }
}

fn to_float(v: &Value) -> Value {
    match v {
        Value::Float(f) => Value::Float(*f),
        Value::Integer(i) => Value::Float(*i as f64),
        Value::String(s) => s
            .trim()
            .parse::<f64>()
            .map(Value::Float)
            .unwrap_or(Value::Null),
        _ => Value::Null,
    }
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
) -> EvalResult {
    let items = match eval_value(&lc.list, row, params, graph)? {
        Value::Null => return Ok(RowValue::NULL),
        Value::List(items) => items,
        other => {
            return Err(EvalError::TypeError {
                context: format!("list comprehension requires a list, got {other:?}"),
            });
        }
    };
    let mut out = Vec::new();
    for item in items {
        let inner = row.with(lc.variable.name.clone(), RowValue::Value(item.clone()));
        if let Some(pred) = &lc.predicate {
            if !eval_to_ternary(pred, &inner, params, graph)?.is_true() {
                continue;
            }
        }
        match &lc.projection {
            Some(proj) => out.push(eval_value(proj, &inner, params, graph)?),
            None => out.push(item),
        }
    }
    Ok(RowValue::Value(Value::List(out)))
}

/// Evaluates a quantifier `all/any/none/single(x IN list WHERE p)` under Kleene 3VL with
/// short-circuiting. A `null` list yields `null`; a `null` predicate outcome leaves the overall
/// result unknown unless a definite element already decided it.
fn eval_quantifier(
    q: &crate::ast::QuantifierExpr,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
) -> EvalResult {
    use crate::ast::QuantifierKind;
    let items = match eval_value(&q.list, row, params, graph)? {
        Value::Null => return Ok(RowValue::NULL),
        Value::List(items) => items,
        other => {
            return Err(EvalError::TypeError {
                context: format!("quantifier requires a list, got {other:?}"),
            });
        }
    };
    let yes = || Ok(RowValue::Value(Value::Boolean(true)));
    let no = || Ok(RowValue::Value(Value::Boolean(false)));
    let mut trues = 0usize;
    let mut nulls = 0usize;
    for item in items {
        let inner = row.with(q.variable.name.clone(), RowValue::Value(item));
        match eval_to_ternary(&q.predicate, &inner, params, graph)? {
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
) -> EvalResult {
    if pc.var.is_some() {
        // Named paths need the path value model (a deferral shared with MATCH paths).
        return Err(EvalError::UnsupportedFunction {
            name: "named path in a pattern comprehension".to_owned(),
        });
    }
    let matches = pattern_element_rows(&pc.element, row, params, graph, false)?;
    let mut out = Vec::new();
    for m in matches {
        if let Some(pred) = &pc.predicate {
            if !eval_to_ternary(pred, &m, params, graph)?.is_true() {
                continue;
            }
        }
        out.push(eval_value(&pc.projection, &m, params, graph)?);
    }
    Ok(RowValue::Value(Value::List(out)))
}

/// Evaluates an existential subquery `EXISTS { [MATCH] pattern [WHERE p] }`: true iff the pattern
/// (all comma-separated parts jointly, constrained by the outer bindings) matches at least once
/// with the predicate `TRUE`. Always boolean, never null.
fn eval_exists_subquery(
    ex: &crate::ast::ExistsSubquery,
    row: &Row,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
) -> EvalResult {
    // Comma-separated parts join through their shared variables: each part's matches seed the next.
    let mut rows = vec![row.clone()];
    for part in &ex.pattern {
        if part.var.is_some() {
            return Err(EvalError::UnsupportedFunction {
                name: "named path in an EXISTS subquery".to_owned(),
            });
        }
        let mut next = Vec::new();
        for r in &rows {
            next.extend(pattern_element_rows(&part.element, r, params, graph, false)?);
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
                if eval_to_ternary(pred, r, params, graph)?.is_true() {
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
    first_only: bool,
) -> Result<Vec<Row>, EvalError> {
    let mut results = Vec::new();
    for start in node_candidates(&element.start, row, params, graph)? {
        let mut seeded = row.clone();
        if let Some(v) = &element.start.variable {
            seeded.set(v.name.clone(), RowValue::Node(NodeRef { id: start }));
        }
        match_chain(
            &element.chain,
            0,
            start,
            seeded,
            &mut Vec::new(),
            &mut results,
            params,
            graph,
            first_only,
        )?;
        if first_only && !results.is_empty() {
            break;
        }
    }
    Ok(results)
}

/// Depth-first chain matcher: extend the partial match at `chain[idx]` from `current`, pushing
/// every complete match into `out`. `used_rels` enforces per-match relationship uniqueness.
#[allow(clippy::too_many_arguments)] // an internal DFS worker; bundling these adds no clarity
fn match_chain(
    chain: &[crate::ast::PatternChainLink],
    idx: usize,
    current: crate::graph_access::NodeId,
    row: Row,
    used_rels: &mut Vec<crate::graph_access::RelId>,
    out: &mut Vec<Row>,
    params: &BoundParameters,
    graph: &dyn GraphAccess,
    first_only: bool,
) -> Result<(), EvalError> {
    let Some(link) = chain.get(idx) else {
        out.push(row);
        return Ok(());
    };
    if link.relationship.range.is_some() {
        // Variable-length inside an expression shares MATCH's var-length machinery (deferred).
        return Err(EvalError::UnsupportedFunction {
            name: "variable-length pattern in an expression".to_owned(),
        });
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
            if !rel_props_match(inc.rel, props, &row, params, graph)? {
                continue;
            }
        }
        // Target node: label/property filters plus the identity constraint when already bound.
        if !node_matches(inc.neighbour, &link.node, &row, params, graph)? {
            continue;
        }
        if let Some(v) = &link.node.variable {
            match next_row.get(&v.name) {
                Some(RowValue::Node(n)) if n.id == inc.neighbour => {}
                Some(_) => continue,
                None => next_row.set(
                    v.name.clone(),
                    RowValue::Node(NodeRef {
                        id: inc.neighbour,
                    }),
                ),
            }
        }
        used_rels.push(inc.rel);
        match_chain(
            chain,
            idx + 1,
            inc.neighbour,
            next_row,
            used_rels,
            out,
            params,
            graph,
            first_only,
        )?;
        used_rels.pop();
        if first_only && !out.is_empty() {
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
) -> Result<Vec<crate::graph_access::NodeId>, EvalError> {
    if let Some(v) = &np.variable {
        if let Some(rv) = row.get(&v.name) {
            return match rv {
                RowValue::Node(n) if node_matches(n.id, np, row, params, graph)? => Ok(vec![n.id]),
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
        if node_matches(id, np, row, params, graph)? {
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
        let entries = eval_props_map(props, row, params, graph)?;
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
) -> Result<bool, EvalError> {
    let entries = eval_props_map(props, row, params, graph)?;
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
) -> Result<Vec<(String, Value)>, EvalError> {
    match eval_value(props, row, params, graph)? {
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
        to_value(eval(&expr, &Row::empty(), &bound, &g).unwrap(), &g)
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
        let err = eval(&expr, &Row::empty(), &BoundParameters::empty(), &g).unwrap_err();
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
            to_value(eval(&expr, &Row::empty(), &bound, &g).unwrap(), &g),
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
    fn unsupported_function_is_named_error() {
        let expr = parse_expr("nodes(null)");
        let g = MemGraph::new();
        let err = eval(&expr, &Row::empty(), &BoundParameters::empty(), &g).unwrap_err();
        assert!(matches!(err, EvalError::UnsupportedFunction { .. }));
    }
}
