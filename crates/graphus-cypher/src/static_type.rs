//! Compile-time **static type checking** of expressions (`04 §7.3`; `rmp` task #61).
//!
//! Semantic analysis ([`crate::semantics`]) defers *value-typed* errors to the runtime by design —
//! "we do not constant-fold or type-infer expression results" — because most type mismatches depend
//! on data the analyser cannot see (`n.prop + 1`, `$param < 3`). The openCypher TCK, however,
//! expects a **compile-time `SyntaxError`/`InvalidArgumentType`** for the subset of mismatches that
//! are *statically decidable*: a `NOT` over an integer literal, `1 IN 2`, arithmetic over a list of
//! string literals inside a quantifier, `type()` on a node, `SKIP 1.5`. This module raises exactly
//! that subset and **nothing else**.
//!
//! # Conservatism is the contract (no false positives)
//!
//! [`SType::Unknown`] is the top of the lattice: the type of any expression whose value type cannot
//! be *proven* at compile time — a variable not known to be a node/relationship (an `UNWIND`/`WITH`
//! value, a parameter-fed binding), a property access, a parameter, a function result, a heterogeneous
//! list. A check **never** fires when an operand is `Unknown`; only a *provably wrong concrete type*
//! is an error. So a dynamic expression can never be a false positive, and the runtime `TypeError`
//! path (the TCK's design for data-dependent mismatches) is left exactly as it was. [`Literal::Null`]
//! is likewise accepted everywhere — a `null` operand yields `null`, never a type error
//! (`04 §7.3`).
//!
//! # What is checked (each cites the `tck/features/**` it satisfies)
//!
//! - **Boolean operators** `NOT` / `AND` / `OR` / `XOR` require boolean operands
//!   (`expressions/boolean/Boolean{1,2,3,4}.feature`).
//! - **Strict arithmetic** `-` / `*` / `/` / `%` / `^` and unary `+` / `-` require numeric operands.
//!   `+` is **not** checked — it is overloaded (numeric add, string and list concatenation), so its
//!   operands are not statically constrained. This drives the quantifier mismatch scenarios, e.g.
//!   `none(x IN ['Clara'] WHERE x % 2 = 0)` (`expressions/quantifier/Quantifier{1,2,3,4}.feature`).
//! - **`IN`** requires a list right-hand side (`expressions/list/List5.feature`).
//! - **Property access** `e.k` requires a node, relationship or map base
//!   (the inline-literal form; the `WITH <literal> AS x … x.k` form needs projection type-flow and
//!   is a named follow-up).
//! - **Functions** `type()` (relationship), `length()` (not a node/relationship), `properties()`
//!   (node / relationship / map) (`expressions/graph/Graph{4,9}.feature`,
//!   `expressions/path/Path3.feature`).
//!
//! Comparison/ordering operators (`<`, `=`, `=~`, `STARTS WITH`, …) are intentionally **not**
//! type-checked: openCypher makes a cross-type comparison yield `null` at runtime, not an error, so
//! a static rejection would be wrong. `SKIP`/`LIMIT` literal typing is enforced by the caller
//! ([`crate::semantics`]) at the projection, where the syntactic position is known.

use std::collections::HashMap;

use crate::ast::{BinaryOp, Expr, ExprKind, Literal, PredicateOp, UnaryOp};
use crate::errors::{SemanticError, SemanticErrorKind};

/// A conservatively-inferred static value type. See the module docs: [`Self::Unknown`] is the top
/// (never the subject of an error), and every concrete variant is only assigned when the type is
/// *provable* from literals, list structure, or a known node/relationship binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SType {
    /// Not statically determinable — never reported as a mismatch.
    Unknown,
    /// The `null` literal (accepted in every typed position).
    Null,
    /// A boolean.
    Bool,
    /// An integer.
    Int,
    /// A float.
    Float,
    /// A string.
    Str,
    /// A list with the given (possibly [`Unknown`](Self::Unknown)) element type.
    List(Box<SType>),
    /// A map / literal map.
    Map,
    /// A node (a variable bound by a node pattern).
    Node,
    /// A relationship (a variable bound by a relationship pattern).
    Relationship,
}

impl SType {
    /// Whether this is a concrete (provable) type — i.e. anything but [`Self::Unknown`] and
    /// [`Self::Null`]. Only a concrete operand can be a static mismatch.
    fn is_concrete(&self) -> bool {
        !matches!(self, Self::Unknown | Self::Null)
    }

    /// Whether this type is (or may be) numeric — an [`Int`](Self::Int) or [`Float`](Self::Float).
    fn is_numeric(&self) -> bool {
        matches!(self, Self::Int | Self::Float)
    }

    /// The least upper bound of two element types in a list literal: equal types collapse to
    /// themselves, [`Null`](Self::Null) is absorbed by its companion (`[null, 'a']` is a list of
    /// strings for typing purposes), and any other disagreement widens to [`Unknown`](Self::Unknown)
    /// — so a heterogeneous list is never the basis of a static error.
    fn join(self, other: Self) -> Self {
        match (self, other) {
            (a, b) if a == b => a,
            (Self::Null, b) => b,
            (a, Self::Null) => a,
            _ => Self::Unknown,
        }
    }
}

/// The variable → static-type environment for a single expression check. Seeded by the caller from
/// the semantic scope (node/relationship bindings); quantifier and list-comprehension iteration
/// variables are layered on locally as the walk descends.
pub type TypeEnv = HashMap<String, SType>;

/// Infers the static type of `expr` under `env`. Returns [`SType::Unknown`] for everything whose
/// type is not provable (see the module docs) — the result is only ever used to *find* a provable
/// mismatch, never to assume one.
fn infer(expr: &Expr, env: &TypeEnv) -> SType {
    match &expr.kind {
        ExprKind::Literal(Literal::Null) => SType::Null,
        ExprKind::Literal(Literal::Boolean(_)) => SType::Bool,
        ExprKind::Literal(Literal::Integer(_)) => SType::Int,
        ExprKind::Literal(Literal::Float(_)) => SType::Float,
        ExprKind::Literal(Literal::String(_)) => SType::Str,
        ExprKind::Variable(name) => env.get(name).cloned().unwrap_or(SType::Unknown),
        ExprKind::Parameter(_) => SType::Unknown,
        ExprKind::List(items) => {
            let elem = items
                .iter()
                .map(|it| infer(it, env))
                .reduce(SType::join)
                .unwrap_or(SType::Unknown);
            SType::List(Box::new(elem))
        }
        ExprKind::Map(_) => SType::Map,
        ExprKind::Unary { op, operand } => match op {
            UnaryOp::Not => SType::Bool,
            // Unary +/- preserve a numeric operand's type and are otherwise non-committal.
            UnaryOp::Plus | UnaryOp::Minus => match infer(operand, env) {
                t @ (SType::Int | SType::Float) => t,
                _ => SType::Unknown,
            },
        },
        ExprKind::Binary { op, .. } => match op {
            BinaryOp::Or | BinaryOp::Xor | BinaryOp::And => SType::Bool,
            BinaryOp::Eq
            | BinaryOp::Neq
            | BinaryOp::Lt
            | BinaryOp::Gt
            | BinaryOp::Lte
            | BinaryOp::Gte
            | BinaryOp::RegexMatch => SType::Bool,
            // Arithmetic result types depend on operand values (int vs float promotion, `+`
            // overloading); we do not need the precise result, so stay non-committal.
            _ => SType::Unknown,
        },
        ExprKind::Predicate { .. } => SType::Bool,
        ExprKind::Quantifier(_) | ExprKind::ExistsSubquery(_) | ExprKind::HasLabels { .. } => {
            SType::Bool
        }
        ExprKind::ListComprehension(_) | ExprKind::PatternComprehension(_) => {
            SType::List(Box::new(SType::Unknown))
        }
        ExprKind::CountStar => SType::Int,
        // Property access, indexing, slicing, function results and CASE are not statically typed.
        ExprKind::Property { .. }
        | ExprKind::Index { .. }
        | ExprKind::Slice { .. }
        | ExprKind::FunctionCall { .. }
        | ExprKind::Case(_) => SType::Unknown,
    }
}

/// Statically type-checks `expr` (and, recursively, its sub-expressions) under `env`, raising a
/// [`SemanticErrorKind::InvalidExpressionType`] for the first provable mismatch. See the module
/// docs for exactly what is and is not checked.
pub fn check_expr(expr: &Expr, env: &TypeEnv) -> Result<(), SemanticError> {
    match &expr.kind {
        ExprKind::Unary { op, operand } => {
            check_expr(operand, env)?;
            match op {
                UnaryOp::Not => require_boolean(operand, env, "operand of NOT")?,
                UnaryOp::Plus | UnaryOp::Minus => {
                    require_numeric(operand, env, "operand of unary +/-")?;
                }
            }
        }
        ExprKind::Binary { op, lhs, rhs } => {
            check_expr(lhs, env)?;
            check_expr(rhs, env)?;
            match op {
                BinaryOp::And | BinaryOp::Or | BinaryOp::Xor => {
                    require_boolean(lhs, env, "operand of a boolean operator")?;
                    require_boolean(rhs, env, "operand of a boolean operator")?;
                }
                BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod | BinaryOp::Pow => {
                    require_numeric(lhs, env, "operand of an arithmetic operator")?;
                    require_numeric(rhs, env, "operand of an arithmetic operator")?;
                }
                // `+` is overloaded; comparisons yield null on type mismatch — neither is checked.
                _ => {}
            }
        }
        ExprKind::Predicate { op, operand, rhs } => {
            check_expr(operand, env)?;
            if let Some(rhs) = rhs {
                check_expr(rhs, env)?;
            }
            if matches!(op, PredicateOp::In) {
                if let Some(rhs) = rhs {
                    require_list(rhs, env, "right-hand side of IN")?;
                }
            }
        }
        ExprKind::Property { base, .. } => {
            check_expr(base, env)?;
            require_graph_or_map(base, env, "base of a property access")?;
        }
        ExprKind::Index { base, index } => {
            check_expr(base, env)?;
            check_expr(index, env)?;
        }
        ExprKind::Slice { base, low, high } => {
            check_expr(base, env)?;
            if let Some(low) = low {
                check_expr(low, env)?;
            }
            if let Some(high) = high {
                check_expr(high, env)?;
            }
        }
        ExprKind::HasLabels { operand, .. } => check_expr(operand, env)?,
        ExprKind::FunctionCall { name, args, .. } => {
            for arg in args {
                check_expr(arg, env)?;
            }
            check_function_args(name, args, env)?;
        }
        ExprKind::List(items) => {
            for it in items {
                check_expr(it, env)?;
            }
        }
        ExprKind::Map(entries) => {
            for (_, v) in entries {
                check_expr(v, env)?;
            }
        }
        ExprKind::Case(case) => {
            if let Some(subj) = &case.subject {
                check_expr(subj, env)?;
            }
            for alt in &case.alternatives {
                check_expr(&alt.when, env)?;
                check_expr(&alt.then, env)?;
            }
            if let Some(else_e) = &case.else_expr {
                check_expr(else_e, env)?;
            }
        }
        ExprKind::Quantifier(q) => {
            check_expr(&q.list, env)?;
            let inner = bind_element(env, &q.variable.name, &q.list);
            check_expr(&q.predicate, &inner)?;
        }
        ExprKind::ListComprehension(lc) => {
            check_expr(&lc.list, env)?;
            let inner = bind_element(env, &lc.variable.name, &lc.list);
            if let Some(pred) = &lc.predicate {
                check_expr(pred, &inner)?;
            }
            if let Some(proj) = &lc.projection {
                check_expr(proj, &inner)?;
            }
        }
        // A pattern comprehension binds pattern (node/relationship/path) variables whose value
        // typing is not the concern here; its embedded predicate/projection reference graph
        // elements, so we leave them to the runtime (conservative: no static claim).
        ExprKind::PatternComprehension(_) | ExprKind::ExistsSubquery(_) => {}
        ExprKind::Literal(_)
        | ExprKind::Parameter(_)
        | ExprKind::Variable(_)
        | ExprKind::CountStar => {}
    }
    Ok(())
}

/// Returns `env` extended with `var` bound to the element type of `list` (when `list` is a
/// statically-typed list literal), so a quantifier / comprehension predicate can be checked against
/// the iteration variable's known type. A non-list or heterogeneous list yields an `Unknown`
/// binding, which is never the basis of an error.
fn bind_element(env: &TypeEnv, var: &str, list: &Expr) -> TypeEnv {
    let elem = match infer(list, env) {
        SType::List(elem) => *elem,
        _ => SType::Unknown,
    };
    let mut inner = env.clone();
    inner.insert(var.to_owned(), elem);
    inner
}

/// Type-checks the arguments of the statically-decidable built-in functions. Unknown functions and
/// arities other than the checked one fall through (handled elsewhere / left to the runtime).
fn check_function_args(name: &[String], args: &[Expr], env: &TypeEnv) -> Result<(), SemanticError> {
    let dotted = name.join(".").to_ascii_lowercase();
    let [arg] = args else { return Ok(()) };
    let ty = infer(arg, env);
    if !ty.is_concrete() {
        return Ok(());
    }
    let bad = match dotted.as_str() {
        // `type()` reads a relationship's type; a node is a provable mismatch.
        "type" => matches!(ty, SType::Node),
        // `length()` measures a path; a node or relationship is a provable mismatch (a path
        // variable is `Unknown` here, so the valid case is never flagged).
        "length" => matches!(ty, SType::Node | SType::Relationship),
        // `properties()` accepts a node, relationship or map; a scalar/list is a provable mismatch.
        "properties" => matches!(
            ty,
            SType::Bool | SType::Int | SType::Float | SType::Str | SType::List(_)
        ),
        _ => false,
    };
    if bad {
        return Err(SemanticError::new(
            SemanticErrorKind::InvalidExpressionType {
                context: format!("argument of `{dotted}()`"),
            },
            arg.span,
        ));
    }
    Ok(())
}

/// Errors if `expr` has a provably non-boolean type.
fn require_boolean(expr: &Expr, env: &TypeEnv, context: &str) -> Result<(), SemanticError> {
    let ty = infer(expr, env);
    if ty.is_concrete() && ty != SType::Bool {
        return Err(mismatch(expr, context));
    }
    Ok(())
}

/// Errors if `expr` has a provably non-numeric type.
fn require_numeric(expr: &Expr, env: &TypeEnv, context: &str) -> Result<(), SemanticError> {
    let ty = infer(expr, env);
    if ty.is_concrete() && !ty.is_numeric() {
        return Err(mismatch(expr, context));
    }
    Ok(())
}

/// Errors if `expr` has a provably non-list type.
fn require_list(expr: &Expr, env: &TypeEnv, context: &str) -> Result<(), SemanticError> {
    let ty = infer(expr, env);
    if ty.is_concrete() && !matches!(ty, SType::List(_)) {
        return Err(mismatch(expr, context));
    }
    Ok(())
}

/// Errors if `expr` has a provably non-graph-element, non-map type (the legal bases of a property
/// access).
fn require_graph_or_map(expr: &Expr, env: &TypeEnv, context: &str) -> Result<(), SemanticError> {
    let ty = infer(expr, env);
    if ty.is_concrete() && !matches!(ty, SType::Node | SType::Relationship | SType::Map) {
        return Err(mismatch(expr, context));
    }
    Ok(())
}

fn mismatch(expr: &Expr, context: &str) -> SemanticError {
    SemanticError::new(
        SemanticErrorKind::InvalidExpressionType {
            context: context.to_owned(),
        },
        expr.span,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::tokenize;
    use crate::parser::parse_tokens;

    /// Parses a bare expression by wrapping it in `RETURN`, returning the projected expression.
    fn expr(src: &str) -> Expr {
        let full = format!("RETURN {src} AS x");
        let toks = tokenize(&full).expect("lex");
        let q = parse_tokens(&toks, &full).expect("parse");
        // Reach into the single RETURN item's expression via Debug-free pattern matching would be
        // verbose; instead re-tokenize is unnecessary — pull it from the AST.
        let crate::ast::QueryBody::Regular { head, .. } = &q.body else {
            panic!("standalone call")
        };
        let crate::ast::Clause::Return(ret) = head.clauses.last().expect("a clause") else {
            panic!("not a RETURN")
        };
        ret.body.items[0].expr.clone()
    }

    fn infer_src(src: &str) -> SType {
        infer(&expr(src), &TypeEnv::new())
    }

    #[test]
    fn infers_literal_types() {
        assert_eq!(infer_src("1"), SType::Int);
        assert_eq!(infer_src("1.5"), SType::Float);
        assert_eq!(infer_src("'a'"), SType::Str);
        assert_eq!(infer_src("true"), SType::Bool);
        assert_eq!(infer_src("null"), SType::Null);
        assert_eq!(infer_src("{a: 1}"), SType::Map);
    }

    #[test]
    fn infers_homogeneous_list_element_type_and_widens_heterogeneous() {
        assert_eq!(infer_src("['a', 'b']"), SType::List(Box::new(SType::Str)));
        // null is absorbed by its companion element type.
        assert_eq!(infer_src("[null, 'a']"), SType::List(Box::new(SType::Str)));
        // a mixed list widens to an Unknown element (never a basis for an error).
        assert_eq!(infer_src("[1, 'a']"), SType::List(Box::new(SType::Unknown)));
        assert_eq!(infer_src("[]"), SType::List(Box::new(SType::Unknown)));
    }

    #[test]
    fn unknown_and_null_are_never_concrete() {
        assert!(!SType::Unknown.is_concrete());
        assert!(!SType::Null.is_concrete());
        assert!(SType::Int.is_concrete());
        assert!(SType::Node.is_concrete());
    }

    #[test]
    fn join_widens_disagreement_and_absorbs_null() {
        assert_eq!(SType::Int.join(SType::Int), SType::Int);
        assert_eq!(SType::Null.join(SType::Str), SType::Str);
        assert_eq!(SType::Str.join(SType::Null), SType::Str);
        assert_eq!(SType::Int.join(SType::Str), SType::Unknown);
    }

    #[test]
    fn check_flags_provable_mismatch_but_not_unknown() {
        // A provable mismatch errors...
        assert!(check_expr(&expr("NOT 1"), &TypeEnv::new()).is_err());
        // ...but a variable of unknown type does not.
        let mut env = TypeEnv::new();
        env.insert("v".to_owned(), SType::Unknown);
        assert!(check_expr(&expr("NOT v"), &env).is_ok());
        // A node-typed variable as a property base is fine; as a NOT operand it is a mismatch.
        env.insert("n".to_owned(), SType::Node);
        assert!(check_expr(&expr("n.prop"), &env).is_ok());
        assert!(check_expr(&expr("NOT n"), &env).is_err());
    }
}
