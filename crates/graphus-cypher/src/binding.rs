//! **Parameter binding** — the execution-time step that binds query parameters to a compiled plan
//! (`04-technical-design.md` §7.5).
//!
//! `04 §7.5` fixes the boundary this module guards:
//!
//! > *"Parameters bind at execution, never at compile, so the cache is parameter-independent. Bound
//! > parameter types are validated against the plan's expectations at bind time (runtime phase)."*
//!
//! # The compile-vs-runtime boundary (and why this module is the runtime side)
//!
//! A [`PhysicalPlan`](crate::physical::PhysicalPlan) is compiled **without** any parameter value
//! (the literal auto-parameterisation of [`crate::plan_cache`] keeps even the lifted literals out of
//! the plan body). The plan is therefore **parameter-independent**: a single cached plan is reused
//! across every parameter set. [`bind_parameters`] is the *separate, later* phase that supplies the
//! values — it runs at **execution time**, and consequently:
//!
//! - A **missing** parameter is a **runtime** error ([`BindError::MissingParameter`]), *not* a
//!   compile error (`04 §7.3`/§7.5). Semantic analysis (the only compile-time phase, `04 §7.3`)
//!   never inspects parameter values, so it cannot and must not raise on a missing/ill-typed
//!   parameter. This module is where that runtime check lives.
//! - An **ill-typed** parameter (e.g. a non-integer `SKIP`/`LIMIT`) is likewise a **runtime** error
//!   ([`BindError::WrongType`]).
//! - Binding **does not mutate the plan** — it produces a [`BoundParameters`] side value the
//!   executor reads. The same plan object is bound, independently, against different parameter sets.
//!
//! # What is validated at bind time
//!
//! `04 §7.5` calls for validating *"bound parameter types … against the plan's expectations"*. The
//! v1 heuristic planner does not yet carry full type inference (that arrives with the cost-based
//! optimiser, `00-overview` §6), so the expectations this module derives are the **sound, position
//! -driven** ones the plan structure makes unambiguous:
//!
//! - **Presence** — every parameter the plan *references* (user `$p` or an auto-parameter,
//!   [`crate::plan_cache`]) must be supplied. This is the headline check.
//! - **`SKIP`/`LIMIT`/`TopN` count** — must be a **non-negative integer** ([`ParamType::Integer`]).
//!   This is a sound expectation because the row-count operators require it by the openCypher grammar
//!   and semantics (`04 §7.5`/§7.6).
//! - Every other position carries no static type expectation yet ([`ParamType::Any`]); its
//!   value-type errors surface during row production in the executor (the executor's runtime phase),
//!   not here. **Deferred (named):** richer per-position type expectations (index-seek value
//!   indexability, arithmetic-operand numeric typing, …) await the typed planner.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use graphus_core::Value;

use crate::ast::{CaseExpr, Expr, ExprKind, PatternPart};
use crate::physical::{PhysicalOp, PhysicalPlan};
use crate::plan_cache::NormalizedQuery;

/// A name → [`Value`] map of the parameters supplied for one execution.
///
/// Holds both **user parameters** (`$name` written in the query) and **auto-parameters** lifted by
/// [`normalize_query`](crate::plan_cache::normalize_query) — they bind identically (`04 §7.5`).
/// Backed by a [`BTreeMap`] for deterministic iteration (reproducible diagnostics and tests).
#[derive(Debug, Clone, Default, PartialEq)]
#[must_use]
pub struct Parameters {
    values: BTreeMap<String, Value>,
}

impl Parameters {
    /// An empty parameter set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts (or replaces) a parameter, returning `self` for chaining.
    pub fn with(mut self, name: impl Into<String>, value: Value) -> Self {
        self.values.insert(name.into(), value);
        self
    }

    /// Inserts (or replaces) a parameter in place.
    pub fn insert(&mut self, name: impl Into<String>, value: Value) {
        self.values.insert(name.into(), value);
    }

    /// Extends the set with the auto-parameters of a [`NormalizedQuery`] (the literals lifted at
    /// normalisation, `04 §7.5`). Existing entries are kept; auto-parameter names are reserved and
    /// cannot collide with user names, so this never overwrites a user parameter.
    pub fn extend_with_auto_params(&mut self, normalized: &NormalizedQuery) {
        for (name, value) in normalized.auto_params() {
            self.values.insert(name.clone(), value.clone());
        }
    }

    /// The value bound to `name`, if any.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.values.get(name)
    }

    /// Whether `name` is bound.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }

    /// The number of bound parameters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether no parameters are bound.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// The static type a parameter is expected to satisfy at a given plan position (`04 §7.5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum ParamType {
    /// A non-negative integer (a `SKIP`/`LIMIT`/`TopN` row count).
    Integer,
    /// No static expectation — any value is accepted at bind time; value-type errors (if any)
    /// surface in the executor's runtime phase.
    Any,
}

impl ParamType {
    /// Whether `value` satisfies this expectation.
    ///
    /// For [`Integer`](Self::Integer) the value must be a **non-negative** [`Value::Integer`] (a
    /// negative count is a runtime type error per the row-count operators' semantics, `04 §7.6`).
    fn accepts(self, value: &Value) -> bool {
        match self {
            Self::Any => true,
            Self::Integer => matches!(value, Value::Integer(n) if *n >= 0),
        }
    }

    /// A human description for diagnostics.
    const fn describe(self) -> &'static str {
        match self {
            Self::Integer => "a non-negative integer",
            Self::Any => "any value",
        }
    }
}

/// What went wrong while binding parameters to a plan (`04 §7.5`, **runtime** phase).
///
/// A concrete error type (a library crate exposes concrete errors; `04 §1.2` reserves `anyhow` for
/// the binaries). The phase is **runtime**, not compile-time: these conditions are only knowable once
/// the caller supplies values, after the plan has compiled (`04 §7.3`/§7.5).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BindError {
    /// A parameter the plan references was not supplied. This is a **runtime** error — not a compile
    /// error (`04 §7.5`).
    MissingParameter {
        /// The unsupplied parameter's name.
        name: String,
    },
    /// A supplied parameter has a type the plan position cannot accept.
    WrongType {
        /// The parameter's name.
        name: String,
        /// The expectation it violated.
        expected: ParamType,
    },
}

impl BindError {
    /// The TCK error **phase** of a binding failure: always **runtime** (`04 §7.3`/§7.5).
    ///
    /// Provided so the connectivity layer's error mapping can assert the compile-vs-runtime split:
    /// a binding error must never be reported as a compile-time error.
    pub const fn phase(&self) -> crate::errors::ErrorPhase {
        crate::errors::ErrorPhase::Runtime
    }

    /// The parameter name the error concerns.
    #[must_use]
    pub fn parameter_name(&self) -> &str {
        match self {
            Self::MissingParameter { name } | Self::WrongType { name, .. } => name,
        }
    }
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingParameter { name } => {
                write!(
                    f,
                    "missing parameter `${}` at execution time",
                    display_name(name)
                )
            }
            Self::WrongType { name, expected } => write!(
                f,
                "parameter `${}` has the wrong type: expected {}",
                display_name(name),
                expected.describe(),
            ),
        }
    }
}

impl std::error::Error for BindError {}

impl From<BindError> for graphus_core::GraphusError {
    /// A binding failure is a Cypher **runtime** error (`04 §7.3`/§7.5).
    fn from(e: BindError) -> Self {
        graphus_core::GraphusError::Runtime(e.to_string())
    }
}

/// Renders a parameter name for diagnostics, trimming the reserved leading-space marker of an
/// auto-parameter so messages read cleanly.
fn display_name(name: &str) -> &str {
    name.trim_start()
}

/// The parameters supplied for one execution, **validated** against a plan's expectations
/// (`04 §7.5`).
///
/// Produced by [`bind_parameters`] once presence and types check out. The executor reads parameter
/// values from here. Because the plan is parameter-independent, the **same** [`PhysicalPlan`] yields
/// a fresh, independent [`BoundParameters`] for each parameter set — exactly the property `04 §7.5`
/// requires of the cache.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct BoundParameters {
    values: BTreeMap<String, Value>,
}

impl BoundParameters {
    /// An empty bound-parameter set (no parameters supplied).
    ///
    /// Useful for the executor and tests that run a parameter-free plan without going through
    /// [`bind_parameters`] explicitly. Equivalent to binding an empty [`Parameters`] against a plan
    /// that references nothing.
    pub fn empty() -> Self {
        Self {
            values: BTreeMap::new(),
        }
    }

    /// The value bound to `name`, if the plan referenced it.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.values.get(name)
    }

    /// The number of parameters the plan referenced and bound.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the plan referenced no parameters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Binds `params` to `plan` at **execution time**, validating presence and position-driven types
/// (`04 §7.5`).
///
/// This is the runtime phase of the compile-vs-runtime split (`04 §7.3`/§7.5): the plan was compiled
/// parameter-independently; here we supply and check the values. The plan is **not** modified.
///
/// # Errors
///
/// - [`BindError::MissingParameter`] if the plan references a parameter `params` does not supply.
/// - [`BindError::WrongType`] if a supplied parameter violates its position's
///   [`ParamType`] expectation (e.g. a non-integer / negative `SKIP`/`LIMIT`).
///
/// Both are **runtime** errors ([`BindError::phase`] is [`ErrorPhase::Runtime`](crate::errors::ErrorPhase::Runtime)),
/// never compile-time.
///
/// # Examples
///
/// ```
/// use graphus_core::Value;
/// use graphus_cypher::binding::{bind_parameters, BindError, Parameters};
/// use graphus_cypher::{catalog::IndexCatalog, lexer::tokenize, lower::lower,
///     parser::parse_tokens, physical::plan_physical, semantics::analyze};
///
/// let src = "MATCH (n) RETURN n LIMIT $top";
/// let toks = tokenize(src).unwrap();
/// let ast = parse_tokens(&toks, src).unwrap();
/// let plan = plan_physical(&lower(&analyze(&ast).unwrap()), &IndexCatalog::empty());
///
/// // Present and correctly typed: OK.
/// let bound = bind_parameters(&plan, &Parameters::new().with("top", Value::Integer(5))).unwrap();
/// assert_eq!(bound.get("top"), Some(&Value::Integer(5)));
///
/// // Missing: a RUNTIME error (not a compile error).
/// let err = bind_parameters(&plan, &Parameters::new()).unwrap_err();
/// assert!(matches!(err, BindError::MissingParameter { .. }));
/// ```
pub fn bind_parameters(
    plan: &PhysicalPlan,
    params: &Parameters,
) -> Result<BoundParameters, BindError> {
    let expectations = collect_param_expectations(plan);

    let mut bound = BTreeMap::new();
    for (name, expected) in &expectations {
        let Some(value) = params.get(name) else {
            return Err(BindError::MissingParameter { name: name.clone() });
        };
        if !expected.accepts(value) {
            return Err(BindError::WrongType {
                name: name.clone(),
                expected: *expected,
            });
        }
        bound.insert(name.clone(), value.clone());
    }
    Ok(BoundParameters { values: bound })
}

/// The set of parameters a plan references, each with its strongest position-driven
/// [`ParamType`] expectation.
///
/// A parameter appearing in **any** [`ParamType::Integer`] position (a `SKIP`/`LIMIT`/`TopN` count)
/// is recorded as [`ParamType::Integer`]; otherwise [`ParamType::Any`]. (Integer subsumes Any: a
/// value satisfying the integer expectation trivially satisfies Any, so promoting to the stronger
/// expectation when a parameter is used in both positions is sound.)
fn collect_param_expectations(plan: &PhysicalPlan) -> BTreeMap<String, ParamType> {
    let mut expectations: BTreeMap<String, ParamType> = BTreeMap::new();
    let mut record = |name: &str, ty: ParamType| {
        expectations
            .entry(name.to_owned())
            .and_modify(|e| {
                // Promote Any -> Integer (the stronger expectation wins).
                if matches!(ty, ParamType::Integer) {
                    *e = ParamType::Integer;
                }
            })
            .or_insert(ty);
    };
    walk_physical(&plan.root, &mut record);
    expectations
}

/// Walks a physical plan, reporting each parameter reference with its position expectation through
/// `record`.
fn walk_physical(op: &PhysicalOp, record: &mut impl FnMut(&str, ParamType)) {
    match op {
        // ---- count positions: Integer expectation ------------------------------------------
        PhysicalOp::Skip { input, count } | PhysicalOp::Limit { input, count } => {
            params_in_expr(count, ParamType::Integer, record);
            walk_physical(input, record);
        }
        PhysicalOp::TopN { input, keys, limit } => {
            params_in_expr(limit, ParamType::Integer, record);
            for k in keys {
                params_in_expr(&k.expr, ParamType::Any, record);
            }
            walk_physical(input, record);
        }

        // ---- value positions: Any expectation ----------------------------------------------
        PhysicalOp::NodeIndexSeek { value, .. } => {
            // Index-seek value: no static type expectation in v1 (indexability is the executor's
            // runtime concern); record as Any. (A seek is a leaf — no input to recurse into.)
            params_in_expr(value, ParamType::Any, record);
        }
        PhysicalOp::NodeIndexRangeSeek { value, .. } => {
            params_in_expr(value, ParamType::Any, record);
        }
        PhysicalOp::Filter { input, predicate } => {
            params_in_expr(predicate, ParamType::Any, record);
            walk_physical(input, record);
        }
        PhysicalOp::Projection { input, items, .. } => {
            for it in items {
                params_in_expr(&it.expr, ParamType::Any, record);
            }
            walk_physical(input, record);
        }
        PhysicalOp::Aggregation {
            input,
            group_keys,
            aggregates,
        } => {
            for c in group_keys.iter().chain(aggregates) {
                params_in_expr(&c.expr, ParamType::Any, record);
            }
            walk_physical(input, record);
        }
        PhysicalOp::Sort { input, keys } => {
            for k in keys {
                params_in_expr(&k.expr, ParamType::Any, record);
            }
            walk_physical(input, record);
        }
        PhysicalOp::Unwind {
            input,
            list,
            variable: _,
        } => {
            params_in_expr(list, ParamType::Any, record);
            walk_physical(input, record);
        }
        PhysicalOp::LoadCsv {
            input,
            url,
            with_headers: _,
            variable: _,
            field_terminator: _,
        } => {
            // The URL expression may reference a `$param` (e.g. `FROM $path AS row`); it is typed as
            // a string at runtime, but the binder only records that it is referenced.
            params_in_expr(url, ParamType::Any, record);
            walk_physical(input, record);
        }

        // ---- traversals carry expressions only in pattern props (handled via Create/Filter) -
        PhysicalOp::ExpandAll { input, .. }
        | PhysicalOp::ExpandInto { input, .. }
        | PhysicalOp::NamedPath { input, .. } => {
            walk_physical(input, record);
        }

        // ---- joins / branches ---------------------------------------------------------------
        PhysicalOp::NestedLoopJoin { left, right } | PhysicalOp::HashJoin { left, right, .. } => {
            walk_physical(left, record);
            walk_physical(right, record);
        }
        PhysicalOp::Union { left, right, .. } => {
            walk_physical(left, record);
            walk_physical(right, record);
        }
        PhysicalOp::Optional { input, .. } | PhysicalOp::Eager { input } => {
            walk_physical(input, record)
        }

        // ---- write operators carry expressions in their pattern/ops -------------------------
        PhysicalOp::Create { input, pattern } | PhysicalOp::Merge { input, pattern, .. } => {
            for part in pattern {
                params_in_create_part(part, record);
            }
            if let PhysicalOp::Merge {
                on_create,
                on_match,
                ..
            } = op
            {
                for set_op in on_create.iter().chain(on_match) {
                    params_in_set_op(set_op, record);
                }
            }
            walk_physical(input, record);
        }
        PhysicalOp::SetClause { input, ops } => {
            for set_op in ops {
                params_in_set_op(set_op, record);
            }
            walk_physical(input, record);
        }
        PhysicalOp::Delete { input, exprs, .. } => {
            for e in exprs {
                params_in_expr(e, ParamType::Any, record);
            }
            walk_physical(input, record);
        }
        PhysicalOp::Remove { input, ops } => {
            for op in ops {
                if let crate::logical::RemoveOp::Property { target } = op {
                    params_in_expr(target, ParamType::Any, record);
                }
            }
            walk_physical(input, record);
        }
        PhysicalOp::ProcedureCall { input, args, .. } => {
            if let Some(args) = args {
                for a in args {
                    params_in_expr(a, ParamType::Any, record);
                }
            }
            if let Some(input) = input {
                walk_physical(input, record);
            }
        }

        // ---- leaves with no expressions -----------------------------------------------------
        // `SpatialIndexSeek`'s centre and radius are plan-time-folded `f64` constants (never
        // `$param`s — a non-constant proximity predicate is declined by the planner), so it carries
        // no parameter references (`rmp` task #73).
        PhysicalOp::AllNodesScan { .. }
        | PhysicalOp::NodeByLabelScan { .. }
        | PhysicalOp::TokenLookupScan { .. }
        | PhysicalOp::SpatialIndexSeek { .. }
        | PhysicalOp::AllRelationshipsScan { .. }
        | PhysicalOp::Argument { .. }
        | PhysicalOp::Empty => {}
    }
}

/// Reports parameters appearing in a write-pattern part's inline property expression.
fn params_in_create_part(
    part: &crate::logical::CreatePart,
    record: &mut impl FnMut(&str, ParamType),
) {
    let props = match part {
        crate::logical::CreatePart::Node { properties, .. }
        | crate::logical::CreatePart::Relationship { properties, .. } => properties,
    };
    if let Some(props) = props {
        params_in_expr(props, ParamType::Any, record);
    }
}

/// Reports parameters appearing in a `SET` op's value/target expressions.
fn params_in_set_op(op: &crate::logical::SetOp, record: &mut impl FnMut(&str, ParamType)) {
    match op {
        crate::logical::SetOp::Property { target, value } => {
            params_in_expr(target, ParamType::Any, record);
            params_in_expr(value, ParamType::Any, record);
        }
        crate::logical::SetOp::ReplaceProperties { value, .. }
        | crate::logical::SetOp::MergeProperties { value, .. } => {
            params_in_expr(value, ParamType::Any, record);
        }
        crate::logical::SetOp::AddLabels { .. } => {}
    }
}

/// Reports every parameter referenced in `expr`, attributing `ty` to each (the caller passes the
/// position expectation). A parameter used as `$p` directly takes `ty`; a parameter buried inside a
/// compound expression takes [`ParamType::Any`] (we only know the *outer* position's expectation
/// applies to the whole expression, not to a sub-term).
fn params_in_expr(expr: &Expr, ty: ParamType, record: &mut impl FnMut(&str, ParamType)) {
    match &expr.kind {
        ExprKind::Parameter(name) => record(name, ty),
        ExprKind::Literal(_) | ExprKind::Variable(_) | ExprKind::CountStar => {}
        // For sub-expressions of a compound term the position expectation no longer applies
        // directly, so descend with `Any` (the integer expectation is only sound for a parameter
        // that *is* the whole count expression, e.g. `LIMIT $n`, not `LIMIT $n + 1`).
        ExprKind::Binary { lhs, rhs, .. } => {
            params_in_expr(lhs, ParamType::Any, record);
            params_in_expr(rhs, ParamType::Any, record);
        }
        ExprKind::Unary { operand, .. } | ExprKind::HasLabels { operand, .. } => {
            params_in_expr(operand, ParamType::Any, record);
        }
        ExprKind::Predicate { operand, rhs, .. } => {
            params_in_expr(operand, ParamType::Any, record);
            if let Some(r) = rhs {
                params_in_expr(r, ParamType::Any, record);
            }
        }
        ExprKind::Property { base, .. } => params_in_expr(base, ParamType::Any, record),
        ExprKind::Index { base, index } => {
            params_in_expr(base, ParamType::Any, record);
            params_in_expr(index, ParamType::Any, record);
        }
        ExprKind::Slice { base, low, high } => {
            params_in_expr(base, ParamType::Any, record);
            if let Some(l) = low {
                params_in_expr(l, ParamType::Any, record);
            }
            if let Some(h) = high {
                params_in_expr(h, ParamType::Any, record);
            }
        }
        ExprKind::FunctionCall { args, .. } => {
            for a in args {
                params_in_expr(a, ParamType::Any, record);
            }
        }
        ExprKind::List(items) => {
            for i in items {
                params_in_expr(i, ParamType::Any, record);
            }
        }
        ExprKind::Map(entries) => {
            for (_, v) in entries {
                params_in_expr(v, ParamType::Any, record);
            }
        }
        ExprKind::Case(case) => params_in_case(case, record),
        ExprKind::ListComprehension(lc) => {
            params_in_expr(&lc.list, ParamType::Any, record);
            if let Some(p) = &lc.predicate {
                params_in_expr(p, ParamType::Any, record);
            }
            if let Some(proj) = &lc.projection {
                params_in_expr(proj, ParamType::Any, record);
            }
        }
        ExprKind::PatternComprehension(pc) => {
            if let Some(p) = &pc.predicate {
                params_in_expr(p, ParamType::Any, record);
            }
            params_in_expr(&pc.projection, ParamType::Any, record);
        }
        ExprKind::Quantifier(q) => {
            params_in_expr(&q.list, ParamType::Any, record);
            params_in_expr(&q.predicate, ParamType::Any, record);
        }
        ExprKind::ExistsSubquery(ex) => {
            for part in &ex.pattern {
                params_in_pattern_part(part, record);
            }
            if let Some(p) = &ex.predicate {
                params_in_expr(p, ParamType::Any, record);
            }
        }
    }
}

/// Reports the parameters referenced by a pattern part's inline property maps (`{p: $x}`).
fn params_in_pattern_part(part: &PatternPart, record: &mut impl FnMut(&str, ParamType)) {
    if let Some(props) = &part.element.start.properties {
        params_in_expr(props, ParamType::Any, record);
    }
    for link in &part.element.chain {
        if let Some(props) = &link.relationship.properties {
            params_in_expr(props, ParamType::Any, record);
        }
        if let Some(props) = &link.node.properties {
            params_in_expr(props, ParamType::Any, record);
        }
    }
}

fn params_in_case(case: &CaseExpr, record: &mut impl FnMut(&str, ParamType)) {
    if let Some(subject) = &case.subject {
        params_in_expr(subject, ParamType::Any, record);
    }
    for alt in &case.alternatives {
        params_in_expr(&alt.when, ParamType::Any, record);
        params_in_expr(&alt.then, ParamType::Any, record);
    }
    if let Some(else_expr) = &case.else_expr {
        params_in_expr(else_expr, ParamType::Any, record);
    }
}

/// The set of parameter **names** a plan references (presence-only view, e.g. for a caller that
/// wants to pre-flight which parameters it must supply).
#[must_use]
pub fn referenced_parameters(plan: &PhysicalPlan) -> BTreeSet<String> {
    collect_param_expectations(plan).into_keys().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::IndexCatalog;
    use crate::lexer::tokenize;
    use crate::lower::lower;
    use crate::parser::parse_tokens;
    use crate::physical::plan_physical;
    use crate::semantics::analyze;

    fn plan(src: &str) -> PhysicalPlan {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        plan_physical(&lower(&validated), &IndexCatalog::empty())
    }

    #[test]
    fn present_parameter_binds() {
        let p = plan("MATCH (n) WHERE n.age = $age RETURN n");
        let bound =
            bind_parameters(&p, &Parameters::new().with("age", Value::Integer(30))).unwrap();
        assert_eq!(bound.get("age"), Some(&Value::Integer(30)));
    }

    #[test]
    fn missing_parameter_is_runtime_error() {
        let p = plan("MATCH (n) WHERE n.age = $age RETURN n");
        let err = bind_parameters(&p, &Parameters::new()).unwrap_err();
        assert_eq!(
            err,
            BindError::MissingParameter {
                name: "age".to_owned()
            }
        );
        // Crucially: RUNTIME phase, not compile-time.
        assert_eq!(err.phase(), crate::errors::ErrorPhase::Runtime);
    }

    #[test]
    fn limit_param_must_be_non_negative_integer() {
        let p = plan("MATCH (n) RETURN n LIMIT $top");
        // A string is the wrong type for a LIMIT count.
        let err = bind_parameters(
            &p,
            &Parameters::new().with("top", Value::String("x".to_owned())),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BindError::WrongType {
                expected: ParamType::Integer,
                ..
            }
        ));
        // A negative integer is likewise rejected.
        let err2 =
            bind_parameters(&p, &Parameters::new().with("top", Value::Integer(-1))).unwrap_err();
        assert!(matches!(err2, BindError::WrongType { .. }));
        // A non-negative integer binds.
        assert!(bind_parameters(&p, &Parameters::new().with("top", Value::Integer(0))).is_ok());
    }

    #[test]
    fn plan_is_parameter_independent_reused_across_sets() {
        let p = plan("MATCH (n) WHERE n.age = $age RETURN n");
        let b1 = bind_parameters(&p, &Parameters::new().with("age", Value::Integer(1))).unwrap();
        let b2 = bind_parameters(&p, &Parameters::new().with("age", Value::Integer(2))).unwrap();
        assert_eq!(b1.get("age"), Some(&Value::Integer(1)));
        assert_eq!(b2.get("age"), Some(&Value::Integer(2)));
        // Same plan object, two independent binds — the cache-friendly property of `04 §7.5`.
    }

    #[test]
    fn referenced_parameters_lists_names() {
        let p = plan("MATCH (n) WHERE n.a = $x AND n.b = $y RETURN n LIMIT $z");
        let names = referenced_parameters(&p);
        assert!(names.contains("x") && names.contains("y") && names.contains("z"));
    }
}
