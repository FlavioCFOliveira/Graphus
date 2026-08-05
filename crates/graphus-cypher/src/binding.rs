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

use crate::ast::{
    CaseExpr, Clause, Expr, ExprKind, MergeAction, PatternPart, ProjectionBody, Query, QueryBody,
    RemoveItem, SetItem, SingleQuery,
};
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
    /// A supplied parameter value nests deeper than [`MAX_VALUE_DEPTH`](crate::value_depth::MAX_VALUE_DEPTH)
    /// (`SEC-190`, CWE-674). Such a value is rejected at the trust boundary because comparing,
    /// ordering or hashing it would otherwise recurse one stack frame per nesting level and overflow
    /// the worker stack — an unrecoverable process abort. This is a **runtime** error.
    ValueTooDeep {
        /// The over-deep parameter's name.
        name: String,
        /// The depth limit that was exceeded.
        limit: usize,
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
            Self::MissingParameter { name }
            | Self::WrongType { name, .. }
            | Self::ValueTooDeep { name, .. } => name,
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
            Self::ValueTooDeep { name, limit } => write!(
                f,
                "parameter `${}` is nested too deeply (limit {limit}); deeply nested values are \
                 rejected to keep evaluation stack-safe",
                display_name(name),
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

    /// Re-materialises these bound values as a raw [`Parameters`] set.
    ///
    /// Used to bind a **correlated subplan** (the full-query form of an `EXISTS { ... }` subquery,
    /// `rmp` #123): the inner plan's parameter set is a subset of the same `$param` namespace, so the
    /// outer query's already-bound values supply it. Every `$param` the inner query references is
    /// also collected from the outer query (see [`params_in_query`]), so it is present here.
    pub fn as_parameters(&self) -> Parameters {
        let mut params = Parameters::new();
        for (name, value) in &self.values {
            params.insert(name.clone(), value.clone());
        }
        params
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
        // SEC-190: reject a pathologically nested parameter value at the trust boundary, before it
        // can drive the depth-recursive equality/ordering/hash routines into a stack overflow. The
        // check is iterative and capped, so it is itself stack-safe and `O(limit)`.
        if crate::value_depth::depth_exceeds(value, crate::value_depth::MAX_VALUE_DEPTH) {
            return Err(BindError::ValueTooDeep {
                name: name.clone(),
                limit: crate::value_depth::MAX_VALUE_DEPTH,
            });
        }
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
///
/// # Why every pattern below is exhaustive (no `..`)
///
/// [`BoundParameters`] carries **exactly** the names this walk records, and [`crate::eval`] resolves
/// an unrecorded `$p` to [`Value::Null`]. An expression field that escapes this walk is therefore not
/// a missing diagnostic — it is a **silent wrong answer**: the comparison goes null, every row is
/// rejected, and the query returns zero rows with no error at all.
///
/// That has now happened four times, always the same way — a planner pass moves an expression *out*
/// of a `Filter` and *onto* an operator field, and this walk is not updated with it:
/// `ExpandAll::to_predicate` (`rmp` #870), `OptionalExpand::predicates` (#882), the count-store
/// `fallback` (#866), and `ValueHashJoin`'s join keys (#960). The last one made **every** `MATCH`
/// whose predicate combines a driving-row variable with a `$param` match nothing, which is precisely
/// the `UNWIND … MATCH … CREATE` idiom every official driver writes.
///
/// So the patterns bind **every** field of **every** variant, with `_` for the ones that hold no
/// expression. That verbosity is the point and must stay: adding a field to any [`PhysicalOp`]
/// variant is then a **compile error here**, which forces whoever adds it to decide whether it
/// carries an expression — instead of shipping another silently empty result.
///
/// [`PhysicalOp::op_expressions`](crate::physical::PhysicalOp) is a second, independently maintained
/// inventory of "which expressions does this operator evaluate", and comparing the two is a useful
/// review check — it had `ValueHashJoin`'s keys right while this walk did not. It is **not** a
/// substitute, though: it deliberately reports nothing for the write operators (`Create`, `Merge`,
/// `SetClause`, `Delete`, `Remove`, `Foreach`, `ProcedureCall`), whose expressions this walk must and
/// does still collect. Reconcile the two only in the read-operator direction.
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
        PhysicalOp::NodeIndexSeek {
            value,
            variable: _,
            label: _,
            property: _,
            ordered: _,
            cached_property: _,
            index: _,
        } => {
            // Index-seek value: no static type expectation in v1 (indexability is the executor's
            // runtime concern); record as Any. (A seek is a leaf — no input to recurse into.)
            params_in_expr(value, ParamType::Any, record);
        }
        PhysicalOp::NodeCompositeIndexSeek {
            values,
            variable: _,
            label: _,
            properties: _,
            cached_property: _,
            index: _,
        } => {
            // Composite index-seek values (`rmp` task #657): one per key, each treated like a single
            // seek value — no static type expectation, recorded as Any. A leaf, so no input to recurse.
            for value in values {
                params_in_expr(value, ParamType::Any, record);
            }
        }
        PhysicalOp::NodeIndexMultiSeek {
            values,
            variable: _,
            label: _,
            property: _,
            index: _,
        }
        | PhysicalOp::RelIndexMultiSeek {
            values,
            relationship: _,
            from: _,
            to: _,
            rel_type: _,
            property: _,
            direction: _,
            index: _,
        } => {
            // The multi-value seek's alternatives (`rmp` task #868): one per `IN`-list element / `OR`
            // branch, each treated exactly like a single seek value — no static type expectation,
            // recorded as Any. They MUST be walked here or a `$param` alternative would never bind.
            // A leaf — no input to recurse into.
            for value in values {
                params_in_expr(value, ParamType::Any, record);
            }
        }
        PhysicalOp::NodeLabelScanEq {
            value,
            variable: _,
            label: _,
            property: _,
        } => {
            // The precise equality-scan value (`rmp` task #325): same treatment as a seek value — no
            // static type expectation, recorded as Any. A leaf, so no input to recurse into.
            params_in_expr(value, ParamType::Any, record);
        }
        PhysicalOp::NodeIndexRangeSeek {
            value,
            variable: _,
            label: _,
            property: _,
            bound: _,
            ordered: _,
            cached_property: _,
            index: _,
        } => {
            params_in_expr(value, ParamType::Any, record);
        }
        PhysicalOp::RelIndexSeek {
            value,
            relationship: _,
            from: _,
            to: _,
            rel_type: _,
            property: _,
            direction: _,
            index: _,
        } => {
            // The relationship-property seek value (`rmp` task #659): same treatment as a node seek
            // value — no static type expectation, recorded as Any. A leaf — no input to recurse into.
            params_in_expr(value, ParamType::Any, record);
        }
        PhysicalOp::RelIndexRangeSeek {
            value,
            relationship: _,
            from: _,
            to: _,
            rel_type: _,
            property: _,
            bound: _,
            direction: _,
            index: _,
        } => {
            // The relationship-property RANGE seek's bound value (`rmp` task #680): commonly a `$param`
            // after literal auto-parameterisation (`WHERE r.amount >= 9000` becomes `>= $AUTOPARAM_n`),
            // so it MUST be walked here or the bound would never bind. Same treatment as the node range
            // seek's bound — no static type expectation, recorded as Any. A leaf — no input to recurse.
            params_in_expr(value, ParamType::Any, record);
        }
        PhysicalOp::RelCompositeIndexSeek {
            values,
            relationship: _,
            from: _,
            to: _,
            rel_type: _,
            properties: _,
            direction: _,
            index: _,
        } => {
            // The composite relationship seek values (`rmp` task #666): one per key, each treated like a
            // single seek value — no static type expectation, recorded as Any. A leaf — no input.
            for value in values {
                params_in_expr(value, ParamType::Any, record);
            }
        }
        PhysicalOp::NodeIndexStartsWithSeek {
            prefix,
            variable: _,
            label: _,
            property: _,
            index: _,
        } => {
            // The STARTS WITH prefix (`rmp` task #658): commonly a `$param` after literal
            // auto-parameterisation. No static type expectation, recorded as Any. A leaf — no input.
            params_in_expr(prefix, ParamType::Any, record);
        }
        PhysicalOp::NodeTextIndexSeek {
            needle,
            variable: _,
            label: _,
            property: _,
            op: _,
            index: _,
        } => {
            // The CONTAINS/ENDS WITH/STARTS WITH needle (`rmp` task #662): commonly a `$param` after
            // literal auto-parameterisation. No static type expectation, recorded as Any. A leaf.
            params_in_expr(needle, ParamType::Any, record);
        }
        PhysicalOp::Filter { input, predicate } => {
            params_in_expr(predicate, ParamType::Any, record);
            walk_physical(input, record);
        }
        PhysicalOp::Projection {
            input,
            items,
            distinct: _,
        } => {
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
        // `rmp` task #866. The count-store operators hold no expressions of their own — the counted
        // shape was fully resolved at plan time — but their `fallback` is the very `Aggregation` above,
        // so the walk must descend into it. Treating them as expression-free *leaves* would silently
        // stop collecting parameter references from the subtree that actually runs whenever the seam
        // declines, and a `$param` in it would then fail to bind.
        PhysicalOp::NodeCountFromCountStore {
            fallback,
            column: _,
            label: _,
        }
        | PhysicalOp::RelationshipCountFromCountStore {
            fallback,
            column: _,
            types: _,
        } => {
            walk_physical(fallback, record);
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

        // ---- traversals -----------------------------------------------------------------------
        // A **fixed-length** hop's inline property map is lowered to an ordinary `Filter` over the
        // relationship binding, so its parameters are collected by the `Filter` arm above. A
        // **variable-length** hop's is not: the map must hold for *every* relationship of the path, so
        // the planner keeps it on the operator (`rel_props`) and the expansion applies it per hop. It is
        // therefore an expression the plan really evaluates and its parameters must be recorded here.
        //
        // Not doing so was a silent wrong answer, not merely a missing diagnostic: `BoundParameters`
        // carries exactly the recorded names, so an unrecorded `$p` was *absent* at evaluation, the
        // comparison went null, every relationship was rejected, and
        // `MATCH (a)-[r:T*1..3 {k: $p}]->(b)` returned **zero rows** while the fixed-length spelling of
        // the same query returned the match. (Literals lifted by
        // [`normalize_query`](crate::plan_cache::normalize_query) would fall in the same hole; today
        // that normalisation only builds the cache key, and no plan is compiled from its text.)
        //
        // `to_predicate` (`rmp` task #870) is the far-endpoint predicate pushed down out of the
        // `Filter` that used to sit above the expansion — the very `Filter` whose parameters were
        // recorded before the pushdown — so it is recorded here for exactly the same reason.
        PhysicalOp::ExpandAll {
            input,
            rel_props,
            to_predicate,
            from: _,
            relationship: _,
            to: _,
            direction: _,
            types: _,
            range: _,
            prior_rels: _,
            pruning: _,
        } => {
            for e in rel_props.iter().chain(to_predicate.iter()) {
                params_in_expr(e, ParamType::Any, record);
            }
            walk_physical(input, record);
        }
        PhysicalOp::ExpandInto {
            input,
            rel_props,
            from: _,
            relationship: _,
            to: _,
            direction: _,
            types: _,
            range: _,
            prior_rels: _,
        } => {
            if let Some(props) = rel_props {
                params_in_expr(props, ParamType::Any, record);
            }
            walk_physical(input, record);
        }
        // Neither carries an expression of its own: a path operator's bounds are `VarLengthRange`
        // (plain `Option<u64>` counts) and its steps are `Var`s.
        PhysicalOp::ShortestPath {
            input,
            from: _,
            to: _,
            relationship: _,
            path: _,
            direction: _,
            types: _,
            range: _,
            all: _,
        }
        | PhysicalOp::NamedPath {
            input,
            variable: _,
            start: _,
            steps: _,
        } => {
            walk_physical(input, record);
        }

        // A quantified path pattern carries its per-iteration interior predicate, which may reference
        // parameters (e.g. `((x)-[r]->(y) WHERE x.age > $min){1,3}`).
        // `extra_hops` holds `QppStep`s, which carry only `Var`s, a direction and relationship types —
        // every interior condition of every hop is folded into the one `interior_predicate`.
        PhysicalOp::QuantifiedPath {
            input,
            interior_predicate,
            from: _,
            to: _,
            group_start: _,
            group_end: _,
            relationship: _,
            direction: _,
            types: _,
            extra_hops: _,
            min: _,
            max: _,
            prior_rels: _,
            into: _,
        } => {
            if let Some(pred) = interior_predicate {
                params_in_expr(pred, ParamType::Any, record);
            }
            walk_physical(input, record);
        }

        // ---- joins / branches ---------------------------------------------------------------
        // `join_keys` are shared column NAMES (`Vec<String>`), not expressions, and `all` is a flag.
        PhysicalOp::NestedLoopJoin { left, right }
        | PhysicalOp::HashJoin {
            left,
            right,
            join_keys: _,
        }
        | PhysicalOp::Union {
            left,
            right,
            all: _,
        } => {
            walk_physical(left, record);
            walk_physical(right, record);
        }
        // `rmp` #960. Unlike every other join, this one carries its own key EXPRESSIONS, and they are
        // the only place those expressions exist — the planner builds a `ValueHashJoin` by CONSUMING
        // the `Filter` that held the equality (`rmp` #865), so after the rewrite there is no `Filter`
        // arm above to record their `$param`s. Grouping it with the other joins for their shared
        // `left`/`right` forced a `..` here, and the two keys fell through it: `BoundParameters` then
        // omitted the name, `eval` resolved it to `Null`, the key never matched, and
        // `UNWIND range(0, 99) AS i MATCH (b:Person {id: (i + 1) % $n}) …` returned ZERO rows against a
        // store that held every one of them. The literal spelling of the same query was unaffected,
        // which is what kept it hidden.
        PhysicalOp::ValueHashJoin {
            left,
            right,
            left_key,
            right_key,
        } => {
            params_in_expr(left_key, ParamType::Any, record);
            params_in_expr(right_key, ParamType::Any, record);
            walk_physical(left, record);
            walk_physical(right, record);
        }
        // `rmp` #869: the semi-join's `$param` expectations live in its INNER branch, which carries the
        // subquery's own operators — so walking it is what keeps
        // `WHERE EXISTS { (u:USER {uidn: $id}) }` declaring `$id`. The `predicate` field is NOT walked:
        // it is the same subquery in its un-rewritten spelling, so recording it too would double-declare
        // every parameter, and it is never evaluated.
        PhysicalOp::SemiApply {
            input,
            inner,
            anti: _,
            predicate: _,
        } => {
            walk_physical(input, record);
            walk_physical(inner, record);
        }
        PhysicalOp::Optional {
            input,
            null_variables: _,
        }
        | PhysicalOp::Eager { input }
        // `rmp` #972: a pure barrier around the statement boundary. It carries no expression of its
        // own, so there is nothing to record here — but the arm is written out rather than left to a
        // fallthrough, because this walk is field-exhaustive ON PURPOSE (`rmp` #960): a missed operator
        // silently loses a `$param` expectation and the parameter reads back as `Null`.
        | PhysicalOp::AdvanceCommand { input } => walk_physical(input, record),
        // `rmp` #882: the fused one-hop `OPTIONAL MATCH` carries the predicates that used to be
        // `Filter` operators of its own, so its parameters must be recorded here or a
        // `OPTIONAL MATCH (a)-[r]->(b) WHERE b.x = $v` would silently lose the `$v` expectation the
        // `Filter` arm above used to record.
        PhysicalOp::OptionalExpand {
            input,
            predicates,
            from: _,
            relationship: _,
            to: _,
            direction: _,
            types: _,
            into: _,
            null_variables: _,
            arguments: _,
        } => {
            for predicate in predicates {
                params_in_expr(predicate, ParamType::Any, record);
            }
            walk_physical(input, record);
        }

        // ---- write operators carry expressions in their pattern/ops -------------------------
        PhysicalOp::Create { input, pattern } => {
            for part in pattern {
                params_in_create_part(part, record);
            }
            walk_physical(input, record);
        }
        // Kept separate from `Create` (rather than sharing an arm and re-matching for the `SET` ops)
        // so that both patterns stay field-exhaustive and cannot drift apart.
        PhysicalOp::Merge {
            input,
            pattern,
            on_create,
            on_match,
        } => {
            for part in pattern {
                params_in_create_part(part, record);
            }
            for set_op in on_create.iter().chain(on_match) {
                params_in_set_op(set_op, record);
            }
            walk_physical(input, record);
        }
        PhysicalOp::SetClause { input, ops } => {
            for set_op in ops {
                params_in_set_op(set_op, record);
            }
            walk_physical(input, record);
        }
        PhysicalOp::Delete {
            input,
            exprs,
            detach: _,
        } => {
            for e in exprs {
                params_in_expr(e, ParamType::Any, record);
            }
            walk_physical(input, record);
        }
        PhysicalOp::Remove { input, ops } => {
            for op in ops {
                // A `match`, not an `if let`: an `if let` is not exhaustiveness-checked, so a future
                // `RemoveOp` variant carrying an expression would compile here and silently lose its
                // `$param`s — the very failure mode this walk exists to prevent.
                match op {
                    crate::logical::RemoveOp::Property { target } => {
                        params_in_expr(target, ParamType::Any, record);
                    }
                    // `REMOVE n:Label` names a variable and a label list; no expression.
                    crate::logical::RemoveOp::Labels {
                        target: _,
                        labels: _,
                    } => {}
                }
            }
            walk_physical(input, record);
        }
        PhysicalOp::Foreach {
            input,
            list,
            body,
            variable: _,
        } => {
            params_in_expr(list, ParamType::Any, record);
            walk_physical(input, record);
            // The body sub-plan may reference `$param`s in its inner update clauses.
            walk_physical(body, record);
        }
        PhysicalOp::ProcedureCall {
            input,
            args,
            name: _,
            yields: _,
        } => {
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
        // `SpatialIndexSeek` / `RelSpatialIndexSeek`'s centre and radius are plan-time-folded `f64`
        // constants (never `$param`s — a non-constant proximity predicate is declined by the planner),
        // so they carry no parameter references (`rmp` tasks #73, #664).
        PhysicalOp::AllNodesScan { variable: _ }
        | PhysicalOp::NodeByLabelScan {
            variable: _,
            label: _,
        }
        | PhysicalOp::TokenLookupScan {
            variable: _,
            label: _,
            index: _,
        }
        | PhysicalOp::NodeIndexScan {
            variable: _,
            label: _,
            property: _,
            ordered: _,
            cached_property: _,
            index: _,
        }
        | PhysicalOp::SpatialIndexSeek {
            variable: _,
            label: _,
            property: _,
            center_x: _,
            center_y: _,
            radius: _,
            index: _,
        }
        | PhysicalOp::RelSpatialIndexSeek {
            relationship: _,
            from: _,
            to: _,
            rel_type: _,
            property: _,
            center_x: _,
            center_y: _,
            radius: _,
            direction: _,
            index: _,
        }
        | PhysicalOp::AllRelationshipsScan {
            relationship: _,
            from: _,
            to: _,
            direction: _,
            types: _,
        }
        | PhysicalOp::Argument { arguments: _ }
        | PhysicalOp::Empty => {}
    }
}

/// Reports parameters appearing in a write-pattern part's inline property expression.
///
/// Field-exhaustive for the same reason [`walk_physical`] is: an unrecorded `$param` in a `CREATE`
/// property map is a silent wrong write, not a diagnostic.
fn params_in_create_part(
    part: &crate::logical::CreatePart,
    record: &mut impl FnMut(&str, ParamType),
) {
    let props = match part {
        crate::logical::CreatePart::Node {
            properties,
            variable: _,
            labels: _,
        }
        | crate::logical::CreatePart::Relationship {
            properties,
            variable: _,
            from: _,
            to: _,
            rel_type: _,
            direction: _,
        } => properties,
    };
    if let Some(props) = props {
        params_in_expr(props, ParamType::Any, record);
    }
}

/// Reports parameters appearing in a `SET` op's value/target expressions.
///
/// Field-exhaustive: see [`params_in_create_part`].
fn params_in_set_op(op: &crate::logical::SetOp, record: &mut impl FnMut(&str, ParamType)) {
    match op {
        crate::logical::SetOp::Property { target, value } => {
            params_in_expr(target, ParamType::Any, record);
            params_in_expr(value, ParamType::Any, record);
        }
        // `target` is a `Var`, not an expression, in both of these.
        crate::logical::SetOp::ReplaceProperties { value, target: _ }
        | crate::logical::SetOp::MergeProperties { value, target: _ } => {
            params_in_expr(value, ParamType::Any, record);
        }
        // `SET n:Label` names a variable and a label list; no expression.
        crate::logical::SetOp::AddLabels {
            target: _,
            labels: _,
        } => {}
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
        ExprKind::Unary { operand, .. }
        | ExprKind::HasLabels { operand, .. }
        | ExprKind::TypePredicate { operand, .. }
        | ExprKind::NormalizedPredicate { operand, .. } => {
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
        ExprKind::ListComprehension(crate::ast::ListComprehension {
            list,
            predicate,
            projection,
            variable: _,
        }) => {
            params_in_expr(list, ParamType::Any, record);
            if let Some(p) = predicate {
                params_in_expr(p, ParamType::Any, record);
            }
            if let Some(proj) = projection {
                params_in_expr(proj, ParamType::Any, record);
            }
        }
        // The comprehension's PATTERN is evaluated per driving row exactly like a `MATCH` pattern —
        // `eval_pattern_comprehension` matches `pc.element` and applies each inline property map — so
        // its `$param`s must be recorded here. They were not, which is the same defect class as `rmp`
        // #960 one level down: `RETURN [(a)-[:KNOWS]->(b:Person {city: $c}) | b.name]` left `$c`
        // unbound, the map comparison went null, and the comprehension yielded an EMPTY LIST for
        // every row while the `WHERE b.city = $c` spelling of the same query returned the match.
        ExprKind::PatternComprehension(pc) => {
            // Destructured exhaustively (rather than reaching for fields) so that a new field on
            // `PatternComprehension` is a compile error here. `element` was missing for exactly that
            // reason. The `&**` is because the payload is boxed; box patterns are not stable.
            let crate::ast::PatternComprehension {
                element,
                predicate,
                projection,
                var: _,
            } = &**pc;
            params_in_pattern_element(element, record);
            if let Some(p) = predicate {
                params_in_expr(p, ParamType::Any, record);
            }
            params_in_expr(projection, ParamType::Any, record);
        }
        ExprKind::Quantifier(q) => {
            let crate::ast::QuantifierExpr {
                list,
                predicate,
                kind: _,
                variable: _,
            } = &**q;
            params_in_expr(list, ParamType::Any, record);
            params_in_expr(predicate, ParamType::Any, record);
        }
        ExprKind::Reduce(r) => {
            let crate::ast::ReduceExpr {
                init,
                list,
                body,
                accumulator: _,
                variable: _,
            } = &**r;
            params_in_expr(init, ParamType::Any, record);
            params_in_expr(list, ParamType::Any, record);
            params_in_expr(body, ParamType::Any, record);
        }
        ExprKind::MapProjection(mp) => {
            let crate::ast::MapProjection { entity, selectors } = &**mp;
            params_in_expr(entity, ParamType::Any, record);
            for sel in selectors {
                // A `match`, not an `if let`, for the reason given on [`walk_physical`]: an `if let`
                // is not exhaustiveness-checked, so a future selector carrying an expression would
                // compile here and silently lose its `$param`s.
                match sel {
                    crate::ast::MapProjectionSelector::Entry { value, key: _ } => {
                        params_in_expr(value, ParamType::Any, record);
                    }
                    // `.name` is a property key; `.*` names nothing. Neither holds an expression.
                    crate::ast::MapProjectionSelector::Property(_)
                    | crate::ast::MapProjectionSelector::AllProperties => {}
                }
            }
        }
        ExprKind::ExistsSubquery(ex) => {
            for part in &ex.pattern {
                params_in_pattern_part(part, record);
            }
            if let Some(p) = &ex.predicate {
                params_in_expr(p, ParamType::Any, record);
            }
            // Full-query form: collect the parameters of the inner read-only query so they are bound
            // into the outer `BoundParameters` and thus available when the subquery is executed.
            if let Some(q) = &ex.full_query {
                params_in_query(q, record);
            }
        }
        // COUNT / COLLECT subqueries: collect the parameters of the pattern (COUNT pattern form) and
        // of the inner correlated query, exactly like `ExistsSubquery`, so they are bound alongside
        // the outer query's parameters.
        ExprKind::CountSubquery(sq) | ExprKind::CollectSubquery(sq) => {
            for part in &sq.pattern {
                params_in_pattern_part(part, record);
            }
            if let Some(p) = &sq.predicate {
                params_in_expr(p, ParamType::Any, record);
            }
            if let Some(q) = &sq.full_query {
                params_in_query(q, record);
            }
        }
    }
}

/// Reports the parameters referenced anywhere in a (sub)query — every clause's expressions, pattern
/// inline properties, projections, and any further nested subqueries. Used for the full-query form
/// of an `EXISTS { ... }` subquery so its `$params` are bound alongside the outer query's.
fn params_in_query(query: &Query, record: &mut impl FnMut(&str, ParamType)) {
    match &query.body {
        QueryBody::Regular { head, unions } => {
            params_in_single_query(head, record);
            for u in unions {
                params_in_single_query(&u.query, record);
            }
        }
        QueryBody::StandaloneCall(call) => {
            if let Some(args) = &call.call.args {
                for a in args {
                    params_in_expr(a, ParamType::Any, record);
                }
            }
            // `CALL … YIELD a, b WHERE <expr>` — the trailing filter is an expression like any other.
            // Unreachable today (a subquery body is always a `QueryBody::Regular`, and the top-level
            // standalone form lowers its `WHERE` into a `Filter` that the plan walk records), but this
            // function's name invites reuse on a top-level query, and omitting it is the identical
            // defect class this module exists to prevent. `crate::plan_cache`'s twin walker already
            // walks it.
            if let Some(crate::ast::StandaloneYield::Items {
                where_clause: Some(w),
                items: _,
            }) = &call.yield_clause
            {
                params_in_expr(w, ParamType::Any, record);
            }
        }
    }
}

fn params_in_single_query(sq: &SingleQuery, record: &mut impl FnMut(&str, ParamType)) {
    for clause in &sq.clauses {
        match clause {
            Clause::Match(m) => {
                for part in &m.pattern {
                    params_in_pattern_part(part, record);
                }
                if let Some(w) = &m.where_clause {
                    params_in_expr(w, ParamType::Any, record);
                }
            }
            Clause::Unwind(u) => params_in_expr(&u.expr, ParamType::Any, record),
            Clause::LoadCsv(l) => params_in_expr(&l.url, ParamType::Any, record),
            Clause::Call(c) => {
                if let Some(args) = &c.call.args {
                    for a in args {
                        params_in_expr(a, ParamType::Any, record);
                    }
                }
                if let Some(w) = &c.where_clause {
                    params_in_expr(w, ParamType::Any, record);
                }
            }
            Clause::CallSubquery(c) => {
                params_in_query(&c.query, record);
                if let Some(t) = &c.in_transactions {
                    if let Some(batch) = &t.batch_size {
                        params_in_expr(batch, ParamType::Any, record);
                    }
                }
            }
            Clause::Create(c) => {
                for part in &c.pattern {
                    params_in_pattern_part(part, record);
                }
            }
            Clause::Merge(m) => {
                params_in_pattern_part(&m.pattern, record);
                for action in &m.actions {
                    let items = match action {
                        MergeAction::OnCreate(items) | MergeAction::OnMatch(items) => items,
                    };
                    for item in items {
                        params_in_set_item(item, record);
                    }
                }
            }
            Clause::Set(s) => {
                for item in &s.items {
                    params_in_set_item(item, record);
                }
            }
            Clause::Delete(d) => {
                for e in &d.exprs {
                    params_in_expr(e, ParamType::Any, record);
                }
            }
            Clause::Remove(r) => {
                for item in &r.items {
                    // A `match`, not an `if let`: see [`walk_physical`]. The AST twin of the
                    // `RemoveOp` walk in the plan walker, and hardened for the same reason.
                    match item {
                        RemoveItem::Property(e) => params_in_expr(e, ParamType::Any, record),
                        // `REMOVE n:Label` names a variable and a label list; no expression.
                        RemoveItem::Labels {
                            target: _,
                            labels: _,
                        } => {}
                    }
                }
            }
            Clause::Foreach(f) => {
                params_in_expr(&f.list, ParamType::Any, record);
                params_in_clauses(&f.body, record);
            }
            Clause::With(w) => {
                params_in_projection_body(&w.body, record);
                if let Some(p) = &w.where_clause {
                    params_in_expr(p, ParamType::Any, record);
                }
            }
            Clause::Return(r) => params_in_projection_body(&r.body, record),
        }
    }
}

/// Walks a list of clauses (e.g. a `FOREACH` body), reporting each `$param` reference through
/// `record`. Shares the per-clause logic with [`params_in_single_query`] by iterating directly.
fn params_in_clauses(clauses: &[Clause], record: &mut impl FnMut(&str, ParamType)) {
    // A `FOREACH` body is a `Vec<Clause>` (not a `SingleQuery`); reuse the single-query walker by
    // wrapping it in an ad-hoc single query is unnecessary — recurse over the inner clauses through a
    // synthetic `SingleQuery` view so the same per-clause arms apply.
    let view = SingleQuery {
        clauses: clauses.to_vec(),
        span: crate::lexer::Span::new(0, 0),
    };
    params_in_single_query(&view, record);
}

fn params_in_set_item(item: &SetItem, record: &mut impl FnMut(&str, ParamType)) {
    match item {
        SetItem::Property { target, value } => {
            params_in_expr(target, ParamType::Any, record);
            params_in_expr(value, ParamType::Any, record);
        }
        SetItem::Replace { value, .. } | SetItem::Merge { value, .. } => {
            params_in_expr(value, ParamType::Any, record);
        }
        SetItem::Labels { .. } => {}
    }
}

fn params_in_projection_body(body: &ProjectionBody, record: &mut impl FnMut(&str, ParamType)) {
    for item in &body.items {
        params_in_expr(&item.expr, ParamType::Any, record);
    }
    for sort in &body.order_by {
        params_in_expr(&sort.expr, ParamType::Any, record);
    }
    if let Some(skip) = &body.skip {
        params_in_expr(skip, ParamType::Integer, record);
    }
    if let Some(limit) = &body.limit {
        params_in_expr(limit, ParamType::Integer, record);
    }
}

/// Reports the parameters referenced by a pattern part's inline property maps (`{p: $x}`).
fn params_in_pattern_part(part: &PatternPart, record: &mut impl FnMut(&str, ParamType)) {
    params_in_pattern_element(&part.element, record);
}

/// Reports the parameters referenced by a pattern **element**'s inline property maps (`{p: $x}`).
///
/// Split out of [`params_in_pattern_part`] so that the two places a pattern element is evaluated —
/// a clause's [`PatternPart`] and a
/// [`PatternComprehension`](crate::ast::PatternComprehension)'s `element` — share ONE implementation.
/// They did not, and the comprehension's copy simply did not exist, so every `$param` written inside a
/// comprehension's pattern was silently unbound.
fn params_in_pattern_element(
    element: &crate::ast::PatternElement,
    record: &mut impl FnMut(&str, ParamType),
) {
    if let Some(props) = &element.start.properties {
        params_in_expr(props, ParamType::Any, record);
    }
    for link in &element.chain {
        if let Some(props) = &link.relationship.properties {
            params_in_expr(props, ParamType::Any, record);
        }
        if let Some(props) = &link.node.properties {
            params_in_expr(props, ParamType::Any, record);
        }
        // A quantified path pattern's interior node maps, extra interior hops, and inner `WHERE` may
        // reference parameters.
        if let Some(qpp) = &link.qpp {
            if let Some(props) = &qpp.interior_start.properties {
                params_in_expr(props, ParamType::Any, record);
            }
            if let Some(props) = &qpp.interior_end.properties {
                params_in_expr(props, ParamType::Any, record);
            }
            for hop in &qpp.interior_extra {
                if let Some(props) = &hop.relationship.properties {
                    params_in_expr(props, ParamType::Any, record);
                }
                if let Some(props) = &hop.node.properties {
                    params_in_expr(props, ParamType::Any, record);
                }
            }
            if let Some(where_expr) = &qpp.inner_where {
                params_in_expr(where_expr, ParamType::Any, record);
            }
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
