//! Cypher **semantic analysis** — the compile-time error phase (`04-technical-design.md` §7.3).
//!
//! This is the pipeline stage between the [`parser`](crate::parser)'s AST and the logical planner
//! (`04 §7.1`: *"semantic analysis → validated AST (★ all COMPILE-TIME errors raised here)"*). It
//! walks the [`Query`] AST to completion and raises **every** statically-detectable Cypher error as
//! a compile-time [`SemanticError`] (`04 §7.3`: *"Semantic analysis is the only phase allowed to
//! emit compile-time errors and it runs to completion before any side effect"*). A [`Query`] that
//! analyses cleanly becomes a [`ValidatedQuery`] — a type-level token that the compile-time checks
//! have passed.
//!
//! # The compile-vs-runtime boundary (load-bearing; `04 §7.3`)
//!
//! The openCypher TCK splits errors by **phase**. This pass raises **only** the compile-time
//! classes ([`SyntaxError`](crate::parser::SyntaxError)-typed `UndefinedVariable` and the
//! `SemanticError`-typed rest — see [`crate::errors`]). It deliberately does **not** raise anything
//! the TCK expects at *runtime*, because those depend on actual data the analyser cannot see:
//!
//! - **Division by zero** (`RETURN 1/0`) — a runtime `ArithmeticError`. `1/0` analyses cleanly here.
//! - **Type coercion / type errors on actual values** (e.g. adding a string to a list at runtime) —
//!   runtime `TypeError`. We do not constant-fold or type-infer expression results.
//! - **Constraint / uniqueness violations**, **entity-not-found**, **property-not-found** — runtime,
//!   raised by the executor against the live graph.
//! - **Missing parameters** (`ParameterMissing`) — a *bind-time* (runtime) check; parameters bind at
//!   execution, never at compile (`04 §7.5`), so an unbound `$p` is **not** a semantic error.
//!
//! The phase split is machine-checked: [`crate::errors::SemanticErrorKind::classification`] maps
//! every variant to `phase = CompileTime`, and `tests/error_classification.rs` asserts it for the
//! whole enum, so the split cannot regress.
//!
//! # Variable scoping (the core)
//!
//! Variables enter scope from: `MATCH`/`CREATE`/`MERGE` patterns (node, relationship and named-path
//! variables), `UNWIND … AS v`, `CALL … YIELD …`, and `WITH`/`RETURN` projection aliases. References
//! in `WHERE`, `RETURN`/`WITH` expressions, `SET`/`REMOVE`/`DELETE` targets, `ORDER BY`, and inline
//! pattern predicates are resolved against the scope **in force at that point**.
//!
//! ## The projection-boundary reset (`WITH` / `RETURN`)
//!
//! A `WITH` or `RETURN` is a **projection boundary**: after it, the scope is **reset** to exactly the
//! projected names (the alias of each item, or the inferable name of a bare variable / `*`
//! expansion). A variable not carried through a `WITH` is therefore **undefined** afterwards — the
//! single most important scoping rule the TCK exercises. `ORDER BY`, `SKIP` and `LIMIT` attached to a
//! projection, and a `WITH … WHERE`, are evaluated **in the post-projection scope** (they see the
//! projected names, per the openCypher grammar where they sit inside the `ProjectionBody`).
//!
//! # Aggregation rules (`04 §7.6` grouping semantics; openCypher)
//!
//! A projection (or `WITH`) item that *contains* an aggregating function (`count`, `sum`, `avg`,
//! `min`, `max`, `collect`, `stdev`, `stdevp`, `percentileCont`, `percentileDisc`, plus the
//! `count(*)` atom) makes the whole projection an **aggregating projection**. Then **every other
//! projected expression must be a pure grouping key** (no free, non-aggregated sub-expression),
//! otherwise the grouping is ambiguous ([`AmbiguousAggregationExpression`]). Aggregates may not be
//! **nested** ([`NestedAggregation`]) and may not appear where aggregation is forbidden — `WHERE`,
//! pattern predicates, variable-length bounds ([`InvalidAggregation`]).
//!
//! [`AmbiguousAggregationExpression`]: crate::errors::SemanticErrorKind::AmbiguousAggregationExpression
//! [`NestedAggregation`]: crate::errors::SemanticErrorKind::NestedAggregation
//! [`InvalidAggregation`]: crate::errors::SemanticErrorKind::InvalidAggregation
//!
//! # Scope, and what is deferred (named, not silently dropped)
//!
//! Modelled at compile time here: undefined-variable resolution with the `WITH`/`RETURN` reset;
//! variable type conflicts (node vs relationship) and `CREATE`/`MERGE` relationship-variable
//! rebinding ([`VariableAlreadyBound`]); aggregation placement/nesting/grouping; `RETURN *` with
//! empty scope; duplicate result columns; `ORDER BY` over out-of-scope names; mandatory `WITH`
//! aliasing; a built-in **function registry** (unknown name + arity for a representative set);
//! `CREATE`/`MERGE` relationship well-formedness (single type, directed, not variable-length);
//! `DELETE` of a non-entity; clause composition (`RETURN` must be last; non-empty query).
//!
//! [`VariableAlreadyBound`]: crate::errors::SemanticErrorKind::VariableAlreadyBound
//!
//! One classified detail is **reserved, not yet reachable**:
//! [`NegativeIntegerArgument`](crate::errors::SemanticErrorKind::NegativeIntegerArgument). Its only
//! v1 syntactic position — a variable-length bound — is parsed into a `u64` by the lexer/parser, so
//! a literal negative bound cannot reach this pass (it is a parse-level concern). The detail is kept
//! in the classification table because it is a real TCK detail that becomes reachable once bounds
//! may be parameter-driven; wiring it then is mechanical.
//!
//! Deferred to later phases / sub-tasks, **by name**: (1) full static **type inference** of
//! expression results (most type mismatches are runtime `TypeError`s by TCK design); (2)
//! **`SET`-on-non-entity** static rejection — the parser already constrains `SET` targets to
//! variables / property chains, and whether the target *is* an entity is generally a runtime fact,
//! so only the structural part is enforced here; (3) **procedure** signature/arity validation
//! (needs the procedure catalogue, an executor concern); (4) the exotic productions the parser
//! itself defers (`FOREACH`, `CALL { subquery }`, existential subqueries, quantifier predicates,
//! `LOAD CSV`, DDL); (5) the two-letter Neo4j **status codes** (escalated, `02 Q2`).

use crate::ast::{
    Clause, CreateClause, DeleteClause, Expr, ExprKind, Literal, LoadCsvClause, MatchClause,
    MergeAction, MergeClause, NodePattern, PatternElement, PatternPart, ProjectionBody,
    ProjectionItem, Query, QueryBody, RelDirection, RelationshipPattern, RemoveClause, RemoveItem,
    SetClause, SetItem, SingleQuery, SortItem, StandaloneCall, StandaloneYield, UnionPart,
    UnwindClause, YieldItem,
};
use crate::errors::{SemanticError, SemanticErrorKind, VarKind};
use crate::function_registry::{self, ArityCheck};
use crate::lexer::Span;
use graphus_core::GraphusError;
use std::collections::HashMap;

/// A [`Query`] that has passed semantic analysis (`04 §7.3`) and is ready for logical planning.
///
/// Holding one is proof that **all compile-time checks have run to completion and succeeded** — the
/// invariant the rest of the pipeline relies on (`04 §7.1`/§7.3). It owns the validated AST. The
/// wrapper is intentionally thin in v1 (it does not yet attach resolved scope/type annotations);
/// those are added when the logical planner needs them, so the type can grow without changing the
/// [`analyze`] contract.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct ValidatedQuery {
    query: Query,
}

impl ValidatedQuery {
    /// Borrows the underlying validated [`Query`] AST.
    pub fn query(&self) -> &Query {
        &self.query
    }

    /// Consumes the wrapper, returning the validated [`Query`] AST.
    pub fn into_query(self) -> Query {
        self.query
    }
}

/// Runs semantic analysis over a parsed [`Query`], returning a [`ValidatedQuery`] on success.
///
/// This is the semantic phase's public entry point (`04 §7.1`). It runs to completion **before any
/// side effect** (`04 §7.3`) and reports the **first** statically-detectable error in a stable
/// left-to-right, clause-then-expression traversal order. (Reporting the first error — rather than
/// collecting all — is the deliberate v1 choice: it matches the parser's single-error contract and
/// what the TCK asserts, where each negative scenario expects one specific `(phase, type, detail)`;
/// the traversal order is documented so callers can rely on *which* error surfaces. Collecting all
/// errors is a future ergonomic addition that would not change the pass/fail verdict.)
///
/// # Errors
///
/// Returns a [`SemanticError`] (always the compile-time phase, `04 §7.3`) carrying the byte
/// [`Span`] of the offending AST node and its TCK `(phase, type, detail)`
/// [`classification`](SemanticError::classification). Use [`analyze_to_graphus`] for the
/// [`GraphusError`]-returning boundary form.
///
/// # Examples
///
/// ```
/// use graphus_cypher::parser::parse_tokens;
/// use graphus_cypher::lexer::tokenize;
/// use graphus_cypher::semantics::analyze;
///
/// let src = "MATCH (n:Person) WHERE n.age > 18 RETURN n.name AS name";
/// let toks = tokenize(src).unwrap();
/// let ast = parse_tokens(&toks, src).unwrap();
/// let validated = analyze(&ast).expect("query is semantically valid");
/// assert_eq!(validated.query().span, ast.span);
/// ```
pub fn analyze(query: &Query) -> Result<ValidatedQuery, SemanticError> {
    Analyzer.check_query(query)?;
    Ok(ValidatedQuery {
        query: query.clone(),
    })
}

/// [`analyze`] at the engine boundary: maps the [`SemanticError`] onto [`GraphusError::Compile`]
/// (`04 §7.3`), discarding the structured form in favour of the positional message the connectivity
/// layer surfaces.
///
/// # Errors
///
/// Returns [`GraphusError::Compile`] for any compile-time semantic error.
pub fn analyze_to_graphus(query: &Query) -> Result<ValidatedQuery, GraphusError> {
    analyze(query).map_err(GraphusError::from)
}

// =================================================================================================
// Scope model
// =================================================================================================

/// The set of variables in scope at a point in analysis, tracking each name's [`VarKind`] and the
/// span where it was first bound (for diagnostics).
///
/// A `Scope` is built up within one query *part* (the run of clauses up to and including a
/// projection boundary) and **reset** at each `WITH`/`RETURN` to exactly the projected names — the
/// rule documented on the module.
#[derive(Debug, Clone, Default)]
struct Scope {
    bindings: HashMap<String, Binding>,
}

#[derive(Debug, Clone, Copy)]
struct Binding {
    kind: VarKind,
}

impl Scope {
    fn contains(&self, name: &str) -> bool {
        self.bindings.contains_key(name)
    }

    fn kind_of(&self, name: &str) -> Option<VarKind> {
        self.bindings.get(name).map(|b| b.kind)
    }

    /// Introduces `name` with `kind`. If the name is already bound, enforces the Cypher rules:
    /// re-binding the **same** kind is allowed (a node variable repeated across `MATCH` parts refers
    /// to the same node); re-binding with a **conflicting** kind is a [`VariableTypeConflict`].
    ///
    /// [`VariableTypeConflict`]: SemanticErrorKind::VariableTypeConflict
    fn bind(&mut self, name: &str, kind: VarKind, span: Span) -> Result<(), SemanticError> {
        if let Some(existing) = self.bindings.get(name) {
            if existing.kind != kind {
                return Err(SemanticError::new(
                    SemanticErrorKind::VariableTypeConflict {
                        name: name.to_owned(),
                        first: existing.kind,
                        second: kind,
                    },
                    span,
                ));
            }
            // Same kind: a benign re-reference (e.g. `MATCH (a) MATCH (a)`), not an error.
            return Ok(());
        }
        self.bindings.insert(name.to_owned(), Binding { kind });
        Ok(())
    }
}

// =================================================================================================
// The analyzer
// =================================================================================================

/// The analysis driver. Stateless beyond per-call locals, so it is a zero-sized walker.
struct Analyzer;

impl Analyzer {
    /// Checks a whole [`Query`]: each single query of a `UNION` chain is analysed independently
    /// (each has its own scope), or the standalone `CALL`.
    fn check_query(&self, query: &Query) -> Result<(), SemanticError> {
        match &query.body {
            QueryBody::Regular { head, unions } => {
                self.check_single_query(head)?;
                for UnionPart { query: sq, .. } in unions {
                    self.check_single_query(sq)?;
                }
                Ok(())
            }
            QueryBody::StandaloneCall(call) => self.check_standalone_call(call),
        }
    }

    /// Checks a single query: validate clause composition, then walk clauses left-to-right,
    /// threading the [`Scope`] and resetting it at every projection boundary.
    fn check_single_query(&self, sq: &SingleQuery) -> Result<(), SemanticError> {
        self.check_clause_composition(sq)?;

        let mut scope = Scope::default();
        for (idx, clause) in sq.clauses.iter().enumerate() {
            match clause {
                Clause::Match(m) => self.check_match(m, &mut scope)?,
                Clause::Unwind(u) => self.check_unwind(u, &mut scope)?,
                Clause::LoadCsv(l) => self.check_load_csv(l, &mut scope)?,
                Clause::Call(c) => self.check_in_query_call(c, &mut scope)?,
                Clause::Create(c) => self.check_create(c, &mut scope)?,
                Clause::Merge(m) => self.check_merge(m, &mut scope)?,
                Clause::Set(s) => self.check_set(s, &scope)?,
                Clause::Delete(d) => self.check_delete(d, &scope)?,
                Clause::Remove(r) => self.check_remove(r, &scope)?,
                Clause::With(w) => {
                    // Projection boundary: WHERE/ORDER BY see the *post*-projection scope.
                    scope = self.check_projection(
                        &w.body,
                        w.span,
                        &scope,
                        w.where_clause.as_ref(),
                        false,
                    )?;
                }
                Clause::Return(r) => {
                    let is_last = idx + 1 == sq.clauses.len();
                    debug_assert!(is_last, "clause composition guarantees RETURN is last");
                    scope = self.check_projection(&r.body, r.span, &scope, None, true)?;
                }
            }
        }
        Ok(())
    }

    /// Validates clause ordering / composition that the parser deliberately left to this phase
    /// (`ast::SingleQuery` doc): the query must be non-empty, and a `RETURN`, if present, must be
    /// the final clause. TCK detail `InvalidClauseComposition`.
    fn check_clause_composition(&self, sq: &SingleQuery) -> Result<(), SemanticError> {
        let Some(last) = sq.clauses.last() else {
            return Err(SemanticError::new(
                SemanticErrorKind::InvalidClauseComposition {
                    reason: "query has no clauses",
                },
                sq.span,
            ));
        };
        for clause in &sq.clauses {
            if let Clause::Return(r) = clause {
                if !std::ptr::eq(clause, last) {
                    return Err(SemanticError::new(
                        SemanticErrorKind::InvalidClauseComposition {
                            reason: "RETURN must be the last clause",
                        },
                        r.span,
                    ));
                }
            }
        }
        Ok(())
    }

    // ---- reading / writing clauses ----------------------------------------------------------

    fn check_match(&self, m: &MatchClause, scope: &mut Scope) -> Result<(), SemanticError> {
        for part in &m.pattern {
            self.bind_pattern_part(part, scope, PatternRole::Read)?;
        }
        if let Some(w) = &m.where_clause {
            self.check_predicate(w, scope, "WHERE")?;
        }
        Ok(())
    }

    fn check_unwind(&self, u: &UnwindClause, scope: &mut Scope) -> Result<(), SemanticError> {
        // The list expression is evaluated in the *current* scope, then the alias is bound.
        self.check_expr_refs(&u.expr, scope)?;
        self.reject_aggregation(&u.expr, "UNWIND")?;
        scope.bind(&u.alias.name, VarKind::Value, u.alias.span)
    }

    /// Validates a `LOAD CSV` clause: the source-URL expression is resolved in the *current* scope
    /// (aggregation forbidden), a statically non-string literal URL is rejected, then the row
    /// variable is bound for the downstream clauses. Like `UNWIND`, the value-typing of a *dynamic*
    /// URL (a variable / parameter / property) is a runtime concern, not a static one.
    fn check_load_csv(&self, l: &LoadCsvClause, scope: &mut Scope) -> Result<(), SemanticError> {
        self.check_expr_refs(&l.url, scope)?;
        self.reject_aggregation(&l.url, "LOAD CSV")?;
        // The openCypher `LoadCSV` grammar requires a string URL expression. A statically-typed
        // non-string literal (e.g. `FROM 42`) is a compile-time error; anything dynamic defers to
        // the runtime type check in the executor.
        if let ExprKind::Literal(lit) = &l.url.kind {
            if !matches!(lit, Literal::String(_)) {
                return Err(SemanticError::new(
                    SemanticErrorKind::InvalidLoadCsvUrl,
                    l.url.span,
                ));
            }
        }
        scope.bind(&l.alias.name, VarKind::Value, l.alias.span)
    }

    fn check_create(&self, c: &CreateClause, scope: &mut Scope) -> Result<(), SemanticError> {
        for part in &c.pattern {
            self.bind_pattern_part(part, scope, PatternRole::Create)?;
        }
        Ok(())
    }

    fn check_merge(&self, m: &MergeClause, scope: &mut Scope) -> Result<(), SemanticError> {
        self.bind_pattern_part(&m.pattern, scope, PatternRole::Create)?;
        for action in &m.actions {
            let items = match action {
                MergeAction::OnCreate(items) | MergeAction::OnMatch(items) => items,
            };
            for item in items {
                self.check_set_item(item, scope)?;
            }
        }
        Ok(())
    }

    fn check_set(&self, s: &SetClause, scope: &Scope) -> Result<(), SemanticError> {
        for item in &s.items {
            self.check_set_item(item, scope)?;
        }
        Ok(())
    }

    fn check_set_item(&self, item: &SetItem, scope: &Scope) -> Result<(), SemanticError> {
        match item {
            SetItem::Property { target, value } => {
                self.check_expr_refs(target, scope)?;
                self.check_expr_refs(value, scope)?;
                self.reject_aggregation(value, "SET")?;
            }
            SetItem::Replace { target, value } | SetItem::Merge { target, value } => {
                self.require_defined(&target.name, target.span, scope)?;
                self.check_expr_refs(value, scope)?;
                self.reject_aggregation(value, "SET")?;
            }
            SetItem::Labels { target, .. } => {
                self.require_defined(&target.name, target.span, scope)?;
            }
        }
        Ok(())
    }

    fn check_delete(&self, d: &DeleteClause, scope: &Scope) -> Result<(), SemanticError> {
        for expr in &d.exprs {
            self.check_expr_refs(expr, scope)?;
            // DELETE targets must be entity references, not arbitrary literals (TCK `InvalidDelete`).
            // We statically reject the clearly-non-entity forms (literals, lists, maps, arithmetic);
            // whether a *variable* names a node/rel/path is a runtime fact, so we accept it here.
            if Self::is_clearly_non_entity(expr) {
                return Err(SemanticError::new(
                    SemanticErrorKind::InvalidDelete,
                    expr.span,
                ));
            }
        }
        Ok(())
    }

    fn check_remove(&self, r: &RemoveClause, scope: &Scope) -> Result<(), SemanticError> {
        for item in &r.items {
            match item {
                RemoveItem::Labels { target, .. } => {
                    self.require_defined(&target.name, target.span, scope)?;
                }
                RemoveItem::Property(expr) => self.check_expr_refs(expr, scope)?,
            }
        }
        Ok(())
    }

    // ---- CALL ... YIELD ---------------------------------------------------------------------

    fn check_in_query_call(
        &self,
        c: &crate::ast::CallClause,
        scope: &mut Scope,
    ) -> Result<(), SemanticError> {
        if let Some(args) = &c.call.args {
            for a in args {
                self.check_expr_refs(a, scope)?;
            }
        }
        if let Some(items) = &c.yield_items {
            self.bind_yield_items(items, scope)?;
            if let Some(w) = &c.where_clause {
                self.check_predicate(w, scope, "WHERE")?;
            }
        }
        Ok(())
    }

    fn check_standalone_call(&self, call: &StandaloneCall) -> Result<(), SemanticError> {
        if let Some(args) = &call.call.args {
            let empty = Scope::default();
            for a in args {
                self.check_expr_refs(a, &empty)?;
            }
        }
        // A standalone `YIELD *` / items introduces names but there is no following clause to
        // reference them, so there is nothing further to resolve here.
        if let Some(StandaloneYield::Items {
            items,
            where_clause,
        }) = &call.yield_clause
        {
            let mut scope = Scope::default();
            self.bind_yield_items(items, &mut scope)?;
            if let Some(w) = where_clause {
                self.check_predicate(w, &scope, "WHERE")?;
            }
        }
        Ok(())
    }

    fn bind_yield_items(
        &self,
        items: &[YieldItem],
        scope: &mut Scope,
    ) -> Result<(), SemanticError> {
        for item in items {
            scope.bind(&item.alias.name, VarKind::Value, item.alias.span)?;
        }
        Ok(())
    }

    // ---- projections (WITH / RETURN) — the boundary reset -----------------------------------

    /// Checks a `WITH`/`RETURN` projection body against the incoming `scope`, returning the **new**
    /// scope (the reset rule). `where_clause` is the optional `WITH … WHERE`, evaluated post-reset.
    /// `is_final_return` relaxes the mandatory-alias rule (a final `RETURN` may project a bare
    /// expression whose result-column name is inferred; `WITH` must alias non-trivial expressions).
    fn check_projection(
        &self,
        body: &ProjectionBody,
        clause_span: Span,
        scope: &Scope,
        where_clause: Option<&Expr>,
        is_final_return: bool,
    ) -> Result<Scope, SemanticError> {
        // `RETURN *` / `WITH *` with nothing in scope is an error (no columns to expand). The TCK
        // raises this as `UndefinedVariable` (the `*` resolves against an empty scope); we point at
        // the whole projection clause since `*` carries no narrower span of its own.
        if body.star && scope.bindings.is_empty() && body.items.is_empty() {
            return Err(SemanticError::new(
                SemanticErrorKind::UndefinedVariable {
                    name: "*".to_owned(),
                },
                clause_span,
            ));
        }

        // 1) Resolve every projected expression against the *incoming* scope and gather each new
        //    column's (name, VarKind, span). A projected entity variable keeps its kind across the
        //    boundary (so `WITH n` still lets `n` be used as a node afterwards); any computed
        //    expression becomes a plain value.
        let aggregating = self.projection_is_aggregating(body);
        let mut columns: Vec<(String, VarKind, Span)> = Vec::new();

        // `*` carries every incoming binding through unchanged (name + kind preserved).
        if body.star {
            for (name, binding) in &scope.bindings {
                columns.push((name.clone(), binding.kind, clause_span));
            }
        }

        for item in &body.items {
            self.check_projection_item(item, scope, aggregating, is_final_return)?;
            let (col_name, kind) = self.column_name_and_kind(item, scope, is_final_return)?;
            columns.push((col_name, kind, item.span));
        }

        // 2) Duplicate result-column names are a ColumnNameConflict (TCK) — checked *before* the new
        //    scope is built, so a name collision is reported as a column conflict regardless of the
        //    colliding kinds (a `*`-carried node `n` plus an explicit `… AS n` is a column conflict,
        //    not a type conflict).
        self.check_duplicate_columns(&columns)?;

        // 3) Build the post-projection scope from the (now-unique) columns. `bind` cannot raise a
        //    type conflict here because the names are distinct (step 2 guaranteed it).
        let mut new_scope = Scope::default();
        for (name, kind, span) in &columns {
            new_scope.bind(name, *kind, *span)?;
        }

        // 4) ORDER BY / SKIP / LIMIT and a trailing WHERE are evaluated in the *post*-projection
        //    scope (they sit inside the ProjectionBody per the grammar). ORDER BY is the one
        //    exception: for a **non-aggregating, non-DISTINCT** projection, openCypher lets it
        //    reference both the projected aliases AND the variables in scope *before* the projection
        //    (`rmp` task #40; Neo4j/openCypher ORDER BY scoping). An aggregating or DISTINCT
        //    projection drops the pre-projection variables, so its ORDER BY sees only the projected
        //    columns. Aliases shadow a pre-projection variable of the same name.
        let order_scope = if aggregating || body.distinct {
            new_scope.clone()
        } else {
            let mut s = scope.clone();
            for (name, binding) in &new_scope.bindings {
                s.bindings.insert(name.clone(), *binding);
            }
            s
        };
        for sort in &body.order_by {
            self.check_order_by_item(sort, &order_scope, aggregating)?;
        }
        if let Some(skip) = &body.skip {
            self.check_expr_refs(skip, &new_scope)?;
            self.reject_aggregation(skip, "SKIP")?;
        }
        if let Some(limit) = &body.limit {
            self.check_expr_refs(limit, &new_scope)?;
            self.reject_aggregation(limit, "LIMIT")?;
        }
        if let Some(w) = where_clause {
            self.check_predicate(w, &new_scope, "WHERE")?;
        }

        Ok(new_scope)
    }

    fn check_projection_item(
        &self,
        item: &ProjectionItem,
        scope: &Scope,
        aggregating: bool,
        is_final_return: bool,
    ) -> Result<(), SemanticError> {
        self.check_expr_refs(&item.expr, scope)?;
        // Aggregations may not be nested anywhere.
        self.reject_nested_aggregation(&item.expr)?;

        // WITH requires an explicit alias for any non-trivial expression; a bare variable or a
        // bare `count(*)`-style aggregate atom is allowed unaliased in a final RETURN where a name
        // can be inferred, but WITH always needs `AS` for a computed expression.
        if item.alias.is_none() && !Self::has_inferable_name(&item.expr) && !is_final_return {
            return Err(SemanticError::new(
                SemanticErrorKind::NoExpressionAlias,
                item.span,
            ));
        }

        // In an aggregating projection, each item that does NOT itself contain an aggregate must be
        // a pure grouping key (just a variable / property path / constant), else the grouping is
        // ambiguous (AmbiguousAggregationExpression).
        if aggregating
            && !Self::contains_aggregate(&item.expr)
            && !Self::is_grouping_key(&item.expr)
        {
            return Err(SemanticError::new(
                SemanticErrorKind::AmbiguousAggregationExpression,
                item.span,
            ));
        }
        Ok(())
    }

    fn check_order_by_item(
        &self,
        sort: &SortItem,
        scope: &Scope,
        aggregating: bool,
    ) -> Result<(), SemanticError> {
        self.check_expr_refs(&sort.expr, scope)?;
        self.reject_nested_aggregation(&sort.expr)?;
        // ORDER BY may use aggregates only when the projection itself aggregates (it sorts the
        // grouped rows); in a non-aggregating projection an aggregate in ORDER BY is invalid.
        if !aggregating && Self::contains_aggregate(&sort.expr) {
            return Err(SemanticError::new(
                SemanticErrorKind::InvalidAggregation {
                    position: "ORDER BY of a non-aggregating projection",
                },
                sort.span,
            ));
        }
        Ok(())
    }

    fn check_duplicate_columns(
        &self,
        columns: &[(String, VarKind, Span)],
    ) -> Result<(), SemanticError> {
        let mut seen: HashMap<&str, ()> = HashMap::with_capacity(columns.len());
        for (name, _kind, span) in columns {
            if seen.insert(name.as_str(), ()).is_some() {
                return Err(SemanticError::new(
                    SemanticErrorKind::ColumnNameConflict { name: name.clone() },
                    *span,
                ));
            }
        }
        Ok(())
    }

    /// The result-column name and resulting [`VarKind`] of a projection item.
    fn column_name_and_kind(
        &self,
        item: &ProjectionItem,
        scope: &Scope,
        _is_final_return: bool,
    ) -> Result<(String, VarKind), SemanticError> {
        if let Some(alias) = &item.alias {
            // An aliased *bare variable* preserves the source variable's kind (`WITH n AS m`,
            // `m` is still a node); any other aliased expression yields a plain value.
            let kind = if let ExprKind::Variable(src) = &item.expr.kind {
                scope.kind_of(src).unwrap_or(VarKind::Value)
            } else {
                VarKind::Value
            };
            return Ok((alias.name.clone(), kind));
        }
        match &item.expr.kind {
            ExprKind::Variable(name) => {
                let kind = scope.kind_of(name).unwrap_or(VarKind::Value);
                Ok((name.clone(), kind))
            }
            // Any other un-aliased expression is named by its verbatim source text (openCypher's
            // column-name rule; the parser captured the slice). `n.x` carries no entity identity,
            // so every such column is a plain value. Must agree with the planner's
            // `projection_column` ([`crate::lower`]) so duplicate detection sees the same names.
            _ => Ok((item.verbatim.clone(), VarKind::Value)),
        }
    }

    // ---- patterns ---------------------------------------------------------------------------

    fn bind_pattern_part(
        &self,
        part: &PatternPart,
        scope: &mut Scope,
        role: PatternRole,
    ) -> Result<(), SemanticError> {
        if let Some(var) = &part.var {
            // A named path variable is a path value.
            scope.bind(&var.name, VarKind::Value, var.span)?;
        }
        self.bind_pattern_element(&part.element, scope, role)
    }

    fn bind_pattern_element(
        &self,
        element: &PatternElement,
        scope: &mut Scope,
        role: PatternRole,
    ) -> Result<(), SemanticError> {
        self.bind_node_pattern(&element.start, scope, role)?;
        for link in &element.chain {
            self.bind_relationship_pattern(&link.relationship, scope, role)?;
            self.bind_node_pattern(&link.node, scope, role)?;
        }
        Ok(())
    }

    fn bind_node_pattern(
        &self,
        node: &NodePattern,
        scope: &mut Scope,
        _role: PatternRole,
    ) -> Result<(), SemanticError> {
        if let Some(var) = &node.variable {
            scope.bind(&var.name, VarKind::Node, var.span)?;
        }
        if let Some(props) = &node.properties {
            self.check_expr_refs(props, scope)?;
            self.reject_aggregation(props, "a pattern")?;
        }
        Ok(())
    }

    fn bind_relationship_pattern(
        &self,
        rel: &RelationshipPattern,
        scope: &mut Scope,
        role: PatternRole,
    ) -> Result<(), SemanticError> {
        if role == PatternRole::Create {
            // CREATE/MERGE relationship well-formedness (TCK):
            // exactly one type, a direction, and no variable-length range.
            if rel.range.is_some() {
                return Err(SemanticError::new(
                    SemanticErrorKind::CreatingVarLength,
                    rel.span,
                ));
            }
            if rel.direction == RelDirection::Undirected {
                return Err(SemanticError::new(
                    SemanticErrorKind::RequiresDirectedRelationship,
                    rel.span,
                ));
            }
            if rel.types.len() != 1 {
                return Err(SemanticError::new(
                    SemanticErrorKind::NoSingleRelationshipType {
                        count: rel.types.len(),
                    },
                    rel.span,
                ));
            }
        }
        if let Some(var) = &rel.variable {
            // A CREATE/MERGE always creates a *new* relationship, so its variable must be fresh:
            // re-using an already-bound name is `VariableAlreadyBound` (TCK; e.g.
            // `MATCH ()-[r]->() CREATE ()-[r]->()`). For MATCH, repeating a relationship variable
            // is handled by `Scope::bind`'s same-kind/conflict rules instead.
            if role == PatternRole::Create && scope.contains(&var.name) {
                return Err(SemanticError::new(
                    SemanticErrorKind::VariableAlreadyBound {
                        name: var.name.clone(),
                    },
                    var.span,
                ));
            }
            scope.bind(&var.name, VarKind::Relationship, var.span)?;
        }
        if let Some(props) = &rel.properties {
            self.check_expr_refs(props, scope)?;
            self.reject_aggregation(props, "a pattern")?;
        }
        Ok(())
    }

    // ---- expression reference resolution ----------------------------------------------------

    /// Resolves every free variable reference in `expr` against `scope`, recursing through the whole
    /// expression tree. Also resolves variables bound *locally* by list/pattern comprehensions
    /// (their iteration variable is in scope only inside the comprehension) and validates function
    /// calls against the registry.
    fn check_expr_refs(&self, expr: &Expr, scope: &Scope) -> Result<(), SemanticError> {
        match &expr.kind {
            ExprKind::Variable(name) => self.require_defined(name, expr.span, scope),
            ExprKind::Literal(_) | ExprKind::Parameter(_) | ExprKind::CountStar => Ok(()),

            ExprKind::Binary { lhs, rhs, .. } => {
                self.check_expr_refs(lhs, scope)?;
                self.check_expr_refs(rhs, scope)
            }
            ExprKind::Unary { operand, .. } | ExprKind::HasLabels { operand, .. } => {
                self.check_expr_refs(operand, scope)
            }
            ExprKind::Predicate { operand, rhs, .. } => {
                self.check_expr_refs(operand, scope)?;
                if let Some(rhs) = rhs {
                    self.check_expr_refs(rhs, scope)?;
                }
                Ok(())
            }
            ExprKind::Property { base, .. } => self.check_expr_refs(base, scope),
            ExprKind::Index { base, index } => {
                self.check_expr_refs(base, scope)?;
                self.check_expr_refs(index, scope)
            }
            ExprKind::Slice { base, low, high } => {
                self.check_expr_refs(base, scope)?;
                if let Some(low) = low {
                    self.check_expr_refs(low, scope)?;
                }
                if let Some(high) = high {
                    self.check_expr_refs(high, scope)?;
                }
                Ok(())
            }
            ExprKind::FunctionCall { name, args, .. } => {
                self.check_function_call(name, args, expr.span)?;
                for a in args {
                    self.check_expr_refs(a, scope)?;
                }
                Ok(())
            }
            ExprKind::List(items) => {
                for it in items {
                    self.check_expr_refs(it, scope)?;
                }
                Ok(())
            }
            ExprKind::Map(entries) => {
                for (_k, v) in entries {
                    self.check_expr_refs(v, scope)?;
                }
                Ok(())
            }
            ExprKind::Case(case) => {
                if let Some(subj) = &case.subject {
                    self.check_expr_refs(subj, scope)?;
                }
                for alt in &case.alternatives {
                    self.check_expr_refs(&alt.when, scope)?;
                    self.check_expr_refs(&alt.then, scope)?;
                }
                if let Some(else_e) = &case.else_expr {
                    self.check_expr_refs(else_e, scope)?;
                }
                Ok(())
            }
            ExprKind::ListComprehension(lc) => {
                // The list is in the outer scope; the iteration variable is local to the body.
                self.check_expr_refs(&lc.list, scope)?;
                let mut inner = scope.clone();
                inner.bind(&lc.variable.name, VarKind::Value, lc.variable.span)?;
                if let Some(pred) = &lc.predicate {
                    self.check_expr_refs(pred, &inner)?;
                }
                if let Some(proj) = &lc.projection {
                    self.check_expr_refs(proj, &inner)?;
                }
                Ok(())
            }
            ExprKind::PatternComprehension(pc) => {
                // The pattern binds node/rel/path variables locally for the predicate + projection.
                let mut inner = scope.clone();
                if let Some(var) = &pc.var {
                    inner.bind(&var.name, VarKind::Value, var.span)?;
                }
                self.bind_pattern_element(&pc.element, &mut inner, PatternRole::Read)?;
                if let Some(pred) = &pc.predicate {
                    self.check_expr_refs(pred, &inner)?;
                }
                self.check_expr_refs(&pc.projection, &inner)
            }
            ExprKind::Quantifier(q) => {
                // The list is in the outer scope; the iteration variable is local to the predicate.
                self.check_expr_refs(&q.list, scope)?;
                let mut inner = scope.clone();
                inner.bind(&q.variable.name, VarKind::Value, q.variable.span)?;
                self.check_expr_refs(&q.predicate, &inner)
            }
            ExprKind::ExistsSubquery(ex) => {
                // The pattern binds its variables locally (outer bindings stay visible as
                // constraints); the WHERE predicate sees both.
                let mut inner = scope.clone();
                for part in &ex.pattern {
                    self.bind_pattern_part(part, &mut inner, PatternRole::Read)?;
                }
                if let Some(pred) = &ex.predicate {
                    self.check_expr_refs(pred, &inner)?;
                }
                Ok(())
            }
        }
    }

    fn check_function_call(
        &self,
        name: &[String],
        args: &[Expr],
        span: Span,
    ) -> Result<(), SemanticError> {
        let dotted = name.join(".");
        match function_registry::lookup(&dotted) {
            Some(sig) => match sig.arity.check(args.len()) {
                ArityCheck::Ok => Ok(()),
                ArityCheck::Wrong => Err(SemanticError::new(
                    SemanticErrorKind::InvalidNumberOfArguments {
                        name: dotted,
                        expected: sig.arity.describe(),
                        got: args.len(),
                    },
                    span,
                )),
            },
            None => Err(SemanticError::new(
                SemanticErrorKind::UnknownFunction { name: dotted },
                span,
            )),
        }
    }

    fn require_defined(&self, name: &str, span: Span, scope: &Scope) -> Result<(), SemanticError> {
        if scope.contains(name) {
            Ok(())
        } else {
            Err(SemanticError::new(
                SemanticErrorKind::UndefinedVariable {
                    name: name.to_owned(),
                },
                span,
            ))
        }
    }

    /// A `WHERE`/predicate: resolve refs and reject aggregation (aggregation is forbidden in
    /// `WHERE`, TCK `InvalidAggregation`).
    fn check_predicate(
        &self,
        expr: &Expr,
        scope: &Scope,
        position: &'static str,
    ) -> Result<(), SemanticError> {
        self.check_expr_refs(expr, scope)?;
        self.reject_aggregation(expr, position)
    }

    /// Errors with [`InvalidAggregation`] if `expr` contains an aggregate anywhere (used for the
    /// positions where aggregation is categorically forbidden).
    ///
    /// [`InvalidAggregation`]: SemanticErrorKind::InvalidAggregation
    fn reject_aggregation(&self, expr: &Expr, position: &'static str) -> Result<(), SemanticError> {
        if Self::contains_aggregate(expr) {
            return Err(SemanticError::new(
                SemanticErrorKind::InvalidAggregation { position },
                expr.span,
            ));
        }
        Ok(())
    }

    /// Errors with [`NestedAggregation`] if any aggregate in `expr` has another aggregate among its
    /// arguments.
    ///
    /// [`NestedAggregation`]: SemanticErrorKind::NestedAggregation
    fn reject_nested_aggregation(&self, expr: &Expr) -> Result<(), SemanticError> {
        Self::find_nested_aggregate(expr, false)
    }

    fn find_nested_aggregate(expr: &Expr, inside_aggregate: bool) -> Result<(), SemanticError> {
        let here_is_aggregate = Self::is_aggregate_call(expr);
        if here_is_aggregate && inside_aggregate {
            return Err(SemanticError::new(
                SemanticErrorKind::NestedAggregation,
                expr.span,
            ));
        }
        let child_inside = inside_aggregate || here_is_aggregate;
        Self::for_each_child(expr, &mut |child| {
            Self::find_nested_aggregate(child, child_inside)
        })
    }

    // ---- pure AST predicates (no scope needed) ----------------------------------------------

    fn projection_is_aggregating(&self, body: &ProjectionBody) -> bool {
        body.items
            .iter()
            .any(|it| Self::contains_aggregate(&it.expr))
    }

    /// `true` if `expr` is itself an aggregating function call (or the `count(*)` atom).
    fn is_aggregate_call(expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::CountStar => true,
            ExprKind::FunctionCall { name, .. } => function_registry::is_aggregate(&name.join(".")),
            _ => false,
        }
    }

    /// `true` if `expr` contains an aggregate anywhere in its tree.
    fn contains_aggregate(expr: &Expr) -> bool {
        if Self::is_aggregate_call(expr) {
            return true;
        }
        let mut found = false;
        let _ = Self::for_each_child(expr, &mut |child| {
            if Self::contains_aggregate(child) {
                found = true;
            }
            Ok(())
        });
        found
    }

    /// A "grouping key" expression in an aggregating projection: a bare variable, a property path
    /// rooted at a variable, an index/slice into such, a constant, a parameter, or a `HasLabels`
    /// test. These are the forms Cypher accepts as non-aggregated terms without ambiguity.
    fn is_grouping_key(expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Variable(_) | ExprKind::Literal(_) | ExprKind::Parameter(_) => true,
            ExprKind::Property { base, .. }
            | ExprKind::Index { base, .. }
            | ExprKind::HasLabels { operand: base, .. } => Self::is_grouping_key(base),
            ExprKind::Slice { base, .. } => Self::is_grouping_key(base),
            _ => false,
        }
    }

    /// Whether a projected expression has a name Cypher can infer without an explicit `AS` (a bare
    /// variable, a property path, or `count(*)`). Used to decide if `WITH` requires aliasing.
    fn has_inferable_name(expr: &Expr) -> bool {
        matches!(
            &expr.kind,
            ExprKind::Variable(_) | ExprKind::Property { .. } | ExprKind::CountStar
        )
    }

    /// Whether `expr` is clearly *not* a graph entity for `DELETE` (a literal, list, map, or
    /// arithmetic result). A variable is accepted (its entity-ness is a runtime fact).
    fn is_clearly_non_entity(expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Literal(_) | ExprKind::List(_) | ExprKind::Map(_) | ExprKind::CountStar => {
                true
            }
            ExprKind::Binary { op, .. } => {
                use crate::ast::BinaryOp;
                matches!(
                    op,
                    BinaryOp::Add
                        | BinaryOp::Sub
                        | BinaryOp::Mul
                        | BinaryOp::Div
                        | BinaryOp::Mod
                        | BinaryOp::Pow
                )
            }
            _ => false,
        }
    }

    /// Invokes `f` on each immediate sub-expression of `expr` (depth-1), short-circuiting on the
    /// first error. Centralises the child-traversal so the various pure walks agree on the shape.
    fn for_each_child(
        expr: &Expr,
        f: &mut impl FnMut(&Expr) -> Result<(), SemanticError>,
    ) -> Result<(), SemanticError> {
        match &expr.kind {
            ExprKind::Literal(_)
            | ExprKind::Parameter(_)
            | ExprKind::Variable(_)
            | ExprKind::CountStar => Ok(()),
            ExprKind::Binary { lhs, rhs, .. } => {
                f(lhs)?;
                f(rhs)
            }
            ExprKind::Unary { operand, .. } | ExprKind::HasLabels { operand, .. } => f(operand),
            ExprKind::Predicate { operand, rhs, .. } => {
                f(operand)?;
                if let Some(rhs) = rhs {
                    f(rhs)?;
                }
                Ok(())
            }
            ExprKind::Property { base, .. } => f(base),
            ExprKind::Index { base, index } => {
                f(base)?;
                f(index)
            }
            ExprKind::Slice { base, low, high } => {
                f(base)?;
                if let Some(low) = low {
                    f(low)?;
                }
                if let Some(high) = high {
                    f(high)?;
                }
                Ok(())
            }
            ExprKind::FunctionCall { args, .. } => {
                for a in args {
                    f(a)?;
                }
                Ok(())
            }
            ExprKind::List(items) => {
                for it in items {
                    f(it)?;
                }
                Ok(())
            }
            ExprKind::Map(entries) => {
                for (_k, v) in entries {
                    f(v)?;
                }
                Ok(())
            }
            ExprKind::Case(case) => {
                if let Some(subj) = &case.subject {
                    f(subj)?;
                }
                for alt in &case.alternatives {
                    f(&alt.when)?;
                    f(&alt.then)?;
                }
                if let Some(else_e) = &case.else_expr {
                    f(else_e)?;
                }
                Ok(())
            }
            ExprKind::ListComprehension(lc) => {
                f(&lc.list)?;
                if let Some(pred) = &lc.predicate {
                    f(pred)?;
                }
                if let Some(proj) = &lc.projection {
                    f(proj)?;
                }
                Ok(())
            }
            ExprKind::Quantifier(q) => {
                f(&q.list)?;
                f(&q.predicate)
            }
            ExprKind::ExistsSubquery(ex) => {
                if let Some(pred) = &ex.predicate {
                    f(pred)?;
                }
                Ok(())
            }
            ExprKind::PatternComprehension(pc) => {
                if let Some(pred) = &pc.predicate {
                    f(pred)?;
                }
                f(&pc.projection)
            }
        }
    }
}

/// Whether a pattern is being **read** (`MATCH`) or **created** (`CREATE`/`MERGE`). Creation imposes
/// extra relationship well-formedness rules (single type, directed, not variable-length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatternRole {
    Read,
    Create,
}

#[cfg(test)]
mod tests {
    //! Unit tests live alongside the broader, scenario-style integration tests in
    //! `tests/semantics.rs`; these cover the pure-AST helper predicates directly.
    use super::*;
    use crate::lexer::tokenize;
    use crate::parser::parse_tokens;

    fn ast(src: &str) -> Query {
        let toks = tokenize(src).expect("lexes");
        parse_tokens(&toks, src).expect("parses")
    }

    #[test]
    fn contains_aggregate_sees_count_star_and_known_aggregates() {
        let q = ast("RETURN count(*)");
        let body = if let Clause::Return(r) = &q.body_single_query().clauses[0] {
            &r.body
        } else {
            unreachable!()
        };
        assert!(Analyzer.projection_is_aggregating(body));
    }

    #[test]
    fn grouping_key_recognises_property_paths() {
        let q = ast("RETURN n.a.b");
        let body = if let Clause::Return(r) = &q.body_single_query().clauses[0] {
            &r.body
        } else {
            unreachable!()
        };
        assert!(Analyzer::is_grouping_key(&body.items[0].expr));
    }
}
