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
//!   execution, never at compile (`04 §7.5`), so an unbound `$p` is **not** a semantic error. The
//!   one TCK-measured exception is the standalone **implicit procedure call** (`CALL proc` without
//!   parentheses), whose arguments *are* the query parameters: the TCK raises a missing input there
//!   at **compile time** (`ParameterMissing`/`MissingParameter`). Because that check needs the
//!   supplied parameter names, it is a separate, explicit entry point —
//!   [`check_implicit_call_parameters`] — run by callers that know the parameters before execution
//!   (the statement plan itself stays parameter-independent, `04 §7.5`).
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
//! expansion). A variable not carried through a `WITH` is therefore **undefined** in the clauses
//! that *follow* the projection — the single most important scoping rule the TCK exercises.
//!
//! The projection's own *trailing* sub-clauses are a deliberate exception, because the openCypher
//! grammar nests them **inside** the `ProjectionBody` (`WITH items [ORDER BY] [SKIP] [LIMIT]
//! [WHERE]`):
//!
//! - A `WITH … WHERE` and the `ORDER BY` expressions are evaluated in a **dual scope** — the
//!   projected aliases **union** the input variables in scope *before* the projection, with aliases
//!   shadowing an input variable of the same name. So `WITH c WHERE r IS NULL` legally references
//!   `r` even though `r` is dropped by the projection (the triadic anti-join, `TriadicSelection1`;
//!   the canonical `WithWhere7` before/after/both test). The engine carries the referenced input
//!   variables across the projection at runtime so the filter actually applies (see `crate::lower`).
//! - The one carve-out: `ORDER BY` over an **aggregating or DISTINCT** projection sees only the
//!   projected columns — those operators collapse rows, so a pre-projection variable has no
//!   well-defined per-row value to sort by (`rmp` task #40). A trailing `WHERE` keeps the dual scope
//!   even there, referencing surviving grouping keys / aggregate aliases (`WithWhere6`).
//! - `SKIP` and `LIMIT` are pure pagination over the projected stream and see only the projected
//!   names.
//!
//! # Aggregation rules (`04 §7.6` grouping semantics; openCypher)
//!
//! A projection (or `WITH`) item that *contains* an aggregating function (`count`, `sum`, `avg`,
//! `min`, `max`, `collect`, `stdev`, `stdevp`, `percentileCont`, `percentileDisc`, plus the
//! `count(*)` atom) makes the whole projection an **aggregating projection**. Every item *without*
//! an aggregate is then a **grouping key** — any expression form, evaluated per row and grouped by
//! equivalence (TCK `clauses/with/With6.feature`, `clauses/return/Return6.feature` \[16\]). An
//! item *with* an aggregate may compose, **outside** its aggregate calls, only constants and the
//! projection's *simple* grouping keys (a projected bare variable or variable-rooted property
//! path, or a property of one — `Return6` \[18\]/\[19\], `With6` \[7\]); any other free
//! sub-expression makes the implicit grouping ambiguous ([`AmbiguousAggregationExpression`] —
//! `Return6` \[20\]/\[21\], `With6` \[8\]/\[9\]: even a complex expression that is itself
//! projected does not qualify). Aggregates may not be **nested** ([`NestedAggregation`]), may not
//! appear where aggregation is forbidden — `WHERE`, pattern predicates, variable-length bounds
//! ([`InvalidAggregation`]) — and may not take the non-deterministic `rand()` among their
//! arguments ([`NonConstantExpression`] — `Return6` \[15\]).
//!
//! [`AmbiguousAggregationExpression`]: crate::errors::SemanticErrorKind::AmbiguousAggregationExpression
//! [`NestedAggregation`]: crate::errors::SemanticErrorKind::NestedAggregation
//! [`InvalidAggregation`]: crate::errors::SemanticErrorKind::InvalidAggregation
//! [`NonConstantExpression`]: crate::errors::SemanticErrorKind::NonConstantExpression
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
//! # Procedure calls (`CALL … [YIELD …]`)
//!
//! Procedure invocations are resolved against a [`ProcedureRegistry`] (rmp #57): an unknown name is
//! `ProcedureError`/`ProcedureNotFound`, a wrong explicit-argument count is
//! `SyntaxError`/`InvalidNumberOfArguments`, a literal argument that cannot satisfy the declared
//! input type is `SyntaxError`/`InvalidArgumentType`, an aggregate in an argument is
//! `InvalidAggregation`, a `YIELD` that (re)binds an in-scope name is `VariableAlreadyBound`, and an
//! in-query call to a procedure **with outputs** but **without `YIELD`** is `UndefinedVariable`
//! (the outputs are unnameable; all spellings verbatim from `tck/features/clauses/call/**`). After
//! validation, a standalone **implicit** call's arguments (`CALL proc` — no parentheses) are
//! resolved to one [`Parameter`](crate::ast::ExprKind::Parameter) expression per declared input, so
//! lowering, binding and execution are uniform over the explicit form.
//!
//! Deferred to later phases / sub-tasks, **by name**: (1) full static **type inference** of
//! expression results (most type mismatches are runtime `TypeError`s by TCK design); (2)
//! **`SET`-on-non-entity** static rejection — the parser already constrains `SET` targets to
//! variables / property chains, and whether the target *is* an entity is generally a runtime fact,
//! so only the structural part is enforced here; (3) the exotic productions the parser
//! itself defers (`FOREACH`, `CALL { subquery }`, DDL); (4) the two-letter Neo4j **status codes**
//! (escalated, `02 Q2`).

use crate::ast::{
    BinaryOp, Clause, CreateClause, DeleteClause, Expr, ExprKind, Literal, LoadCsvClause,
    MatchClause, MergeAction, MergeClause, NodePattern, PatternElement, PatternPart,
    PatternPartKind, ProjectionBody, ProjectionItem, Query, QueryBody, RelDirection,
    RelationshipPattern, RemoveClause, RemoveItem, SetClause, SetItem, SingleQuery, SortItem,
    StandaloneCall, StandaloneYield, UnaryOp, UnionPart, UnwindClause, Variable, YieldItem,
};
use crate::errors::{SemanticError, SemanticErrorKind, VarKind};
use crate::function_registry::{self, ArityCheck, FunctionRegistry};
use crate::lexer::Span;
use crate::procedure_registry::{self, FieldType, ProcedureRegistry, ProcedureSignature};
use crate::static_type::{self, SType, TypeEnv};
use graphus_core::GraphusError;
use std::collections::{BTreeSet, HashMap};

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
    analyze_with_procedures(query, procedure_registry::builtins())
}

/// [`analyze`] against a caller-supplied [`ProcedureRegistry`] (`04 §7.3`; rmp #57).
///
/// Procedure invocations (`CALL …`) are resolved against `procedures` — see the module docs for
/// the checks. The **same** registry must back execution
/// ([`execute_with_procedures`](crate::executor::execute_with_procedures)), or the compile-time
/// procedure guarantees are void. The registry-less [`analyze`] uses the engine
/// [built-ins](crate::procedure_registry::builtins).
///
/// On success, a standalone **implicit** procedure call's arguments are resolved to one
/// [`Parameter`](crate::ast::ExprKind::Parameter) expression per declared input (openCypher
/// `ImplicitProcedureInvocation` takes its arguments from the query parameters by input name), so
/// the rest of the pipeline is uniform over the explicit form.
///
/// # Errors
///
/// Returns a [`SemanticError`] exactly as [`analyze`] does, plus the procedure-resolution errors
/// described in the module docs.
pub fn analyze_with_procedures(
    query: &Query,
    procedures: &dyn ProcedureRegistry,
) -> Result<ValidatedQuery, SemanticError> {
    // A pure pass-through to the extensions form with an empty function registry: the function-less
    // callers (this one, used by the TCK harness, and `analyze`) see only the built-in functions, so
    // their behaviour is byte-identical to before the extension mechanism (`rmp` task #75).
    analyze_with_extensions(query, function_registry::no_functions(), procedures)
}

/// [`analyze`] against caller-supplied **function** and **procedure** registries (`rmp` task #75).
///
/// The full extension form: extension *functions* are resolved against `functions` (after the
/// built-ins, which always take precedence) and procedures against `procedures`. The **same** two
/// registries must back execution
/// ([`execute_with_extensions`](crate::executor::execute_with_extensions)), or the compile-time
/// guarantees are void. [`analyze`] and [`analyze_with_procedures`] are thin wrappers over this with
/// an empty [`FunctionRegistry`](crate::function_registry::no_functions).
///
/// Compile-time function checks: a function name that is neither a built-in nor a registered UDF is
/// [`UnknownFunction`](SemanticErrorKind::UnknownFunction); a wrong argument count for a built-in or
/// a UDF is [`InvalidNumberOfArguments`](SemanticErrorKind::InvalidNumberOfArguments). Both classify
/// as `SyntaxError` (TCK-faithful). Argument *types* are a runtime concern (see
/// [`crate::function_registry`]).
///
/// # Errors
///
/// Returns a [`SemanticError`] exactly as [`analyze_with_procedures`] does, plus an
/// `UnknownFunction`/`InvalidNumberOfArguments` for a registered UDF call shape that is wrong.
pub fn analyze_with_extensions(
    query: &Query,
    functions: &dyn FunctionRegistry,
    procedures: &dyn ProcedureRegistry,
) -> Result<ValidatedQuery, SemanticError> {
    Analyzer {
        functions,
        procedures,
    }
    .check_query(query)?;
    let mut query = query.clone();
    resolve_implicit_call_arguments(&mut query, procedures);
    Ok(ValidatedQuery { query })
}

/// Rewrites a validated standalone **implicit** call's `args: None` into one
/// [`ExprKind::Parameter`] per declared input, in declaration order (openCypher
/// `ImplicitProcedureInvocation`). A no-op for every other query shape; the procedure is known to
/// exist because [`Analyzer::check_standalone_call`] already resolved it.
fn resolve_implicit_call_arguments(query: &mut Query, procedures: &dyn ProcedureRegistry) {
    let QueryBody::StandaloneCall(call) = &mut query.body else {
        return;
    };
    if call.call.args.is_some() {
        return;
    }
    let Some(sig) = procedures.signature(&call.call.name.join(".")) else {
        return;
    };
    let span = call.call.span;
    call.call.args = Some(
        sig.inputs
            .iter()
            .map(|input| Expr::new(ExprKind::Parameter(input.name.clone()), span))
            .collect(),
    );
}

/// Whether a procedure argument whose type is **statically known** — a bare literal — cannot
/// satisfy the declared input type (TCK `InvalidArgumentType`,
/// `tck/features/clauses/call/Call2.feature`). Deliberately conservative: any non-literal
/// expression (a parameter, property access, arithmetic, …) is left to the runtime, where type
/// mismatches on actual values belong (`04 §7.3`). Coercions ([`FieldType::accepts`]):
/// `INTEGER` → `FLOAT`/`NUMBER`, `FLOAT` → `NUMBER`, `null` wherever nullable.
fn literal_violates_type(arg: &Expr, ty: FieldType) -> bool {
    // A representative value of the literal's class is enough — `accepts` discriminates on the
    // class, never the magnitude.
    let representative = match &arg.kind {
        ExprKind::Literal(Literal::Null) => graphus_core::Value::Null,
        ExprKind::Literal(Literal::Boolean(b)) => graphus_core::Value::Boolean(*b),
        ExprKind::Literal(Literal::Integer(_)) => graphus_core::Value::Integer(0),
        ExprKind::Literal(Literal::Float(f)) => graphus_core::Value::Float(*f),
        ExprKind::Literal(Literal::String(s)) => graphus_core::Value::String(s.clone()),
        _ => return false,
    };
    !ty.accepts(&representative)
}

/// Validates a standalone **implicit** procedure call's arguments against the **supplied query
/// parameters** (openCypher `ImplicitProcedureInvocation`: the arguments are the parameters, keyed
/// by input name). The TCK raises a missing input at **compile time**
/// (`ParameterMissing`/`MissingParameter`, `tck/features/clauses/call/Call1.feature`), so callers
/// that know the parameters before execution (the TCK harness; a Bolt `RUN` message, where query
/// and parameters arrive together) run this check after [`analyze_with_procedures`] and before
/// planning/execution. It is a separate entry point — not part of [`analyze`] — because the
/// compiled plan itself must stay parameter-independent (`04 §7.5`).
///
/// A no-op (`Ok`) for any other query shape, for an explicit call, and for an unknown procedure
/// (that is [`analyze`]'s `ProcedureNotFound`).
///
/// # Errors
///
/// Returns [`SemanticErrorKind::MissingParameter`] for the first (declaration-order) input whose
/// name is not among `supplied`.
pub fn check_implicit_call_parameters(
    query: &Query,
    supplied: &crate::binding::Parameters,
    procedures: &dyn ProcedureRegistry,
) -> Result<(), SemanticError> {
    let QueryBody::StandaloneCall(call) = &query.body else {
        return Ok(());
    };
    if call.call.args.is_some() {
        return Ok(());
    }
    let Some(sig) = procedures.signature(&call.call.name.join(".")) else {
        return Ok(());
    };
    for input in &sig.inputs {
        if supplied.get(&input.name).is_none() {
            return Err(SemanticError::new(
                SemanticErrorKind::MissingParameter {
                    name: input.name.clone(),
                },
                call.call.span,
            ));
        }
    }
    Ok(())
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

#[derive(Debug, Clone)]
struct Binding {
    kind: VarKind,
    /// The variable's statically-inferred value type, when known. Node/relationship/path kinds carry
    /// their corresponding [`SType`]; a plain value binding ([`VarKind::Value`]) carries the static
    /// type of the projected expression when it is provable (`WITH 123 AS x` → [`SType::Int`]), or
    /// [`SType::Unknown`] otherwise. Used by [`Analyzer::scope_types`] so a downstream clause can
    /// statically reject e.g. `x.num` on a non-graph `x` (`expressions/graph/Graph6.feature` [9]).
    stype: SType,
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
        self.bind_typed(name, kind, kind_default_stype(kind), span)
    }

    /// As [`Self::bind`], but records an explicit static value type for the binding (used when an
    /// aliased projection's expression has a provable type, so a downstream property access on a
    /// non-graph value can be rejected at compile time).
    fn bind_typed(
        &mut self,
        name: &str,
        kind: VarKind,
        stype: SType,
        span: Span,
    ) -> Result<(), SemanticError> {
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
        self.bindings
            .insert(name.to_owned(), Binding { kind, stype });
        Ok(())
    }
}

/// The default static type for a binding of `kind`, used when no projected-expression type is known.
fn kind_default_stype(kind: VarKind) -> SType {
    match kind {
        VarKind::Node => SType::Node,
        VarKind::Relationship => SType::Relationship,
        VarKind::Path => SType::Path,
        VarKind::Value => SType::Unknown,
    }
}

/// The grouping-key context of one (potentially aggregating) projection body, computed once per
/// projection and consumed by the aggregation rules (module docs *Aggregation rules*).
struct GroupingKeys<'a> {
    /// Path signatures of the **simple** non-aggregated items (a bare variable or variable-rooted
    /// property path) — the keys an aggregate-containing *projection item* may re-use.
    simple: Vec<Vec<&'a str>>,
    /// [`Self::simple`] plus every non-aggregated item's alias (single-segment) — the keys an
    /// aggregate-containing *ORDER BY item* may re-use (ORDER BY sees the post-projection names).
    with_aliases: Vec<Vec<&'a str>>,
    /// Whether some non-aggregated item is **complex** (a computed grouping key) — drives the
    /// ORDER BY classification split (`AmbiguousAggregationExpression` vs `UndefinedVariable`).
    has_complex: bool,
}

// =================================================================================================
// The analyzer
// =================================================================================================

/// The analysis driver. Stateless beyond per-call locals and the catalogues it resolves callable
/// invocations against: the **function** registry (extension UDFs; `rmp` #75) and the **procedure**
/// registry (`CALL` invocations; `rmp` #57). Built-in functions/procedures always take precedence
/// over these caller-supplied sets.
struct Analyzer<'a> {
    /// The extension-function catalogue (`rmp` #75). Consulted only when a name is **not** a
    /// built-in (built-ins win), for the compile-time unknown-function / wrong-arity / aggregate
    /// checks.
    functions: &'a dyn FunctionRegistry,
    /// The procedure catalogue (`04 §7.3`; rmp #57).
    procedures: &'a dyn ProcedureRegistry,
}

impl Analyzer<'_> {
    /// Checks a whole [`Query`]: each single query of a `UNION` chain is analysed independently
    /// (each has its own scope), or the standalone `CALL`. The branches of a `UNION` must all
    /// return the same column names — TCK `DifferentColumnsInUnion`.
    fn check_query(&self, query: &Query) -> Result<(), SemanticError> {
        match &query.body {
            QueryBody::Regular { head, unions } => {
                let head_cols = self.check_single_query(head)?;
                for UnionPart { query: sq, .. } in unions {
                    let cols = self.check_single_query(sq)?;
                    // Compare as name sets (order-insensitive; both branches end in RETURN when a
                    // UNION is well-formed, so a `None` side only happens alongside other errors).
                    if let (Some(a), Some(b)) = (&head_cols, &cols) {
                        if a != b {
                            return Err(SemanticError::new(
                                SemanticErrorKind::DifferentColumnsInUnion,
                                sq.span,
                            ));
                        }
                    }
                }
                Ok(())
            }
            QueryBody::StandaloneCall(call) => self.check_standalone_call(call),
        }
    }

    /// Checks a single query: validate clause composition, then walk clauses left-to-right,
    /// threading the [`Scope`] and resetting it at every projection boundary. Returns the final
    /// `RETURN`'s column-name set (`None` for a write-only query), for the `UNION` shape check.
    fn check_single_query(
        &self,
        sq: &SingleQuery,
    ) -> Result<Option<BTreeSet<String>>, SemanticError> {
        self.check_clause_composition(sq)?;

        let mut scope = Scope::default();
        let mut final_columns = None;
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
                    // The post-RETURN scope is exactly the result columns.
                    final_columns = Some(scope.bindings.keys().cloned().collect());
                }
            }
        }
        Ok(final_columns)
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
        self.check_expr(&u.expr, scope)?;
        Self::check_pattern_predicate_placement(&u.expr, false)?;
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
                self.check_expr(value, scope)?;
                Self::check_pattern_predicate_placement(value, false)?;
                self.reject_aggregation(value, "SET")?;
            }
            SetItem::Replace { target, value } | SetItem::Merge { target, value } => {
                self.require_defined(&target.name, target.span, scope)?;
                self.check_expr(value, scope)?;
                Self::check_pattern_predicate_placement(value, false)?;
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
            self.check_expr(expr, scope)?;
            // DELETE targets must be entity references, not arbitrary literals. We statically reject
            // the clearly-non-entity forms; whether a *variable* names a node/rel/path is a runtime
            // fact, so we accept it here. openCypher distinguishes two compile-time details:
            //   * an arithmetic / typed-scalar expression (`DELETE 1 + 1`) is `InvalidArgumentType`;
            //   * any other non-entity form — literals, lists, maps, a label/type predicate such as
            //     `DELETE n:Person` / `DELETE r:T` — is `InvalidDelete`
            // (`clauses/delete/Delete{1,2,5}.feature`).
            if let Some(kind) = Self::non_entity_delete_error(expr) {
                return Err(SemanticError::new(kind, expr.span));
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
                RemoveItem::Property(expr) => self.check_expr(expr, scope)?,
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
        let sig = self.resolve_procedure(&c.call)?;
        self.check_call_arguments(&c.call, sig, scope)?;
        // An in-query call to a procedure **with outputs** must name them with `YIELD` — without
        // it the outputs are unnameable by the following clauses. The TCK raises this as the
        // compile-time `UndefinedVariable` (`tck/features/clauses/call/Call1.feature` [12]).
        if c.yield_items.is_none() && !sig.outputs.is_empty() {
            return Err(SemanticError::new(
                SemanticErrorKind::UndefinedVariable {
                    name: sig.outputs[0].name.clone(),
                },
                c.call.span,
            ));
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
        let sig = self.resolve_procedure(&call.call)?;
        let empty = Scope::default();
        self.check_call_arguments(&call.call, sig, &empty)?;
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

    /// Resolves a procedure invocation's dotted name against the registry. TCK
    /// `ProcedureError`/`ProcedureNotFound` on a miss (`tck/features/clauses/call/Call1.feature`).
    fn resolve_procedure(
        &self,
        call: &crate::ast::ProcedureCall,
    ) -> Result<&ProcedureSignature, SemanticError> {
        let dotted = call.name.join(".");
        self.procedures.signature(&dotted).ok_or_else(|| {
            SemanticError::new(
                SemanticErrorKind::ProcedureNotFound { name: dotted },
                call.span,
            )
        })
    }

    /// Checks a procedure invocation's **explicit** argument list against `sig`: scope-resolves
    /// each expression, rejects aggregates (TCK `InvalidAggregation`,
    /// `tck/features/clauses/call/Call1.feature` [16]), enforces the exact declared arity (TCK
    /// `InvalidNumberOfArguments`), and statically type-checks **literal** arguments against the
    /// declared input types (TCK `InvalidArgumentType`,
    /// `tck/features/clauses/call/Call2.feature`). The implicit form (`args: None`) has nothing to
    /// check here — its arguments are the query parameters, validated by
    /// [`check_implicit_call_parameters`].
    fn check_call_arguments(
        &self,
        call: &crate::ast::ProcedureCall,
        sig: &ProcedureSignature,
        scope: &Scope,
    ) -> Result<(), SemanticError> {
        let Some(args) = &call.args else {
            return Ok(());
        };
        for a in args {
            self.check_expr(a, scope)?;
            self.reject_aggregation(a, "a procedure CALL argument")?;
        }
        if args.len() != sig.inputs.len() {
            return Err(SemanticError::new(
                SemanticErrorKind::InvalidNumberOfArguments {
                    name: sig.name.clone(),
                    expected: sig.inputs.len().to_string(),
                    got: args.len(),
                },
                call.span,
            ));
        }
        for (arg, input) in args.iter().zip(&sig.inputs) {
            if literal_violates_type(arg, input.ty) {
                return Err(SemanticError::new(
                    SemanticErrorKind::InvalidProcedureArgumentType {
                        name: sig.name.clone(),
                        parameter: input.name.clone(),
                        expected: input.ty.to_string(),
                    },
                    arg.span,
                ));
            }
        }
        Ok(())
    }

    /// Binds `YIELD` items into `scope`. A `YIELD` **introduces** each alias, so a name already in
    /// scope — bound by an earlier clause, or by a previous item of the same `YIELD` — is the TCK
    /// compile-time `VariableAlreadyBound` (`tck/features/clauses/call/Call1.feature` [15],
    /// `Call5.feature` [5]/[6]); this is stricter than [`Scope::bind`]'s benign same-kind re-binding
    /// rule for `MATCH` patterns.
    fn bind_yield_items(
        &self,
        items: &[YieldItem],
        scope: &mut Scope,
    ) -> Result<(), SemanticError> {
        for item in items {
            if scope.contains(&item.alias.name) {
                return Err(SemanticError::new(
                    SemanticErrorKind::VariableAlreadyBound {
                        name: item.alias.name.clone(),
                    },
                    item.alias.span,
                ));
            }
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
        let mut columns: Vec<(String, VarKind, SType, Span)> = Vec::new();
        // The incoming scope's static-type environment, so an aliased projection (`WITH 123 AS x`)
        // can carry its provable value type forward for the next clause's static checks.
        let incoming_types = Self::scope_types(scope);

        // The grouping-key context for the aggregation rules: the simple grouping keys of this
        // projection, plus (for `*`) every carried binding, which is a bare-variable grouping key.
        let mut keys = self.grouping_keys(body);
        if body.star {
            for name in scope.bindings.keys() {
                keys.simple.push(vec![name.as_str()]);
                keys.with_aliases.push(vec![name.as_str()]);
            }
        }

        // `*` carries every incoming binding through unchanged (name + kind preserved).
        if body.star {
            for (name, binding) in &scope.bindings {
                columns.push((
                    name.clone(),
                    binding.kind,
                    binding.stype.clone(),
                    clause_span,
                ));
            }
        }

        for item in &body.items {
            self.check_projection_item(item, scope, aggregating, &keys, is_final_return)?;
            let (col_name, kind) = self.column_name_and_kind(item, scope, is_final_return)?;
            // A bare entity variable keeps its concrete type; any other expression carries its
            // statically-inferred value type (often `Unknown`, but a literal/typed expression is
            // provable — `WITH 123 AS x` makes `x` an `Int`, so `x.num` later is a static mismatch).
            let stype = if matches!(kind, VarKind::Value) {
                static_type::infer_type(&item.expr, &incoming_types)
            } else {
                kind_default_stype(kind)
            };
            columns.push((col_name, kind, stype, item.span));
        }

        // 2) Duplicate result-column names are a ColumnNameConflict (TCK) — checked *before* the new
        //    scope is built, so a name collision is reported as a column conflict regardless of the
        //    colliding kinds (a `*`-carried node `n` plus an explicit `… AS n` is a column conflict,
        //    not a type conflict).
        self.check_duplicate_columns(&columns)?;

        // 3) Build the post-projection scope from the (now-unique) columns. `bind` cannot raise a
        //    type conflict here because the names are distinct (step 2 guaranteed it).
        let mut new_scope = Scope::default();
        for (name, kind, stype, span) in &columns {
            new_scope.bind_typed(name, *kind, stype.clone(), *span)?;
        }

        // 4) ORDER BY / SKIP / LIMIT and a trailing WHERE are evaluated against the projection body.
        //    Per the openCypher grammar a `WITH … [ORDER BY] [SKIP] [LIMIT] [WHERE]` lets the
        //    `ORDER BY` and the trailing `WHERE` reference **both** the projected aliases AND the
        //    input variables in scope *before* the projection — the "dual scope" (`WithWhere7`,
        //    the canonical before/after/both test; `TriadicSelection1`'s `WITH c WHERE r IS NULL`
        //    anti-join). Aliases shadow a pre-projection variable of the same name.
        //
        //    The one carve-out is `ORDER BY` over an **aggregating or DISTINCT** projection: such a
        //    projection collapses rows, so the pre-projection variables no longer have a well-defined
        //    per-output-row value and `ORDER BY` sees only the projected columns (`rmp` task #40).
        //    A trailing `WHERE`, by contrast, *always* sees the dual scope: even over an aggregating
        //    projection it may reference a surviving grouping key (`WithWhere6`:
        //    `WITH a, count(*) AS relCount WHERE relCount > 1`), and the engine carries the needed
        //    input variables across the projection so the filter can be applied (see `crate::lower`).
        let dual_scope = {
            let mut s = scope.clone();
            for (name, binding) in &new_scope.bindings {
                s.bindings.insert(name.clone(), binding.clone());
            }
            s
        };
        let order_scope = if aggregating || body.distinct {
            &new_scope
        } else {
            &dual_scope
        };
        for sort in &body.order_by {
            self.check_order_by_item(sort, order_scope, aggregating, &keys)?;
        }
        if let Some(skip) = &body.skip {
            self.check_expr(skip, &new_scope)?;
            self.reject_aggregation(skip, "SKIP")?;
            Self::check_skip_limit_literal(skip, "SKIP")?;
        }
        if let Some(limit) = &body.limit {
            self.check_expr(limit, &new_scope)?;
            self.reject_aggregation(limit, "LIMIT")?;
            Self::check_skip_limit_literal(limit, "LIMIT")?;
        }
        if let Some(w) = where_clause {
            self.check_predicate(w, &dual_scope, "WHERE")?;
        }

        Ok(new_scope)
    }

    fn check_projection_item(
        &self,
        item: &ProjectionItem,
        scope: &Scope,
        aggregating: bool,
        keys: &GroupingKeys<'_>,
        is_final_return: bool,
    ) -> Result<(), SemanticError> {
        self.check_expr(&item.expr, scope)?;
        // A projection is a value position: a bare pattern predicate is `UnexpectedSyntax` here.
        Self::check_pattern_predicate_placement(&item.expr, false)?;
        // Aggregations may not be nested anywhere, and may not draw from `rand()`.
        self.reject_nested_aggregation(&item.expr)?;
        self.reject_nondeterministic_in_aggregate(&item.expr)?;

        // WITH requires an explicit alias for any non-trivial expression; a bare variable or a
        // bare `count(*)`-style aggregate atom is allowed unaliased in a final RETURN where a name
        // can be inferred, but WITH always needs `AS` for a computed expression.
        if item.alias.is_none() && !Self::has_inferable_name(&item.expr) && !is_final_return {
            return Err(SemanticError::new(
                SemanticErrorKind::NoExpressionAlias,
                item.span,
            ));
        }

        // In an aggregating projection, an item *without* an aggregate is a grouping key (any
        // expression form — see the module docs). An item *with* an aggregate may compose, outside
        // its aggregate calls, only constants and the projection's simple grouping keys; any other
        // free sub-expression is an AmbiguousAggregationExpression (TCK `Return6` [18]–[21],
        // `With6` [7]–[9]).
        if aggregating && self.contains_aggregate(&item.expr) {
            self.check_aggregate_item_references(&item.expr, &keys.simple, &mut Vec::new())?;
        }
        Ok(())
    }

    fn check_order_by_item(
        &self,
        sort: &SortItem,
        scope: &Scope,
        aggregating: bool,
        keys: &GroupingKeys<'_>,
    ) -> Result<(), SemanticError> {
        // An aggregate-containing sort key of an aggregating projection obeys the same in-item
        // grouping rule as a projection item — checked *before* the scope check, and only when the
        // projection has a computed (complex) grouping key: the TCK classifies
        // `ORDER BY me.age + you.age + count(*)` after `WITH me.age + you.age AS ages, count(*)`
        // as AmbiguousAggregationExpression (`WithOrderBy4` [20], `ReturnOrderBy6` [5]), but the
        // same shape with *no* projected grouping key as UndefinedVariable (`WithOrderBy4` [19],
        // `ReturnOrderBy6` [4]) — which the scope check below raises. ORDER BY runs post-
        // projection, so the projected aliases also count as grouping keys here.
        if aggregating && self.contains_aggregate(&sort.expr) && keys.has_complex {
            self.check_aggregate_item_references(&sort.expr, &keys.with_aliases, &mut Vec::new())?;
        }
        self.check_expr(&sort.expr, scope)?;
        self.reject_nested_aggregation(&sort.expr)?;
        self.reject_nondeterministic_in_aggregate(&sort.expr)?;
        // ORDER BY may use aggregates only when the projection itself aggregates (it sorts the
        // grouped rows); in a non-aggregating projection an aggregate in ORDER BY is invalid.
        if !aggregating && self.contains_aggregate(&sort.expr) {
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
        columns: &[(String, VarKind, SType, Span)],
    ) -> Result<(), SemanticError> {
        let mut seen: HashMap<&str, ()> = HashMap::with_capacity(columns.len());
        for (name, _kind, _stype, span) in columns {
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

    /// Visits every **named** variable in a pattern part — the optional path variable, every node
    /// variable, and every relationship variable — calling `f` on each. Used to enforce the
    /// pattern-predicate rule that all named variables must already be bound (`UndefinedVariable`).
    fn for_each_pattern_variable(
        part: &PatternPart,
        f: &mut impl FnMut(&Variable) -> Result<(), SemanticError>,
    ) -> Result<(), SemanticError> {
        if let Some(var) = &part.var {
            f(var)?;
        }
        let element = &part.element;
        if let Some(var) = &element.start.variable {
            f(var)?;
        }
        for link in &element.chain {
            if let Some(var) = &link.relationship.variable {
                f(var)?;
            }
            if let Some(var) = &link.node.variable {
                f(var)?;
            }
        }
        Ok(())
    }

    fn bind_pattern_part(
        &self,
        part: &PatternPart,
        scope: &mut Scope,
        role: PatternRole,
    ) -> Result<(), SemanticError> {
        // A `shortestPath(...)` / `allShortestPaths(...)` wraps a single variable-length pattern and
        // is read-only by nature: it may never appear in a CREATE/MERGE write pattern, and its
        // inner pattern must be exactly one variable-length relationship between two node patterns.
        if part.kind != PatternPartKind::Normal {
            self.check_shortest_path(part, role)?;
        }
        if let Some(var) = &part.var {
            // A named path variable can never re-use an existing name (paths do not unify), and
            // its own pattern cannot re-use the path name for a node/relationship either: both are
            // `VariableAlreadyBound` (TCK Match6) — unlike the node/relationship cross-kind
            // re-bind, which is `VariableTypeConflict`.
            if scope.contains(&var.name) || element_uses_name(&part.element, &var.name) {
                return Err(SemanticError::new(
                    SemanticErrorKind::VariableAlreadyBound {
                        name: var.name.clone(),
                    },
                    var.span,
                ));
            }
            scope.bind(&var.name, VarKind::Path, var.span)?;
        }
        self.bind_pattern_element(&part.element, scope, role)
    }

    /// Validates the inner pattern of a `shortestPath(...)` / `allShortestPaths(...)` search
    /// function (openCypher / Neo4j-dialect path search), enforcing the supported shape:
    ///
    /// - It may only appear in a read (`MATCH`/`OPTIONAL MATCH`) pattern, never a `CREATE`/`MERGE`.
    /// - The wrapped pattern is exactly **one** relationship between **two** node patterns
    ///   (`(a)-[...]-(b)`), with no longer chain.
    /// - That single relationship is **variable-length** (`-[*]-`, `-[*1..6]-`, …); a fixed-length
    ///   relationship has a known single length and is not a shortest-path search.
    ///
    /// Faults are reported as [`SemanticErrorKind::InvalidShortestPath`] (a compile-time
    /// `SyntaxError`, mirroring how the reference implementations reject these forms). Node and
    /// relationship variables inside the pattern are bound by the ordinary element walk afterwards.
    fn check_shortest_path(
        &self,
        part: &PatternPart,
        role: PatternRole,
    ) -> Result<(), SemanticError> {
        if role != PatternRole::Read {
            return Err(SemanticError::new(
                SemanticErrorKind::InvalidShortestPath {
                    reason: "shortestPath/allShortestPaths can only be used in a MATCH pattern"
                        .to_owned(),
                },
                part.span,
            ));
        }
        if part.element.chain.len() != 1 {
            return Err(SemanticError::new(
                SemanticErrorKind::InvalidShortestPath {
                    reason: format!(
                        "the pattern must be a single relationship between two nodes, \
                         but it has {} relationship(s)",
                        part.element.chain.len()
                    ),
                },
                part.element.span,
            ));
        }
        let rel = &part.element.chain[0].relationship;
        if rel.range.is_none() {
            return Err(SemanticError::new(
                SemanticErrorKind::InvalidShortestPath {
                    reason: "the relationship must be variable-length (e.g. `-[*]-`, `-[*1..6]-`)"
                        .to_owned(),
                },
                rel.span,
            ));
        }
        Ok(())
    }

    fn bind_pattern_element(
        &self,
        element: &PatternElement,
        scope: &mut Scope,
        role: PatternRole,
    ) -> Result<(), SemanticError> {
        // In a CREATE/MERGE pattern an already-bound node variable is only legal as a *bare
        // endpoint* of a relationship chain (`MATCH (a), (b) CREATE (a)-[:R]->(b)`). A standalone
        // node part re-using a bound name always creates a new node and so conflicts: TCK
        // `VariableAlreadyBound` (`Fail when creating a node that is already bound`).
        if role == PatternRole::Create && element.chain.is_empty() {
            if let Some(var) = &element.start.variable {
                if scope.contains(&var.name) {
                    return Err(SemanticError::new(
                        SemanticErrorKind::VariableAlreadyBound {
                            name: var.name.clone(),
                        },
                        var.span,
                    ));
                }
            }
        }
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
        role: PatternRole,
    ) -> Result<(), SemanticError> {
        if let Some(var) = &node.variable {
            // A bound node variable inside a CREATE/MERGE pattern may only be re-used bare: adding
            // labels or properties to it would redefine the existing node — TCK
            // `VariableAlreadyBound` (`Fail when adding a new label predicate on a node that is
            // already bound`).
            if role == PatternRole::Create
                && scope.contains(&var.name)
                && (!node.labels.is_empty() || node.properties.is_some())
            {
                return Err(SemanticError::new(
                    SemanticErrorKind::VariableAlreadyBound {
                        name: var.name.clone(),
                    },
                    var.span,
                ));
            }
            scope.bind(&var.name, VarKind::Node, var.span)?;
        }
        if let Some(props) = &node.properties {
            self.check_expr(props, scope)?;
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
        // A CREATE/MERGE always creates a *new* relationship, so its variable must be fresh:
        // re-using an already-bound name is `VariableAlreadyBound` (TCK; e.g.
        // `MATCH ()-[r]->() CREATE ()-[r]->()`). Checked BEFORE the well-formedness rules below —
        // the TCK expects the variable fault to win when both apply (Create2 [23]). For MATCH,
        // repeating a relationship variable is handled by `Scope::bind`'s same-kind/conflict rules.
        if role == PatternRole::Create {
            if let Some(var) = &rel.variable {
                if scope.contains(&var.name) {
                    return Err(SemanticError::new(
                        SemanticErrorKind::VariableAlreadyBound {
                            name: var.name.clone(),
                        },
                        var.span,
                    ));
                }
            }
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
            scope.bind(&var.name, VarKind::Relationship, var.span)?;
        }
        if let Some(props) = &rel.properties {
            self.check_expr(props, scope)?;
            self.reject_aggregation(props, "a pattern")?;
        }
        Ok(())
    }

    // ---- expression reference resolution ----------------------------------------------------

    /// Resolves every free variable reference in `expr` against `scope`, recursing through the whole
    /// expression tree. Also resolves variables bound *locally* by list/pattern comprehensions
    /// (their iteration variable is in scope only inside the comprehension) and validates function
    /// calls against the registry.
    /// Resolves variable references **and** statically type-checks `expr` (`rmp` task #61): the
    /// every-position entry point used wherever a value expression appears. The type check is purely
    /// additive — it raises a [`SemanticErrorKind::InvalidExpressionType`] only for a *provable*
    /// mismatch and is otherwise a no-op (see [`crate::static_type`]).
    fn check_expr(&self, expr: &Expr, scope: &Scope) -> Result<(), SemanticError> {
        self.check_expr_refs(expr, scope)?;
        static_type::check_expr(expr, &Self::scope_types(scope))
    }

    /// Builds the variable → static-type environment for a [`static_type`] check from the semantic
    /// scope: a node/relationship binding carries its element type; every other binding (an
    /// `UNWIND`/`WITH` value, a `YIELD` output) is [`SType::Unknown`], so it is never the basis of a
    /// static type error (`rmp` task #61 conservatism).
    fn scope_types(scope: &Scope) -> TypeEnv {
        scope
            .bindings
            .iter()
            .map(|(name, binding)| (name.clone(), binding.stype.clone()))
            .collect()
    }

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
                // A bare *pattern predicate* (`(n)-[]->()`) may not **introduce** variables: every
                // named node/relationship variable must already be bound in the outer scope, else
                // openCypher raises `UndefinedVariable` (TCK `expressions/pattern/Pattern1` [10]).
                // An explicit `EXISTS { ... }` has no such restriction — it binds freely.
                if ex.from_pattern_predicate {
                    for part in &ex.pattern {
                        Self::for_each_pattern_variable(part, &mut |var| {
                            self.require_defined(&var.name, var.span, scope)
                        })?;
                    }
                }
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
        // 1) Built-ins take precedence (they may not be shadowed by a UDF — see
        //    `function_registry::FunctionSet::register`). A built-in with a wrong arity is the TCK
        //    `SyntaxError`/`InvalidNumberOfArguments`, unchanged.
        if let Some(sig) = function_registry::lookup(&dotted) {
            return match sig.arity.check(args.len()) {
                ArityCheck::Ok => Ok(()),
                ArityCheck::Wrong => Err(SemanticError::new(
                    SemanticErrorKind::InvalidNumberOfArguments {
                        name: dotted,
                        expected: sig.arity.describe(),
                        got: args.len(),
                    },
                    span,
                )),
            };
        }
        // 2) Not a built-in: try the extension-function registry (`rmp` #75). A registered UDF with
        //    a wrong arity is the **same** class as a built-in's — `SyntaxError`/
        //    `InvalidNumberOfArguments` — the correct compile-time class for a function arity error.
        if let Some(sig) = self.functions.signature(&dotted) {
            return match sig.arity.check(args.len()) {
                ArityCheck::Ok => Ok(()),
                ArityCheck::Wrong => Err(SemanticError::new(
                    SemanticErrorKind::InvalidNumberOfArguments {
                        name: dotted,
                        expected: sig.arity.describe(),
                        got: args.len(),
                    },
                    span,
                )),
            };
        }
        // 3) Neither a built-in nor a UDF: the TCK `SyntaxError`/`UnknownFunction`, unchanged.
        Err(SemanticError::new(
            SemanticErrorKind::UnknownFunction { name: dotted },
            span,
        ))
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
        self.check_expr(expr, scope)?;
        // A `WHERE` is a predicate position: bare pattern predicates are legal here (and under the
        // boolean operators nested in it), so start the placement walk in predicate context.
        Self::check_pattern_predicate_placement(expr, true)?;
        self.reject_aggregation(expr, position)
    }

    /// Enforces that a bare **pattern predicate** (`(n)-[]->()` written as an
    /// [`ExprKind::ExistsSubquery`] with `from_pattern_predicate`) appears only in a *predicate
    /// position* — a `WHERE`, or an operand of `NOT` / `AND` / `OR` / `XOR` reachable from one.
    /// Anywhere else (a projection, a `SET` right-hand side, a function argument, a comparison /
    /// arithmetic operand, a collection element) it is the openCypher `UnexpectedSyntax` error (TCK
    /// `expressions/pattern/Pattern1` [22]–[24], `expressions/list/List6` [6]).
    ///
    /// `in_predicate` carries whether the *current* expression sits in a predicate position. The
    /// boolean connectives propagate it to their operands; every other parent puts its children into
    /// **value** position. Predicate slots nested inside an otherwise value-position expression — a
    /// list/pattern-comprehension `WHERE`, a quantifier predicate, an `EXISTS { ... }` `WHERE` — are
    /// re-entered in predicate context, since they are genuine sub-predicates.
    fn check_pattern_predicate_placement(
        expr: &Expr,
        in_predicate: bool,
    ) -> Result<(), SemanticError> {
        match &expr.kind {
            ExprKind::ExistsSubquery(ex) => {
                if ex.from_pattern_predicate && !in_predicate {
                    return Err(SemanticError::new(
                        SemanticErrorKind::PatternPredicateInExpression,
                        expr.span,
                    ));
                }
                // The optional `WHERE` of an `EXISTS { ... }` is itself a predicate position.
                if let Some(pred) = &ex.predicate {
                    Self::check_pattern_predicate_placement(pred, true)?;
                }
                Ok(())
            }
            // `NOT` propagates the predicate context to its operand.
            ExprKind::Unary {
                op: UnaryOp::Not,
                operand,
            } => Self::check_pattern_predicate_placement(operand, in_predicate),
            // `AND` / `OR` / `XOR` propagate; every other binary operator is a value context.
            ExprKind::Binary { op, lhs, rhs } => {
                let boolean = matches!(op, BinaryOp::And | BinaryOp::Or | BinaryOp::Xor);
                let child_ctx = in_predicate && boolean;
                Self::check_pattern_predicate_placement(lhs, child_ctx)?;
                Self::check_pattern_predicate_placement(rhs, child_ctx)
            }
            // Comprehensions / quantifiers: the iterated list is a value, but their `WHERE` is a
            // predicate; the projection is a value.
            ExprKind::ListComprehension(lc) => {
                Self::check_pattern_predicate_placement(&lc.list, false)?;
                if let Some(pred) = &lc.predicate {
                    Self::check_pattern_predicate_placement(pred, true)?;
                }
                if let Some(proj) = &lc.projection {
                    Self::check_pattern_predicate_placement(proj, false)?;
                }
                Ok(())
            }
            ExprKind::PatternComprehension(pc) => {
                if let Some(pred) = &pc.predicate {
                    Self::check_pattern_predicate_placement(pred, true)?;
                }
                Self::check_pattern_predicate_placement(&pc.projection, false)
            }
            ExprKind::Quantifier(q) => {
                Self::check_pattern_predicate_placement(&q.list, false)?;
                Self::check_pattern_predicate_placement(&q.predicate, true)
            }
            // Any other expression node: all children are value positions.
            _ => Self::for_each_child(expr, &mut |child| {
                Self::check_pattern_predicate_placement(child, false)
            }),
        }
    }

    /// A `SKIP`/`LIMIT` count must be a non-negative-integer **constant** expression
    /// (`tck/features/clauses/return-skip-limit/**`). Statically decidable here:
    ///
    /// - a **literal** of any other scalar type (`SKIP 1.5`) — `SyntaxError`/`InvalidArgumentType`;
    /// - a **negated integer literal** (`SKIP -1`) — `SyntaxError`/`NegativeIntegerArgument`;
    /// - a **row-dependent** expression (`SKIP n.count`, a free variable reference) —
    ///   `SyntaxError`/`NonConstantExpression`.
    ///
    /// A *constant* dynamic count (a parameter, `SKIP toInteger(rand()*9)`) is a runtime concern
    /// and is **not** flagged — the statement plan stays parameter-independent (`04 §7.5`).
    fn check_skip_limit_literal(expr: &Expr, position: &'static str) -> Result<(), SemanticError> {
        if let ExprKind::Unary {
            op: UnaryOp::Minus,
            operand,
        } = &expr.kind
        {
            if matches!(&operand.kind, ExprKind::Literal(Literal::Integer(_))) {
                return Err(SemanticError::new(
                    SemanticErrorKind::NegativeIntegerArgument,
                    expr.span,
                ));
            }
        }
        if let ExprKind::Literal(lit) = &expr.kind {
            if !matches!(lit, Literal::Integer(_) | Literal::Null) {
                return Err(SemanticError::new(
                    SemanticErrorKind::InvalidExpressionType {
                        context: format!("{position} requires an integer"),
                    },
                    expr.span,
                ));
            }
        }
        if Self::references_free_variable(expr, &mut Vec::new()) {
            return Err(SemanticError::new(
                SemanticErrorKind::NonConstantExpression { position },
                expr.span,
            ));
        }
        Ok(())
    }

    /// Errors with [`InvalidAggregation`] if `expr` contains an aggregate anywhere (used for the
    /// positions where aggregation is categorically forbidden).
    ///
    /// [`InvalidAggregation`]: SemanticErrorKind::InvalidAggregation
    fn reject_aggregation(&self, expr: &Expr, position: &'static str) -> Result<(), SemanticError> {
        if self.contains_aggregate(expr) {
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
        self.find_nested_aggregate(expr, false)
    }

    fn find_nested_aggregate(
        &self,
        expr: &Expr,
        inside_aggregate: bool,
    ) -> Result<(), SemanticError> {
        let here_is_aggregate = self.is_aggregate_call(expr);
        if here_is_aggregate && inside_aggregate {
            return Err(SemanticError::new(
                SemanticErrorKind::NestedAggregation,
                expr.span,
            ));
        }
        let child_inside = inside_aggregate || here_is_aggregate;
        Self::for_each_child(expr, &mut |child| {
            self.find_nested_aggregate(child, child_inside)
        })
    }

    // ---- pure AST predicates (no scope needed) ----------------------------------------------

    fn projection_is_aggregating(&self, body: &ProjectionBody) -> bool {
        body.items
            .iter()
            .any(|it| self.contains_aggregate(&it.expr))
    }

    /// `true` if `expr` is itself an aggregating function call (or the `count(*)` atom).
    ///
    /// A built-in aggregate is recognised by [`function_registry::is_aggregate`]; an **aggregate
    /// UDF** (`rmp` #75) is recognised by its registered signature's `aggregate` flag, so it
    /// participates in the aggregation-placement rules. (Registration is supported; the per-group
    /// fold of a custom aggregate is a named v1 deferral — see [`crate::function_registry`].)
    fn is_aggregate_call(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::CountStar => true,
            ExprKind::FunctionCall { name, .. } => {
                let dotted = name.join(".");
                function_registry::is_aggregate(&dotted)
                    || self
                        .functions
                        .signature(&dotted)
                        .is_some_and(|s| s.aggregate)
            }
            _ => false,
        }
    }

    /// `true` if `expr` contains an aggregate anywhere in its tree.
    fn contains_aggregate(&self, expr: &Expr) -> bool {
        if self.is_aggregate_call(expr) {
            return true;
        }
        let mut found = false;
        let _ = Self::for_each_child(expr, &mut |child| {
            if self.contains_aggregate(child) {
                found = true;
            }
            Ok(())
        });
        found
    }

    /// The path signature of a **simple** expression — a bare variable or a property path rooted
    /// at a variable — as the variable name followed by the property keys (`me.age` → `["me",
    /// "age"]`). `None` for any other form. These are the only expressions that qualify as
    /// re-usable grouping keys *inside* an aggregate-containing item (module docs; TCK `Return6`
    /// [18]/[19] vs [21]).
    fn simple_path_signature(expr: &Expr) -> Option<Vec<&str>> {
        match &expr.kind {
            ExprKind::Variable(name) => Some(vec![name.as_str()]),
            ExprKind::Property { base, key } => {
                let mut sig = Self::simple_path_signature(base)?;
                sig.push(key.as_str());
                Some(sig)
            }
            _ => None,
        }
    }

    /// Whether `sig` is determined by one of the projected simple grouping `keys`: it is a key, or
    /// a property (path) *of* a key — `n.x` is grouped when `n` is a key, but `me` is not grouped
    /// by the key `me.age`.
    fn signature_is_grouped(sig: &[&str], keys: &[Vec<&str>]) -> bool {
        keys.iter()
            .any(|k| sig.len() >= k.len() && sig[..k.len()] == k[..])
    }

    /// Collects the grouping-key context of one projection body (the non-aggregated items): the
    /// simple keys' path signatures, the same plus the items' aliases (for the post-projection
    /// ORDER BY variant of the rule), and whether some non-aggregated item is *complex* (a
    /// computed grouping key — which drives the ORDER BY classification split, see
    /// [`Self::check_order_by_item`]).
    fn grouping_keys<'b>(&self, body: &'b ProjectionBody) -> GroupingKeys<'b> {
        let mut simple = Vec::new();
        let mut with_aliases = Vec::new();
        let mut has_complex = false;
        for item in &body.items {
            if self.contains_aggregate(&item.expr) {
                continue;
            }
            match Self::simple_path_signature(&item.expr) {
                Some(sig) => {
                    simple.push(sig.clone());
                    with_aliases.push(sig);
                }
                None => has_complex = true,
            }
            if let Some(alias) = &item.alias {
                with_aliases.push(vec![alias.name.as_str()]);
            }
        }
        GroupingKeys {
            simple,
            with_aliases,
            has_complex,
        }
    }

    /// Enforces the in-item grouping rule on an **aggregate-containing** expression: outside its
    /// aggregate calls, only constants (literals/parameters), locally-bound iteration variables,
    /// and the projection's simple grouping `keys` (or properties of them) may appear; any other
    /// free variable / property path raises [`AmbiguousAggregationExpression`] (TCK `Return6`
    /// [20]/[21], `With6` [8]/[9] — even a complex expression that is itself projected does not
    /// qualify).
    ///
    /// [`AmbiguousAggregationExpression`]: SemanticErrorKind::AmbiguousAggregationExpression
    fn check_aggregate_item_references(
        &self,
        expr: &Expr,
        keys: &[Vec<&str>],
        locals: &mut Vec<String>,
    ) -> Result<(), SemanticError> {
        // The interior of an aggregate call is folded per group — free references are its point.
        if self.is_aggregate_call(expr) {
            return Ok(());
        }
        // A bare variable / variable-rooted property path: legal iff grouped or locally bound.
        if let Some(sig) = Self::simple_path_signature(expr) {
            if Self::signature_is_grouped(&sig, keys) || locals.iter().any(|l| l == sig[0]) {
                return Ok(());
            }
            return Err(SemanticError::new(
                SemanticErrorKind::AmbiguousAggregationExpression,
                expr.span,
            ));
        }
        match &expr.kind {
            // Iteration constructs bind their variable for the predicate/projection parts only.
            ExprKind::ListComprehension(lc) => {
                self.check_aggregate_item_references(&lc.list, keys, locals)?;
                locals.push(lc.variable.name.clone());
                let result = (|| {
                    if let Some(pred) = &lc.predicate {
                        self.check_aggregate_item_references(pred, keys, locals)?;
                    }
                    if let Some(proj) = &lc.projection {
                        self.check_aggregate_item_references(proj, keys, locals)?;
                    }
                    Ok(())
                })();
                locals.pop();
                result
            }
            ExprKind::Quantifier(q) => {
                self.check_aggregate_item_references(&q.list, keys, locals)?;
                locals.push(q.variable.name.clone());
                let result = self.check_aggregate_item_references(&q.predicate, keys, locals);
                locals.pop();
                result
            }
            // Pattern-scoped forms bind their own pattern variables and cannot host aggregates;
            // they are left to the general scope checks (conservative: never flagged here).
            ExprKind::PatternComprehension(_) | ExprKind::ExistsSubquery(_) => Ok(()),
            _ => Self::for_each_child(expr, &mut |child| {
                self.check_aggregate_item_references(child, keys, locals)
            }),
        }
    }

    /// Rejects the non-deterministic `rand()` inside an aggregating function's arguments with
    /// [`NonConstantExpression`] (TCK `clauses/return/Return6.feature` [15]: `RETURN count(rand())`
    /// → `SyntaxError`/`NonConstantExpression`): the per-group fold has no defined row order, so
    /// the draw would be observable, implementation-defined behaviour.
    ///
    /// [`NonConstantExpression`]: SemanticErrorKind::NonConstantExpression
    fn reject_nondeterministic_in_aggregate(&self, expr: &Expr) -> Result<(), SemanticError> {
        if self.is_aggregate_call(expr) {
            if let ExprKind::FunctionCall { args, .. } = &expr.kind {
                for arg in args {
                    if let Some(span) = Self::find_rand_call(arg) {
                        return Err(SemanticError::new(
                            SemanticErrorKind::NonConstantExpression {
                                position: "an aggregating function",
                            },
                            span,
                        ));
                    }
                }
            }
        }
        Self::for_each_child(expr, &mut |child| {
            self.reject_nondeterministic_in_aggregate(child)
        })
    }

    /// The span of the first `rand()` call in `expr`, if any.
    fn find_rand_call(expr: &Expr) -> Option<Span> {
        if let ExprKind::FunctionCall { name, .. } = &expr.kind {
            if name.len() == 1 && name[0].eq_ignore_ascii_case("rand") {
                return Some(expr.span);
            }
        }
        let mut found = None;
        let _ = Self::for_each_child(expr, &mut |child| {
            if found.is_none() {
                found = Self::find_rand_call(child);
            }
            Ok(())
        });
        found
    }

    /// Whether `expr` references a **free** (non-locally-bound) variable — i.e. its value depends
    /// on the current row. Iteration constructs bind their variable locally; pattern-scoped forms
    /// (pattern comprehensions, `EXISTS`) read the graph and are therefore never constant.
    fn references_free_variable(expr: &Expr, locals: &mut Vec<String>) -> bool {
        match &expr.kind {
            ExprKind::Variable(name) => !locals.iter().any(|l| l == name),
            ExprKind::ListComprehension(lc) => {
                if Self::references_free_variable(&lc.list, locals) {
                    return true;
                }
                locals.push(lc.variable.name.clone());
                let found = lc
                    .predicate
                    .as_ref()
                    .is_some_and(|p| Self::references_free_variable(p, locals))
                    || lc
                        .projection
                        .as_ref()
                        .is_some_and(|p| Self::references_free_variable(p, locals));
                locals.pop();
                found
            }
            ExprKind::Quantifier(q) => {
                if Self::references_free_variable(&q.list, locals) {
                    return true;
                }
                locals.push(q.variable.name.clone());
                let found = Self::references_free_variable(&q.predicate, locals);
                locals.pop();
                found
            }
            ExprKind::PatternComprehension(_) | ExprKind::ExistsSubquery(_) => true,
            _ => {
                let mut found = false;
                let _ = Self::for_each_child(expr, &mut |child| {
                    if !found {
                        found = Self::references_free_variable(child, locals);
                    }
                    Ok(())
                });
                found
            }
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

    /// Classifies a `DELETE` target that is *clearly* not a graph entity, returning the openCypher
    /// compile-time error kind, or `None` if the expression could name a node/rel/path at runtime
    /// (a variable, property, index, function call, …) and so is accepted here.
    ///
    /// Two details are distinguished:
    ///   * an **arithmetic** expression (`DELETE 1 + 1`) is `InvalidExpressionType` →
    ///     `InvalidArgumentType` (`clauses/delete/Delete5.feature` \[9\]);
    ///   * any other clearly-non-entity form — a literal, list, map, `count(*)`, or a label/type
    ///     predicate such as `DELETE n:Person` / `DELETE r:T` — is `InvalidDelete`
    ///     (`clauses/delete/Delete{1,2}.feature`).
    fn non_entity_delete_error(expr: &Expr) -> Option<SemanticErrorKind> {
        match &expr.kind {
            // An arithmetic result is a number: a wrong *type* for DELETE → `InvalidArgumentType`.
            ExprKind::Binary {
                op:
                    BinaryOp::Add
                    | BinaryOp::Sub
                    | BinaryOp::Mul
                    | BinaryOp::Div
                    | BinaryOp::Mod
                    | BinaryOp::Pow,
                ..
            } => Some(SemanticErrorKind::InvalidExpressionType {
                context: "DELETE requires a node, relationship or path, not a number".to_owned(),
            }),
            // A literal/list/map/count(*) and the `expr:Label` label-predicate form are the
            // syntactic `InvalidDelete` family.
            ExprKind::Literal(_)
            | ExprKind::List(_)
            | ExprKind::Map(_)
            | ExprKind::CountStar
            | ExprKind::HasLabels { .. } => Some(SemanticErrorKind::InvalidDelete),
            _ => None,
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

/// Whether any node or relationship variable inside `element` is named `name` (the same-pattern
/// path-name re-use check, TCK `VariableAlreadyBound`).
fn element_uses_name(element: &PatternElement, name: &str) -> bool {
    let node_uses =
        |node: &crate::ast::NodePattern| node.variable.as_ref().is_some_and(|v| v.name == name);
    node_uses(&element.start)
        || element.chain.iter().any(|link| {
            link.relationship
                .variable
                .as_ref()
                .is_some_and(|v| v.name == name)
                || node_uses(&link.node)
        })
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
        let analyzer = Analyzer {
            functions: function_registry::no_functions(),
            procedures: procedure_registry::builtins(),
        };
        assert!(analyzer.projection_is_aggregating(body));
    }

    #[test]
    fn projected_literal_type_flows_into_static_property_check() {
        // An aliased literal carries its provable type forward, so a property access on the
        // non-graph value is a compile-time mismatch (`expressions/graph/Graph6.feature` [9]).
        for exp in ["123", "42.45", "true", "'string'", "[123, true]"] {
            let q = ast(&format!("WITH {exp} AS x RETURN x.num"));
            let err = analyze(&q).expect_err("non-graph property base must be rejected");
            assert!(
                matches!(err.kind, SemanticErrorKind::InvalidExpressionType { .. }),
                "{exp}: unexpected kind {:?}",
                err.kind
            );
        }
        // A node carried through WITH stays a node, so its property access is accepted.
        assert!(analyze(&ast("MATCH (n) WITH n AS m RETURN m.prop")).is_ok());
        // An unknown value (`UNWIND`) is never the basis of a static error.
        assert!(analyze(&ast("UNWIND [1, 2] AS x RETURN x.num")).is_ok());
    }

    #[test]
    fn labels_on_a_named_path_is_a_compile_time_error() {
        // `labels(p)` on a named path is a compile-time SyntaxError
        // (`expressions/graph/Graph3.feature` [8]); `type()` on a node likewise.
        let err = analyze(&ast("MATCH p = (a) RETURN labels(p)"))
            .expect_err("labels() on a path must be rejected");
        assert!(matches!(
            err.kind,
            SemanticErrorKind::InvalidExpressionType { .. }
        ));
        assert!(analyze(&ast("MATCH (r) RETURN type(r)")).is_err());
        // A relationship variable into `type()`, and a path into `length()`, are accepted.
        assert!(analyze(&ast("MATCH ()-[r]->() RETURN type(r)")).is_ok());
        assert!(analyze(&ast("MATCH p = ()-[*]-() RETURN length(p)")).is_ok());
    }

    #[test]
    fn simple_path_signature_recognises_property_paths() {
        let q = ast("RETURN n.a.b");
        let body = if let Clause::Return(r) = &q.body_single_query().clauses[0] {
            &r.body
        } else {
            unreachable!()
        };
        assert_eq!(
            Analyzer::simple_path_signature(&body.items[0].expr),
            Some(vec!["n", "a", "b"])
        );

        let q = ast("RETURN n.a + 1");
        let body = if let Clause::Return(r) = &q.body_single_query().clauses[0] {
            &r.body
        } else {
            unreachable!()
        };
        assert_eq!(Analyzer::simple_path_signature(&body.items[0].expr), None);
    }

    #[test]
    fn signature_prefix_rule_matches_keys_and_their_properties() {
        let keys = vec![vec!["n"], vec!["me", "age"]];
        // A key itself, and a property of a key, are grouped.
        assert!(Analyzer::signature_is_grouped(&["n"], &keys));
        assert!(Analyzer::signature_is_grouped(&["n", "x"], &keys));
        assert!(Analyzer::signature_is_grouped(&["me", "age"], &keys));
        // The *root* of a property key is not determined by it, nor is a sibling property.
        assert!(!Analyzer::signature_is_grouped(&["me"], &keys));
        assert!(!Analyzer::signature_is_grouped(&["me", "other"], &keys));
    }
}
