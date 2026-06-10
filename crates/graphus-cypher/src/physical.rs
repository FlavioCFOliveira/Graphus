//! The Cypher **physical plan** and the heuristic, index-aware **physical planner**
//! (`04-technical-design.md` §7.1, §6.6).
//!
//! [`plan_physical`] lowers a [logical plan](crate::logical::LogicalOp) into a [`PhysicalPlan`]: the
//! tree of [`PhysicalOp`]s the executor (the next sub-task) consumes, plus the set of catalog
//! [`IndexId`](crate::catalog::IndexId)s the plan depends on (for cache invalidation, `04 §6.6`).
//! The physical plan makes the *strategy* choices the logical plan deliberately left open
//! (`04 §7.1`):
//!
//! > *"physical planner → physical plan (index seeks, expand-into vs expand-all, hash vs
//! > nested-loop join, sort, limit pushdown)"*.
//!
//! # The four physical decisions (and why each is sound)
//!
//! v1 is **heuristic / rule-based with index awareness** (`04 §6.6`); a cost-based optimiser with
//! statistics is Phase 2 (`00-overview` §6). Each rule below is chosen so it is *obviously*
//! correct — it never changes the rows a plan produces, only how they are produced.
//!
//! 1. **Index selection.** A [`NodeByLabelScan`](crate::logical::LogicalOp::NodeByLabelScan)
//!    immediately under a [`Filter`](crate::logical::LogicalOp::Filter) whose predicate is an
//!    **equality** on an *indexed* labelled property (`n.p = v`) becomes a
//!    [`NodeIndexSeek`](PhysicalOp::NodeIndexSeek); a **range** predicate (`n.p > v`, `<`, `>=`,
//!    `<=`) on an indexed property becomes a [`NodeIndexRangeSeek`](PhysicalOp::NodeIndexRangeSeek).
//!    A bare label scan with a matching **token-lookup** index becomes a
//!    [`TokenLookupScan`](PhysicalOp::TokenLookupScan). With no usable index the access falls back
//!    to [`NodeByLabelScan`](PhysicalOp::NodeByLabelScan) / [`AllNodesScan`](PhysicalOp::AllNodesScan)
//!    plus the residual [`Filter`](PhysicalOp::Filter). **Soundness:** a seek returns exactly the
//!    records matching the predicate the [`Filter`] tested, so consuming the predicate into the seek
//!    is equivalence-preserving; any predicate the seek does *not* fully cover is retained as a
//!    residual filter.
//! 2. **Expand-into vs expand-all** (`04 §7.1`). An [`Expand`](crate::logical::LogicalOp::Expand) is
//!    realised as [`ExpandInto`](PhysicalOp::ExpandInto) when **both** endpoints are already bound by
//!    the input (a connection/cycle check — enumerate the edges *between* two known nodes), else
//!    [`ExpandAll`](PhysicalOp::ExpandAll) (enumerate neighbours of the bound `from`). **Soundness:**
//!    both enumerate the same relationship set; expand-into is merely the specialisation that filters
//!    on a `to` already in scope.
//! 3. **Hash vs nested-loop join** (`04 §7.1`). The relational join points —
//!    [`Apply`](crate::logical::LogicalOp::Apply) and the distinct
//!    [`Union`](crate::logical::LogicalOp::Union) — pick a join *strategy* by a documented rule:
//!    an **equi-join** (the two sides share one or more join-key columns by name) compiles to a
//!    [`HashJoin`](PhysicalOp::HashJoin); otherwise a [`NestedLoopJoin`](PhysicalOp::NestedLoopJoin).
//!    See [`choose_join`]. **Soundness:** both compute the same correlated/combined result; the
//!    strategy is a performance choice only. (A correlated `Apply` whose right branch genuinely reads
//!    the left row through an [`Argument`](crate::logical::LogicalOp::Argument) is always a
//!    nested-loop — a hash join cannot express the per-row correlation.)
//! 4. **Sort/Limit pushdown** (`04 §7.1`). A [`Limit`](crate::logical::LogicalOp::Limit) directly
//!    over a [`Sort`](crate::logical::LogicalOp::Sort) fuses into a single
//!    [`TopN`](PhysicalOp::TopN) (compute only the top *k* rows instead of sorting all then
//!    truncating). A `Limit` directly over a **row-count-preserving** projection (a non-`DISTINCT`,
//!    non-aggregating [`Projection`](crate::logical::LogicalOp::Projection)) is pushed **below** the
//!    projection. **Soundness:** `TopN(k, sort) ≡ Limit(k, Sort(sort))` by definition; and pushing a
//!    `Limit` below a projection that maps rows one-to-one (no `DISTINCT`, no aggregation) yields the
//!    same first-*k* rows in the same order, because such a projection neither drops nor adds rows.
//!    The pushdown is explicitly **NOT** applied below a `DISTINCT` projection or an
//!    [`Aggregation`](crate::logical::LogicalOp::Aggregation) — those change the row count, so
//!    limiting first would change the result (a negative test guards this).
//!
//! # Covered vs deferred (named)
//!
//! **Covered:** all [`LogicalOp`](crate::logical::LogicalOp) variants are lowered to a physical
//! form (the relational, graph, write, and procedure operators carry through; the four decisions
//! above specialise where they apply). Index selection covers single-property **equality** and
//! **range** node predicates, the **token-lookup** label scan, and single-property **relationship**
//! predicates routed through the catalog.
//!
//! **Deferred, by name:** (1) **cost-based optimisation** — selectivity-driven access-path choice,
//! join reordering, multi-predicate composite-index seeds beyond a single leading-key predicate, and
//! general predicate pushdown (Phase 2, `00-overview` §6; `04 §6.6`); (2) **`AllRelationshipsScan`
//! index routing** — a relationship-type-only scan keeps its logical form (the relationship-property
//! seek requires a property predicate, lowered when a [`Filter`] supplies one over an expand, which
//! is itself Phase-2 territory); (3) **composite multi-key seeks** — only a composite's *leading*
//! key drives a seek here, matching the catalog's [`label_property`](crate::catalog::IndexCatalog::label_property)
//! contract; (4) **`IN`-list / `STARTS WITH` index acceleration** — treated as residual filters in
//! v1.

use crate::ast::{BinaryOp, Expr, ExprKind, Label, RelType};
use crate::catalog::{IndexCatalog, IndexDescriptor, IndexId};
use crate::logical::{
    CreatePart, LogicalOp, ProjectionColumn, RemoveOp, SetOp, SortKey, Var, YieldColumn,
};
use std::collections::BTreeSet;
use std::fmt;

/// A compiled **physical plan**: the operator tree plus the catalog indexes it depends on.
///
/// The dependency set is the mechanism `04 §6.6` describes — *"plans record which indexes they
/// depend on so the plan cache is invalidated on schema/index change"*. The plan cache
/// ([`crate::plan_cache`]) keys on `schema_version` (bumped on any DDL/index change), and the
/// recorded [`IndexId`]s additionally enable finer-grained invalidation later.
///
/// A `PhysicalPlan` is **parameter-independent** (`04 §7.5`): it embeds no bound parameter values,
/// so a single compiled plan is reused across every parameter set (parameters bind at execution via
/// [`crate::binding::bind_parameters`]).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct PhysicalPlan {
    /// The root physical operator (the last thing computed; data flows leaves → root).
    pub root: PhysicalOp,
    /// The catalog index ids this plan's access paths depend on, ascending and de-duplicated.
    index_dependencies: BTreeSet<IndexId>,
}

impl PhysicalPlan {
    /// The catalog [`IndexId`]s this plan depends on, ascending (`04 §6.6`).
    ///
    /// A change to any of these indexes (or a `schema_version` bump) must invalidate the cached
    /// plan ([`crate::plan_cache`]).
    pub fn index_dependencies(&self) -> impl Iterator<Item = IndexId> + '_ {
        self.index_dependencies.iter().copied()
    }

    /// Whether this plan depends on `id`.
    #[must_use]
    pub fn depends_on(&self, id: IndexId) -> bool {
        self.index_dependencies.contains(&id)
    }
}

impl fmt::Display for PhysicalPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.root.fmt(f)
    }
}

/// The bound a [`NodeIndexRangeSeek`](PhysicalOp::NodeIndexRangeSeek) uses for one side of a range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum RangeBound {
    /// `>` (strictly greater than the bound value).
    GreaterThan,
    /// `>=` (greater than or equal).
    GreaterOrEqual,
    /// `<` (strictly less than).
    LessThan,
    /// `<=` (less than or equal).
    LessOrEqual,
}

impl RangeBound {
    /// The bound implied by a comparison operator with the property on the **left**
    /// (`n.p <op> value`). Returns `None` for non-range operators.
    fn from_property_lhs(op: BinaryOp) -> Option<Self> {
        match op {
            BinaryOp::Gt => Some(Self::GreaterThan),
            BinaryOp::Gte => Some(Self::GreaterOrEqual),
            BinaryOp::Lt => Some(Self::LessThan),
            BinaryOp::Lte => Some(Self::LessOrEqual),
            _ => None,
        }
    }

    /// The symmetric bound when the property is on the **right** (`value <op> n.p`), i.e. the
    /// operator is mirrored.
    fn mirrored(self) -> Self {
        match self {
            Self::GreaterThan => Self::LessThan,
            Self::GreaterOrEqual => Self::LessOrEqual,
            Self::LessThan => Self::GreaterThan,
            Self::LessOrEqual => Self::GreaterOrEqual,
        }
    }

    /// The operator spelling for plan rendering.
    const fn symbol(self) -> &'static str {
        match self {
            Self::GreaterThan => ">",
            Self::GreaterOrEqual => ">=",
            Self::LessThan => "<",
            Self::LessOrEqual => "<=",
        }
    }
}

/// A node in a [physical plan](PhysicalPlan) tree: one executor-ready operator (`04 §7.1`).
///
/// The relational, graph, write, and procedure operators mirror their [logical
/// counterparts](crate::logical::LogicalOp) one-for-one (the executor needs them all); the
/// **physical specialisations** — index seeks, expand-into/all, hash/nested-loop join, top-n — are
/// the extra variants the physical planner introduces.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum PhysicalOp {
    // ---- leaf reads (physical access paths) ---------------------------------------------------
    /// Full all-nodes store scan (fallback for an unlabelled node, `04 §7.1`).
    AllNodesScan {
        /// The node variable bound by each row.
        variable: Var,
    },
    /// Label scan via a full store scan filtered by label (fallback when no token-lookup index
    /// exists for the label).
    NodeByLabelScan {
        /// The node variable bound by each row.
        variable: Var,
        /// The label scanned for.
        label: Label,
    },
    /// **Token-lookup index scan** for `MATCH (n:Label)` — a per-token range scan over the
    /// label/token-lookup index instead of a full store scan (`04 §6.2`).
    TokenLookupScan {
        /// The node variable bound by each row.
        variable: Var,
        /// The label served by the token-lookup index.
        label: Label,
        /// The catalog index backing the scan.
        index: IndexId,
    },
    /// **Index equality seek**: records of `label` whose `property` equals the seek expression
    /// (`04 §7.1` *"index seeks"*). The `value` expression is the unevaluated AST (literal or
    /// parameter), evaluated by the executor at run time.
    NodeIndexSeek {
        /// The node variable bound by each row.
        variable: Var,
        /// The label the index covers.
        label: Label,
        /// The indexed property key.
        property: String,
        /// The equality seek value (unevaluated AST; commonly a parameter after auto-parameterisation).
        value: Expr,
        /// The catalog index backing the seek.
        index: IndexId,
    },
    /// **Index range seek**: records of `label` whose `property` satisfies a range predicate
    /// (`04 §7.1`).
    NodeIndexRangeSeek {
        /// The node variable bound by each row.
        variable: Var,
        /// The label the index covers.
        label: Label,
        /// The indexed property key.
        property: String,
        /// The range bound operator (`>`, `>=`, `<`, `<=`).
        bound: RangeBound,
        /// The bound value expression (unevaluated AST).
        value: Expr,
        /// The catalog index backing the seek.
        index: IndexId,
    },
    /// Full relationship scan binding the relationship and its endpoints (carried through from the
    /// logical [`AllRelationshipsScan`](crate::logical::LogicalOp::AllRelationshipsScan)).
    AllRelationshipsScan {
        /// The relationship variable.
        relationship: Var,
        /// The source-endpoint variable.
        from: Var,
        /// The target-endpoint variable.
        to: Var,
        /// The arrow direction.
        direction: crate::ast::RelDirection,
        /// The relationship-type alternatives; empty means "any type".
        types: Vec<RelType>,
    },
    /// The single-row correlation argument of a join (carried through from
    /// [`Argument`](crate::logical::LogicalOp::Argument)).
    Argument {
        /// The variables provided by the enclosing join's left side.
        arguments: Vec<Var>,
    },
    /// A single empty row (carried through from [`Empty`](crate::logical::LogicalOp::Empty)).
    Empty,

    // ---- graph traversal (physical expand strategy) -------------------------------------------
    /// **Expand-all**: enumerate the neighbours of the bound `from`, binding `relationship` and the
    /// new `to` (`04 §7.1`).
    ExpandAll {
        /// The upstream relation (binds `from`).
        input: Box<PhysicalOp>,
        /// The bound anchor node to expand from.
        from: Var,
        /// The relationship variable bound by the traversal.
        relationship: Var,
        /// The far-endpoint variable bound by the traversal.
        to: Var,
        /// The traversal direction.
        direction: crate::ast::RelDirection,
        /// The relationship-type alternatives; empty means "any type".
        types: Vec<RelType>,
        /// The variable-length range, if any.
        range: Option<crate::ast::VarLengthRange>,
    },
    /// **Expand-into**: both endpoints are already bound; enumerate only the relationships
    /// **between** them (a connection / cycle check, `04 §7.1`).
    ExpandInto {
        /// The upstream relation (binds **both** `from` and `to`).
        input: Box<PhysicalOp>,
        /// The bound source endpoint.
        from: Var,
        /// The relationship variable bound by the traversal.
        relationship: Var,
        /// The bound target endpoint.
        to: Var,
        /// The traversal direction.
        direction: crate::ast::RelDirection,
        /// The relationship-type alternatives; empty means "any type".
        types: Vec<RelType>,
        /// The variable-length range, if any.
        range: Option<crate::ast::VarLengthRange>,
    },

    // ---- relational ---------------------------------------------------------------------------
    /// Keep rows whose `predicate` is `TRUE` (residual filter; three-valued logic, `04 §7.6`).
    Filter {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The residual predicate (unevaluated AST).
        predicate: Expr,
    },
    /// Project each row to a new tuple of named columns; `distinct` de-duplicates.
    Projection {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The projected columns, in result order.
        items: Vec<ProjectionColumn>,
        /// `true` for `DISTINCT`.
        distinct: bool,
    },
    /// Group by `group_keys` and compute `aggregates` per group.
    Aggregation {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The grouping-key columns; empty = single group.
        group_keys: Vec<ProjectionColumn>,
        /// The aggregate columns.
        aggregates: Vec<ProjectionColumn>,
    },
    /// Sort the input by `keys` (full sort; used when no adjacent `LIMIT` fuses it into a
    /// [`TopN`](Self::TopN)).
    Sort {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The sort keys, primary first.
        keys: Vec<SortKey>,
    },
    /// **Top-N**: the fused `Sort` + `Limit` — emit only the first `limit` rows in sort order
    /// (`04 §7.1` sort/limit). `limit` is the unevaluated AST limit expression.
    TopN {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The sort keys, primary first.
        keys: Vec<SortKey>,
        /// The number-of-rows-to-keep expression.
        limit: Expr,
    },
    /// Discard the first `count` rows (`SKIP`).
    Skip {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The number-of-rows-to-skip expression.
        count: Expr,
    },
    /// Keep at most `count` rows (`LIMIT`).
    Limit {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The maximum-row-count expression.
        count: Expr,
    },
    /// **Eager barrier**: drain `input` completely, then emit the buffered rows.
    ///
    /// Inserted by the planner between a [`Limit`](Self::Limit) and an input subtree containing a
    /// write operator, so the write side effects run to completion no matter how many rows the
    /// limit lets through. openCypher write clauses are *eager*: `LIMIT` bounds the **returned**
    /// rows, never the side effects — `CREATE (n) RETURN n LIMIT 0` must still create the node.
    Eager {
        /// The upstream relation, drained in full before any row is emitted.
        input: Box<PhysicalOp>,
    },
    /// Expand `list` into one row per element bound to `variable` (`UNWIND`).
    Unwind {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The list expression.
        list: Expr,
        /// The element variable.
        variable: Var,
    },
    /// Stream a CSV source, binding one row per record to `variable` (`LOAD CSV`).
    LoadCsv {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// Whether the first record names the columns (`WITH HEADERS`).
        with_headers: bool,
        /// The URL expression (a string at runtime).
        url: Expr,
        /// The record variable.
        variable: Var,
        /// The optional single-character field separator (defaults to `,`).
        field_terminator: Option<char>,
    },

    // ---- joins (physical join strategy) -------------------------------------------------------
    /// **Nested-loop join** / correlated apply: for each left row, evaluate the right branch with
    /// the left bindings available (`04 §7.1`). The only realisation for a *correlated* `Apply`
    /// (the right branch reads the left row through an [`Argument`](Self::Argument)).
    NestedLoopJoin {
        /// The left (driving) relation.
        left: Box<PhysicalOp>,
        /// The right (per-left-row) relation.
        right: Box<PhysicalOp>,
    },
    /// **Hash join**: build a hash table on the join keys of one side, probe with the other
    /// (`04 §7.1`). Chosen for an **equi-join** (shared join-key columns); see [`choose_join`].
    HashJoin {
        /// The build (left) relation.
        left: Box<PhysicalOp>,
        /// The probe (right) relation.
        right: Box<PhysicalOp>,
        /// The column names joined on (present on both sides), ascending.
        join_keys: Vec<String>,
    },
    /// Combine two branches, optionally de-duplicating (`UNION` / `UNION ALL`).
    Union {
        /// The left branch.
        left: Box<PhysicalOp>,
        /// The right branch.
        right: Box<PhysicalOp>,
        /// `true` for `UNION ALL` (keep duplicates).
        all: bool,
    },
    /// Left-outer guarantee for `OPTIONAL MATCH`: at least one row per drive, null-filling
    /// `null_variables` on the no-match path.
    Optional {
        /// The optional subplan.
        input: Box<PhysicalOp>,
        /// The variables null-filled when `input` is empty.
        null_variables: Vec<Var>,
    },

    // ---- write --------------------------------------------------------------------------------
    /// Create the `pattern` once per input row (`CREATE`).
    Create {
        /// The driving relation.
        input: Box<PhysicalOp>,
        /// The entities to create.
        pattern: Vec<CreatePart>,
    },
    /// Match-or-create `pattern`, running the create/match side-effects (`MERGE`).
    Merge {
        /// The driving relation.
        input: Box<PhysicalOp>,
        /// The single pattern to match-or-create.
        pattern: Vec<CreatePart>,
        /// `ON CREATE SET` actions.
        on_create: Vec<SetOp>,
        /// `ON MATCH SET` actions.
        on_match: Vec<SetOp>,
    },
    /// Apply property/label mutations to bound entities (`SET`).
    SetClause {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The mutations, in source order.
        ops: Vec<SetOp>,
    },
    /// Delete the entities identified by `exprs` (`[DETACH] DELETE`).
    Delete {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// `true` for `DETACH DELETE`.
        detach: bool,
        /// The entity-reference expressions.
        exprs: Vec<Expr>,
    },
    /// Remove labels/properties from bound entities (`REMOVE`).
    Remove {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The removals, in source order.
        ops: Vec<RemoveOp>,
    },

    // ---- procedure ----------------------------------------------------------------------------
    /// Invoke a procedure, binding the `yields` columns (`CALL … YIELD`).
    ProcedureCall {
        /// The upstream relation when correlated; `None` for a leading call.
        input: Option<Box<PhysicalOp>>,
        /// The dotted procedure name.
        name: Vec<String>,
        /// The argument expressions; `None` for the implicit form.
        args: Option<Vec<Expr>>,
        /// The `YIELD` columns; `None` when there is no `YIELD`.
        yields: Option<Vec<YieldColumn>>,
    },
}

/// Lowers a [logical plan](LogicalOp) into a [`PhysicalPlan`], consulting `catalog` for index-aware
/// access-path selection (`04 §7.1`, §6.6).
///
/// This is the physical planner's entry point. It is **total and infallible** — like the logical
/// planner ([`crate::lower`]), it transforms an already-validated plan and makes only sound,
/// rule-based strategy choices, never re-checking compile-time invariants. The returned plan records
/// every catalog [`IndexId`] it depends on (`04 §6.6`).
///
/// # Examples
///
/// ```
/// use graphus_cypher::{catalog::IndexCatalog, lexer::tokenize, lower::lower, parser::parse_tokens,
///     physical::plan_physical, semantics::analyze};
///
/// let catalog = IndexCatalog::builder().with_label_property("Person", "name").build();
/// let toks = tokenize("MATCH (n:Person {name: 'Ada'}) RETURN n").unwrap();
/// let ast = parse_tokens(&toks, "MATCH (n:Person {name: 'Ada'}) RETURN n").unwrap();
/// let validated = analyze(&ast).unwrap();
/// let logical = lower(&validated);
/// let physical = plan_physical(&logical, &catalog);
/// // The equality on the indexed `name` property became an index seek.
/// assert!(physical.to_string().contains("NodeIndexSeek"));
/// // … and the plan records its dependency on the index.
/// assert_eq!(physical.index_dependencies().count(), 1);
/// ```
pub fn plan_physical(logical: &LogicalOp, catalog: &IndexCatalog) -> PhysicalPlan {
    let mut deps = BTreeSet::new();
    let root = Planner { catalog }.lower(logical, &mut deps);
    PhysicalPlan {
        root,
        index_dependencies: deps,
    }
}

/// The physical-planning driver, borrowing the catalog for the duration of one compilation.
struct Planner<'c> {
    catalog: &'c IndexCatalog,
}

impl Planner<'_> {
    /// Lowers one logical operator to its physical form, recording index dependencies into `deps`.
    fn lower(&self, op: &LogicalOp, deps: &mut BTreeSet<IndexId>) -> PhysicalOp {
        match op {
            // ---- leaf reads: index-aware selection -------------------------------------------
            LogicalOp::AllNodesScan { variable } => PhysicalOp::AllNodesScan {
                variable: variable.clone(),
            },
            LogicalOp::NodeByLabelScan { variable, label } => {
                self.lower_label_scan(variable, label, deps)
            }
            LogicalOp::AllRelationshipsScan {
                relationship,
                from,
                to,
                direction,
                types,
            } => PhysicalOp::AllRelationshipsScan {
                relationship: relationship.clone(),
                from: from.clone(),
                to: to.clone(),
                direction: *direction,
                types: types.clone(),
            },
            LogicalOp::Argument { arguments } => PhysicalOp::Argument {
                arguments: arguments.clone(),
            },
            LogicalOp::Empty => PhysicalOp::Empty,

            // ---- Filter: the index-selection trigger -----------------------------------------
            LogicalOp::Filter { input, predicate } => self.lower_filter(input, predicate, deps),

            // ---- Expand: into vs all ---------------------------------------------------------
            LogicalOp::Expand {
                input,
                from,
                relationship,
                to,
                direction,
                types,
                range,
            } => {
                let phys_input = self.lower(input, deps);
                // Expand-into iff BOTH endpoints are already bound by the input.
                let bound = bound_vars(&phys_input);
                let both_bound = bound.iter().any(|v| v.name == from.name)
                    && bound.iter().any(|v| v.name == to.name);
                let input = Box::new(phys_input);
                if both_bound {
                    PhysicalOp::ExpandInto {
                        input,
                        from: from.clone(),
                        relationship: relationship.clone(),
                        to: to.clone(),
                        direction: *direction,
                        types: types.clone(),
                        range: *range,
                    }
                } else {
                    PhysicalOp::ExpandAll {
                        input,
                        from: from.clone(),
                        relationship: relationship.clone(),
                        to: to.clone(),
                        direction: *direction,
                        types: types.clone(),
                        range: *range,
                    }
                }
            }

            // ---- relational ------------------------------------------------------------------
            LogicalOp::Projection {
                input,
                items,
                distinct,
            } => PhysicalOp::Projection {
                input: Box::new(self.lower(input, deps)),
                items: items.clone(),
                distinct: *distinct,
            },
            LogicalOp::Aggregation {
                input,
                group_keys,
                aggregates,
            } => PhysicalOp::Aggregation {
                input: Box::new(self.lower(input, deps)),
                group_keys: group_keys.clone(),
                aggregates: aggregates.clone(),
            },
            LogicalOp::Sort { input, keys } => PhysicalOp::Sort {
                input: Box::new(self.lower(input, deps)),
                keys: keys.clone(),
            },
            LogicalOp::Skip { input, count } => PhysicalOp::Skip {
                input: Box::new(self.lower(input, deps)),
                count: count.clone(),
            },
            LogicalOp::Limit { input, count } => self.lower_limit(input, count, deps),
            LogicalOp::Unwind {
                input,
                list,
                variable,
            } => PhysicalOp::Unwind {
                input: Box::new(self.lower(input, deps)),
                list: list.clone(),
                variable: variable.clone(),
            },
            LogicalOp::LoadCsv {
                input,
                with_headers,
                url,
                variable,
                field_terminator,
            } => PhysicalOp::LoadCsv {
                input: Box::new(self.lower(input, deps)),
                with_headers: *with_headers,
                url: url.clone(),
                variable: variable.clone(),
                field_terminator: *field_terminator,
            },

            // ---- joins: hash vs nested-loop --------------------------------------------------
            LogicalOp::Apply { left, right } => {
                let phys_left = self.lower(left, deps);
                let phys_right = self.lower(right, deps);
                choose_join(phys_left, phys_right, right)
            }
            LogicalOp::Optional {
                input,
                null_variables,
            } => PhysicalOp::Optional {
                input: Box::new(self.lower(input, deps)),
                null_variables: null_variables.clone(),
            },
            LogicalOp::Union { left, right, all } => PhysicalOp::Union {
                left: Box::new(self.lower(left, deps)),
                right: Box::new(self.lower(right, deps)),
                all: *all,
            },

            // ---- write -----------------------------------------------------------------------
            LogicalOp::Create { input, pattern } => PhysicalOp::Create {
                input: Box::new(self.lower(input, deps)),
                pattern: pattern.clone(),
            },
            LogicalOp::Merge {
                input,
                pattern,
                on_create,
                on_match,
            } => PhysicalOp::Merge {
                input: Box::new(self.lower(input, deps)),
                pattern: pattern.clone(),
                on_create: on_create.clone(),
                on_match: on_match.clone(),
            },
            LogicalOp::SetClause { input, ops } => PhysicalOp::SetClause {
                input: Box::new(self.lower(input, deps)),
                ops: ops.clone(),
            },
            LogicalOp::Delete {
                input,
                detach,
                exprs,
            } => PhysicalOp::Delete {
                input: Box::new(self.lower(input, deps)),
                detach: *detach,
                exprs: exprs.clone(),
            },
            LogicalOp::Remove { input, ops } => PhysicalOp::Remove {
                input: Box::new(self.lower(input, deps)),
                ops: ops.clone(),
            },

            // ---- procedure -------------------------------------------------------------------
            LogicalOp::ProcedureCall {
                input,
                name,
                args,
                yields,
            } => PhysicalOp::ProcedureCall {
                input: input.as_ref().map(|i| Box::new(self.lower(i, deps))),
                name: name.clone(),
                args: args.clone(),
                yields: yields.clone(),
            },
        }
    }

    /// Lowers a bare label scan: a token-lookup index scan when the catalog has one, else a label
    /// store scan (`04 §6.2`/§6.6).
    fn lower_label_scan(
        &self,
        variable: &Var,
        label: &Label,
        deps: &mut BTreeSet<IndexId>,
    ) -> PhysicalOp {
        if let Some(idx) = self.catalog.token_lookup(label) {
            deps.insert(idx.id);
            PhysicalOp::TokenLookupScan {
                variable: variable.clone(),
                label: label.clone(),
                index: idx.id,
            }
        } else {
            PhysicalOp::NodeByLabelScan {
                variable: variable.clone(),
                label: label.clone(),
            }
        }
    }

    /// Lowers a `Filter` over its input, attempting index selection when the filter sits directly
    /// over a label scan and its predicate is an index-usable single-property predicate.
    ///
    /// The predicate is decomposed at top-level `AND`s into conjuncts; the planner tries to consume
    /// **one** conjunct into an index seek (the strongest available) and re-attaches the rest as a
    /// residual [`Filter`](PhysicalOp::Filter). When the input is not a directly-indexable label
    /// scan, or no conjunct matches an index, the whole predicate stays a residual filter over the
    /// physically-lowered input.
    fn lower_filter(
        &self,
        input: &LogicalOp,
        predicate: &Expr,
        deps: &mut BTreeSet<IndexId>,
    ) -> PhysicalOp {
        // Index selection only fires directly over a label scan (the logical anchor of a labelled
        // node). Anything else: lower the input normally and keep the predicate as a residual filter.
        let LogicalOp::NodeByLabelScan { variable, label } = input else {
            return PhysicalOp::Filter {
                input: Box::new(self.lower(input, deps)),
                predicate: predicate.clone(),
            };
        };

        let conjuncts = split_conjuncts(predicate);
        // Find the first conjunct that names an index-usable predicate on this variable+label.
        for (i, conj) in conjuncts.iter().enumerate() {
            if let Some(pp) = analyze_property_predicate(conj, &variable.name) {
                if let Some(idx) = self.match_index(label, &pp) {
                    deps.insert(idx.id);
                    let seek = build_seek(variable, label, &pp, idx.id);
                    // Re-attach the remaining conjuncts (all but the consumed one) as a residual
                    // filter, preserving their order.
                    let residual: Vec<&Expr> = conjuncts
                        .iter()
                        .enumerate()
                        .filter(|(j, _)| *j != i)
                        .map(|(_, e)| *e)
                        .collect();
                    return attach_residual(seek, &residual);
                }
            }
        }

        // No index applied: label scan (possibly token-lookup) + the full predicate as a filter.
        let scan = self.lower_label_scan(variable, label, deps);
        PhysicalOp::Filter {
            input: Box::new(scan),
            predicate: predicate.clone(),
        }
    }

    /// The catalog index that serves `pp` on `label`, if any (equality/range → property/composite).
    fn match_index<'a>(
        &'a self,
        label: &Label,
        pp: &PropertyPredicate,
    ) -> Option<&'a IndexDescriptor> {
        // Both equality and range predicates on a single property are served by a property index
        // (or a composite whose leading key matches), per the catalog's `label_property` contract.
        self.catalog.label_property(label, &pp.property)
    }

    /// Lowers a `Limit`: fuse a `Limit(Sort)` into [`TopN`](PhysicalOp::TopN), or push a `Limit`
    /// below a row-count-preserving projection; otherwise a plain [`Limit`](PhysicalOp::Limit).
    ///
    /// **Eager-write barrier.** openCypher write clauses are eager: `LIMIT` bounds the returned
    /// rows, never the side effects (`CREATE (n) RETURN n LIMIT 0` still creates the node). A
    /// `Limit` operator stops pulling from its input once satisfied, which would suppress upstream
    /// writes — so when the limited subtree contains a write operator it is wrapped in an
    /// [`Eager`](PhysicalOp::Eager) barrier that drains it in full first. `TopN` needs no barrier:
    /// sorting already consumes its whole input.
    fn lower_limit(
        &self,
        input: &LogicalOp,
        count: &Expr,
        deps: &mut BTreeSet<IndexId>,
    ) -> PhysicalOp {
        match input {
            // Limit directly over a Sort -> Top-N (compute only the top k rows). Sound by
            // definition: TopN(k, sort) == Limit(k, Sort(sort)).
            LogicalOp::Sort {
                input: sort_input,
                keys,
            } => PhysicalOp::TopN {
                input: Box::new(self.lower(sort_input, deps)),
                keys: keys.clone(),
                limit: count.clone(),
            },
            // Limit over a row-count-preserving projection (no DISTINCT, no aggregation) -> push the
            // limit BELOW the projection. Sound: a 1:1 projection neither drops nor adds rows, so the
            // first k rows are the same before and after projecting.
            LogicalOp::Projection {
                input: proj_input,
                items,
                distinct: false,
            } => {
                let pushed = PhysicalOp::Limit {
                    input: Box::new(eager_over_writes(self.lower(proj_input, deps))),
                    count: count.clone(),
                };
                PhysicalOp::Projection {
                    input: Box::new(pushed),
                    items: items.clone(),
                    distinct: false,
                }
            }
            // Any other input (incl. DISTINCT projection / Aggregation): plain Limit, NOT pushed —
            // pushing below a row-count-changing operator would change the result.
            other => PhysicalOp::Limit {
                input: Box::new(eager_over_writes(self.lower(other, deps))),
                count: count.clone(),
            },
        }
    }
}

/// Wraps `input` in an [`Eager`](PhysicalOp::Eager) barrier when its subtree contains a write
/// operator, so a `Limit` above cannot suppress the writes (see [`Planner::lower_limit`]).
fn eager_over_writes(input: PhysicalOp) -> PhysicalOp {
    if contains_write(&input) {
        PhysicalOp::Eager {
            input: Box::new(input),
        }
    } else {
        input
    }
}

/// Whether the physical (sub)plan contains a write operator
/// (`Create`/`Merge`/`SetClause`/`Delete`/`Remove`) anywhere.
fn contains_write(op: &PhysicalOp) -> bool {
    match op {
        PhysicalOp::Create { .. }
        | PhysicalOp::Merge { .. }
        | PhysicalOp::SetClause { .. }
        | PhysicalOp::Delete { .. }
        | PhysicalOp::Remove { .. } => true,
        PhysicalOp::Filter { input, .. }
        | PhysicalOp::Projection { input, .. }
        | PhysicalOp::Aggregation { input, .. }
        | PhysicalOp::Sort { input, .. }
        | PhysicalOp::TopN { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Eager { input }
        | PhysicalOp::Unwind { input, .. }
        | PhysicalOp::LoadCsv { input, .. }
        | PhysicalOp::ExpandAll { input, .. }
        | PhysicalOp::ExpandInto { input, .. }
        | PhysicalOp::Optional { input, .. } => contains_write(input),
        PhysicalOp::NestedLoopJoin { left, right }
        | PhysicalOp::HashJoin { left, right, .. }
        | PhysicalOp::Union { left, right, .. } => contains_write(left) || contains_write(right),
        PhysicalOp::ProcedureCall { input, .. } => input.as_deref().is_some_and(contains_write),
        PhysicalOp::AllNodesScan { .. }
        | PhysicalOp::NodeByLabelScan { .. }
        | PhysicalOp::TokenLookupScan { .. }
        | PhysicalOp::NodeIndexSeek { .. }
        | PhysicalOp::NodeIndexRangeSeek { .. }
        | PhysicalOp::AllRelationshipsScan { .. }
        | PhysicalOp::Argument { .. }
        | PhysicalOp::Empty => false,
    }
}

/// Chooses the physical join for a logical [`Apply`](LogicalOp::Apply): hash join for an equi-join,
/// else nested-loop (`04 §7.1`).
///
/// **The rule (documented and rule-based, cost is Phase 2):**
///
/// - If the right branch is **correlated** — it reads the left row's bindings through an
///   [`Argument`](LogicalOp::Argument) leaf — only a [`NestedLoopJoin`](PhysicalOp::NestedLoopJoin)
///   can express the per-left-row evaluation (a hash join has no place to feed the correlation).
///   This is the common shape the logical planner emits for `OPTIONAL MATCH`, correlated `CALL`,
///   and comma-pattern components ([`crate::lower`]).
/// - Otherwise the two branches are **independent** and joined on the columns they **share by
///   name** (an equi-join on those keys). With at least one shared key, a
///   [`HashJoin`](PhysicalOp::HashJoin) on those keys is chosen; with **no** shared key (a cartesian
///   product) a [`NestedLoopJoin`](PhysicalOp::NestedLoopJoin) is the realisation.
///
/// **Soundness:** every branch computes the same row set regardless of strategy; hash vs nested-loop
/// is purely a performance decision.
pub fn choose_join(left: PhysicalOp, right: PhysicalOp, logical_right: &LogicalOp) -> PhysicalOp {
    if logical_op_is_correlated(logical_right) {
        return PhysicalOp::NestedLoopJoin {
            left: Box::new(left),
            right: Box::new(right),
        };
    }
    let left_cols = bound_var_names(&left);
    let right_cols = bound_var_names(&right);
    let join_keys: Vec<String> = left_cols
        .iter()
        .filter(|c| right_cols.contains(*c))
        .cloned()
        .collect();
    if join_keys.is_empty() {
        PhysicalOp::NestedLoopJoin {
            left: Box::new(left),
            right: Box::new(right),
        }
    } else {
        PhysicalOp::HashJoin {
            left: Box::new(left),
            right: Box::new(right),
            join_keys,
        }
    }
}

/// Whether a logical (sub)plan reads correlated bindings — i.e. it roots at, or contains on its
/// leftmost spine, an [`Argument`](LogicalOp::Argument) leaf. Such a branch must be nested-loop
/// joined (the [`Argument`](LogicalOp::Argument) is fed one left row at a time).
fn logical_op_is_correlated(op: &LogicalOp) -> bool {
    match op {
        LogicalOp::Argument { .. } => true,
        LogicalOp::Optional { input, .. }
        | LogicalOp::Filter { input, .. }
        | LogicalOp::Projection { input, .. }
        | LogicalOp::Aggregation { input, .. }
        | LogicalOp::Sort { input, .. }
        | LogicalOp::Skip { input, .. }
        | LogicalOp::Limit { input, .. }
        | LogicalOp::Unwind { input, .. }
        | LogicalOp::LoadCsv { input, .. }
        | LogicalOp::Expand { input, .. }
        | LogicalOp::Create { input, .. }
        | LogicalOp::Merge { input, .. }
        | LogicalOp::SetClause { input, .. }
        | LogicalOp::Delete { input, .. }
        | LogicalOp::Remove { input, .. } => logical_op_is_correlated(input),
        LogicalOp::ProcedureCall { input, .. } => {
            input.as_deref().is_some_and(logical_op_is_correlated)
        }
        // A binary operator is correlated if either side is (the correlation can sit in either).
        LogicalOp::Apply { left, right } | LogicalOp::Union { left, right, .. } => {
            logical_op_is_correlated(left) || logical_op_is_correlated(right)
        }
        _ => false,
    }
}

// =================================================================================================
// Predicate analysis for index selection
// =================================================================================================

/// One index-usable single-property predicate extracted from a filter conjunct.
#[derive(Debug, Clone, PartialEq)]
struct PropertyPredicate {
    /// The property key (`p` in `n.p`).
    property: String,
    /// What kind of predicate it is.
    kind: PropertyPredicateKind,
}

#[derive(Debug, Clone, PartialEq)]
enum PropertyPredicateKind {
    /// `n.p = value` (equality seek).
    Equality { value: Expr },
    /// `n.p <op> value` for a comparison op (range seek). `bound` already accounts for the side the
    /// property appeared on.
    Range { bound: RangeBound, value: Expr },
}

/// Analyses a single conjunct: does it constrain `variable.<prop>` against a value, in a form an
/// index can serve? Returns the property and predicate kind, or `None`.
///
/// Recognised forms (with the property on either side of a comparison):
/// - `var.prop = value` and `value = var.prop` → equality.
/// - `var.prop <op> value` / `value <op> var.prop` for `<`, `>`, `<=`, `>=` → range.
///
/// The `value` side must **not** itself reference the same `variable` (an index seek needs a value
/// independent of the row being produced); a literal or parameter is the common case.
fn analyze_property_predicate(expr: &Expr, variable: &str) -> Option<PropertyPredicate> {
    let ExprKind::Binary { op, lhs, rhs } = &expr.kind else {
        return None;
    };

    // Property on the left: `var.prop <op> value`.
    if let Some(prop) = property_of(lhs, variable) {
        if !expr_references_var(rhs, variable) {
            return predicate_from(*op, prop, rhs, false);
        }
    }
    // Property on the right: `value <op> var.prop`.
    if let Some(prop) = property_of(rhs, variable) {
        if !expr_references_var(lhs, variable) {
            return predicate_from(*op, prop, lhs, true);
        }
    }
    None
}

/// Builds a [`PropertyPredicate`] from a comparison operator. `property_on_right` mirrors range
/// bounds (so `value < n.p` becomes `n.p > value`).
fn predicate_from(
    op: BinaryOp,
    property: String,
    value: &Expr,
    property_on_right: bool,
) -> Option<PropertyPredicate> {
    match op {
        BinaryOp::Eq => Some(PropertyPredicate {
            property,
            kind: PropertyPredicateKind::Equality {
                value: value.clone(),
            },
        }),
        BinaryOp::Gt | BinaryOp::Gte | BinaryOp::Lt | BinaryOp::Lte => {
            let mut bound = RangeBound::from_property_lhs(op)?;
            if property_on_right {
                bound = bound.mirrored();
            }
            Some(PropertyPredicate {
                property,
                kind: PropertyPredicateKind::Range {
                    bound,
                    value: value.clone(),
                },
            })
        }
        _ => None,
    }
}

/// If `expr` is exactly `variable.key`, returns `key`.
fn property_of(expr: &Expr, variable: &str) -> Option<String> {
    if let ExprKind::Property { base, key } = &expr.kind {
        if let ExprKind::Variable(name) = &base.kind {
            if name == variable {
                return Some(key.clone());
            }
        }
    }
    None
}

/// Whether `expr` references the variable `variable` anywhere (used to reject a seek value that
/// depends on the row being produced).
fn expr_references_var(expr: &Expr, variable: &str) -> bool {
    match &expr.kind {
        ExprKind::Variable(name) => name == variable,
        ExprKind::Literal(_) | ExprKind::Parameter(_) | ExprKind::CountStar => false,
        ExprKind::Binary { lhs, rhs, .. } => {
            expr_references_var(lhs, variable) || expr_references_var(rhs, variable)
        }
        ExprKind::Unary { operand, .. } | ExprKind::HasLabels { operand, .. } => {
            expr_references_var(operand, variable)
        }
        ExprKind::Predicate { operand, rhs, .. } => {
            expr_references_var(operand, variable)
                || rhs
                    .as_deref()
                    .is_some_and(|r| expr_references_var(r, variable))
        }
        ExprKind::Property { base, .. } => expr_references_var(base, variable),
        ExprKind::Index { base, index } => {
            expr_references_var(base, variable) || expr_references_var(index, variable)
        }
        ExprKind::Slice { base, low, high } => {
            expr_references_var(base, variable)
                || low
                    .as_deref()
                    .is_some_and(|l| expr_references_var(l, variable))
                || high
                    .as_deref()
                    .is_some_and(|h| expr_references_var(h, variable))
        }
        ExprKind::FunctionCall { args, .. } => {
            args.iter().any(|a| expr_references_var(a, variable))
        }
        ExprKind::List(items) => items.iter().any(|i| expr_references_var(i, variable)),
        ExprKind::Map(entries) => entries
            .iter()
            .any(|(_, v)| expr_references_var(v, variable)),
        ExprKind::Case(case) => {
            case.subject
                .as_deref()
                .is_some_and(|s| expr_references_var(s, variable))
                || case.alternatives.iter().any(|alt| {
                    expr_references_var(&alt.when, variable)
                        || expr_references_var(&alt.then, variable)
                })
                || case
                    .else_expr
                    .as_deref()
                    .is_some_and(|e| expr_references_var(e, variable))
        }
        // Comprehensions, quantifiers and existential subqueries establish their own scope;
        // conservatively treat them as referencing the variable so a seek is never built on a
        // value that might shadow/close over it.
        ExprKind::ListComprehension(_)
        | ExprKind::PatternComprehension(_)
        | ExprKind::Quantifier(_)
        | ExprKind::ExistsSubquery(_) => true,
    }
}

/// Builds the physical seek operator for a matched [`PropertyPredicate`].
fn build_seek(variable: &Var, label: &Label, pp: &PropertyPredicate, index: IndexId) -> PhysicalOp {
    match &pp.kind {
        PropertyPredicateKind::Equality { value } => PhysicalOp::NodeIndexSeek {
            variable: variable.clone(),
            label: label.clone(),
            property: pp.property.clone(),
            value: value.clone(),
            index,
        },
        PropertyPredicateKind::Range { bound, value } => PhysicalOp::NodeIndexRangeSeek {
            variable: variable.clone(),
            label: label.clone(),
            property: pp.property.clone(),
            bound: *bound,
            value: value.clone(),
            index,
        },
    }
}

/// Re-attaches the residual conjuncts (everything not consumed by a seek) as a single
/// [`Filter`](PhysicalOp::Filter) above `base`, AND-ing them in order. An empty residual leaves
/// `base` bare.
fn attach_residual(base: PhysicalOp, residual: &[&Expr]) -> PhysicalOp {
    let Some((first, rest)) = residual.split_first() else {
        return base;
    };
    let mut combined = (*first).clone();
    for e in rest {
        let span = crate::lexer::Span::new(combined.span.start, e.span.end);
        combined = Expr::new(
            ExprKind::Binary {
                op: BinaryOp::And,
                lhs: Box::new(combined),
                rhs: Box::new((*e).clone()),
            },
            span,
        );
    }
    PhysicalOp::Filter {
        input: Box::new(base),
        predicate: combined,
    }
}

/// Splits a predicate into its top-level `AND` conjuncts (left-to-right). A non-`AND` expression is
/// a single conjunct. The flattening lets the planner consume one conjunct into an index seek and
/// retain the rest as a residual filter.
fn split_conjuncts(expr: &Expr) -> Vec<&Expr> {
    let mut out = Vec::new();
    collect_conjuncts(expr, &mut out);
    out
}

fn collect_conjuncts<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    if let ExprKind::Binary {
        op: BinaryOp::And,
        lhs,
        rhs,
    } = &expr.kind
    {
        collect_conjuncts(lhs, out);
        collect_conjuncts(rhs, out);
    } else {
        out.push(expr);
    }
}

// =================================================================================================
// Bound-variable analysis (for expand-into and join-key inference)
// =================================================================================================

/// Collects the variables a physical (sub)plan binds, in introduction order, de-duplicated by name.
///
/// Mirrors the logical planner's `collect_bound_vars` ([`crate::lower`]) over the physical operator
/// set: scans/expands/unwind introduce variables; projections/aggregations **reset** the visible set
/// to their output columns (the projection-boundary rule, `04 §7.3`).
fn bound_vars(plan: &PhysicalOp) -> Vec<Var> {
    let mut out = Vec::new();
    gather_bound_vars(plan, &mut out);
    out
}

/// The names of the variables a physical (sub)plan binds.
fn bound_var_names(plan: &PhysicalOp) -> Vec<String> {
    bound_vars(plan).into_iter().map(|v| v.name).collect()
}

fn push_unique(out: &mut Vec<Var>, var: Var) {
    if !out.iter().any(|v| v.name == var.name) {
        out.push(var);
    }
}

fn gather_bound_vars(plan: &PhysicalOp, out: &mut Vec<Var>) {
    match plan {
        PhysicalOp::AllNodesScan { variable }
        | PhysicalOp::NodeByLabelScan { variable, .. }
        | PhysicalOp::TokenLookupScan { variable, .. }
        | PhysicalOp::NodeIndexSeek { variable, .. }
        | PhysicalOp::NodeIndexRangeSeek { variable, .. } => push_unique(out, variable.clone()),
        PhysicalOp::AllRelationshipsScan {
            relationship,
            from,
            to,
            ..
        } => {
            push_unique(out, from.clone());
            push_unique(out, relationship.clone());
            push_unique(out, to.clone());
        }
        PhysicalOp::Argument { arguments } => {
            for a in arguments {
                push_unique(out, a.clone());
            }
        }
        PhysicalOp::Empty => {}
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
            gather_bound_vars(input, out);
            push_unique(out, relationship.clone());
            push_unique(out, to.clone());
        }
        PhysicalOp::Filter { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Eager { input }
        | PhysicalOp::Sort { input, .. } => gather_bound_vars(input, out),
        PhysicalOp::TopN { input, .. } => gather_bound_vars(input, out),
        PhysicalOp::Unwind {
            input, variable, ..
        }
        | PhysicalOp::LoadCsv {
            input, variable, ..
        } => {
            gather_bound_vars(input, out);
            push_unique(out, variable.clone());
        }
        PhysicalOp::Projection { items, .. } => {
            out.clear();
            for col in items {
                push_unique(out, Var::named(&col.alias));
            }
        }
        PhysicalOp::Aggregation {
            group_keys,
            aggregates,
            ..
        } => {
            out.clear();
            for col in group_keys.iter().chain(aggregates) {
                push_unique(out, Var::named(&col.alias));
            }
        }
        PhysicalOp::NestedLoopJoin { left, right } | PhysicalOp::HashJoin { left, right, .. } => {
            gather_bound_vars(left, out);
            gather_bound_vars(right, out);
        }
        PhysicalOp::Optional {
            input,
            null_variables,
        } => {
            gather_bound_vars(input, out);
            for v in null_variables {
                push_unique(out, v.clone());
            }
        }
        PhysicalOp::Union { left, .. } => gather_bound_vars(left, out),
        PhysicalOp::Create { input, pattern } | PhysicalOp::Merge { input, pattern, .. } => {
            gather_bound_vars(input, out);
            for part in pattern {
                match part {
                    CreatePart::Node { variable, .. }
                    | CreatePart::Relationship { variable, .. } => {
                        push_unique(out, variable.clone())
                    }
                }
            }
        }
        PhysicalOp::SetClause { input, .. }
        | PhysicalOp::Delete { input, .. }
        | PhysicalOp::Remove { input, .. } => gather_bound_vars(input, out),
        PhysicalOp::ProcedureCall { input, yields, .. } => {
            if let Some(input) = input {
                gather_bound_vars(input, out);
            }
            if let Some(yields) = yields {
                for y in yields {
                    push_unique(out, y.variable.clone());
                }
            }
        }
    }
}

// =================================================================================================
// Pretty-printer (diagnostics + golden tests, matching the logical Display style)
// =================================================================================================

impl fmt::Display for PhysicalOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_indented(f, 0)
    }
}

impl PhysicalOp {
    /// Recursive [`Display`] worker: header at `depth`, then inputs at `depth + 1`. Mirrors the
    /// logical [`Display`](crate::logical::LogicalOp) layout so the two read alike.
    fn fmt_indented(&self, f: &mut fmt::Formatter<'_>, depth: usize) -> fmt::Result {
        use crate::logical::display_helpers as h;
        for _ in 0..depth {
            f.write_str("  ")?;
        }
        match self {
            Self::AllNodesScan { variable } => writeln!(f, "AllNodesScan({variable})"),
            Self::NodeByLabelScan { variable, label } => {
                writeln!(f, "NodeByLabelScan({variable}:{})", label.name)
            }
            Self::TokenLookupScan {
                variable,
                label,
                index,
            } => writeln!(f, "TokenLookupScan({variable}:{} via {index})", label.name),
            Self::NodeIndexSeek {
                variable,
                label,
                property,
                value,
                index,
            } => writeln!(
                f,
                "NodeIndexSeek({variable}:{} {property} = {} via {index})",
                label.name,
                h::expr(value),
            ),
            Self::NodeIndexRangeSeek {
                variable,
                label,
                property,
                bound,
                value,
                index,
            } => writeln!(
                f,
                "NodeIndexRangeSeek({variable}:{} {property} {} {} via {index})",
                label.name,
                bound.symbol(),
                h::expr(value),
            ),
            Self::AllRelationshipsScan {
                relationship,
                from,
                to,
                direction,
                types,
            } => writeln!(
                f,
                "AllRelationshipsScan({}{relationship}{}{to} from {from}{})",
                h::arrow_left(*direction),
                h::arrow_right(*direction),
                h::types(types),
            ),
            Self::Argument { arguments } => writeln!(f, "Argument({})", h::vars(arguments)),
            Self::Empty => writeln!(f, "Empty"),

            Self::ExpandAll {
                input,
                from,
                relationship,
                to,
                direction,
                types,
                range,
            } => {
                writeln!(
                    f,
                    "ExpandAll({from}){}{relationship}{}{}{}({to})",
                    h::arrow_left(*direction),
                    h::types(types),
                    h::range(range),
                    h::arrow_right(*direction),
                )?;
                input.fmt_indented(f, depth + 1)
            }
            Self::ExpandInto {
                input,
                from,
                relationship,
                to,
                direction,
                types,
                range,
            } => {
                writeln!(
                    f,
                    "ExpandInto({from}){}{relationship}{}{}{}({to})",
                    h::arrow_left(*direction),
                    h::types(types),
                    h::range(range),
                    h::arrow_right(*direction),
                )?;
                input.fmt_indented(f, depth + 1)
            }

            Self::Filter { input, predicate } => {
                writeln!(f, "Filter({})", h::expr(predicate))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Projection {
                input,
                items,
                distinct,
            } => {
                writeln!(
                    f,
                    "Projection{}({})",
                    if *distinct { " DISTINCT" } else { "" },
                    h::columns(items),
                )?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Aggregation {
                input,
                group_keys,
                aggregates,
            } => {
                writeln!(
                    f,
                    "Aggregation(keys=[{}], aggs=[{}])",
                    h::columns(group_keys),
                    h::columns(aggregates),
                )?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Sort { input, keys } => {
                writeln!(f, "Sort({})", h::sort_keys(keys))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::TopN { input, keys, limit } => {
                writeln!(f, "TopN({} LIMIT {})", h::sort_keys(keys), h::expr(limit))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Skip { input, count } => {
                writeln!(f, "Skip({})", h::expr(count))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Limit { input, count } => {
                writeln!(f, "Limit({})", h::expr(count))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Eager { input } => {
                writeln!(f, "Eager")?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Unwind {
                input,
                list,
                variable,
            } => {
                writeln!(f, "Unwind({} AS {variable})", h::expr(list))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::LoadCsv {
                input,
                with_headers,
                url,
                variable,
                field_terminator,
            } => {
                let headers = if *with_headers { " WITH HEADERS" } else { "" };
                let term = field_terminator
                    .map(|c| format!(" FIELDTERMINATOR {c:?}"))
                    .unwrap_or_default();
                writeln!(
                    f,
                    "LoadCsv({headers} FROM {} AS {variable}{term})",
                    h::expr(url)
                )?;
                input.fmt_indented(f, depth + 1)
            }

            Self::NestedLoopJoin { left, right } => {
                writeln!(f, "NestedLoopJoin")?;
                left.fmt_indented(f, depth + 1)?;
                right.fmt_indented(f, depth + 1)
            }
            Self::HashJoin {
                left,
                right,
                join_keys,
            } => {
                writeln!(f, "HashJoin(on=[{}])", join_keys.join(", "))?;
                left.fmt_indented(f, depth + 1)?;
                right.fmt_indented(f, depth + 1)
            }
            Self::Union { left, right, all } => {
                writeln!(f, "Union{}", if *all { " ALL" } else { "" })?;
                left.fmt_indented(f, depth + 1)?;
                right.fmt_indented(f, depth + 1)
            }
            Self::Optional {
                input,
                null_variables,
            } => {
                writeln!(f, "Optional(nulls=[{}])", h::vars(null_variables))?;
                input.fmt_indented(f, depth + 1)
            }

            Self::Create { input, pattern } => {
                writeln!(f, "Create({})", h::create_parts(pattern))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Merge {
                input,
                pattern,
                on_create,
                on_match,
            } => {
                writeln!(
                    f,
                    "Merge({}{}{})",
                    h::create_parts(pattern),
                    h::merge_actions("ON CREATE", on_create),
                    h::merge_actions("ON MATCH", on_match),
                )?;
                input.fmt_indented(f, depth + 1)
            }
            Self::SetClause { input, ops } => {
                writeln!(f, "Set({})", h::set_ops(ops))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Delete {
                input,
                detach,
                exprs,
            } => {
                let rendered: Vec<String> = exprs.iter().map(h::expr).collect();
                writeln!(
                    f,
                    "{}Delete({})",
                    if *detach { "Detach" } else { "" },
                    rendered.join(", "),
                )?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Remove { input, ops } => {
                writeln!(f, "Remove({})", h::remove_ops(ops))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::ProcedureCall {
                input,
                name,
                args,
                yields,
            } => {
                writeln!(
                    f,
                    "ProcedureCall({}{}{})",
                    name.join("."),
                    h::call_args(args),
                    h::yields(yields),
                )?;
                if let Some(input) = input {
                    input.fmt_indented(f, depth + 1)?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::IndexCatalog;
    use crate::lexer::tokenize;
    use crate::lower::lower;
    use crate::parser::parse_tokens;
    use crate::semantics::analyze;

    fn physical(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        let logical = lower(&validated);
        plan_physical(&logical, catalog)
    }

    #[test]
    fn limit_over_a_write_gets_an_eager_barrier() {
        let plan = physical("CREATE (n) RETURN n LIMIT 0", &IndexCatalog::empty());
        let rendered = plan.to_string();
        assert!(rendered.contains("Eager"), "{rendered}");
        // The barrier sits between the Limit and the write.
        let limit_pos = rendered.find("Limit").expect("limit");
        let eager_pos = rendered.find("Eager").expect("eager");
        let create_pos = rendered.find("Create").expect("create");
        assert!(
            limit_pos < eager_pos && eager_pos < create_pos,
            "{rendered}"
        );
    }

    #[test]
    fn limit_over_a_pure_read_has_no_eager_barrier() {
        let plan = physical("MATCH (n) RETURN n LIMIT 1", &IndexCatalog::empty());
        assert!(!plan.to_string().contains("Eager"), "{plan}");
    }

    #[test]
    fn equality_on_indexed_property_becomes_index_seek() {
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "age")
            .build();
        let plan = physical("MATCH (n:Person) WHERE n.age = 30 RETURN n", &catalog);
        assert!(plan.to_string().contains("NodeIndexSeek"), "{plan}");
        assert_eq!(plan.index_dependencies().count(), 1);
    }

    #[test]
    fn inline_property_equality_becomes_index_seek() {
        // The LDBC point-lookup shape (rmp #58): an inline `{id: x}` map is hoisted to an equality
        // filter by the logical planner and must use the index, recording the IndexId dependency.
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "id")
            .build();
        let plan = physical("MATCH (n:Person {id: 5}) RETURN n", &catalog);
        let rendered = plan.to_string();
        assert!(rendered.contains("NodeIndexSeek"), "{rendered}");
        assert!(!rendered.contains("NodeByLabelScan"), "{rendered}");
        assert_eq!(plan.index_dependencies().count(), 1);

        // Multi-key inline map: one key drives the seek, the rest stay a residual filter.
        let plan = physical("MATCH (n:Person {id: 5, name: 'x'}) RETURN n", &catalog);
        let rendered = plan.to_string();
        assert!(rendered.contains("NodeIndexSeek"), "{rendered}");
        assert!(rendered.contains("Filter"), "{rendered}");

        // The anchored end of an expand uses the seek too.
        let plan = physical("MATCH (a:Person {id: 5})-[:KNOWS]->(b) RETURN b", &catalog);
        assert!(plan.to_string().contains("NodeIndexSeek"), "{plan}");
    }

    #[test]
    fn no_index_falls_back_to_label_scan_and_filter() {
        let catalog = IndexCatalog::empty();
        let plan = physical("MATCH (n:Person) WHERE n.age = 30 RETURN n", &catalog);
        let rendered = plan.to_string();
        assert!(rendered.contains("NodeByLabelScan"), "{rendered}");
        assert!(rendered.contains("Filter"), "{rendered}");
        assert!(!rendered.contains("Seek"), "{rendered}");
        assert_eq!(plan.index_dependencies().count(), 0);
    }

    #[test]
    fn range_predicate_becomes_range_seek() {
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "age")
            .build();
        let plan = physical("MATCH (n:Person) WHERE n.age > 18 RETURN n", &catalog);
        assert!(plan.to_string().contains("NodeIndexRangeSeek"), "{plan}");
    }

    #[test]
    fn limit_over_sort_is_topn() {
        let catalog = IndexCatalog::empty();
        let plan = physical("MATCH (n) RETURN n ORDER BY n.age LIMIT 3", &catalog);
        assert!(plan.to_string().contains("TopN"), "{plan}");
    }

    #[test]
    fn limit_not_pushed_below_distinct() {
        let catalog = IndexCatalog::empty();
        let plan = physical("MATCH (n) RETURN DISTINCT n.age LIMIT 3", &catalog);
        let rendered = plan.to_string();
        // The Limit stays above the DISTINCT projection (not pushed below it).
        let limit_at = rendered.find("Limit").expect("has Limit");
        let proj_at = rendered
            .find("Projection DISTINCT")
            .expect("has DISTINCT proj");
        assert!(
            limit_at < proj_at,
            "Limit must be above DISTINCT: {rendered}"
        );
    }
}
