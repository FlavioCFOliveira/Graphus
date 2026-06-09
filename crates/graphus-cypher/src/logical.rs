//! The Cypher **logical plan** — a tree of relational-graph algebra operators
//! (`04-technical-design.md` §7.1).
//!
//! The logical planner (see [`crate::lower`]) lowers a
//! [`ValidatedQuery`](crate::semantics::ValidatedQuery) into a tree of [`LogicalOp`]s, the
//! *"relational-graph algebra: Expand, NodeScan, Filter, Project, Apply, Optional, Merge, Create,
//! SetProperty, …"* named in `04 §7.1`. This module defines the operator vocabulary; the lowering
//! rules and their justification live on [`crate::lower`].
//!
//! # What "logical" means here (the physical boundary)
//!
//! A logical plan describes **what** to compute, not **how**. It is deliberately
//! **index-agnostic** and **strategy-agnostic**: the choice of an index seek over a label scan, of
//! `Expand(Into)` over `Expand(All)` when both endpoints are already bound, of a hash join over a
//! nested-loop join, and of limit/sort pushdown, are all the **physical** planner's job
//! (`04 §7.1`: *"physical planner → physical plan (index seeks, expand-into vs expand-all, hash vs
//! nested-loop join, sort, limit pushdown)"*). Consequently:
//!
//! - Leaf reads are only [`AllNodesScan`](LogicalOp::AllNodesScan),
//!   [`NodeByLabelScan`](LogicalOp::NodeByLabelScan) and the relationship scans — **never** an
//!   index seek.
//! - [`Expand`](LogicalOp::Expand) carries the *logical* relationship traversal (endpoints,
//!   direction, type filter, variable-length range). Whether the executor runs it as expand-all or
//!   expand-into is a physical decision, so this module does **not** distinguish them. See the note
//!   on [`Expand`](LogicalOp::Expand).
//!
//! # Tree shape and the [`Display`] pretty-printer
//!
//! Operators form a tree: each non-leaf owns its input(s) in `Box`/`Vec`. The convention (matching
//! the Volcano model of `04 §7.4`) is that **data flows from the leaves up to the root**, so the
//! root is the last thing computed (typically the final `RETURN` projection). The [`Display`]
//! implementation renders the tree leaf-deepest-indented, which the golden plan-shape tests in
//! `tests/logical_planner.rs` assert against.

use crate::ast::{Expr, Label, MapKey, RelDirection, RelType, SortDirection, VarLengthRange};
use std::fmt;

/// A node in a [logical plan](self) tree: one relational-graph algebra operator
/// (`04 §7.1`).
///
/// Each variant documents the openCypher construct it represents and how its input(s) feed it.
/// Operators that consume an upstream relation own it as a boxed `input`; binary operators
/// (`Union`, `Apply`) own both sides. Leaves ([`AllNodesScan`](Self::AllNodesScan),
/// [`NodeByLabelScan`](Self::NodeByLabelScan), the relationship scans,
/// [`Argument`](Self::Argument), [`Empty`](Self::Empty)) own no input.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum LogicalOp {
    // ---- leaves -------------------------------------------------------------------------------
    /// Scan **every** node in the graph, binding it to `variable` (openCypher anonymous/unlabelled
    /// `MATCH (n)`).
    ///
    /// The physical planner may realise this as a full store scan; the logical plan only states the
    /// set of rows produced (one per node).
    AllNodesScan {
        /// The node variable bound by each produced row.
        variable: Var,
    },

    /// Scan all nodes carrying `label`, binding each to `variable` (openCypher `MATCH (n:Label)`).
    ///
    /// This stays **label-logical**: it is *not* an index seek. The physical planner decides
    /// whether to satisfy it from a label index, a scan-and-filter, or a property index when an
    /// adjacent [`Filter`](Self::Filter) permits (`04 §7.1`).
    NodeByLabelScan {
        /// The node variable bound by each produced row.
        variable: Var,
        /// The single label the scan is restricted to.
        label: Label,
    },

    /// Scan **every** relationship in the graph, binding the relationship and its endpoints.
    ///
    /// Used when a `MATCH` introduces a relationship pattern with no anchored node to expand from
    /// (e.g. `MATCH ()-[r]->()` with both endpoints anonymous). The physical planner chooses how to
    /// enumerate; the logical plan only states the produced bindings. The `types` filter, when
    /// non-empty, restricts to relationships whose type is among them.
    AllRelationshipsScan {
        /// The relationship variable bound by each row.
        relationship: Var,
        /// The source-endpoint node variable.
        from: Var,
        /// The target-endpoint node variable.
        to: Var,
        /// The arrow direction of the originating pattern.
        direction: RelDirection,
        /// The relationship-type alternatives (`:A|B`); empty means "any type".
        types: Vec<RelType>,
    },

    /// The right-hand-side **argument** leaf of an [`Apply`](Self::Apply): a single row carrying the
    /// variables the left side has already bound, which the right branch reads from.
    ///
    /// This is the standard relational-algebra device for correlated subplans (`04 §7.1` lists
    /// `Apply`): the right branch is planned as if its `arguments` were a one-row input, and
    /// [`Apply`](Self::Apply) re-evaluates it once per left row with those variables bound.
    Argument {
        /// The variables provided by the enclosing [`Apply`](Self::Apply)'s left side.
        arguments: Vec<Var>,
    },

    /// A single empty row with no bindings — the neutral input that begins a plan with no leading
    /// read clause (e.g. `RETURN 1`, `CREATE (n)`, `UNWIND [1,2] AS x`).
    ///
    /// It produces exactly one row, so a projection on top of it yields one result row, matching
    /// Cypher's evaluation of a query with no `MATCH`.
    Empty,

    // ---- graph --------------------------------------------------------------------------------
    /// Traverse from an already-bound node `from` across a relationship, binding `relationship` and
    /// the far endpoint `to` (openCypher relationship pattern `(from)-[rel]->(to)`).
    ///
    /// `from` is **required** to be bound by the `input` (the anchor of the expansion); `to` may be
    /// new (bind the discovered node) or already bound (a cycle / connection check). This module
    /// does **not** distinguish "expand-all" from "expand-into": whether the executor enumerates
    /// neighbours (`to` new) or checks a known pair (`to` bound) is a **physical** choice
    /// (`04 §7.1`). The logical operator records the traversal and lets the physical planner pick.
    Expand {
        /// The upstream relation, which must already bind [`from`](Self::Expand::from).
        input: Box<LogicalOp>,
        /// The already-bound anchor node to expand from.
        from: Var,
        /// The relationship variable bound by the traversal (anonymous relationships get a
        /// generated name; see [`Var`]).
        relationship: Var,
        /// The far-endpoint node variable.
        to: Var,
        /// The traversal direction.
        direction: RelDirection,
        /// The relationship-type alternatives (`:A|B`); empty means "any type".
        types: Vec<RelType>,
        /// The variable-length range (`*`, `*1..3`), if the pattern was variable-length; `None` for
        /// a single hop.
        range: Option<VarLengthRange>,
    },

    // ---- relational ---------------------------------------------------------------------------
    /// Keep only the input rows for which `predicate` evaluates to `TRUE` (openCypher `WHERE`, and
    /// the implicit filters from inline pattern predicates).
    ///
    /// Three-valued logic applies at execution: a `NULL`/`FALSE` result drops the row
    /// (`04 §7.6`). The predicate is the unevaluated AST [`Expr`]; evaluation is the executor's job.
    Filter {
        /// The upstream relation.
        input: Box<LogicalOp>,
        /// The predicate expression (kept as the validated AST).
        predicate: Expr,
    },

    /// Project each input row to a new tuple of named columns (openCypher `RETURN` / `WITH` body),
    /// optionally de-duplicating with `DISTINCT`.
    ///
    /// A `Projection` is the **projection boundary** of `04 §7.1`/§7.3: after it, only the listed
    /// columns are in scope. `DISTINCT` de-duplicates by Cypher *equivalence* (`04 §7.6`;
    /// [`crate::equivalence`]), distinct from `=`.
    Projection {
        /// The upstream relation.
        input: Box<LogicalOp>,
        /// The projected columns, in result order.
        items: Vec<ProjectionColumn>,
        /// `true` for `DISTINCT` (de-duplicate the projected tuples).
        distinct: bool,
    },

    /// Group the input by `group_keys` and compute `aggregates` per group (openCypher aggregating
    /// `RETURN`/`WITH`; `04 §7.6` grouping semantics).
    ///
    /// With **no** group keys the whole input is one group (`RETURN count(*)` over all rows). The
    /// `count(*)`-style atom and the aggregating functions (`count`, `sum`, `collect`, …) become
    /// [`aggregates`](Self::Aggregation::aggregates); every other projected term is a grouping key
    /// (the semantic pass already proved the projection is unambiguous, [`crate::semantics`]).
    /// Grouping uses Cypher *equivalence* (`04 §7.6`), so `NULL` groups with `NULL`.
    Aggregation {
        /// The upstream relation.
        input: Box<LogicalOp>,
        /// The grouping-key columns (the non-aggregated projected terms); empty = single group.
        group_keys: Vec<ProjectionColumn>,
        /// The aggregate columns to compute per group.
        aggregates: Vec<ProjectionColumn>,
    },

    /// Sort the input rows by the `keys` (openCypher `ORDER BY`).
    ///
    /// Ordering follows Cypher's total order across value classes (`04 §7.6`; [`crate::ordering`]).
    Sort {
        /// The upstream relation.
        input: Box<LogicalOp>,
        /// The sort keys, in priority order (first is the primary key).
        keys: Vec<SortKey>,
    },

    /// Discard the first `count` rows (openCypher `SKIP`). `count` is the unevaluated AST [`Expr`]
    /// (commonly a literal or parameter); evaluation is the executor's job.
    Skip {
        /// The upstream relation.
        input: Box<LogicalOp>,
        /// The number-of-rows-to-skip expression.
        count: Expr,
    },

    /// Keep at most `count` rows (openCypher `LIMIT`). `count` is the unevaluated AST [`Expr`].
    Limit {
        /// The upstream relation.
        input: Box<LogicalOp>,
        /// The maximum-row-count expression.
        count: Expr,
    },

    /// Expand `list` into one row per element, binding each to `variable` (openCypher
    /// `UNWIND <list> AS v`).
    ///
    /// When there is no upstream read clause the `input` is [`Empty`](Self::Empty) (a top-level
    /// `UNWIND`); otherwise it unwinds per incoming row (a correlated unwind).
    Unwind {
        /// The upstream relation.
        input: Box<LogicalOp>,
        /// The list expression to expand (unevaluated AST).
        list: Expr,
        /// The variable each element is bound to.
        variable: Var,
    },

    /// Correlated application: for each row of `input` (the left), evaluate `subplan` (the right)
    /// with the left row's variables bound, concatenating the results (openCypher `Apply`,
    /// `04 §7.1`).
    ///
    /// This is the join device for **correlated** subplans: the right branch's [`Argument`] leaf
    /// receives the left row's bindings. Graphus uses it to lower `OPTIONAL MATCH` (an
    /// [`Optional`](Self::Optional)-wrapped right side; see [`crate::lower`]) and `CALL` placed
    /// after other clauses.
    Apply {
        /// The left (driving) relation.
        left: Box<LogicalOp>,
        /// The right (correlated) subplan; its [`Argument`] leaf is fed the left row's bindings.
        right: Box<LogicalOp>,
    },

    /// Left-outer semantics for `OPTIONAL MATCH`: produce the `input`'s rows, but if `input`
    /// yields **no** row, emit a single row with the optional pattern's new variables bound to
    /// `NULL` (openCypher `Optional`, `04 §7.1`).
    ///
    /// `Optional` is placed on the **right** side of an [`Apply`](Self::Apply): the apply drives it
    /// once per outer row, and `Optional` guarantees at least one output row per drive, so the outer
    /// row is never dropped — exactly the left-outer-join semantics `OPTIONAL MATCH` requires.
    /// `null_variables` lists the variables the optional pattern introduces (bound to `NULL` on the
    /// no-match path) so the executor knows which columns to null-fill.
    Optional {
        /// The optional subplan (typically rooted at an [`Argument`](Self::Argument)).
        input: Box<LogicalOp>,
        /// The variables the optional pattern introduces, null-filled when `input` is empty.
        null_variables: Vec<Var>,
    },

    /// Combine two branch plans (openCypher `UNION` / `UNION ALL`).
    ///
    /// `all = true` keeps duplicates (`UNION ALL`); `all = false` de-duplicates the combined rows by
    /// Cypher *equivalence* (`UNION`; `04 §7.6`). Both branches must project union-compatible
    /// columns (the semantic pass enforces column compatibility, [`crate::semantics`]).
    Union {
        /// The left branch plan.
        left: Box<LogicalOp>,
        /// The right branch plan.
        right: Box<LogicalOp>,
        /// `true` for `UNION ALL` (keep duplicates); `false` for `UNION` (distinct).
        all: bool,
    },

    // ---- write --------------------------------------------------------------------------------
    /// Create the nodes and relationships described by `pattern` (openCypher `CREATE`).
    ///
    /// Runs once per input row (so `MATCH (a) CREATE (b)` creates one `b` per matched `a`). With no
    /// preceding read clause the `input` is [`Empty`](Self::Empty), creating the pattern exactly
    /// once.
    Create {
        /// The upstream relation driving the creation (one creation per row).
        input: Box<LogicalOp>,
        /// The graph entities to create.
        pattern: Vec<CreatePart>,
    },

    /// Match-or-create the single `pattern`, running `on_create` / `on_match` side-effects
    /// (openCypher `MERGE`).
    ///
    /// `MERGE` is *get-or-create*: if the pattern already matches, the matched binding is used and
    /// `on_match` runs; otherwise the pattern is created and `on_create` runs. Both action lists are
    /// [`SetOp`]s (the `ON CREATE SET` / `ON MATCH SET` items). The match-vs-create branching is the
    /// executor's job against the live graph; the logical operator records the intent.
    Merge {
        /// The upstream relation driving the merge (one merge per row).
        input: Box<LogicalOp>,
        /// The single pattern to match-or-create.
        pattern: Vec<CreatePart>,
        /// `ON CREATE SET` actions (applied only when the pattern was created).
        on_create: Vec<SetOp>,
        /// `ON MATCH SET` actions (applied only when the pattern already existed).
        on_match: Vec<SetOp>,
    },

    /// Apply property / map / label mutations to already-bound entities (openCypher `SET`).
    SetClause {
        /// The upstream relation.
        input: Box<LogicalOp>,
        /// The mutations to apply, in source order.
        ops: Vec<SetOp>,
    },

    /// Delete the entities identified by `exprs` (openCypher `[DETACH] DELETE`).
    ///
    /// `detach = true` first removes a node's incident relationships (`DETACH DELETE`); without it,
    /// deleting a node that still has relationships is a runtime error (raised by the executor, not
    /// here — `04 §7.3`).
    Delete {
        /// The upstream relation.
        input: Box<LogicalOp>,
        /// `true` for `DETACH DELETE`.
        detach: bool,
        /// The entity-reference expressions to delete (unevaluated AST).
        exprs: Vec<Expr>,
    },

    /// Remove labels and/or properties from already-bound entities (openCypher `REMOVE`).
    Remove {
        /// The upstream relation.
        input: Box<LogicalOp>,
        /// The removals to apply, in source order.
        ops: Vec<RemoveOp>,
    },

    // ---- procedure ----------------------------------------------------------------------------
    /// Invoke a procedure and stream its result rows, binding the `yields` columns (openCypher
    /// `CALL proc(args) [YIELD ...]`).
    ///
    /// A **leading** `CALL` has `input = None` (it is a row source). A `CALL` placed *after* other
    /// clauses is lowered correlated, wrapped in an [`Apply`](Self::Apply) over the prior plan with
    /// `input = Some(Argument)`; see [`crate::lower`]. Procedure-signature validation is deferred to
    /// the executor (it needs the procedure catalogue — `04 §7.3`; [`crate::semantics`]).
    ProcedureCall {
        /// The upstream relation when the call is correlated; `None` for a leading/standalone call.
        input: Option<Box<LogicalOp>>,
        /// The dotted procedure name (`["db", "labels"]` for `db.labels`).
        name: Vec<String>,
        /// The argument expressions (unevaluated AST); `None` for the implicit, parenthesis-less
        /// form.
        args: Option<Vec<Expr>>,
        /// The `YIELD` columns bound into scope; `None` when there is no `YIELD`.
        yields: Option<Vec<YieldColumn>>,
    },
}

/// A variable binding produced or consumed by a [`LogicalOp`].
///
/// Carries the variable name and whether it was **explicit** in the query (e.g. `n` in
/// `MATCH (n)`) or **synthetic** — generated by the planner for an anonymous pattern element (e.g.
/// the relationship in `MATCH (a)-->(b)`). Synthetic names use a reserved `  ` (two-space) prefix
/// that cannot collide with a user identifier (the lexer never produces a name beginning with a
/// space), matching Neo4j's anonymous-variable convention.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct Var {
    /// The variable name (user-written, or planner-generated for an anonymous element).
    pub name: String,
    /// `true` if the planner synthesised this name for an anonymous pattern element.
    pub synthetic: bool,
}

impl Var {
    /// Builds a named (user-written) variable binding.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            synthetic: false,
        }
    }

    /// Builds a synthetic (planner-generated) variable binding for an anonymous pattern element.
    ///
    /// The name is prefixed with a reserved two-space marker so it can never collide with a
    /// user-written identifier (the lexer rejects leading spaces in identifiers).
    pub fn synthetic(seq: usize) -> Self {
        Self {
            name: format!("  anon_{seq}"),
            synthetic: true,
        }
    }
}

impl fmt::Display for Var {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Render synthetic names with an `anon_` marker (the stored name keeps the reserved
        // space-prefix); user names render verbatim.
        if self.synthetic {
            write!(f, "{}", self.name.trim_start())
        } else {
            f.write_str(&self.name)
        }
    }
}

/// A projected column of a [`Projection`](LogicalOp::Projection) or
/// [`Aggregation`](LogicalOp::Aggregation): an expression and the column name it is bound to.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct ProjectionColumn {
    /// The projected expression (unevaluated validated AST).
    pub expr: Expr,
    /// The result column name (the explicit `AS` alias, or Cypher's inferred name).
    pub alias: String,
}

/// One `ORDER BY` key of a [`Sort`](LogicalOp::Sort): an expression and its direction.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct SortKey {
    /// The sort expression (unevaluated validated AST).
    pub expr: Expr,
    /// Ascending or descending.
    pub direction: SortDirection,
}

/// A `YIELD` column of a [`ProcedureCall`](LogicalOp::ProcedureCall): the bound name and the source
/// result field it renames, if any.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct YieldColumn {
    /// The source procedure result field, when `field AS var` was written; `None` for a bare
    /// `var`.
    pub field: Option<String>,
    /// The variable the field is bound to.
    pub variable: Var,
}

/// One node or relationship entity to be created by a [`Create`](LogicalOp::Create) /
/// [`Merge`](LogicalOp::Merge), lowered from a pattern element.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum CreatePart {
    /// Create a node with the given variable, labels and inline properties.
    Node {
        /// The node variable (synthetic if the pattern node was anonymous).
        variable: Var,
        /// The labels to set on the new node.
        labels: Vec<Label>,
        /// The inline property map expression, if written.
        properties: Option<Expr>,
    },
    /// Create a relationship between two (already-listed) endpoint variables.
    Relationship {
        /// The relationship variable (synthetic if anonymous).
        variable: Var,
        /// The source endpoint node variable.
        from: Var,
        /// The target endpoint node variable.
        to: Var,
        /// The relationship type (CREATE/MERGE require exactly one — enforced by the semantic
        /// pass; the planner records it as a single [`RelType`]).
        rel_type: RelType,
        /// The arrow direction.
        direction: RelDirection,
        /// The inline property map expression, if written.
        properties: Option<Expr>,
    },
}

/// One mutation of a [`SetClause`](LogicalOp::SetClause) (or a `MERGE` action), lowered from an
/// AST [`SetItem`](crate::ast::SetItem).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum SetOp {
    /// `a.b = value` — set a single property.
    Property {
        /// The target property-access expression (`a.b`).
        target: Expr,
        /// The value expression.
        value: Expr,
    },
    /// `n = map` — replace **all** of `n`'s properties from `map`.
    ReplaceProperties {
        /// The target entity variable.
        target: Var,
        /// The replacement map expression.
        value: Expr,
    },
    /// `n += map` — merge `map` into `n`'s properties (keep unmentioned ones).
    MergeProperties {
        /// The target entity variable.
        target: Var,
        /// The merge map expression.
        value: Expr,
    },
    /// `n:Label1:Label2` — add labels to `n`.
    AddLabels {
        /// The target entity variable.
        target: Var,
        /// The labels to add.
        labels: Vec<Label>,
    },
}

/// One removal of a [`Remove`](LogicalOp::Remove), lowered from an AST
/// [`RemoveItem`](crate::ast::RemoveItem).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum RemoveOp {
    /// `n:Label1:Label2` — remove labels from `n`.
    Labels {
        /// The target entity variable.
        target: Var,
        /// The labels to remove.
        labels: Vec<Label>,
    },
    /// `a.b` — remove a single property.
    Property {
        /// The target property-access expression.
        target: Expr,
    },
}

// =================================================================================================
// Pretty-printer
// =================================================================================================

impl fmt::Display for LogicalOp {
    /// Renders the plan as an indented tree, root first, each input one level deeper.
    ///
    /// The format is stable and is what the golden tests in `tests/logical_planner.rs` assert. It
    /// is a diagnostics aid, **not** a serialization format (it does not round-trip expressions).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_indented(f, 0)
    }
}

impl LogicalOp {
    /// Recursive [`Display`] worker: writes `self`'s header at `depth`, then its inputs at
    /// `depth + 1`.
    fn fmt_indented(&self, f: &mut fmt::Formatter<'_>, depth: usize) -> fmt::Result {
        for _ in 0..depth {
            f.write_str("  ")?;
        }
        match self {
            Self::AllNodesScan { variable } => writeln!(f, "AllNodesScan({variable})"),
            Self::NodeByLabelScan { variable, label } => {
                writeln!(f, "NodeByLabelScan({variable}:{})", label.name)
            }
            Self::AllRelationshipsScan {
                relationship,
                from,
                to,
                direction,
                types,
            } => {
                writeln!(
                    f,
                    "AllRelationshipsScan({}{relationship}{}{to} from {from}{})",
                    arrow_left(*direction),
                    arrow_right(*direction),
                    fmt_types(types),
                )
            }
            Self::Argument { arguments } => {
                writeln!(f, "Argument({})", fmt_vars(arguments))
            }
            Self::Empty => writeln!(f, "Empty"),

            Self::Expand {
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
                    "Expand({from}){}{relationship}{}{}{}({to})",
                    arrow_left(*direction),
                    fmt_types(types),
                    fmt_range(range),
                    arrow_right(*direction),
                )?;
                input.fmt_indented(f, depth + 1)
            }

            Self::Filter { input, predicate } => {
                writeln!(f, "Filter({})", fmt_expr(predicate))?;
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
                    fmt_columns(items),
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
                    fmt_columns(group_keys),
                    fmt_columns(aggregates),
                )?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Sort { input, keys } => {
                writeln!(f, "Sort({})", fmt_sort_keys(keys))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Skip { input, count } => {
                writeln!(f, "Skip({})", fmt_expr(count))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Limit { input, count } => {
                writeln!(f, "Limit({})", fmt_expr(count))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Unwind {
                input,
                list,
                variable,
            } => {
                writeln!(f, "Unwind({} AS {variable})", fmt_expr(list))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Apply { left, right } => {
                writeln!(f, "Apply")?;
                left.fmt_indented(f, depth + 1)?;
                right.fmt_indented(f, depth + 1)
            }
            Self::Optional {
                input,
                null_variables,
            } => {
                writeln!(f, "Optional(nulls=[{}])", fmt_vars(null_variables))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Union { left, right, all } => {
                writeln!(f, "Union{}", if *all { " ALL" } else { "" })?;
                left.fmt_indented(f, depth + 1)?;
                right.fmt_indented(f, depth + 1)
            }

            Self::Create { input, pattern } => {
                writeln!(f, "Create({})", fmt_create_parts(pattern))?;
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
                    fmt_create_parts(pattern),
                    fmt_merge_actions("ON CREATE", on_create),
                    fmt_merge_actions("ON MATCH", on_match),
                )?;
                input.fmt_indented(f, depth + 1)
            }
            Self::SetClause { input, ops } => {
                writeln!(f, "Set({})", fmt_set_ops(ops))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Delete {
                input,
                detach,
                exprs,
            } => {
                let rendered: Vec<String> = exprs.iter().map(fmt_expr).collect();
                writeln!(
                    f,
                    "{}Delete({})",
                    if *detach { "Detach" } else { "" },
                    rendered.join(", "),
                )?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Remove { input, ops } => {
                writeln!(f, "Remove({})", fmt_remove_ops(ops))?;
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
                    fmt_call_args(args),
                    fmt_yields(yields),
                )?;
                if let Some(input) = input {
                    input.fmt_indented(f, depth + 1)?;
                }
                Ok(())
            }
        }
    }
}

// ---- Display helpers (diagnostics only; no semantic load) -------------------------------------

/// Renders a list of [`SortKey`]s as `expr ASC, expr DESC, …` (shared by the logical `Sort` and the
/// physical `Sort`/`TopN` pretty-printers via [`display_helpers`]).
fn fmt_sort_keys(keys: &[SortKey]) -> String {
    let rendered: Vec<String> = keys
        .iter()
        .map(|k| {
            format!(
                "{} {}",
                fmt_expr(&k.expr),
                match k.direction {
                    SortDirection::Ascending => "ASC",
                    SortDirection::Descending => "DESC",
                }
            )
        })
        .collect();
    rendered.join(", ")
}

fn arrow_left(direction: RelDirection) -> &'static str {
    match direction {
        RelDirection::RightToLeft => "<-[",
        RelDirection::LeftToRight | RelDirection::Undirected => "-[",
    }
}

fn arrow_right(direction: RelDirection) -> &'static str {
    match direction {
        RelDirection::LeftToRight => "]->",
        RelDirection::RightToLeft | RelDirection::Undirected => "]-",
    }
}

fn fmt_types(types: &[RelType]) -> String {
    if types.is_empty() {
        String::new()
    } else {
        let names: Vec<&str> = types.iter().map(|t| t.name.as_str()).collect();
        format!(":{}", names.join("|"))
    }
}

fn fmt_range(range: &Option<VarLengthRange>) -> String {
    match range {
        None => String::new(),
        Some(r) => match (r.min, r.max) {
            (None, None) => "*".to_owned(),
            (Some(min), Some(max)) if min == max => format!("*{min}"),
            (min, max) => format!(
                "*{}..{}",
                min.map(|n| n.to_string()).unwrap_or_default(),
                max.map(|n| n.to_string()).unwrap_or_default(),
            ),
        },
    }
}

fn fmt_vars(vars: &[Var]) -> String {
    let names: Vec<String> = vars.iter().map(ToString::to_string).collect();
    names.join(", ")
}

fn fmt_columns(cols: &[ProjectionColumn]) -> String {
    let rendered: Vec<String> = cols
        .iter()
        .map(|c| format!("{} AS {}", fmt_expr(&c.expr), c.alias))
        .collect();
    rendered.join(", ")
}

fn fmt_create_parts(parts: &[CreatePart]) -> String {
    let rendered: Vec<String> = parts
        .iter()
        .map(|p| match p {
            CreatePart::Node {
                variable, labels, ..
            } => {
                let label_str: String = labels.iter().map(|l| format!(":{}", l.name)).collect();
                format!("({variable}{label_str})")
            }
            CreatePart::Relationship {
                variable,
                from,
                to,
                rel_type,
                direction,
                ..
            } => format!(
                "({from}){}{variable}:{}{}({to})",
                arrow_left(*direction),
                rel_type.name,
                arrow_right(*direction),
            ),
        })
        .collect();
    rendered.join(", ")
}

fn fmt_merge_actions(label: &str, ops: &[SetOp]) -> String {
    if ops.is_empty() {
        String::new()
    } else {
        format!(" {label} SET {}", fmt_set_ops(ops))
    }
}

fn fmt_set_ops(ops: &[SetOp]) -> String {
    let rendered: Vec<String> = ops
        .iter()
        .map(|op| match op {
            SetOp::Property { target, value } => {
                format!("{} = {}", fmt_expr(target), fmt_expr(value))
            }
            SetOp::ReplaceProperties { target, value } => {
                format!("{target} = {}", fmt_expr(value))
            }
            SetOp::MergeProperties { target, value } => {
                format!("{target} += {}", fmt_expr(value))
            }
            SetOp::AddLabels { target, labels } => {
                let label_str: String = labels.iter().map(|l| format!(":{}", l.name)).collect();
                format!("{target}{label_str}")
            }
        })
        .collect();
    rendered.join(", ")
}

fn fmt_remove_ops(ops: &[RemoveOp]) -> String {
    let rendered: Vec<String> = ops
        .iter()
        .map(|op| match op {
            RemoveOp::Labels { target, labels } => {
                let label_str: String = labels.iter().map(|l| format!(":{}", l.name)).collect();
                format!("{target}{label_str}")
            }
            RemoveOp::Property { target } => fmt_expr(target),
        })
        .collect();
    rendered.join(", ")
}

fn fmt_call_args(args: &Option<Vec<Expr>>) -> String {
    match args {
        None => String::new(),
        Some(args) => {
            let rendered: Vec<String> = args.iter().map(fmt_expr).collect();
            format!("({})", rendered.join(", "))
        }
    }
}

fn fmt_yields(yields: &Option<Vec<YieldColumn>>) -> String {
    match yields {
        None => String::new(),
        Some(cols) => {
            let rendered: Vec<String> = cols
                .iter()
                .map(|c| match &c.field {
                    Some(field) => format!("{field} AS {}", c.variable),
                    None => c.variable.to_string(),
                })
                .collect();
            format!(" YIELD {}", rendered.join(", "))
        }
    }
}

/// Renders an [`Expr`] to a compact, stable string for plan diagnostics.
///
/// This intentionally covers the common forms precisely (variables, literals, properties,
/// operators) and renders the rarer forms with a structural placeholder. It is **not** a Cypher
/// pretty-printer and is used only by the plan [`Display`] / golden tests.
fn fmt_expr(expr: &Expr) -> String {
    use crate::ast::{BinaryOp, ExprKind, Literal, PredicateOp, UnaryOp};
    match &expr.kind {
        ExprKind::Literal(lit) => match lit {
            Literal::Integer(i) => i.value.to_string(),
            Literal::Float(x) => x.to_string(),
            Literal::String(s) => format!("'{s}'"),
            Literal::Boolean(b) => b.to_string(),
            Literal::Null => "null".to_owned(),
        },
        ExprKind::Parameter(name) => format!("${name}"),
        ExprKind::Variable(name) => name.clone(),
        ExprKind::Binary { op, lhs, rhs } => {
            let sym = match op {
                BinaryOp::Or => "OR",
                BinaryOp::Xor => "XOR",
                BinaryOp::And => "AND",
                BinaryOp::Eq => "=",
                BinaryOp::Neq => "<>",
                BinaryOp::Lt => "<",
                BinaryOp::Gt => ">",
                BinaryOp::Lte => "<=",
                BinaryOp::Gte => ">=",
                BinaryOp::RegexMatch => "=~",
                BinaryOp::Add => "+",
                BinaryOp::Sub => "-",
                BinaryOp::Mul => "*",
                BinaryOp::Div => "/",
                BinaryOp::Mod => "%",
                BinaryOp::Pow => "^",
            };
            format!("({} {sym} {})", fmt_expr(lhs), fmt_expr(rhs))
        }
        ExprKind::Unary { op, operand } => {
            let sym = match op {
                UnaryOp::Not => "NOT ",
                UnaryOp::Plus => "+",
                UnaryOp::Minus => "-",
            };
            format!("{sym}{}", fmt_expr(operand))
        }
        ExprKind::Predicate { op, operand, rhs } => {
            let lhs = fmt_expr(operand);
            match op {
                PredicateOp::IsNull => format!("{lhs} IS NULL"),
                PredicateOp::IsNotNull => format!("{lhs} IS NOT NULL"),
                PredicateOp::StartsWith => {
                    format!("{lhs} STARTS WITH {}", fmt_opt_rhs(rhs))
                }
                PredicateOp::EndsWith => format!("{lhs} ENDS WITH {}", fmt_opt_rhs(rhs)),
                PredicateOp::Contains => format!("{lhs} CONTAINS {}", fmt_opt_rhs(rhs)),
                PredicateOp::In => format!("{lhs} IN {}", fmt_opt_rhs(rhs)),
            }
        }
        ExprKind::Property { base, key } => format!("{}.{key}", fmt_expr(base)),
        ExprKind::Index { base, index } => format!("{}[{}]", fmt_expr(base), fmt_expr(index)),
        ExprKind::Slice { base, low, high } => format!(
            "{}[{}..{}]",
            fmt_expr(base),
            low.as_deref().map(fmt_expr).unwrap_or_default(),
            high.as_deref().map(fmt_expr).unwrap_or_default(),
        ),
        ExprKind::HasLabels { operand, labels } => {
            let label_str: String = labels.iter().map(|l| format!(":{}", l.name)).collect();
            format!("{}{label_str}", fmt_expr(operand))
        }
        ExprKind::FunctionCall {
            name,
            distinct,
            args,
        } => {
            let rendered: Vec<String> = args.iter().map(fmt_expr).collect();
            format!(
                "{}({}{})",
                name.join("."),
                if *distinct { "DISTINCT " } else { "" },
                rendered.join(", "),
            )
        }
        ExprKind::CountStar => "count(*)".to_owned(),
        ExprKind::List(items) => {
            let rendered: Vec<String> = items.iter().map(fmt_expr).collect();
            format!("[{}]", rendered.join(", "))
        }
        ExprKind::Map(entries) => {
            let rendered: Vec<String> = entries
                .iter()
                .map(|(MapKey { name, .. }, v)| format!("{name}: {}", fmt_expr(v)))
                .collect();
            format!("{{{}}}", rendered.join(", "))
        }
        ExprKind::Case(_) => "CASE(...)".to_owned(),
        ExprKind::ListComprehension(_) => "[list-comprehension]".to_owned(),
        ExprKind::PatternComprehension(_) => "[pattern-comprehension]".to_owned(),
    }
}

fn fmt_opt_rhs(rhs: &Option<Box<Expr>>) -> String {
    rhs.as_deref().map(fmt_expr).unwrap_or_default()
}

/// Crate-internal re-exports of the [`LogicalOp`] [`Display`] helpers so the
/// [physical plan](crate::physical) pretty-printer can render the operators it carries through
/// (relationship arrows, types, columns, set/remove ops, expressions, …) **identically** to the
/// logical printer. Keeping one set of helpers guarantees the two renderings never drift.
///
/// These are pure diagnostics formatters with no semantic load (the same caveat as on the private
/// helpers): they are stable enough for golden tests but are **not** a serialization format.
pub(crate) mod display_helpers {
    use super::{
        CreatePart, Expr, ProjectionColumn, RelDirection, RelType, RemoveOp, SetOp, SortKey, Var,
        VarLengthRange, YieldColumn,
    };

    /// See [`super::arrow_left`].
    pub(crate) fn arrow_left(direction: RelDirection) -> &'static str {
        super::arrow_left(direction)
    }
    /// See [`super::arrow_right`].
    pub(crate) fn arrow_right(direction: RelDirection) -> &'static str {
        super::arrow_right(direction)
    }
    /// See [`super::fmt_types`].
    pub(crate) fn types(types: &[RelType]) -> String {
        super::fmt_types(types)
    }
    /// See [`super::fmt_range`].
    pub(crate) fn range(range: &Option<VarLengthRange>) -> String {
        super::fmt_range(range)
    }
    /// See [`super::fmt_vars`].
    pub(crate) fn vars(vars: &[Var]) -> String {
        super::fmt_vars(vars)
    }
    /// See [`super::fmt_columns`].
    pub(crate) fn columns(cols: &[ProjectionColumn]) -> String {
        super::fmt_columns(cols)
    }
    /// See [`super::fmt_sort_keys`].
    pub(crate) fn sort_keys(keys: &[SortKey]) -> String {
        super::fmt_sort_keys(keys)
    }
    /// See [`super::fmt_create_parts`].
    pub(crate) fn create_parts(parts: &[CreatePart]) -> String {
        super::fmt_create_parts(parts)
    }
    /// See [`super::fmt_merge_actions`].
    pub(crate) fn merge_actions(label: &str, ops: &[SetOp]) -> String {
        super::fmt_merge_actions(label, ops)
    }
    /// See [`super::fmt_set_ops`].
    pub(crate) fn set_ops(ops: &[SetOp]) -> String {
        super::fmt_set_ops(ops)
    }
    /// See [`super::fmt_remove_ops`].
    pub(crate) fn remove_ops(ops: &[RemoveOp]) -> String {
        super::fmt_remove_ops(ops)
    }
    /// See [`super::fmt_call_args`].
    pub(crate) fn call_args(args: &Option<Vec<Expr>>) -> String {
        super::fmt_call_args(args)
    }
    /// See [`super::fmt_yields`].
    pub(crate) fn yields(yields: &Option<Vec<YieldColumn>>) -> String {
        super::fmt_yields(yields)
    }
    /// See [`super::fmt_expr`].
    pub(crate) fn expr(expr: &Expr) -> String {
        super::fmt_expr(expr)
    }
}
