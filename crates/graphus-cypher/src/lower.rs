//! The Cypher **logical planner** — lowering a validated query to a [logical plan](crate::logical)
//! (`04-technical-design.md` §7.1).
//!
//! [`lower`] is the entry point: it takes a [`ValidatedQuery`](crate::semantics::ValidatedQuery)
//! (the output of semantic analysis — proof that all compile-time checks have passed, `04 §7.3`)
//! and produces a [`LogicalOp`] tree, the *"relational-graph algebra"* of `04 §7.1`.
//!
//! Because the input is a [`ValidatedQuery`], the planner may assume every compile-time invariant
//! holds (variables resolve, aggregation placement is legal, clause composition is valid, …) and
//! therefore lowers **without** re-checking them; it is a total, infallible transformation over a
//! validated query. It performs only **conservative, clearly semantics-preserving** normalisation
//! (documented under [Normalisation](#normalisation)); cost-based optimisation is Phase 2
//! (`00-overview`).
//!
//! # The lowering rules, per clause
//!
//! A [`SingleQuery`] is a chain of clauses lowered left-to-right, **threading the current relation
//! (the "plan so far")** so each clause builds on its predecessors' bindings:
//!
//! - **`MATCH p [WHERE pred]`** lowers the pattern to a leaf scan for the anchor node, then an
//!   [`Expand`](LogicalOp::Expand) per relationship in the chain (carrying its direction, type
//!   filter and variable-length range), then — if a `WHERE` is present — a
//!   [`Filter`](LogicalOp::Filter). So `MATCH (a)-[r]->(b) WHERE pred` becomes
//!   `Filter(pred) ▸ Expand(a)-[r]->(b) ▸ scan(a)`. When a `MATCH` follows existing clauses, its
//!   leading scan is joined to the prior plan with [`Apply`](LogicalOp::Apply) over an
//!   [`Argument`](LogicalOp::Argument) so the new pattern is correlated with the carried bindings.
//! - **`OPTIONAL MATCH`** lowers with **left-outer** semantics: the optional pattern is planned on
//!   the right of an [`Apply`](LogicalOp::Apply), wrapped in [`Optional`](LogicalOp::Optional) so
//!   the outer row survives even with no match (the new variables become `NULL`). See
//!   [Optional](#optional-match).
//! - **`WITH` / `RETURN`** are **projection boundaries**: each lowers to a
//!   [`Projection`](LogicalOp::Projection) (or an [`Aggregation`](LogicalOp::Aggregation) when the
//!   body aggregates), then the `ORDER BY`/`SKIP`/`LIMIT`/`DISTINCT` modifiers and a `WITH … WHERE`
//!   stack on top in the order the openCypher grammar fixes (see
//!   [`lower_projection_body`](Self::lower_projection_body)).
//! - **`UNWIND e AS v`** lowers to [`Unwind`](LogicalOp::Unwind) over the plan so far (or over
//!   [`Empty`](LogicalOp::Empty) when leading).
//! - **`CALL … YIELD`** lowers to [`ProcedureCall`](LogicalOp::ProcedureCall); leading, it is a row
//!   source; after other clauses, it is correlated via [`Apply`](LogicalOp::Apply).
//! - **`CREATE` / `MERGE` / `SET` / `DELETE` / `REMOVE`** lower to the matching write operator over
//!   the plan so far (the write runs once per driving row).
//!
//! A `UNION` chain ([`QueryBody::Regular`] with `unions`) lowers each single query independently and
//! folds them left-associatively into [`Union`](LogicalOp::Union) operators, carrying the per-step
//! `ALL` flag. A [`QueryBody::StandaloneCall`] lowers directly to a leading
//! [`ProcedureCall`](LogicalOp::ProcedureCall).
//!
//! # Optional MATCH
//!
//! `OPTIONAL MATCH` is a left-outer join: every row from the preceding plan is preserved; where the
//! optional pattern matches, its variables bind; where it does not, they are `NULL`. The standard
//! relational-graph-algebra lowering (the one named in `04 §7.1`) is
//! `Apply(left, Optional(rhs_pattern))`: the [`Apply`](LogicalOp::Apply) drives the right branch
//! once per left row with the left bindings available (through the
//! [`Argument`](LogicalOp::Argument) leaf), and [`Optional`](LogicalOp::Optional) guarantees the
//! drive yields **at least one** row — the matched rows, or one all-`NULL` row — so the left row is
//! never dropped. (Source: openCypher `OPTIONAL MATCH` semantics; the relational `Apply`/`Optional`
//! encoding is the textbook lowering and the algebra `04 §7.1` enumerates.)
//!
//! # Normalisation
//!
//! The planner applies exactly one conservative rewrite, **inline-predicate hoisting**, and is
//! careful to *not* apply it where it would change semantics:
//!
//! - **Inline-property-map predicates** on a `MATCH` node/relationship pattern (`MATCH (n {k: v})`)
//!   are lowered into an explicit [`Filter`](LogicalOp::Filter) on the equality `n.k = v`, placed
//!   **immediately above the scan/expand that binds the entity** — i.e. pushed as close to its leaf
//!   as is sound. This is semantics-preserving for an *equality* property constraint (`MATCH
//!   (n {k: v})` is exactly `MATCH (n) WHERE n.k = v` for a non-null `v`; the executor applies
//!   Cypher equality, `04 §7.6`). The filter is attached to the operator that *binds the entity*
//!   so it can never be hoisted above that binding (which would reference an unbound variable). A
//!   `WHERE` predicate, by contrast, is **not** decomposed or pushed past the scans of the
//!   variables it might reference: a `WHERE` may reference variables bound later in the same
//!   `MATCH` (across the whole pattern), so it stays above the full pattern's scans/expands. This
//!   keeps the one rewrite obviously sound; aggressive predicate pushdown and join reordering are
//!   deferred to the Phase 2 cost-based optimiser (`00-overview`).
//!
//! # Covered vs deferred (named)
//!
//! **Covered:** all [`Clause`] variants the parser/semantics accept — `MATCH` (with multi-hop and
//! variable-length expansion, multiple comma-separated pattern parts, and inline-property
//! normalisation), `OPTIONAL MATCH`, `WHERE`, `WITH`/`RETURN` (with `DISTINCT`, `*`, `ORDER BY`,
//! `SKIP`, `LIMIT`, aggregation grouping), `UNWIND`, `CALL … YIELD` (in-query and standalone),
//! `CREATE`, `MERGE` (+ `ON CREATE`/`ON MATCH SET`), `SET`, `DELETE`/`DETACH DELETE`, `REMOVE`, and
//! `UNION`/`UNION ALL`.
//!
//! **Deferred, by name:** (1) **cost-based optimisation** — join reordering, selectivity-driven
//! scan choice, general predicate pushdown, common-subexpression elimination (Phase 2,
//! `00-overview`); (2) **physical concerns** — index-seek selection, expand-into vs expand-all,
//! hash vs nested-loop join, sort/limit pushdown (the physical planner, `04 §7.1`); (3) the
//! parser-deferred exotic productions (`FOREACH`, `CALL { subquery }`, existential subqueries,
//! quantifier predicates, `LOAD CSV`, DDL — they never reach a [`ValidatedQuery`], so the planner
//! has nothing to lower); (4) **named-path value construction** — a `MATCH p = (...)` binds the
//! path variable `p` in the scope, but materialising the path value is an executor concern, so the
//! logical plan records the traversal without a dedicated path-build operator yet.

use crate::ast::{
    Clause, CreateClause, DeleteClause, Expr, ExprKind, LoadCsvClause, MatchClause, MergeAction,
    MergeClause, NodePattern, PatternElement, PatternPart, ProjectionBody, ProjectionItem, Query,
    QueryBody, RelType, RelationshipPattern, RemoveClause, RemoveItem, SetClause, SetItem,
    SingleQuery, StandaloneCall, StandaloneYield, UnionPart, UnwindClause,
};
use crate::function_registry;
use crate::lexer::Span;
use crate::logical::{
    CreatePart, LogicalOp, ProjectionColumn, RemoveOp, SetOp, SortKey, Var, YieldColumn,
};
use crate::semantics::ValidatedQuery;

/// Lowers a [`ValidatedQuery`] into a [logical plan](crate::logical) (`04 §7.1`).
///
/// This is the logical planner's public entry point: it consumes the validated AST and returns the
/// root [`LogicalOp`] of the plan tree. Because the input has already passed semantic analysis
/// (`04 §7.3`), the lowering is **total and infallible** — every compile-time invariant the planner
/// relies on (resolvable variables, legal aggregation, valid clause composition) is guaranteed by
/// the [`ValidatedQuery`] token, so there is no error path here.
///
/// # Examples
///
/// ```
/// use graphus_cypher::lexer::tokenize;
/// use graphus_cypher::parser::parse_tokens;
/// use graphus_cypher::semantics::analyze;
/// use graphus_cypher::lower::lower;
///
/// let src = "MATCH (n:Person) WHERE n.age > 18 RETURN n.name AS name";
/// let toks = tokenize(src).unwrap();
/// let ast = parse_tokens(&toks, src).unwrap();
/// let validated = analyze(&ast).unwrap();
/// let plan = lower(&validated);
/// // Root is the RETURN projection; the WHERE became a Filter above the label scan.
/// let rendered = plan.to_string();
/// assert!(rendered.starts_with("Projection("));
/// assert!(rendered.contains("Filter("));
/// assert!(rendered.contains("NodeByLabelScan(n:Person)"));
/// ```
pub fn lower(query: &ValidatedQuery) -> LogicalOp {
    Planner::default().lower_query(query.query())
}

/// The lowering driver. Carries only the synthetic-variable counter, so anonymous pattern elements
/// across the whole query get distinct generated names.
#[derive(Default)]
struct Planner {
    /// Monotonic counter feeding [`Var::synthetic`] for anonymous nodes/relationships.
    anon_counter: usize,
}

impl Planner {
    /// Lowers a whole [`Query`]: a `UNION` chain or a standalone `CALL`.
    fn lower_query(&mut self, query: &Query) -> LogicalOp {
        match &query.body {
            QueryBody::Regular { head, unions } => self.lower_union_chain(head, unions),
            QueryBody::StandaloneCall(call) => self.lower_standalone_call(call),
        }
    }

    /// Folds a `UNION` chain left-associatively into [`Union`](LogicalOp::Union) operators.
    ///
    /// `a UNION b UNION ALL c` becomes `Union(all)( Union(distinct)(a, b), c )`. Each
    /// [`UnionPart`] carries the `ALL` flag of the `UNION` keyword that precedes its query, matching
    /// openCypher's left-associative `RegularQuery = SingleQuery, { Union }`.
    fn lower_union_chain(&mut self, head: &SingleQuery, unions: &[UnionPart]) -> LogicalOp {
        let mut acc = self.lower_single_query(head);
        for part in unions {
            let right = self.lower_single_query(&part.query);
            acc = LogicalOp::Union {
                left: Box::new(acc),
                right: Box::new(right),
                all: part.all,
            };
        }
        acc
    }

    /// Lowers a [`SingleQuery`]: thread the "plan so far" through the clause list left-to-right.
    ///
    /// `current` is `None` until the first clause establishes a row source; subsequent clauses build
    /// on it. A leading reading clause (`MATCH`/`UNWIND`/`CALL`) *creates* the source; a leading
    /// non-reading clause (`RETURN 1`, `CREATE (n)`) starts from [`Empty`](LogicalOp::Empty) (one
    /// row), matching Cypher's evaluation of a clause-with-no-driving-rows.
    fn lower_single_query(&mut self, sq: &SingleQuery) -> LogicalOp {
        let mut current: Option<LogicalOp> = None;
        for clause in &sq.clauses {
            current = Some(self.lower_clause(clause, current));
        }
        // Semantic analysis guarantees a non-empty query, so `current` is always `Some`. The
        // `unwrap_or` keeps the function total without a panic on the (unreachable) empty case.
        current.unwrap_or(LogicalOp::Empty)
    }

    /// Lowers one clause given the plan accumulated so far (`current`).
    fn lower_clause(&mut self, clause: &Clause, current: Option<LogicalOp>) -> LogicalOp {
        match clause {
            Clause::Match(m) => self.lower_match(m, current),
            Clause::Unwind(u) => self.lower_unwind(u, current),
            Clause::LoadCsv(l) => self.lower_load_csv(l, current),
            Clause::Call(c) => self.lower_in_query_call(c, current),
            Clause::Create(c) => self.lower_create(c, current),
            Clause::Merge(m) => self.lower_merge(m, current),
            Clause::Set(s) => self.lower_set(s, current),
            Clause::Delete(d) => self.lower_delete(d, current),
            Clause::Remove(r) => self.lower_remove(r, current),
            Clause::With(w) => {
                self.lower_projection_body(&w.body, w.where_clause.as_ref(), w.span, current)
            }
            Clause::Return(r) => self.lower_projection_body(&r.body, None, r.span, current),
        }
    }

    // ---- MATCH / OPTIONAL MATCH -------------------------------------------------------------

    /// Lowers a `MATCH` / `OPTIONAL MATCH`.
    ///
    /// The pattern parts lower to scans + expands (+ inline-property filters). A trailing `WHERE`
    /// becomes a [`Filter`](LogicalOp::Filter) above the whole pattern (a `WHERE` may reference any
    /// variable bound by the pattern, so it is **not** pushed below the scans). For
    /// `OPTIONAL MATCH`, the whole pattern (with its `WHERE`) is wrapped per
    /// [Optional](crate::lower#optional-match): planned over an [`Argument`](LogicalOp::Argument),
    /// wrapped in [`Optional`](LogicalOp::Optional), and applied to the prior plan.
    fn lower_match(&mut self, m: &MatchClause, current: Option<LogicalOp>) -> LogicalOp {
        if m.optional {
            self.lower_optional_match(m, current)
        } else {
            self.lower_required_match(m, current)
        }
    }

    /// Required (non-optional) `MATCH`: lower the pattern over the prior plan, then `WHERE`.
    fn lower_required_match(&mut self, m: &MatchClause, current: Option<LogicalOp>) -> LogicalOp {
        let mut plan = self.lower_pattern_parts(&m.pattern, current);
        if let Some(pred) = &m.where_clause {
            plan = LogicalOp::Filter {
                input: Box::new(plan),
                predicate: pred.clone(),
            };
        }
        plan
    }

    /// `OPTIONAL MATCH`: left-outer via `Apply(left, Optional(rhs))`.
    ///
    /// With no prior plan (a leading `OPTIONAL MATCH`), there is no outer row to preserve, so it is
    /// just the required-match lowering. Otherwise the optional pattern is planned with its leaf
    /// scans correlated to the carried bindings (an [`Argument`](LogicalOp::Argument) base), wrapped
    /// in [`Optional`](LogicalOp::Optional) over the variables it introduces, and applied.
    fn lower_optional_match(&mut self, m: &MatchClause, current: Option<LogicalOp>) -> LogicalOp {
        let Some(left) = current else {
            // Leading OPTIONAL MATCH has no left row to preserve; it behaves like MATCH.
            return self.lower_required_match(m, None);
        };

        let arguments = collect_bound_vars(&left);
        let argument = LogicalOp::Argument {
            arguments: arguments.clone(),
        };

        // Plan the optional pattern correlated with the carried bindings, then its WHERE.
        let mut rhs = self.lower_pattern_parts(&m.pattern, Some(argument));
        if let Some(pred) = &m.where_clause {
            rhs = LogicalOp::Filter {
                input: Box::new(rhs),
                predicate: pred.clone(),
            };
        }

        // The variables the optional pattern *newly* introduces are null-filled on the no-match
        // path. These are the pattern's bound variables minus the carried-in arguments.
        let mut null_variables = self.pattern_introduced_vars(&m.pattern);
        null_variables.retain(|v| !arguments.contains(v));

        let optional = LogicalOp::Optional {
            input: Box::new(rhs),
            null_variables,
        };
        LogicalOp::Apply {
            left: Box::new(left),
            right: Box::new(optional),
        }
    }

    /// Lowers the comma-separated pattern parts of a `MATCH` over `current`.
    ///
    /// Each part is lowered in turn, threading the plan so later parts are correlated with earlier
    /// ones (a cross-pattern shared variable is just a binding already present in the plan).
    fn lower_pattern_parts(
        &mut self,
        parts: &[PatternPart],
        current: Option<LogicalOp>,
    ) -> LogicalOp {
        let mut plan = current;
        for part in parts {
            plan = Some(self.lower_pattern_part(part, plan));
        }
        plan.unwrap_or(LogicalOp::Empty)
    }

    /// Lowers one pattern part (a node, then a chain of `relationship node` links) over `current`.
    ///
    /// The anchor node becomes a scan (or, if it is already bound by `current`, reuses that
    /// binding); each chain link becomes an [`Expand`](LogicalOp::Expand). Inline property maps are
    /// hoisted to [`Filter`](LogicalOp::Filter)s immediately above their binding operator
    /// (the [Normalisation](crate::lower#normalisation) rule).
    fn lower_pattern_part(&mut self, part: &PatternPart, current: Option<LogicalOp>) -> LogicalOp {
        let element = &part.element;
        // The anchor node: scan it unless `current` already binds it, then filter on inline props.
        let anchor_var = self.node_var(&element.start);
        let mut plan = match current {
            // Already have a plan: if it binds the anchor, the node is shared (correlated); we do
            // not re-scan. Otherwise a comma-pattern introduces a fresh disconnected component,
            // which the physical planner turns into a (cartesian) join; logically we expand from a
            // fresh scan correlated with the existing plan via Apply over an Argument.
            Some(plan) if plan_binds(&plan, &anchor_var) => plan,
            Some(plan) => {
                let scan = self.scan_node(&element.start, &anchor_var);
                let args = collect_bound_vars(&plan);
                // Correlate the new component with the carried bindings.
                let scan = self.correlate_scan(scan, args);
                LogicalOp::Apply {
                    left: Box::new(plan),
                    right: Box::new(scan),
                }
            }
            None => self.scan_node(&element.start, &anchor_var),
        };
        plan = self.filter_inline_props(plan, element.start.properties.as_ref(), &anchor_var);

        // Each chain link: expand to the next node, then filter the link's inline props.
        let mut from = anchor_var;
        for link in &element.chain {
            let rel_var = self.rel_var(&link.relationship);
            let to_var = self.node_var(&link.node);
            plan = LogicalOp::Expand {
                input: Box::new(plan),
                from: from.clone(),
                relationship: rel_var.clone(),
                to: to_var.clone(),
                direction: link.relationship.direction,
                types: link.relationship.types.clone(),
                range: link.relationship.range,
            };
            plan = self.filter_inline_props(plan, link.relationship.properties.as_ref(), &rel_var);
            plan = self.filter_inline_props(plan, link.node.properties.as_ref(), &to_var);
            from = to_var;
        }
        plan
    }

    /// Wraps a fresh leaf scan so it reads from an [`Argument`](LogicalOp::Argument) of the carried
    /// bindings, making a disconnected comma-pattern component correlated rather than free.
    ///
    /// In the logical plan a [`NodeByLabelScan`]/[`AllNodesScan`] is itself a leaf; to attach it as
    /// the right side of an [`Apply`](LogicalOp::Apply) we keep the scan as-is (it ignores the
    /// argument row's columns and produces its own). The [`Argument`](LogicalOp::Argument) is the
    /// `Apply`'s correlation contract; the scan does not need to read it, so we return the scan
    /// unchanged here. (Kept as a named step so the correlation intent is explicit and so the
    /// physical planner can later choose expand-into when the component connects back.)
    fn correlate_scan(&mut self, scan: LogicalOp, _args: Vec<Var>) -> LogicalOp {
        scan
    }

    /// Builds the leaf scan for an anchor node: a label scan if it has labels (using the first
    /// label — the others, if any, become a [`Filter`] via inline handling), else an all-nodes
    /// scan.
    ///
    /// Choosing the *first* label keeps the plan label-logical: the physical planner picks which
    /// label index (if any) to seek and adds the residual label checks (`04 §7.1`). When a node has
    /// multiple labels we still emit one [`NodeByLabelScan`] plus a [`Filter`] on the remaining
    /// labels so the logical plan is complete and index-agnostic.
    fn scan_node(&mut self, node: &NodePattern, var: &Var) -> LogicalOp {
        if let Some(first) = node.labels.first() {
            let mut plan = LogicalOp::NodeByLabelScan {
                variable: var.clone(),
                label: first.clone(),
            };
            if node.labels.len() > 1 {
                // Residual labels become a HasLabels filter over the remaining labels.
                let predicate = Expr::new(
                    ExprKind::HasLabels {
                        operand: Box::new(Expr::new(
                            ExprKind::Variable(var.name.clone()),
                            node.span,
                        )),
                        labels: node.labels[1..].to_vec(),
                    },
                    node.span,
                );
                plan = LogicalOp::Filter {
                    input: Box::new(plan),
                    predicate,
                };
            }
            plan
        } else {
            LogicalOp::AllNodesScan {
                variable: var.clone(),
            }
        }
    }

    /// If `properties` is an inline map literal, hoist it into an equality
    /// [`Filter`](LogicalOp::Filter) on `entity` placed immediately above `plan` (the scan/expand
    /// that just bound `entity`). A `null` value still produces `entity.k = null`, whose runtime
    /// three-valued result drops the row — matching Cypher's inline-property semantics
    /// (`04 §7.6`). A parameter-form property map (`MATCH (n $props)`) is left for the executor:
    /// its keys are unknown until bind time, so it cannot be decomposed into static equalities here
    /// — the planner keeps it as a parameter filter.
    fn filter_inline_props(
        &mut self,
        plan: LogicalOp,
        properties: Option<&Expr>,
        entity: &Var,
    ) -> LogicalOp {
        let Some(props) = properties else {
            return plan;
        };
        match &props.kind {
            ExprKind::Map(entries) => {
                let mut plan = plan;
                for (key, value) in entries {
                    let lhs = Expr::new(
                        ExprKind::Property {
                            base: Box::new(Expr::new(
                                ExprKind::Variable(entity.name.clone()),
                                props.span,
                            )),
                            key: key.name.clone(),
                        },
                        props.span,
                    );
                    let predicate = Expr::new(
                        ExprKind::Binary {
                            op: crate::ast::BinaryOp::Eq,
                            lhs: Box::new(lhs),
                            rhs: Box::new(value.clone()),
                        },
                        props.span,
                    );
                    plan = LogicalOp::Filter {
                        input: Box::new(plan),
                        predicate,
                    };
                }
                plan
            }
            // A parameter (`$props`) map: keep as a single opaque property-match filter so the
            // executor can resolve it at bind time. We model it as `entity = $props`-style equality
            // over the property map by reusing the parameter expr against the entity variable.
            ExprKind::Parameter(_) => {
                let predicate = Expr::new(
                    ExprKind::Binary {
                        op: crate::ast::BinaryOp::Eq,
                        lhs: Box::new(Expr::new(
                            ExprKind::Variable(entity.name.clone()),
                            props.span,
                        )),
                        rhs: Box::new(props.clone()),
                    },
                    props.span,
                );
                LogicalOp::Filter {
                    input: Box::new(plan),
                    predicate,
                }
            }
            // The semantic/parse phases restrict pattern properties to map literals or parameters,
            // so other forms are unreachable; keep the plan unchanged to stay total.
            _ => plan,
        }
    }

    // ---- UNWIND -----------------------------------------------------------------------------

    fn lower_unwind(&mut self, u: &UnwindClause, current: Option<LogicalOp>) -> LogicalOp {
        let input = current.unwrap_or(LogicalOp::Empty);
        LogicalOp::Unwind {
            input: Box::new(input),
            list: u.expr.clone(),
            variable: Var::named(&u.alias.name),
        }
    }

    // ---- LOAD CSV ---------------------------------------------------------------------------

    /// Lowers `LOAD CSV ... FROM e AS v` to a [`LoadCsv`](LogicalOp::LoadCsv) source over the plan so
    /// far (the [`Empty`](LogicalOp::Empty) single row for a leading `LOAD CSV`), exactly as
    /// [`lower_unwind`](Self::lower_unwind) treats `UNWIND` — each CSV record becomes one row bound to
    /// `v`, fanned across the incoming rows.
    fn lower_load_csv(&mut self, l: &LoadCsvClause, current: Option<LogicalOp>) -> LogicalOp {
        let input = current.unwrap_or(LogicalOp::Empty);
        LogicalOp::LoadCsv {
            input: Box::new(input),
            with_headers: l.with_headers,
            url: l.url.clone(),
            variable: Var::named(&l.alias.name),
            field_terminator: l.field_terminator,
        }
    }

    // ---- CALL ... YIELD ---------------------------------------------------------------------

    /// Lowers an in-query `CALL … YIELD`. Leading, it is a row source; after other clauses it is
    /// correlated via [`Apply`](LogicalOp::Apply) over an [`Argument`](LogicalOp::Argument).
    fn lower_in_query_call(
        &mut self,
        c: &crate::ast::CallClause,
        current: Option<LogicalOp>,
    ) -> LogicalOp {
        let yields = c.yield_items.as_ref().map(|items| {
            items
                .iter()
                .map(|y| YieldColumn {
                    field: y.field.clone(),
                    variable: Var::named(&y.alias.name),
                })
                .collect()
        });

        let call = match current {
            None => LogicalOp::ProcedureCall {
                input: None,
                name: c.call.name.clone(),
                args: c.call.args.clone(),
                yields,
            },
            Some(left) => {
                let args = collect_bound_vars(&left);
                let correlated = LogicalOp::ProcedureCall {
                    input: Some(Box::new(LogicalOp::Argument { arguments: args })),
                    name: c.call.name.clone(),
                    args: c.call.args.clone(),
                    yields,
                };
                LogicalOp::Apply {
                    left: Box::new(left),
                    right: Box::new(correlated),
                }
            }
        };

        // A `YIELD … WHERE pred` filters the yielded rows.
        if let Some(pred) = &c.where_clause {
            LogicalOp::Filter {
                input: Box::new(call),
                predicate: pred.clone(),
            }
        } else {
            call
        }
    }

    /// Lowers a standalone `CALL` (the whole statement is a procedure call).
    fn lower_standalone_call(&mut self, call: &StandaloneCall) -> LogicalOp {
        let yields = match &call.yield_clause {
            None | Some(StandaloneYield::Star) => None,
            Some(StandaloneYield::Items { items, .. }) => Some(
                items
                    .iter()
                    .map(|y| YieldColumn {
                        field: y.field.clone(),
                        variable: Var::named(&y.alias.name),
                    })
                    .collect(),
            ),
        };
        let call_op = LogicalOp::ProcedureCall {
            input: None,
            name: call.call.name.clone(),
            args: call.call.args.clone(),
            yields,
        };
        // A standalone `YIELD … WHERE` filters the result rows.
        if let Some(StandaloneYield::Items {
            where_clause: Some(pred),
            ..
        }) = &call.yield_clause
        {
            LogicalOp::Filter {
                input: Box::new(call_op),
                predicate: pred.clone(),
            }
        } else {
            call_op
        }
    }

    // ---- WITH / RETURN (projection boundary) ------------------------------------------------

    /// Lowers a `WITH`/`RETURN` [`ProjectionBody`] (the projection boundary).
    ///
    /// The stacking order follows the openCypher grammar (`ProjectionBody = [DISTINCT] items
    /// [Order] [Skip] [Limit]`) and Cypher's evaluation order: **project/aggregate first**, then
    /// `ORDER BY`, then `SKIP`, then `LIMIT`, then a trailing `WITH … WHERE`:
    ///
    /// ```text
    /// (WHERE) ▸ Limit ▸ Skip ▸ Sort ▸ Projection|Aggregation ▸ input
    /// ```
    ///
    /// `DISTINCT` rides on the [`Projection`](LogicalOp::Projection). When the body aggregates, the
    /// projection becomes an [`Aggregation`](LogicalOp::Aggregation) whose group keys are the
    /// non-aggregating items and whose aggregates are the aggregating items (the semantic pass
    /// already proved the split is unambiguous, [`crate::semantics`]).
    fn lower_projection_body(
        &mut self,
        body: &ProjectionBody,
        where_clause: Option<&Expr>,
        clause_span: Span,
        current: Option<LogicalOp>,
    ) -> LogicalOp {
        let input = current.unwrap_or(LogicalOp::Empty);

        // Build the projected columns. `*` carries through the incoming bindings; the planner does
        // not know the runtime column set, so `*` is represented by projecting each currently-bound
        // variable as itself (a faithful, index-agnostic expansion). openCypher orders the
        // `*`-expanded columns alphabetically by variable name (the TCK asserts this shape).
        let mut star_cols: Vec<ProjectionColumn> = Vec::new();
        if body.star {
            for v in collect_bound_vars(&input) {
                // Planner-introduced synthetic variables (anonymous pattern parts) are not
                // user-visible bindings; `*` must never project them.
                if v.synthetic {
                    continue;
                }
                star_cols.push(ProjectionColumn {
                    expr: Expr::new(ExprKind::Variable(v.name.clone()), clause_span),
                    alias: v.name.clone(),
                });
            }
            star_cols.sort_by(|a, b| a.alias.cmp(&b.alias));
        }
        let explicit_cols: Vec<ProjectionColumn> = body
            .items
            .iter()
            .map(|item| self.projection_column(item))
            .collect();

        let mut plan = if body_aggregates(body) {
            // Partition explicit items into grouping keys and aggregates. `*`-carried columns are
            // always grouping keys (bare variables).
            let mut group_keys = star_cols;
            let mut aggregates = Vec::new();
            // The result shape must keep the source column order (`RETURN n.a AS a, count(*) AS c,
            // n.b AS b` yields columns a, c, b), but the Aggregation operator emits its keys first,
            // then the aggregates. Track the source order and restore it with a re-ordering
            // projection when the two differ.
            let mut source_order: Vec<String> =
                group_keys.iter().map(|c| c.alias.clone()).collect();
            for (item, col) in body.items.iter().zip(explicit_cols) {
                source_order.push(col.alias.clone());
                if expr_contains_aggregate(&item.expr) {
                    aggregates.push(col);
                } else {
                    group_keys.push(col);
                }
            }
            let emitted: Vec<String> = group_keys
                .iter()
                .chain(&aggregates)
                .map(|c| c.alias.clone())
                .collect();
            let agg = LogicalOp::Aggregation {
                input: Box::new(input),
                group_keys,
                aggregates,
            };
            if emitted == source_order {
                agg
            } else {
                let items = source_order
                    .into_iter()
                    .map(|name| ProjectionColumn {
                        expr: Expr::new(ExprKind::Variable(name.clone()), clause_span),
                        alias: name,
                    })
                    .collect();
                LogicalOp::Projection {
                    input: Box::new(agg),
                    items,
                    distinct: false,
                }
            }
        } else {
            let mut items = star_cols;
            items.extend(explicit_cols);
            LogicalOp::Projection {
                input: Box::new(input),
                items,
                distinct: body.distinct,
            }
        };

        // ORDER BY ▸ SKIP ▸ LIMIT, then WHERE (post-projection scope).
        if !body.order_by.is_empty() {
            let keys = body
                .order_by
                .iter()
                .map(|s| SortKey {
                    expr: s.expr.clone(),
                    direction: s.direction,
                })
                .collect();
            plan = LogicalOp::Sort {
                input: Box::new(plan),
                keys,
            };
        }
        if let Some(skip) = &body.skip {
            plan = LogicalOp::Skip {
                input: Box::new(plan),
                count: skip.clone(),
            };
        }
        if let Some(limit) = &body.limit {
            plan = LogicalOp::Limit {
                input: Box::new(plan),
                count: limit.clone(),
            };
        }
        if let Some(pred) = where_clause {
            plan = LogicalOp::Filter {
                input: Box::new(plan),
                predicate: pred.clone(),
            };
        }
        plan
    }

    /// Lowers one projection item to a [`ProjectionColumn`], using the explicit `AS` alias or
    /// Cypher's inferred column name.
    ///
    /// openCypher names an un-aliased column by the expression's **verbatim source text** (captured
    /// by the parser into [`ProjectionItem::verbatim`]): `RETURN a.x` yields a column named `a.x`,
    /// `RETURN 1 + 2` one named `1 + 2`. A bare variable is named by the variable itself, so a
    /// backtick-escaped `` RETURN `x` `` yields column `x` (no backticks).
    fn projection_column(&self, item: &ProjectionItem) -> ProjectionColumn {
        let alias = match &item.alias {
            Some(a) => a.name.clone(),
            None => match &item.expr.kind {
                ExprKind::Variable(n) => n.clone(),
                _ => item.verbatim.clone(),
            },
        };
        ProjectionColumn {
            expr: item.expr.clone(),
            alias,
        }
    }

    // ---- CREATE / MERGE / SET / DELETE / REMOVE ---------------------------------------------

    fn lower_create(&mut self, c: &CreateClause, current: Option<LogicalOp>) -> LogicalOp {
        let input = current.unwrap_or(LogicalOp::Empty);
        let pattern = self.lower_create_parts(&c.pattern);
        LogicalOp::Create {
            input: Box::new(input),
            pattern,
        }
    }

    fn lower_merge(&mut self, m: &MergeClause, current: Option<LogicalOp>) -> LogicalOp {
        let input = current.unwrap_or(LogicalOp::Empty);
        let pattern = self.lower_create_parts(std::slice::from_ref(&m.pattern));
        let mut on_create = Vec::new();
        let mut on_match = Vec::new();
        for action in &m.actions {
            match action {
                MergeAction::OnCreate(items) => {
                    on_create.extend(items.iter().map(lower_set_item));
                }
                MergeAction::OnMatch(items) => {
                    on_match.extend(items.iter().map(lower_set_item));
                }
            }
        }
        LogicalOp::Merge {
            input: Box::new(input),
            pattern,
            on_create,
            on_match,
        }
    }

    fn lower_set(&mut self, s: &SetClause, current: Option<LogicalOp>) -> LogicalOp {
        let input = current.unwrap_or(LogicalOp::Empty);
        let ops = s.items.iter().map(lower_set_item).collect();
        LogicalOp::SetClause {
            input: Box::new(input),
            ops,
        }
    }

    fn lower_delete(&mut self, d: &DeleteClause, current: Option<LogicalOp>) -> LogicalOp {
        let input = current.unwrap_or(LogicalOp::Empty);
        LogicalOp::Delete {
            input: Box::new(input),
            detach: d.detach,
            exprs: d.exprs.clone(),
        }
    }

    fn lower_remove(&mut self, r: &RemoveClause, current: Option<LogicalOp>) -> LogicalOp {
        let input = current.unwrap_or(LogicalOp::Empty);
        let ops = r
            .items
            .iter()
            .map(|item| match item {
                RemoveItem::Labels { target, labels } => RemoveOp::Labels {
                    target: Var::named(&target.name),
                    labels: labels.clone(),
                },
                RemoveItem::Property(expr) => RemoveOp::Property {
                    target: expr.clone(),
                },
            })
            .collect();
        LogicalOp::Remove {
            input: Box::new(input),
            ops,
        }
    }

    /// Lowers create/merge pattern parts into the flat [`CreatePart`] list.
    ///
    /// Each pattern element becomes one [`CreatePart::Node`] per node and one
    /// [`CreatePart::Relationship`] per chain link. The semantic pass guarantees each created
    /// relationship has exactly one type, a direction, and no variable-length range, so the planner
    /// can take the single type unconditionally.
    fn lower_create_parts(&mut self, parts: &[PatternPart]) -> Vec<CreatePart> {
        let mut out = Vec::new();
        for part in parts {
            self.lower_create_element(&part.element, &mut out);
        }
        out
    }

    fn lower_create_element(&mut self, element: &PatternElement, out: &mut Vec<CreatePart>) {
        let mut from = self.node_var(&element.start);
        out.push(CreatePart::Node {
            variable: from.clone(),
            labels: element.start.labels.clone(),
            properties: element.start.properties.clone(),
        });
        for link in &element.chain {
            let to = self.node_var(&link.node);
            out.push(CreatePart::Node {
                variable: to.clone(),
                labels: link.node.labels.clone(),
                properties: link.node.properties.clone(),
            });
            let rel_var = self.rel_var(&link.relationship);
            // Semantic analysis guarantees exactly one type on a created relationship.
            let rel_type = link
                .relationship
                .types
                .first()
                .cloned()
                .unwrap_or_else(|| RelType {
                    name: String::new(),
                    span: link.relationship.span,
                });
            out.push(CreatePart::Relationship {
                variable: rel_var,
                from: from.clone(),
                to: to.clone(),
                rel_type,
                direction: link.relationship.direction,
                properties: link.relationship.properties.clone(),
            });
            from = to;
        }
    }

    // ---- variable naming --------------------------------------------------------------------

    /// The [`Var`] for a node pattern: its written variable, or a fresh synthetic name.
    fn node_var(&mut self, node: &NodePattern) -> Var {
        match &node.variable {
            Some(v) => Var::named(&v.name),
            None => self.fresh_synthetic(),
        }
    }

    /// The [`Var`] for a relationship pattern: its written variable, or a fresh synthetic name.
    fn rel_var(&mut self, rel: &RelationshipPattern) -> Var {
        match &rel.variable {
            Some(v) => Var::named(&v.name),
            None => self.fresh_synthetic(),
        }
    }

    fn fresh_synthetic(&mut self) -> Var {
        let v = Var::synthetic(self.anon_counter);
        self.anon_counter += 1;
        v
    }

    /// The set of variables a `MATCH` pattern introduces (named node/rel/path variables only —
    /// anonymous elements introduce nothing referenceable). Used to compute an
    /// `OPTIONAL MATCH`'s null-filled columns.
    fn pattern_introduced_vars(&self, parts: &[PatternPart]) -> Vec<Var> {
        let mut out = Vec::new();
        for part in parts {
            if let Some(v) = &part.var {
                push_unique(&mut out, Var::named(&v.name));
            }
            let element = &part.element;
            if let Some(v) = &element.start.variable {
                push_unique(&mut out, Var::named(&v.name));
            }
            for link in &element.chain {
                if let Some(v) = &link.relationship.variable {
                    push_unique(&mut out, Var::named(&v.name));
                }
                if let Some(v) = &link.node.variable {
                    push_unique(&mut out, Var::named(&v.name));
                }
            }
        }
        out
    }
}

// =================================================================================================
// Free helpers
// =================================================================================================

/// Lowers an AST [`SetItem`] to a logical [`SetOp`].
fn lower_set_item(item: &SetItem) -> SetOp {
    match item {
        SetItem::Property { target, value } => SetOp::Property {
            target: target.clone(),
            value: value.clone(),
        },
        SetItem::Replace { target, value } => SetOp::ReplaceProperties {
            target: Var::named(&target.name),
            value: value.clone(),
        },
        SetItem::Merge { target, value } => SetOp::MergeProperties {
            target: Var::named(&target.name),
            value: value.clone(),
        },
        SetItem::Labels { target, labels } => SetOp::AddLabels {
            target: Var::named(&target.name),
            labels: labels.clone(),
        },
    }
}

/// Whether a projection/with body is an **aggregating** projection (some item contains an
/// aggregate). Mirrors the semantic pass's rule ([`crate::semantics`]).
fn body_aggregates(body: &ProjectionBody) -> bool {
    body.items
        .iter()
        .any(|it| expr_contains_aggregate(&it.expr))
}

/// Whether `expr` contains an aggregating function call (or the `count(*)` atom) anywhere.
fn expr_contains_aggregate(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::CountStar => true,
        ExprKind::FunctionCall { name, .. } if function_registry::is_aggregate(&name.join(".")) => {
            true
        }
        ExprKind::FunctionCall { args, .. } => args.iter().any(expr_contains_aggregate),
        ExprKind::Binary { lhs, rhs, .. } => {
            expr_contains_aggregate(lhs) || expr_contains_aggregate(rhs)
        }
        ExprKind::Unary { operand, .. } | ExprKind::HasLabels { operand, .. } => {
            expr_contains_aggregate(operand)
        }
        ExprKind::Predicate { operand, rhs, .. } => {
            expr_contains_aggregate(operand) || rhs.as_deref().is_some_and(expr_contains_aggregate)
        }
        ExprKind::Property { base, .. } => expr_contains_aggregate(base),
        ExprKind::Index { base, index } => {
            expr_contains_aggregate(base) || expr_contains_aggregate(index)
        }
        ExprKind::Slice { base, low, high } => {
            expr_contains_aggregate(base)
                || low.as_deref().is_some_and(expr_contains_aggregate)
                || high.as_deref().is_some_and(expr_contains_aggregate)
        }
        ExprKind::List(items) => items.iter().any(expr_contains_aggregate),
        ExprKind::Map(entries) => entries.iter().any(|(_, v)| expr_contains_aggregate(v)),
        ExprKind::Case(case) => {
            case.subject.as_deref().is_some_and(expr_contains_aggregate)
                || case.alternatives.iter().any(|alt| {
                    expr_contains_aggregate(&alt.when) || expr_contains_aggregate(&alt.then)
                })
                || case
                    .else_expr
                    .as_deref()
                    .is_some_and(expr_contains_aggregate)
        }
        ExprKind::Literal(_) | ExprKind::Parameter(_) | ExprKind::Variable(_) => false,
        // Comprehensions, quantifiers and existential subqueries establish their own scope; an
        // aggregate cannot legally appear inside (the semantic pass rejects it), so they never
        // contribute an aggregate here.
        ExprKind::ListComprehension(_)
        | ExprKind::PatternComprehension(_)
        | ExprKind::Quantifier(_)
        | ExprKind::ExistsSubquery(_) => false,
    }
}

/// Pushes `var` into `out` only if a variable of the same name is not already present.
fn push_unique(out: &mut Vec<Var>, var: Var) {
    if !out.iter().any(|v| v.name == var.name) {
        out.push(var);
    }
}

/// Whether `plan` already binds a variable named like `var` (so a repeated pattern variable is a
/// shared binding, not a re-scan).
fn plan_binds(plan: &LogicalOp, var: &Var) -> bool {
    collect_bound_vars(plan).iter().any(|v| v.name == var.name)
}

/// Collects the variables a (sub)plan binds, in a stable order (the order they are introduced,
/// de-duplicated by name).
///
/// Used to populate the [`Argument`](LogicalOp::Argument) of a correlated subplan and the
/// `*`-expansion of a projection. It walks the operator tree gathering each operator's *output*
/// bindings: scans/expands/unwind introduce their variables; projections/aggregations *reset* the
/// visible set to their output columns (the projection-boundary rule, `04 §7.3`).
fn collect_bound_vars(plan: &LogicalOp) -> Vec<Var> {
    let mut out = Vec::new();
    gather_bound_vars(plan, &mut out);
    out
}

fn gather_bound_vars(plan: &LogicalOp, out: &mut Vec<Var>) {
    match plan {
        LogicalOp::AllNodesScan { variable } | LogicalOp::NodeByLabelScan { variable, .. } => {
            push_unique(out, variable.clone());
        }
        LogicalOp::AllRelationshipsScan {
            relationship,
            from,
            to,
            ..
        } => {
            push_unique(out, from.clone());
            push_unique(out, relationship.clone());
            push_unique(out, to.clone());
        }
        LogicalOp::Argument { arguments } => {
            for a in arguments {
                push_unique(out, a.clone());
            }
        }
        LogicalOp::Empty => {}
        LogicalOp::Expand {
            input,
            relationship,
            to,
            ..
        } => {
            gather_bound_vars(input, out);
            push_unique(out, relationship.clone());
            push_unique(out, to.clone());
        }
        LogicalOp::Filter { input, .. }
        | LogicalOp::Skip { input, .. }
        | LogicalOp::Limit { input, .. }
        | LogicalOp::Sort { input, .. } => gather_bound_vars(input, out),
        LogicalOp::Unwind {
            input, variable, ..
        }
        | LogicalOp::LoadCsv {
            input, variable, ..
        } => {
            gather_bound_vars(input, out);
            push_unique(out, variable.clone());
        }
        LogicalOp::Projection { items, .. } => {
            // A projection RESETS the visible bindings to exactly its output columns.
            out.clear();
            for col in items {
                push_unique(out, Var::named(&col.alias));
            }
        }
        LogicalOp::Aggregation {
            group_keys,
            aggregates,
            ..
        } => {
            out.clear();
            for col in group_keys.iter().chain(aggregates) {
                push_unique(out, Var::named(&col.alias));
            }
        }
        LogicalOp::Apply { left, right } => {
            gather_bound_vars(left, out);
            gather_bound_vars(right, out);
        }
        LogicalOp::Optional {
            input,
            null_variables,
        } => {
            gather_bound_vars(input, out);
            for v in null_variables {
                push_unique(out, v.clone());
            }
        }
        LogicalOp::Union { left, .. } => {
            // Both branches are union-compatible; take the left branch's columns as the result
            // schema (they share column names by the union-compatibility rule).
            gather_bound_vars(left, out);
        }
        // Write operators carry their input's bindings forward and may add the created/merged
        // entity variables; the planner threads them through unchanged here (the executor binds
        // created entities).
        LogicalOp::Create { input, pattern } | LogicalOp::Merge { input, pattern, .. } => {
            gather_bound_vars(input, out);
            for part in pattern {
                match part {
                    CreatePart::Node { variable, .. }
                    | CreatePart::Relationship { variable, .. } => {
                        push_unique(out, variable.clone());
                    }
                }
            }
        }
        LogicalOp::SetClause { input, .. }
        | LogicalOp::Delete { input, .. }
        | LogicalOp::Remove { input, .. } => gather_bound_vars(input, out),
        LogicalOp::ProcedureCall { input, yields, .. } => {
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

#[cfg(test)]
mod tests {
    //! Focused unit tests for the lowering helpers; the broad, scenario-style plan-shape assertions
    //! live in `tests/logical_planner.rs`.
    use super::*;
    use crate::lexer::tokenize;
    use crate::parser::parse_tokens;
    use crate::semantics::analyze;

    fn plan_of(src: &str) -> LogicalOp {
        let toks = tokenize(src).expect("lexes");
        let ast = parse_tokens(&toks, src).expect("parses");
        let validated = analyze(&ast).expect("analyses");
        lower(&validated)
    }

    #[test]
    fn collect_bound_vars_resets_at_projection() {
        // After a WITH that projects only `m`, the visible bindings are just `m` (the reset rule).
        let plan = plan_of("MATCH (n) WITH n AS m RETURN m");
        // The root is the RETURN projection over the WITH projection; the WITH must have reset to
        // `m`, so the RETURN's input exposes only `m`.
        if let LogicalOp::Projection { input, .. } = &plan {
            let vars = collect_bound_vars(input);
            assert_eq!(vars.len(), 1);
            assert_eq!(vars[0].name, "m");
        } else {
            panic!("expected a Projection root, got {plan}");
        }
    }

    #[test]
    fn synthetic_vars_are_distinct() {
        let mut p = Planner::default();
        let a = p.fresh_synthetic();
        let b = p.fresh_synthetic();
        assert_ne!(a.name, b.name);
        assert!(a.synthetic && b.synthetic);
    }

    #[test]
    fn unaliased_column_takes_verbatim_source_text() {
        let toks = tokenize("RETURN n.a.b").unwrap();
        let ast = parse_tokens(&toks, "RETURN n.a.b").unwrap();
        if let Clause::Return(r) = &ast.body_single_query().clauses[0] {
            let col = Planner::default().projection_column(&r.body.items[0]);
            assert_eq!(col.alias, "n.a.b");
        } else {
            unreachable!()
        }
    }

    #[test]
    fn expr_contains_aggregate_detects_nested_count() {
        let toks = tokenize("RETURN 1 + count(*)").unwrap();
        let ast = parse_tokens(&toks, "RETURN 1 + count(*)").unwrap();
        if let Clause::Return(r) = &ast.body_single_query().clauses[0] {
            assert!(expr_contains_aggregate(&r.body.items[0].expr));
        } else {
            unreachable!()
        }
    }
}
