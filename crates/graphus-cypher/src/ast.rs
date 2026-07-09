//! The Cypher **abstract syntax tree** produced by the [`parser`](crate::parser).
//!
//! This module is the typed output of the recursive-descent + Pratt parser
//! (`04-technical-design.md` §7.1 — *"parser (hand-written recursive descent / Pratt) → AST"*). It
//! models the **core** of the openCypher query language; the shapes and field names track the
//! openCypher EBNF productions (M23, mirrored at
//! <https://s3.amazonaws.com/artifacts.opencypher.org/M23/cypher.ebnf>) so the AST reads as a direct
//! transcription of the grammar. Each major type cites the production it implements.
//!
//! # What an AST node carries
//!
//! Every node records a byte [`Span`] into the original query so that a later
//! **semantic** pass (the next sub-task) can raise compile-time errors with precise positions
//! (`04 §7.3`); the parser itself only raises **syntax** errors (see [`SyntaxError`](crate::parser::SyntaxError)).
//! The span on a composite node covers its full extent (first token start .. last token end).
//!
//! # Relationship to the value model
//!
//! Literal *values* reuse nothing from [`graphus_core::Value`] directly — the AST keeps literals in
//! their **unevaluated** form ([`Literal`]) because a literal in source text (e.g. an integer beyond
//! `i64`, or a map literal) is a syntactic construct whose evaluation / range-checking belongs to
//! later phases (`04 §7.3`). Decoded payloads (string contents, the integer magnitude + base) come
//! straight from the [`lexer`](crate::lexer) tokens.
//!
//! # Scope and deferrals
//!
//! The covered surface and the explicitly-deferred productions are documented on
//! [`parser`](crate::parser); in short, the common read/write surface is covered and a few exotic
//! productions (`CALL { subquery }`, existential subqueries, quantifier predicates, DDL) are
//! deferred as named follow-ups rather than silently omitted.

use crate::lexer::Span;

/// A complete parsed Cypher statement: the top-level [`Cypher = Statement`] production.
///
/// A statement is either a regular query (one or more single queries joined by `UNION`) or a
/// standalone procedure `CALL` (openCypher `Query = RegularQuery | StandaloneCall`). The optional
/// trailing `;` is accepted and discarded by the parser.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct Query {
    /// An optional leading `USE <graph>` graph (database) selector (`rmp` #640). Parsed and exposed
    /// so the server can **route** the statement to the target database; the single-graph Cypher
    /// engine itself treats it as advisory metadata (see [`UseGraph`]).
    pub use_graph: Option<UseGraph>,
    /// The body of the query.
    pub body: QueryBody,
    /// The byte span covering the whole statement (excluding any trailing `;`).
    pub span: Span,
}

impl Query {
    /// The target graph of a leading `USE` clause, if any (`rmp` #640) — the routing hook the server
    /// reads to dispatch the statement to the correct per-database engine.
    #[must_use]
    pub fn use_graph(&self) -> Option<&UseGraph> {
        self.use_graph.as_ref()
    }
}

/// A `USE <graph>` graph (database) selector (`rmp` #640; openCypher / Neo4j 5.x `UseClause`).
///
/// The Cypher engine operates over a **single** graph, so database selection is performed *above* it
/// (in the server/engine), not inside query execution. This node therefore serves two roles:
///
/// 1. **Routing hook** — the parsed target [`name`](Self::name) (a simple name such as `neo4j`, or a
///    composite `namespace.constituent`) is exposed via [`Query::use_graph`] so the server can route
///    the statement to the correct database before it ever reaches the engine.
/// 2. **Self-consistency check** — [`targets`](Self::targets) lets a caller that already knows the
///    graph it is bound to confirm a `USE` names *that* graph (a no-op) versus a different one.
///
/// Graphus does not implement in-query cross-database execution; a `USE` naming a database other than
/// the one the connection is bound to must be resolved by the server's routing layer (or rejected
/// there). The engine never silently executes a `USE <other-db>` against the wrong graph — it simply
/// carries the selector through for the routing layer to honour.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct UseGraph {
    /// The dot-separated graph reference segments, in source order (e.g. `["neo4j"]` for `USE neo4j`,
    /// `["composite", "shard1"]` for `USE composite.shard1`). Always at least one segment.
    pub name: Vec<String>,
    /// The byte span covering the `USE <graph>` clause.
    pub span: Span,
}

impl UseGraph {
    /// The target graph reference rendered as a dotted string (e.g. `composite.shard1`).
    #[must_use]
    pub fn target(&self) -> String {
        self.name.join(".")
    }

    /// Whether this `USE` selects the graph named `current` (ASCII case-insensitive on each segment),
    /// i.e. it is a no-op for a connection already bound to that graph. A caller that knows its bound
    /// graph name uses this to distinguish a redundant `USE <current>` from a `USE <other>` that
    /// requires routing.
    #[must_use]
    pub fn targets(&self, current: &str) -> bool {
        self.target().eq_ignore_ascii_case(current)
    }

    /// Resolves this `USE` against the graph the connection is bound to (`current`), for a caller
    /// (the server's routing layer) that cannot switch databases mid-statement (`rmp` #640):
    ///
    /// * `Ok(())` when the `USE` names `current` — a redundant, no-op selector that the engine
    ///   executes normally against its single bound graph;
    /// * `Err(..)` when it names a **different** graph — a clear, Neo4j-like compile-time error, since
    ///   the single-graph engine cannot execute a cross-database query. A server that supports
    ///   routing should instead dispatch the statement to the target database's engine *before*
    ///   calling this; this is the fail-safe for when it cannot.
    ///
    /// # Errors
    ///
    /// Returns [`GraphusError::Compile`](graphus_core::GraphusError::Compile) when the target differs
    /// from `current`.
    pub fn check_target(&self, current: &str) -> Result<(), graphus_core::GraphusError> {
        if self.targets(current) {
            Ok(())
        } else {
            Err(graphus_core::GraphusError::Compile(format!(
                "USE clause selects database '{}', but this connection is bound to '{current}'. \
                 Cross-database queries are not supported on a standard database; connect to '{}' \
                 directly or route through a composite database.",
                self.target(),
                self.target(),
            )))
        }
    }
}

/// The body of a [`Query`]: a `UNION` chain of single queries, or a standalone `CALL`.
///
/// openCypher `Query = RegularQuery | StandaloneCall`, `RegularQuery = SingleQuery, { Union }`.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum QueryBody {
    /// One or more [`SingleQuery`] parts combined left-associatively by `UNION` / `UNION ALL`.
    ///
    /// The first element is the leftmost single query; each subsequent [`UnionPart`] records the
    /// `ALL` flag of the `UNION` that precedes its single query.
    Regular {
        /// The leftmost single query.
        head: SingleQuery,
        /// The `UNION [ALL] <single query>` continuations, in source order.
        unions: Vec<UnionPart>,
    },
    /// A standalone procedure call (`CALL proc(...) [YIELD ...]`) used as a whole statement.
    StandaloneCall(StandaloneCall),
}

/// One `UNION [ALL] <SingleQuery>` continuation of a regular query.
///
/// openCypher `Union = ('UNION', 'ALL', SingleQuery) | ('UNION', SingleQuery)`.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct UnionPart {
    /// `true` for `UNION ALL` (keep duplicates); `false` for plain `UNION` (distinct).
    pub all: bool,
    /// The single query on the right-hand side of this `UNION`.
    pub query: SingleQuery,
    /// Span from the `UNION` keyword to the end of the right-hand single query.
    pub span: Span,
}

/// A single query: a sequence of [`Clause`]s (openCypher `SingleQuery`).
///
/// The parser accepts the union of `SinglePartQuery` and `MultiPartQuery` as a flat clause list and
/// leaves clause-ordering validation (e.g. `RETURN` must be last, `WITH` separates parts) to the
/// semantic pass (`04 §7.3`) — the grammar's structural constraints beyond "a list of clauses" are
/// semantic, not syntactic, so enforcing them here would conflate the phases.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct SingleQuery {
    /// The clauses in source order.
    pub clauses: Vec<Clause>,
    /// Span covering all clauses.
    pub span: Span,
}

/// A top-level query clause (openCypher `ReadingClause | UpdatingClause | With | Return`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum Clause {
    /// `[OPTIONAL] MATCH <pattern> [WHERE <expr>]` (openCypher `Match`).
    Match(MatchClause),
    /// `UNWIND <expr> AS <var>` (openCypher `Unwind`).
    Unwind(UnwindClause),
    /// `LOAD CSV [WITH HEADERS] FROM <expr> AS <var> [FIELDTERMINATOR <char>]` (openCypher
    /// `LoadCSV`).
    LoadCsv(LoadCsvClause),
    /// `CALL proc(...) [YIELD ...]` used inside a query (openCypher `InQueryCall`).
    Call(CallClause),
    /// `CALL { <subquery> } [IN TRANSACTIONS [OF n ROWS]]` — a Cypher **subquery** (Neo4j
    /// `CallSubquery`). The braces hold a complete inner query (which may itself contain
    /// `UNION` / `UNION ALL`); it runs correlated, once per driving row.
    CallSubquery(CallSubqueryClause),
    /// `CREATE <pattern>` (openCypher `Create`).
    Create(CreateClause),
    /// `MERGE <pattern-part> { ON CREATE SET ... | ON MATCH SET ... }` (openCypher `Merge`).
    Merge(MergeClause),
    /// `SET <set-item>, ...` (openCypher `Set`).
    Set(SetClause),
    /// `[DETACH] DELETE <expr>, ...` (openCypher `Delete`).
    Delete(DeleteClause),
    /// `REMOVE <remove-item>, ...` (openCypher `Remove`).
    Remove(RemoveClause),
    /// `FOREACH ( <var> IN <expr> | <update-clause>+ )` (openCypher `Foreach`).
    Foreach(ForeachClause),
    /// `WITH <projection> [WHERE <expr>]` (openCypher `With`).
    With(WithClause),
    /// `RETURN <projection>` (openCypher `Return`).
    Return(ReturnClause),
}

impl Clause {
    /// The byte span of this clause.
    pub fn span(&self) -> Span {
        match self {
            Self::Match(c) => c.span,
            Self::Unwind(c) => c.span,
            Self::LoadCsv(c) => c.span,
            Self::Call(c) => c.span,
            Self::CallSubquery(c) => c.span,
            Self::Create(c) => c.span,
            Self::Merge(c) => c.span,
            Self::Set(c) => c.span,
            Self::Delete(c) => c.span,
            Self::Remove(c) => c.span,
            Self::Foreach(c) => c.span,
            Self::With(c) => c.span,
            Self::Return(c) => c.span,
        }
    }
}

/// `[OPTIONAL] MATCH <pattern> [WHERE <expr>]` (openCypher `Match`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct MatchClause {
    /// `true` if preceded by `OPTIONAL`.
    pub optional: bool,
    /// The comma-separated pattern parts (openCypher `Pattern`).
    pub pattern: Vec<PatternPart>,
    /// The optional `WHERE` predicate.
    pub where_clause: Option<Expr>,
    /// Span from `OPTIONAL`/`MATCH` to the end of the pattern or `WHERE` expression.
    pub span: Span,
}

/// `UNWIND <expr> AS <var>` (openCypher `Unwind`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct UnwindClause {
    /// The list expression to unwind.
    pub expr: Expr,
    /// The variable each element is bound to.
    pub alias: Variable,
    /// Span from `UNWIND` to the alias.
    pub span: Span,
}

/// `FOREACH ( <var> IN <list-expr> | <update-clause>+ )` (openCypher
/// `Foreach = FOREACH '(' Variable IN Expression '|' { UpdatingClause } ')'`).
///
/// A per-row side-effect clause: for each input row, the `list` expression is evaluated **once**, and
/// for every element the loop [`variable`](Self::variable) is bound and the [`body`](Self::body)
/// update clauses run in order. `FOREACH` does **not** change row cardinality — the driving row is
/// passed through unchanged — and the loop variable is **local** to the clause (it does not escape to
/// later clauses). The grammar restricts `body` to *updating* clauses only
/// (`CREATE`/`SET`/`REMOVE`/`DELETE`/`MERGE` and nested `FOREACH`); the parser enforces that
/// (a reading/projection clause inside `FOREACH` is a [`SyntaxError`](crate::parser::SyntaxError)).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct ForeachClause {
    /// The loop variable, bound to each element of [`list`](Self::list) in turn (local to the clause).
    pub variable: Variable,
    /// The list expression, evaluated once per input row.
    pub list: Expr,
    /// The update clauses run per element (guaranteed by the parser to be updating clauses only).
    pub body: Vec<Clause>,
    /// Span from `FOREACH` to the closing `)`.
    pub span: Span,
}

/// `LOAD CSV [WITH HEADERS] FROM <url-expr> AS <var> [FIELDTERMINATOR <char>]` (openCypher
/// `LoadCSV`).
///
/// A driving *source* clause, like [`UnwindClause`]: each CSV record becomes one row bound to
/// [`alias`](Self::alias), feeding the downstream clauses. Without `WITH HEADERS` the row value is a
/// `List` of the record's string fields; with `WITH HEADERS` it is a `Map` from each header name to
/// the field's string value (an absent trailing field maps to `null`). The grammar mirrors the
/// openCypher `LoadCSV` rule.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct LoadCsvClause {
    /// `true` when `WITH HEADERS` was given: the first record names the columns and each subsequent
    /// record is bound as a `Map{header -> value}`; otherwise each record is bound as a `List`.
    pub with_headers: bool,
    /// The URL expression naming the CSV source (a string at runtime — `file://` URLs and bare /
    /// relative file paths are supported; non-`file` schemes are rejected at runtime, per the Neo4j
    /// `LOAD CSV` security model).
    pub url: Expr,
    /// The variable each record is bound to.
    pub alias: Variable,
    /// The optional single-character field separator (`FIELDTERMINATOR '<char>'`); defaults to `,`.
    pub field_terminator: Option<char>,
    /// Span from `LOAD` to the last token of the clause.
    pub span: Span,
}

/// `CREATE <pattern>` (openCypher `Create`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct CreateClause {
    /// The pattern parts to create.
    pub pattern: Vec<PatternPart>,
    /// Span from `CREATE` to the end of the pattern.
    pub span: Span,
}

/// `MERGE <pattern-part> { ON CREATE SET ... | ON MATCH SET ... }` (openCypher `Merge`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct MergeClause {
    /// The single pattern part to merge (openCypher `Merge = MERGE, PatternPart, { MergeAction }`).
    pub pattern: PatternPart,
    /// The `ON CREATE SET` / `ON MATCH SET` actions, in source order.
    pub actions: Vec<MergeAction>,
    /// Span from `MERGE` to the last action (or pattern if none).
    pub span: Span,
}

/// A `MERGE` side-effect action (openCypher `MergeAction`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum MergeAction {
    /// `ON CREATE SET <set-items>`.
    OnCreate(Vec<SetItem>),
    /// `ON MATCH SET <set-items>`.
    OnMatch(Vec<SetItem>),
}

/// `SET <set-item>, ...` (openCypher `Set`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct SetClause {
    /// The set items.
    pub items: Vec<SetItem>,
    /// Span from `SET` to the last item.
    pub span: Span,
}

/// A single `SET` assignment (openCypher `SetItem`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum SetItem {
    /// `a.b = <expr>` — set a property to a value (openCypher `PropertyExpression '=' Expression`).
    Property {
        /// The target property access (an [`ExprKind::Property`] chain rooted at a variable).
        target: Expr,
        /// The value expression.
        value: Expr,
    },
    /// `n = <expr>` — replace all properties of `n` from a map (openCypher `Variable '=' Expression`).
    Replace {
        /// The target variable.
        target: Variable,
        /// The map expression.
        value: Expr,
    },
    /// `n += <expr>` — merge properties of `n` from a map (openCypher `Variable '+=' Expression`).
    Merge {
        /// The target variable.
        target: Variable,
        /// The map expression.
        value: Expr,
    },
    /// `n:Label1:Label2` — add labels to `n` (openCypher `Variable NodeLabels`).
    Labels {
        /// The target variable.
        target: Variable,
        /// The labels to add.
        labels: Vec<Label>,
    },
}

/// `[DETACH] DELETE <expr>, ...` (openCypher `Delete`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct DeleteClause {
    /// `true` if `DETACH DELETE`.
    pub detach: bool,
    /// The expressions identifying entities to delete.
    pub exprs: Vec<Expr>,
    /// Span from `DETACH`/`DELETE` to the last expression.
    pub span: Span,
}

/// `REMOVE <remove-item>, ...` (openCypher `Remove`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct RemoveClause {
    /// The remove items.
    pub items: Vec<RemoveItem>,
    /// Span from `REMOVE` to the last item.
    pub span: Span,
}

/// A single `REMOVE` item (openCypher `RemoveItem`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum RemoveItem {
    /// `n:Label1:Label2` — remove labels from `n` (openCypher `Variable NodeLabels`).
    Labels {
        /// The target variable.
        target: Variable,
        /// The labels to remove.
        labels: Vec<Label>,
    },
    /// `a.b` — remove a property (openCypher `PropertyExpression`).
    Property(Expr),
}

/// `WITH <projection> [WHERE <expr>]` (openCypher `With`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct WithClause {
    /// The projection body (items + modifiers).
    pub body: ProjectionBody,
    /// The optional `WHERE` predicate applied after projection.
    pub where_clause: Option<Expr>,
    /// Span from `WITH` to the end of the projection / `WHERE`.
    pub span: Span,
}

/// `RETURN <projection>` (openCypher `Return`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct ReturnClause {
    /// The projection body (items + modifiers).
    pub body: ProjectionBody,
    /// Span from `RETURN` to the end of the projection.
    pub span: Span,
}

/// The shared projection body of `RETURN` and `WITH` (openCypher `ProjectionBody`).
///
/// `[DISTINCT] (ProjectionItems) [Order] [Skip] [Limit]`.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct ProjectionBody {
    /// `true` if `DISTINCT` was present.
    pub distinct: bool,
    /// `true` if the projection is `*` (`RETURN *` / `WITH *`); items may still follow it.
    pub star: bool,
    /// The explicit projection items (empty iff `star` and no extra items).
    pub items: Vec<ProjectionItem>,
    /// The optional `ORDER BY` sort items.
    pub order_by: Vec<SortItem>,
    /// The optional `SKIP <expr>`.
    pub skip: Option<Expr>,
    /// The optional `LIMIT <expr>`.
    pub limit: Option<Expr>,
}

/// A single projection item (openCypher `ProjectionItem`).
///
/// `Expression AS Variable` or a bare `Expression`.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct ProjectionItem {
    /// The projected expression.
    pub expr: Expr,
    /// The optional `AS` alias.
    pub alias: Option<Variable>,
    /// The verbatim source text of `expr`. openCypher names an un-aliased projection column by the
    /// exact query text of its expression (`RETURN a.x` yields a column named `a.x`), so the parser
    /// captures the source slice here — downstream phases have no access to the original source.
    pub verbatim: String,
    /// Span from the expression start to the alias / expression end.
    pub span: Span,
}

/// One `ORDER BY` sort key (openCypher `SortItem`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct SortItem {
    /// The expression to sort by.
    pub expr: Expr,
    /// The sort direction.
    pub direction: SortDirection,
    /// Span from the expression to the optional direction keyword.
    pub span: Span,
}

/// The direction of a [`SortItem`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum SortDirection {
    /// `ASC` / `ASCENDING`, or the default when no direction is written.
    Ascending,
    /// `DESC` / `DESCENDING`.
    Descending,
}

/// A `CALL ... [YIELD ...]` clause appearing inside a query (openCypher `InQueryCall`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct CallClause {
    /// The procedure invocation.
    pub call: ProcedureCall,
    /// The optional `YIELD` items. `None` = no `YIELD` clause.
    pub yield_items: Option<Vec<YieldItem>>,
    /// The optional `WHERE` filter attached to `YIELD` (openCypher `YieldItems ... [Where]`).
    pub where_clause: Option<Expr>,
    /// Span from `CALL` to the end of the call / `YIELD`.
    pub span: Span,
}

/// `CALL { <subquery> } [IN TRANSACTIONS [OF n ROWS]]` — a Cypher **subquery** clause (Neo4j
/// `CallSubquery`).
///
/// The braces hold a complete inner [`Query`] (openCypher `RegularQuery`), which may itself contain
/// a `UNION` / `UNION ALL` chain. The subquery runs **correlated**, **once per driving row** of the
/// enclosing query:
///
/// - A **returning** subquery (its final clause, in every `UNION` branch, is `RETURN`) multiplies
///   cardinality: each driving row is combined with each row the subquery returns for it, and its
///   returned variables enter the outer scope. A driving row for which the subquery returns nothing
///   is dropped (inner-apply semantics).
/// - A **unit** subquery (no `RETURN`) runs purely for its side effects and passes each driving row
///   through **unchanged** (cardinality preserved).
///
/// **Scope isolation:** unlike [`ExprKind::CountSubquery`] / [`ExprKind::CollectSubquery`] (which see
/// the outer scope implicitly), a `CALL { ... }` subquery sees **only** the variables it explicitly
/// imports via a leading *importing* `WITH` (a first clause consisting solely of bare variable
/// references). See [`crate::semantics`] for the importing-`WITH` rules.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct CallSubqueryClause {
    /// The inner query (a `RegularQuery`; may contain `UNION` / `UNION ALL`). Boxed to keep
    /// [`Clause`] small.
    pub query: Box<Query>,
    /// The `IN TRANSACTIONS [OF n ROWS]` modifier, if present.
    pub in_transactions: Option<InTransactions>,
    /// Span from `CALL` to the closing `}` (or the end of the `IN TRANSACTIONS` modifier).
    pub span: Span,
}

/// The `IN TRANSACTIONS [OF <expr> ROW[S]]` modifier of a [`CallSubqueryClause`] (Neo4j
/// `SubqueryInTransactionsParameters`).
///
/// # Engine limitation
///
/// Graphus runs on a **single-writer** transactional engine that does not support nested
/// sub-transactions. `IN TRANSACTIONS` is therefore executed with **batched semantics inside the
/// enclosing transaction**: the subquery still runs once per driving row and the (optional) batch
/// size is accepted and validated, but each batch is **not** committed as an independent
/// transaction. Consequently the results are identical to a plain `CALL { ... }` subquery; only the
/// durability/partial-commit behaviour of Neo4j's real sub-transactions differs. This limitation is
/// documented in `specification` and surfaced to the user in the manual.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct InTransactions {
    /// The `OF <expr> ROW[S]` batch size, if given (must evaluate to a positive integer). `None`
    /// means the default batch size (Neo4j: 1000 rows).
    pub batch_size: Option<Expr>,
    /// Span from `IN` to the last token of the modifier.
    pub span: Span,
}

/// A standalone `CALL ... [YIELD * | items]` used as a whole statement (openCypher `StandaloneCall`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct StandaloneCall {
    /// The procedure invocation.
    pub call: ProcedureCall,
    /// The `YIELD` form, if present.
    pub yield_clause: Option<StandaloneYield>,
    /// Span from `CALL` to the end of the call / `YIELD`.
    pub span: Span,
}

/// The `YIELD` form of a [`StandaloneCall`] (openCypher `'*' | YieldItems`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum StandaloneYield {
    /// `YIELD *`.
    Star,
    /// `YIELD a, b AS c` with an optional trailing `WHERE`.
    Items {
        /// The yielded items.
        items: Vec<YieldItem>,
        /// The optional `WHERE` filter.
        where_clause: Option<Expr>,
    },
}

/// A procedure invocation `ns.proc(args...)` or, for implicit form, `ns.proc` with no parentheses
/// (openCypher `ExplicitProcedureInvocation` / `ImplicitProcedureInvocation`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct ProcedureCall {
    /// The dotted procedure name (`Namespace SymbolicName`), e.g. `["db", "labels"]` for
    /// `db.labels`.
    pub name: Vec<String>,
    /// The argument expressions. `None` = implicit form (no parentheses, only legal standalone);
    /// `Some` = explicit form, even when empty (`proc()`).
    pub args: Option<Vec<Expr>>,
    /// Span covering the name and argument list.
    pub span: Span,
}

/// A single `YIELD` item (openCypher `YieldItem`): `[field AS] var`.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct YieldItem {
    /// The optional source result field name when `field AS var` is used.
    pub field: Option<String>,
    /// The bound variable.
    pub alias: Variable,
    /// Span covering the item.
    pub span: Span,
}

// =================================================================================================
// Patterns
// =================================================================================================

/// One pattern part of a `Pattern`, optionally a named path (openCypher `PatternPart`).
///
/// `p = (...)-[...]->(...)` (named path) or a bare anonymous pattern. The [`kind`](Self::kind)
/// distinguishes an ordinary pattern from a `shortestPath(...)` / `allShortestPaths(...)` wrapper.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct PatternPart {
    /// The path variable if `var = ...` was written (openCypher `Variable '=' AnonymousPatternPart`).
    pub var: Option<Variable>,
    /// Whether the element is wrapped in `shortestPath(...)` / `allShortestPaths(...)`.
    pub kind: PatternPartKind,
    /// The pattern element (a node, then zero or more `relationship node` chain links). For a
    /// shortest-path part this is the single inner pattern of the `shortestPath(...)` call.
    pub element: PatternElement,
    /// Span covering the (optional) variable and the element.
    pub span: Span,
}

/// Whether a [`PatternPart`] is an ordinary pattern or a shortest-path search function.
///
/// `shortestPath` / `allShortestPaths` are openCypher path-search functions (in the openCypher
/// reference implementation and the Neo4j Cypher dialect). They wrap a single variable-length
/// pattern `(a)-[*]-(b)` and return the minimal-relationship-count path(s) between the endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum PatternPartKind {
    /// An ordinary pattern element (no shortest-path wrapper).
    Normal,
    /// `shortestPath((a)-[*]-(b))` — one minimal-length path (any one when several are minimal).
    ShortestPath,
    /// `allShortestPaths((a)-[*]-(b))` — every path of the minimal length.
    AllShortestPaths,
}

/// A pattern element: a node followed by a chain of `(relationship)(node)` links
/// (openCypher `PatternElement = NodePattern, { PatternElementChain }`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct PatternElement {
    /// The starting node.
    pub start: NodePattern,
    /// The relationship→node chain links, in source order.
    pub chain: Vec<PatternChainLink>,
    /// Span covering the whole element.
    pub span: Span,
}

/// One `relationship node` link of a [`PatternElement`] (openCypher `PatternElementChain`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct PatternChainLink {
    /// The relationship pattern connecting the previous node to [`node`](Self::node).
    pub relationship: RelationshipPattern,
    /// The node reached through the relationship.
    pub node: NodePattern,
}

/// A node pattern `(v:Label1:Label2 {props})` (openCypher `NodePattern`). All parts are optional.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct NodePattern {
    /// The optional bound variable.
    pub variable: Option<Variable>,
    /// The (possibly empty) **conjunctive** label list — the index-friendly fast path holding
    /// `:A`, the legacy `:A:B`, or an all-`&` expression `:A&B`. When the label constraint is a
    /// general [`LabelExpr`] (using `|`, `!`, `%`, or grouping) this is empty and
    /// [`label_expr`](Self::label_expr) carries it instead. At most one of the two is populated.
    pub labels: Vec<Label>,
    /// A general [`LabelExpr`] label constraint (`:A|B`, `:!A`, `:%`, `:(A&B)|C`), when the
    /// constraint is not a pure conjunction of labels; else `None`. Mutually exclusive with a
    /// non-empty [`labels`](Self::labels).
    pub label_expr: Option<LabelExpr>,
    /// The optional inline property map / parameter (openCypher `Properties = MapLiteral | Parameter`).
    pub properties: Option<Expr>,
    /// Span from `(` to `)`.
    pub span: Span,
}

/// A relationship pattern, with direction and an optional detail bracket `[r:T {p}*1..2]`
/// (openCypher `RelationshipPattern`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct RelationshipPattern {
    /// The arrow direction.
    pub direction: RelDirection,
    /// The optional bound variable.
    pub variable: Option<Variable>,
    /// The (possibly empty) **disjunctive** relationship type alternatives (`:A|B|C`) — the
    /// fast path that drives type-indexed expansion. When the type constraint is a general
    /// [`LabelExpr`] (using `!`, `&`, or grouping) this is empty and
    /// [`type_expr`](Self::type_expr) carries it instead. At most one of the two is populated.
    pub types: Vec<RelType>,
    /// A general [`LabelExpr`] type constraint (`:!A`, `:A&B`, `:(A|B)&!C`), when the constraint
    /// is not a pure disjunction of types; else `None`. Mutually exclusive with a non-empty
    /// [`types`](Self::types). The wildcard `:%` on a relationship imposes no constraint (a
    /// relationship always has a type), so it is normalised to an empty [`types`](Self::types).
    pub type_expr: Option<LabelExpr>,
    /// The optional variable-length range (`*`, `*2`, `*1..3`, `*..5`).
    pub range: Option<VarLengthRange>,
    /// The optional inline property map / parameter.
    pub properties: Option<Expr>,
    /// Span covering the whole relationship pattern (arrows + bracket).
    pub span: Span,
}

/// The direction of a [`RelationshipPattern`] (openCypher `RelationshipPattern` arrow alternatives).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum RelDirection {
    /// `-[...]->`  (left to right).
    LeftToRight,
    /// `<-[...]-`  (right to left).
    RightToLeft,
    /// `-[...]-`   (undirected).
    Undirected,
}

/// A variable-length relationship range (openCypher `RangeLiteral`): `* | *n | *m..n | *..n | *m..`.
///
/// `None` bounds mean "unbounded on that side". A bare `*` is `min = None, max = None`. A single
/// `*n` (no `..`) is represented by `exact = true` with `min == max == Some(n)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub struct VarLengthRange {
    /// Lower bound, inclusive; `None` = unbounded below (defaults to 1 semantically).
    pub min: Option<u64>,
    /// Upper bound, inclusive; `None` = unbounded above.
    pub max: Option<u64>,
    /// `true` if the source wrote a single hop count `*n` with no `..` (so `min == max == Some(n)`),
    /// distinguishing it from `*n..n`. Purely for faithful round-tripping / diagnostics.
    pub exact: bool,
}

/// A node label reference `:Name` (openCypher `NodeLabel`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct Label {
    /// The label name.
    pub name: String,
    /// Span covering `:Name`.
    pub span: Span,
}

/// A relationship type reference `:Name` within `:A|B|C` (openCypher `RelTypeName`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct RelType {
    /// The relationship type name.
    pub name: String,
    /// Span covering the name.
    pub span: Span,
}

/// A **label expression** — the GPM / Neo4j 5.x boolean predicate over an entity's label set
/// (for a node) or its single type (for a relationship).
///
/// Built from name [`Leaf`](Self::Leaf)s and the wildcard [`Wildcard`](Self::Wildcard) `%`,
/// combined with negation `!`, conjunction `&`, and disjunction `|`. Grouping `( … )` is not a
/// distinct variant: parentheses only reshape the tree, and the tree shape captures the grouping
/// exactly (`(A&B)|C` is [`Disjunction`](Self::Disjunction) of a [`Conjunction`](Self::Conjunction)
/// and a [`Leaf`](Self::Leaf), which is structurally distinct from `A&(B|C)`).
///
/// **Semantics** (Neo4j 5.x, `expressions/predicates/label-expression-predicates`):
/// - `&` = AND, `|` = OR, `!` = NOT.
/// - `%` matches any label (a node with ≥1 label) / any type (a relationship — always, since a
///   relationship always has exactly one type). A node with **no** labels fails `%` and passes `!A`.
/// - Operator precedence, tightest first: `!` > `&` > `|`. Parentheses override.
/// - The legacy colon conjunction `:A:B` is desugared by the parser to `A & B`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub enum LabelExpr {
    /// A single label / type name leaf, e.g. `A`.
    Leaf {
        /// The label / type name.
        name: String,
        /// Span covering the name (excluding any leading `:`).
        span: Span,
    },
    /// The wildcard `%` — any label (node: matches iff the node carries ≥1 label) / any type
    /// (relationship: always matches, as a relationship always has exactly one type).
    Wildcard {
        /// Span covering `%`.
        span: Span,
    },
    /// Negation `!expr`.
    Negation {
        /// The negated sub-expression.
        operand: Box<LabelExpr>,
        /// Span covering `!expr`.
        span: Span,
    },
    /// Conjunction `lhs & rhs` (also the desugaring of the legacy colon form `:A:B`).
    Conjunction {
        /// Left operand.
        lhs: Box<LabelExpr>,
        /// Right operand.
        rhs: Box<LabelExpr>,
        /// Span covering the whole conjunction.
        span: Span,
    },
    /// Disjunction `lhs | rhs`.
    Disjunction {
        /// Left operand.
        lhs: Box<LabelExpr>,
        /// Right operand.
        rhs: Box<LabelExpr>,
        /// Span covering the whole disjunction.
        span: Span,
    },
}

impl LabelExpr {
    /// The byte span of this sub-expression.
    pub const fn span(&self) -> Span {
        match self {
            Self::Leaf { span, .. }
            | Self::Wildcard { span }
            | Self::Negation { span, .. }
            | Self::Conjunction { span, .. }
            | Self::Disjunction { span, .. } => *span,
        }
    }

    /// Whether the expression is exactly the wildcard `%`.
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        matches!(self, Self::Wildcard { .. })
    }

    /// The [`Label`] of a single-leaf expression, or `None` for any compound / wildcard form.
    #[must_use]
    pub fn as_single_leaf(&self) -> Option<Label> {
        match self {
            Self::Leaf { name, span } => Some(Label {
                name: name.clone(),
                span: *span,
            }),
            _ => None,
        }
    }

    /// The pure conjunction of name leaves (`A`, `A&B`, `A&B&C`), or `None` when the expression
    /// uses `|`, `!`, or `%`. Lets a conjunctive node-label constraint be routed through the
    /// index-friendly `Vec<Label>` fast path (a label scan plus residual `HasLabels` filter).
    #[must_use]
    pub fn as_conjunction_labels(&self) -> Option<Vec<Label>> {
        let mut out = Vec::new();
        self.collect_conjunction(&mut out).then_some(out)
    }

    fn collect_conjunction(&self, out: &mut Vec<Label>) -> bool {
        match self {
            Self::Leaf { name, span } => {
                out.push(Label {
                    name: name.clone(),
                    span: *span,
                });
                true
            }
            Self::Conjunction { lhs, rhs, .. } => {
                lhs.collect_conjunction(out) && rhs.collect_conjunction(out)
            }
            _ => false,
        }
    }

    /// The pure disjunction of name leaves (`A`, `A|B`, `A|B|C`), or `None` when the expression
    /// uses `&`, `!`, or `%`. Lets a disjunctive relationship-type constraint be routed through the
    /// existing `Vec<RelType>` fast path (which drives type-indexed expansion).
    #[must_use]
    pub fn as_disjunction_types(&self) -> Option<Vec<RelType>> {
        let mut out = Vec::new();
        self.collect_disjunction(&mut out).then_some(out)
    }

    fn collect_disjunction(&self, out: &mut Vec<RelType>) -> bool {
        match self {
            Self::Leaf { name, span } => {
                out.push(RelType {
                    name: name.clone(),
                    span: *span,
                });
                true
            }
            Self::Disjunction { lhs, rhs, .. } => {
                lhs.collect_disjunction(out) && rhs.collect_disjunction(out)
            }
            _ => false,
        }
    }

    /// Builds the left-nested conjunction `A & B & …` of `labels`, or `None` for an empty slice.
    /// The inverse of [`as_conjunction_labels`](Self::as_conjunction_labels); used to lower a
    /// residual `Vec<Label>` back into a `HasLabels` predicate.
    #[must_use]
    pub fn all_of(labels: &[Label]) -> Option<Self> {
        let mut it = labels.iter();
        let first = it.next()?;
        let mut acc = Self::Leaf {
            name: first.name.clone(),
            span: first.span,
        };
        for l in it {
            let span = Span::new(acc.span().start, l.span.end);
            acc = Self::Conjunction {
                lhs: Box::new(acc),
                rhs: Box::new(Self::Leaf {
                    name: l.name.clone(),
                    span: l.span,
                }),
                span,
            };
        }
        Some(acc)
    }

    /// Evaluates the expression against an entity's label set.
    ///
    /// `contains(name)` reports whether the entity carries `name`; `has_any` is whether the entity
    /// has at least one label (a node) — for a relationship it is always `true`, and the "set" is
    /// the single type. A node with no labels passes `has_any == false`, so `%` is `false` and
    /// `!A` is `true` for it (Neo4j 5.x semantics).
    #[must_use]
    pub fn evaluate(&self, contains: &impl Fn(&str) -> bool, has_any: bool) -> bool {
        match self {
            Self::Leaf { name, .. } => contains(name),
            Self::Wildcard { .. } => has_any,
            Self::Negation { operand, .. } => !operand.evaluate(contains, has_any),
            Self::Conjunction { lhs, rhs, .. } => {
                lhs.evaluate(contains, has_any) && rhs.evaluate(contains, has_any)
            }
            Self::Disjunction { lhs, rhs, .. } => {
                lhs.evaluate(contains, has_any) || rhs.evaluate(contains, has_any)
            }
        }
    }

    /// Appends every name leaf, in left-to-right order, to `out` (for reference / authorization
    /// analysis — the set of label/type names a pattern mentions). The wildcard contributes none.
    pub fn collect_leaf_names<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Self::Leaf { name, .. } => out.push(name),
            Self::Wildcard { .. } => {}
            Self::Negation { operand, .. } => operand.collect_leaf_names(out),
            Self::Conjunction { lhs, rhs, .. } | Self::Disjunction { lhs, rhs, .. } => {
                lhs.collect_leaf_names(out);
                rhs.collect_leaf_names(out);
            }
        }
    }

    /// Zeroes every span in the tree, so two structurally identical expressions compare equal
    /// regardless of source position (mirrors [`Expr::zero_spans_in_place`]).
    fn zero_spans_in_place(&mut self) {
        match self {
            Self::Leaf { span, .. } | Self::Wildcard { span } => *span = Span::new(0, 0),
            Self::Negation { operand, span } => {
                *span = Span::new(0, 0);
                operand.zero_spans_in_place();
            }
            Self::Conjunction { lhs, rhs, span } | Self::Disjunction { lhs, rhs, span } => {
                *span = Span::new(0, 0);
                lhs.zero_spans_in_place();
                rhs.zero_spans_in_place();
            }
        }
    }
}

/// A variable reference (openCypher `Variable = SymbolicName`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct Variable {
    /// The variable name (backticks already stripped by the lexer).
    pub name: String,
    /// Span covering the name.
    pub span: Span,
}

// =================================================================================================
// Expressions
// =================================================================================================

/// A Cypher expression node: the [`kind`](Self::kind) plus its byte [`span`](Self::span).
///
/// The structure mirrors the openCypher expression-precedence grammar (see the
/// [`parser`](crate::parser) precedence table). Binary and unary operators are flattened into
/// [`ExprKind::Binary`] / [`ExprKind::Unary`] with an explicit operator, so precedence and
/// associativity are encoded purely by *tree shape* (the Pratt parser builds the correct shape).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct Expr {
    /// The expression variant.
    pub kind: ExprKind,
    /// The byte span of the whole expression.
    pub span: Span,
}

impl Expr {
    /// Builds an expression node.
    pub fn new(kind: ExprKind, span: Span) -> Self {
        Self { kind, span }
    }

    /// Structural equality that ignores byte [`Span`]s.
    ///
    /// Two expressions parsed from different source positions (e.g. the same `n.age` written once in
    /// a projection and again in an `ORDER BY`) compare equal here even though their spans differ.
    /// Used by the projection-boundary lowering to recognise an `ORDER BY` sub-expression that
    /// re-states a projected grouping key or aggregate (`crate::lower`, `crate::semantics`).
    #[must_use]
    pub fn eq_ignoring_span(&self, other: &Expr) -> bool {
        self.clone().zeroed_spans() == other.clone().zeroed_spans()
    }

    /// Returns a clone of this expression with every span (its own and all descendants') reset to
    /// `0..0`, so the derived [`PartialEq`] becomes span-insensitive.
    fn zeroed_spans(mut self) -> Expr {
        self.zero_spans_in_place();
        self
    }

    fn zero_spans_in_place(&mut self) {
        self.span = Span::new(0, 0);
        match &mut self.kind {
            ExprKind::Literal(_)
            | ExprKind::Parameter(_)
            | ExprKind::Variable(_)
            | ExprKind::CountStar => {}
            ExprKind::Binary { lhs, rhs, .. } => {
                lhs.zero_spans_in_place();
                rhs.zero_spans_in_place();
            }
            ExprKind::Unary { operand, .. } => {
                operand.zero_spans_in_place();
            }
            ExprKind::HasLabels { operand, expr } => {
                operand.zero_spans_in_place();
                expr.zero_spans_in_place();
            }
            ExprKind::Predicate { operand, rhs, .. } => {
                operand.zero_spans_in_place();
                if let Some(rhs) = rhs {
                    rhs.zero_spans_in_place();
                }
            }
            ExprKind::TypePredicate { operand, .. }
            | ExprKind::NormalizedPredicate { operand, .. } => {
                operand.zero_spans_in_place();
            }
            ExprKind::Property { base, .. } => base.zero_spans_in_place(),
            ExprKind::Index { base, index } => {
                base.zero_spans_in_place();
                index.zero_spans_in_place();
            }
            ExprKind::Slice { base, low, high } => {
                base.zero_spans_in_place();
                if let Some(low) = low {
                    low.zero_spans_in_place();
                }
                if let Some(high) = high {
                    high.zero_spans_in_place();
                }
            }
            ExprKind::FunctionCall { args, .. } => {
                for a in args {
                    a.zero_spans_in_place();
                }
            }
            ExprKind::List(items) => {
                for it in items {
                    it.zero_spans_in_place();
                }
            }
            ExprKind::Map(entries) => {
                for (_k, v) in entries {
                    v.zero_spans_in_place();
                }
            }
            ExprKind::Case(case) => {
                if let Some(subj) = &mut case.subject {
                    subj.zero_spans_in_place();
                }
                for alt in &mut case.alternatives {
                    alt.when.zero_spans_in_place();
                    alt.then.zero_spans_in_place();
                }
                if let Some(else_e) = &mut case.else_expr {
                    else_e.zero_spans_in_place();
                }
            }
            ExprKind::ListComprehension(lc) => {
                lc.list.zero_spans_in_place();
                if let Some(pred) = &mut lc.predicate {
                    pred.zero_spans_in_place();
                }
                if let Some(proj) = &mut lc.projection {
                    proj.zero_spans_in_place();
                }
            }
            ExprKind::Quantifier(q) => {
                q.list.zero_spans_in_place();
                q.predicate.zero_spans_in_place();
            }
            ExprKind::Reduce(r) => {
                r.init.zero_spans_in_place();
                r.list.zero_spans_in_place();
                r.body.zero_spans_in_place();
            }
            ExprKind::MapProjection(mp) => {
                mp.entity.zero_spans_in_place();
                for sel in &mut mp.selectors {
                    if let MapProjectionSelector::Entry { value, .. } = sel {
                        value.zero_spans_in_place();
                    }
                }
            }
            // Pattern-scoped forms embed patterns that themselves embed expressions; an `ORDER BY`
            // restatement never targets these, so a shallow zeroing of the boxed node's own
            // expression children is sufficient for the equality use-case (the embedded patterns'
            // spans are left as-is, which only ever makes two such forms compare *unequal* — the
            // conservative, safe direction: no spurious substitution).
            ExprKind::PatternComprehension(pc) => {
                if let Some(pred) = &mut pc.predicate {
                    pred.zero_spans_in_place();
                }
            }
            ExprKind::ExistsSubquery(ex) => {
                if let Some(pred) = &mut ex.predicate {
                    pred.zero_spans_in_place();
                }
                // Full-query form: recurse into the inner query, zeroing every contained
                // expression's span. Mirrors the conservative pattern-form behaviour above — the
                // inner clauses' *structural* spans are left as-is (which can only ever make two
                // such forms compare *unequal*, the safe direction for the plan-cache equality
                // use-case), while the embedded *expression* spans are zeroed so two inner queries
                // that differ only in source offsets of their expressions compare equal.
                if let Some(q) = &mut ex.full_query {
                    q.zero_expr_spans_in_place();
                }
            }
            ExprKind::CountSubquery(sq) | ExprKind::CollectSubquery(sq) => {
                // Same conservative treatment as `ExistsSubquery`: zero the embedded expression
                // spans (the pattern-form `WHERE` and every expression of the full inner query),
                // leaving structural clause/pattern spans as-is.
                if let Some(pred) = &mut sq.predicate {
                    pred.zero_spans_in_place();
                }
                if let Some(q) = &mut sq.full_query {
                    q.zero_expr_spans_in_place();
                }
            }
        }
    }
}

impl Query {
    /// Zeroes the [`Span`] of every **expression** contained anywhere in this query (recursively,
    /// through every clause and any nested subqueries).
    ///
    /// This is the query-level counterpart of [`Expr::zero_spans_in_place`], used to normalise the
    /// inner query of an [`ExprKind::ExistsSubquery`] full-query form for plan-cache key equality.
    /// Structural clause/pattern spans are intentionally **not** touched (see the
    /// [`ExprKind::ExistsSubquery`] arm of [`Expr::zero_spans_in_place`]).
    pub fn zero_expr_spans_in_place(&mut self) {
        match &mut self.body {
            QueryBody::Regular { head, unions } => {
                head.zero_expr_spans_in_place();
                for u in unions {
                    u.query.zero_expr_spans_in_place();
                }
            }
            QueryBody::StandaloneCall(_) => {}
        }
    }
}

impl SingleQuery {
    fn zero_expr_spans_in_place(&mut self) {
        for clause in &mut self.clauses {
            clause.zero_expr_spans_in_place();
        }
    }
}

impl Clause {
    /// Zeroes the span of every expression reachable from this clause (recursively).
    fn zero_expr_spans_in_place(&mut self) {
        match self {
            Self::Match(c) => {
                for part in &mut c.pattern {
                    part.zero_expr_spans_in_place();
                }
                if let Some(w) = &mut c.where_clause {
                    w.zero_spans_in_place();
                }
            }
            Self::Unwind(c) => c.expr.zero_spans_in_place(),
            Self::LoadCsv(c) => c.url.zero_spans_in_place(),
            Self::Call(c) => {
                if let Some(args) = &mut c.call.args {
                    for arg in args {
                        arg.zero_spans_in_place();
                    }
                }
                if let Some(w) = &mut c.where_clause {
                    w.zero_spans_in_place();
                }
            }
            Self::CallSubquery(c) => {
                c.query.zero_expr_spans_in_place();
                if let Some(t) = &mut c.in_transactions {
                    if let Some(batch) = &mut t.batch_size {
                        batch.zero_spans_in_place();
                    }
                }
            }
            Self::Create(c) => {
                for part in &mut c.pattern {
                    part.zero_expr_spans_in_place();
                }
            }
            Self::Merge(c) => {
                c.pattern.zero_expr_spans_in_place();
                for action in &mut c.actions {
                    let items = match action {
                        MergeAction::OnCreate(items) | MergeAction::OnMatch(items) => items,
                    };
                    for item in items {
                        item.zero_expr_spans_in_place();
                    }
                }
            }
            Self::Set(c) => {
                for item in &mut c.items {
                    item.zero_expr_spans_in_place();
                }
            }
            Self::Delete(c) => {
                for e in &mut c.exprs {
                    e.zero_spans_in_place();
                }
            }
            Self::Remove(c) => {
                for item in &mut c.items {
                    if let RemoveItem::Property(e) = item {
                        e.zero_spans_in_place();
                    }
                }
            }
            Self::Foreach(c) => {
                c.list.zero_spans_in_place();
                for clause in &mut c.body {
                    clause.zero_expr_spans_in_place();
                }
            }
            Self::With(c) => {
                c.body.zero_expr_spans_in_place();
                if let Some(w) = &mut c.where_clause {
                    w.zero_spans_in_place();
                }
            }
            Self::Return(c) => c.body.zero_expr_spans_in_place(),
        }
    }
}

impl SetItem {
    fn zero_expr_spans_in_place(&mut self) {
        match self {
            Self::Property { target, value } => {
                target.zero_spans_in_place();
                value.zero_spans_in_place();
            }
            Self::Replace { value, .. } | Self::Merge { value, .. } => value.zero_spans_in_place(),
            Self::Labels { .. } => {}
        }
    }
}

impl ProjectionBody {
    fn zero_expr_spans_in_place(&mut self) {
        for item in &mut self.items {
            item.expr.zero_spans_in_place();
        }
        for sort in &mut self.order_by {
            sort.expr.zero_spans_in_place();
        }
        if let Some(skip) = &mut self.skip {
            skip.zero_spans_in_place();
        }
        if let Some(limit) = &mut self.limit {
            limit.zero_spans_in_place();
        }
    }
}

impl PatternPart {
    fn zero_expr_spans_in_place(&mut self) {
        self.element.zero_expr_spans_in_place();
    }
}

impl PatternElement {
    fn zero_expr_spans_in_place(&mut self) {
        self.start.zero_expr_spans_in_place();
        for link in &mut self.chain {
            if let Some(props) = &mut link.relationship.properties {
                props.zero_spans_in_place();
            }
            if let Some(type_expr) = &mut link.relationship.type_expr {
                type_expr.zero_spans_in_place();
            }
            link.node.zero_expr_spans_in_place();
        }
    }
}

impl NodePattern {
    fn zero_expr_spans_in_place(&mut self) {
        if let Some(props) = &mut self.properties {
            props.zero_spans_in_place();
        }
        if let Some(label_expr) = &mut self.label_expr {
            label_expr.zero_spans_in_place();
        }
    }
}

/// The variants of an [`Expr`].
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum ExprKind {
    /// A literal value (openCypher `Literal`).
    Literal(Literal),
    /// A query parameter `$name` / `$0` (openCypher `Parameter`), name without the `$`.
    Parameter(String),
    /// A variable reference (openCypher `Variable`).
    Variable(String),

    /// A binary operator application (openCypher `OrExpression` .. `PowerOfExpression`).
    Binary {
        /// The operator.
        op: BinaryOp,
        /// Left operand.
        lhs: Box<Expr>,
        /// Right operand.
        rhs: Box<Expr>,
    },
    /// A unary operator application (openCypher `NotExpression` / `UnaryAddOrSubtractExpression`).
    Unary {
        /// The operator.
        op: UnaryOp,
        /// The operand.
        operand: Box<Expr>,
    },
    /// A string/list/null postfix predicate (openCypher `StringListNullPredicateExpression`):
    /// `STARTS WITH` / `ENDS WITH` / `CONTAINS` / `IN` / `IS NULL` / `IS NOT NULL`.
    Predicate {
        /// The predicate kind.
        op: PredicateOp,
        /// The subject expression.
        operand: Box<Expr>,
        /// The right-hand operand, present for binary predicates (`STARTS WITH`/`IN`/…) and `None`
        /// for the nullary `IS NULL` / `IS NOT NULL`.
        rhs: Option<Box<Expr>>,
    },

    /// Property access `expr.key` (openCypher `PropertyLookup`).
    Property {
        /// The base expression.
        base: Box<Expr>,
        /// The property key.
        key: String,
    },
    /// List indexing `expr[index]` (openCypher `ListOperatorExpression` single-index form).
    Index {
        /// The base expression.
        base: Box<Expr>,
        /// The index expression.
        index: Box<Expr>,
    },
    /// List slicing `expr[lo..hi]` with optional bounds (openCypher `ListOperatorExpression` slice
    /// form).
    Slice {
        /// The base expression.
        base: Box<Expr>,
        /// The lower bound, if written.
        low: Option<Box<Expr>>,
        /// The upper bound, if written.
        high: Option<Box<Expr>>,
    },
    /// A label-expression predicate `expr:LabelExpr` (openCypher `NonArithmeticOperatorExpression`
    /// trailing label predicate; Neo4j 5.x label expressions) — evaluates the boolean
    /// [`LabelExpr`] against the entity's label set (node) or single type (relationship). The legacy
    /// `expr:A:B` conjunction is one [`LabelExpr`] shape among many.
    HasLabels {
        /// The base expression.
        operand: Box<Expr>,
        /// The label expression tested against the entity.
        expr: LabelExpr,
    },

    /// A function call `ns.fn([DISTINCT] args...)` (openCypher `FunctionInvocation`).
    FunctionCall {
        /// The dotted function name.
        name: Vec<String>,
        /// `true` if the argument list began with `DISTINCT`.
        distinct: bool,
        /// The argument expressions.
        args: Vec<Expr>,
    },
    /// `count(*)` — the special star-count atom (openCypher `Atom` `COUNT '(' '*' ')'`).
    CountStar,

    /// A list literal `[a, b, c]` (openCypher `ListLiteral`).
    List(Vec<Expr>),
    /// A map literal `{k: v, ...}` (openCypher `MapLiteral`).
    Map(Vec<(MapKey, Expr)>),

    /// A `CASE` expression, simple or searched (openCypher `CaseExpression`).
    Case(CaseExpr),

    /// A list comprehension `[x IN list WHERE p | expr]` (openCypher `ListComprehension`).
    ListComprehension(ListComprehension),
    /// A pattern comprehension `[p = (a)-->(b) WHERE p | expr]` (openCypher `PatternComprehension`).
    ///
    /// Boxed because a pattern comprehension embeds a [`PatternElement`] whose node patterns can in
    /// turn embed [`Expr`]s (inline property maps), which would otherwise make [`Expr`] infinitely
    /// sized.
    PatternComprehension(Box<PatternComprehension>),

    /// A quantifier predicate `all/any/none/single(x IN list WHERE p)` (openCypher
    /// `Quantifier`).
    Quantifier(Box<QuantifierExpr>),
    /// A list fold `reduce(acc = init, x IN list | body)` (openCypher / Neo4j `reduce`). Boxed to
    /// keep [`Expr`] small: a [`ReduceExpr`] carries three boxed sub-expressions plus two
    /// [`Variable`]s.
    Reduce(Box<ReduceExpr>),
    /// A map projection `entity { .prop, .*, key: expr, var }` (Neo4j map projection). Boxed for the
    /// same size reason as [`Reduce`](Self::Reduce).
    MapProjection(Box<MapProjection>),
    /// An existential subquery `EXISTS { [MATCH] pattern [WHERE p] }` (openCypher
    /// `ExistentialSubquery`). Boxed for the same embedded-pattern reason as
    /// [`PatternComprehension`](Self::PatternComprehension).
    ExistsSubquery(Box<ExistsSubquery>),
    /// A counting subquery `COUNT { [MATCH] pattern [WHERE p] }` or `COUNT { <full query> }` (Neo4j
    /// `CountExpression`). Evaluates to the [`Integer`](Value::Integer) number of rows the correlated
    /// subquery matches. Boxed for the same embedded-pattern reason as
    /// [`PatternComprehension`](Self::PatternComprehension).
    CountSubquery(Box<SubqueryExpr>),
    /// A collecting subquery `COLLECT { <full query with a single-column RETURN> }` (Neo4j
    /// `CollectExpression`). Evaluates to a [`List`](Value) of the single returned column's value
    /// across every row the correlated subquery produces. Boxed like the other subquery forms.
    CollectSubquery(Box<SubqueryExpr>),

    /// A GQL / Neo4j 5.x **type predicate** `expr IS [NOT] :: <TYPE>` (equivalently
    /// `expr IS [NOT] TYPED <TYPE>` or `expr :: <TYPE>`; `rmp` #636). Evaluates to a boolean:
    /// whether the operand's runtime value conforms to the declared [`TypeExpr`]. Every Cypher type
    /// is nullable by default, so a `null` operand satisfies any type unless it carries a trailing
    /// `NOT NULL` (see [`TypeExpr`]). `negated` is `true` for the `IS NOT ::` form.
    TypePredicate {
        /// The subject expression whose value is type-checked.
        operand: Box<Expr>,
        /// `true` for the negated `IS NOT :: <TYPE>` form.
        negated: bool,
        /// The declared target type.
        type_expr: TypeExpr,
    },
    /// A Unicode **normalization predicate** `expr IS [NOT] [<form>] NORMALIZED` (`rmp` #636). Tests
    /// whether a `STRING` operand is already in the given Unicode normalization form (`NFC` by
    /// default). Per Neo4j, a `null` or non-`STRING` operand yields `null` (never an error).
    /// `negated` is `true` for the `IS NOT [<form>] NORMALIZED` form.
    NormalizedPredicate {
        /// The subject expression whose string value is tested.
        operand: Box<Expr>,
        /// `true` for the negated `IS NOT [<form>] NORMALIZED` form.
        negated: bool,
        /// The Unicode normalization form to test against.
        form: NormalForm,
    },
}

/// A Unicode normalization form for the [`NormalizedPredicate`](ExprKind::NormalizedPredicate)
/// (`rmp` #636). `NFC` is the default when the `IS NORMALIZED` predicate omits an explicit form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[must_use]
pub enum NormalForm {
    /// Canonical Decomposition followed by Canonical Composition (the default).
    #[default]
    Nfc,
    /// Canonical Decomposition.
    Nfd,
    /// Compatibility Decomposition followed by Canonical Composition.
    Nfkc,
    /// Compatibility Decomposition.
    Nfkd,
}

impl std::fmt::Display for NormalForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Nfc => "NFC",
            Self::Nfd => "NFD",
            Self::Nfkc => "NFKC",
            Self::Nfkd => "NFKD",
        })
    }
}

/// A predefined (nominal) GQL / Cypher value type used inside a [`TypeExpr`] (`rmp` #636). The
/// nullability of a written type lives on the enclosing [`TypeExpr`] variant, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum PredefinedType {
    /// `BOOLEAN` (synonym `BOOL`).
    Boolean,
    /// `STRING` (synonym `VARCHAR`).
    String,
    /// `INTEGER` (synonyms `INT`, `SIGNED INTEGER`).
    Integer,
    /// `FLOAT`.
    Float,
    /// `DATE`.
    Date,
    /// `LOCAL TIME` (synonym `TIME WITHOUT TIMEZONE`).
    LocalTime,
    /// `ZONED TIME` (synonym `TIME WITH TIMEZONE`).
    ZonedTime,
    /// `LOCAL DATETIME` (synonym `TIMESTAMP WITHOUT TIMEZONE`).
    LocalDateTime,
    /// `ZONED DATETIME` (synonym `TIMESTAMP WITH TIMEZONE`).
    ZonedDateTime,
    /// `DURATION`.
    Duration,
    /// `POINT`.
    Point,
    /// `NODE` (synonyms `ANY NODE`, `VERTEX`, `ANY VERTEX`).
    Node,
    /// `RELATIONSHIP` (synonyms `ANY RELATIONSHIP`, `EDGE`, `ANY EDGE`).
    Relationship,
    /// `PATH`.
    Path,
    /// `MAP`.
    Map,
    /// `PROPERTY VALUE` (synonym `ANY PROPERTY VALUE`) — any non-null storable property value.
    PropertyValue,
}

impl PredefinedType {
    /// The canonical openCypher spelling of this type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boolean => "BOOLEAN",
            Self::String => "STRING",
            Self::Integer => "INTEGER",
            Self::Float => "FLOAT",
            Self::Date => "DATE",
            Self::LocalTime => "LOCAL TIME",
            Self::ZonedTime => "ZONED TIME",
            Self::LocalDateTime => "LOCAL DATETIME",
            Self::ZonedDateTime => "ZONED DATETIME",
            Self::Duration => "DURATION",
            Self::Point => "POINT",
            Self::Node => "NODE",
            Self::Relationship => "RELATIONSHIP",
            Self::Path => "PATH",
            Self::Map => "MAP",
            Self::PropertyValue => "PROPERTY VALUE",
        }
    }
}

/// A GQL / Cypher value type as written in a type predicate `expr IS :: <TYPE>` (`rmp` #636).
///
/// Every type is **nullable** by default — a written `INTEGER` denotes "integer or null", so
/// `null IS :: INTEGER` is `true`. A trailing `NOT NULL` (carried by the `not_null` flag on the
/// applicable variants) removes `null` from the type, so `null IS :: INTEGER NOT NULL` is `false`.
/// The [`Nothing`](Self::Nothing) type is the empty type (matches nothing, not even `null`) and
/// [`Null`](Self::Null) is the type whose only value is `null`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub enum TypeExpr {
    /// A predefined nominal type (`INTEGER`, `STRING`, `POINT`, `NODE`, …) with its nullability.
    Predefined {
        /// The nominal type.
        name: PredefinedType,
        /// `true` if written `… NOT NULL` (excludes `null`).
        not_null: bool,
    },
    /// `LIST<inner>` (synonym `ARRAY<inner>`): a list every element of which conforms to `inner`.
    List {
        /// The element type.
        inner: Box<TypeExpr>,
        /// `true` if written `LIST<inner> NOT NULL` (excludes `null`).
        not_null: bool,
    },
    /// `ANY` / `ANY VALUE`: matches every value. `NOT NULL` (`ANY NOT NULL`) excludes `null`.
    Any {
        /// `true` if written `ANY NOT NULL`.
        not_null: bool,
    },
    /// `NOTHING`: the empty type — matches no value (not even `null`).
    Nothing,
    /// `NULL`: the type whose only value is `null`.
    Null,
    /// A closed dynamic union `A | B | …` (also written `ANY<A | B | …>`): matches a value that
    /// conforms to **any** member. Always holds two or more members (a single member collapses to
    /// that member at parse time).
    Union(Vec<TypeExpr>),
}

impl std::fmt::Display for TypeExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Predefined { name, not_null } => {
                f.write_str(name.as_str())?;
                if *not_null {
                    f.write_str(" NOT NULL")?;
                }
                Ok(())
            }
            Self::List { inner, not_null } => {
                write!(f, "LIST<{inner}>")?;
                if *not_null {
                    f.write_str(" NOT NULL")?;
                }
                Ok(())
            }
            Self::Any { not_null } => {
                f.write_str("ANY")?;
                if *not_null {
                    f.write_str(" NOT NULL")?;
                }
                Ok(())
            }
            Self::Nothing => f.write_str("NOTHING"),
            Self::Null => f.write_str("NULL"),
            Self::Union(members) => {
                for (i, m) in members.iter().enumerate() {
                    if i > 0 {
                        f.write_str(" | ")?;
                    }
                    write!(f, "{m}")?;
                }
                Ok(())
            }
        }
    }
}

/// A literal in the AST (openCypher `Literal`), kept unevaluated; range/encoding checks are deferred
/// to later phases (`04 §7.3`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum Literal {
    /// An integer literal, already resolved to its signed 64-bit value. The parser decodes the
    /// lexer's magnitude + base, folds a directly-adjacent unary minus, and range-checks against
    /// `i64::MIN..=i64::MAX` at compile time (an out-of-range literal is a compile-time `SyntaxError`,
    /// openCypher `IntegerOverflow`; `04 §7.3`, `tck/.../literals/Literals2-4`).
    Integer(i64),
    /// A floating-point literal.
    Float(f64),
    /// A string literal (escapes already resolved by the lexer).
    String(String),
    /// A boolean literal.
    Boolean(bool),
    /// The `null` literal.
    Null,
}

/// A key in a [`map literal`](ExprKind::Map) (openCypher `PropertyKeyName`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct MapKey {
    /// The key name.
    pub name: String,
    /// Span covering the key.
    pub span: Span,
}

/// A binary operator (precedence is encoded by parse-tree shape; see the
/// [`parser`](crate::parser) precedence table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum BinaryOp {
    /// `OR`
    Or,
    /// `XOR`
    Xor,
    /// `AND`
    And,
    /// `=`
    Eq,
    /// `<>`
    Neq,
    /// `<`
    Lt,
    /// `>`
    Gt,
    /// `<=`
    Lte,
    /// `>=`
    Gte,
    /// `=~` (regular-expression match)
    RegexMatch,
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mul,
    /// `/`
    Div,
    /// `%`
    Mod,
    /// `^` (exponentiation, right-associative)
    Pow,
}

/// A unary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum UnaryOp {
    /// `NOT`
    Not,
    /// unary `+`
    Plus,
    /// unary `-`
    Minus,
}

/// A string/list/null postfix predicate operator (openCypher
/// `StringPredicateExpression | ListPredicateExpression | NullPredicateExpression`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum PredicateOp {
    /// `STARTS WITH`
    StartsWith,
    /// `ENDS WITH`
    EndsWith,
    /// `CONTAINS`
    Contains,
    /// `IN`
    In,
    /// `IS NULL`
    IsNull,
    /// `IS NOT NULL`
    IsNotNull,
}

/// A `CASE` expression (openCypher `CaseExpression`), simple or searched.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct CaseExpr {
    /// The subject of a *simple* `CASE expr WHEN v THEN r ...`; `None` for the *searched* form
    /// `CASE WHEN cond THEN r ...`.
    pub subject: Option<Box<Expr>>,
    /// The `WHEN ... THEN ...` alternatives (openCypher `CaseAlternative`), at least one.
    pub alternatives: Vec<CaseAlternative>,
    /// The optional `ELSE` result.
    pub else_expr: Option<Box<Expr>>,
}

/// A single `WHEN <expr> THEN <expr>` arm of a [`CaseExpr`] (openCypher `CaseAlternative`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct CaseAlternative {
    /// The `WHEN` condition (a value in the simple form, a predicate in the searched form).
    pub when: Expr,
    /// The `THEN` result.
    pub then: Expr,
}

/// A list comprehension `[var IN list WHERE pred | projection]` (openCypher `ListComprehension`,
/// `FilterExpression = IdInColl [Where]`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct ListComprehension {
    /// The iteration variable.
    pub variable: Variable,
    /// The list being iterated.
    pub list: Box<Expr>,
    /// The optional `WHERE` filter predicate.
    pub predicate: Option<Box<Expr>>,
    /// The optional `| projection` expression; absent means "the variable itself" (a filter-only
    /// comprehension).
    pub projection: Option<Box<Expr>>,
}

/// A pattern comprehension `[p = (a)-->(b) WHERE pred | projection]` (openCypher
/// `PatternComprehension`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct PatternComprehension {
    /// The optional named-path variable (`p = ...`).
    pub var: Option<Variable>,
    /// The relationship pattern (a node followed by at least one chain link).
    pub element: PatternElement,
    /// The optional `WHERE` predicate.
    pub predicate: Option<Box<Expr>>,
    /// The mandatory `| projection` expression.
    pub projection: Box<Expr>,
}

/// A quantifier predicate `all/any/none/single(var IN list WHERE pred)` (openCypher `Quantifier`).
///
/// Evaluates the predicate for each list element with `var` bound, combining the per-element
/// ternary results per the quantifier kind (Kleene 3VL with short-circuiting).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct QuantifierExpr {
    /// Which quantifier was written.
    pub kind: QuantifierKind,
    /// The iteration variable.
    pub variable: Variable,
    /// The list being quantified over.
    pub list: Box<Expr>,
    /// The `WHERE` predicate tested per element.
    pub predicate: Box<Expr>,
}

/// The four openCypher quantifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum QuantifierKind {
    /// `all(...)` — every element satisfies the predicate.
    All,
    /// `any(...)` — at least one element satisfies the predicate.
    Any,
    /// `none(...)` — no element satisfies the predicate.
    None,
    /// `single(...)` — exactly one element satisfies the predicate.
    Single,
}

/// A list fold `reduce(accumulator = init, variable IN list | body)` (openCypher / Neo4j `reduce`).
///
/// Evaluates as a left fold: the accumulator starts at `init`, and for each element of `list` the
/// `body` is evaluated with both `accumulator` and `variable` bound, its result becoming the new
/// accumulator; the final accumulator is returned. An empty list yields `init`; a `null` list yields
/// `null`. The `accumulator` and `variable` are scoped to `body` only (they do not escape).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct ReduceExpr {
    /// The accumulator variable, bound to `init` initially and to each fold step's result after.
    pub accumulator: Variable,
    /// The initial accumulator value, evaluated in the enclosing scope.
    pub init: Box<Expr>,
    /// The iteration variable, bound to each element of `list` in turn.
    pub variable: Variable,
    /// The list being folded, evaluated in the enclosing scope.
    pub list: Box<Expr>,
    /// The fold step, evaluated with `accumulator` and `variable` in scope.
    pub body: Box<Expr>,
}

/// A map projection `entity { selector, ... }` (Neo4j map projection): reshapes a node, relationship
/// or map into a new map by projecting selected properties and/or literal entries.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct MapProjection {
    /// The projected entity — a node, relationship or map (evaluated once). A `null` entity makes the
    /// whole projection `null`.
    pub entity: Box<Expr>,
    /// The selectors, in source order.
    pub selectors: Vec<MapProjectionSelector>,
}

/// One element of a [`MapProjection`] (Neo4j map-projection selector).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum MapProjectionSelector {
    /// A property selector `.name` — the entity's `name` property (`name: entity.name`).
    Property(String),
    /// The all-properties selector `.*` — every property of the entity. Applied **before** the other
    /// selectors (mirroring Neo4j's `includeAllProps` flag), which may then override individual keys.
    AllProperties,
    /// A literal entry `key: expr`, **or** the variable-selector shorthand `var` (desugared at parse
    /// time to `var: var`, i.e. `key` = the variable name and `value` an [`ExprKind::Variable`]) so
    /// every generic expression walker handles it uniformly — exactly as Neo4j desugars it.
    Entry {
        /// The result key.
        key: MapKey,
        /// The entry's value expression, evaluated in the enclosing scope.
        value: Box<Expr>,
    },
}

/// An existential subquery (openCypher `ExistentialSubquery`).
///
/// Two arms, distinguished by [`full_query`](Self::full_query) / [`is_full_query`](Self::is_full_query):
///
/// - **Pattern form** (`full_query` is `None`): `EXISTS { [MATCH] pattern [WHERE pred] }` — true iff
///   the pattern (constrained by the outer row's bindings and the optional `WHERE`) matches at least
///   once. The [`pattern`](Self::pattern) / [`predicate`](Self::predicate) fields carry the parts.
///   This is also how a bare **pattern predicate** (`(n)-[]->()`) desugars
///   ([`from_pattern_predicate`](Self::from_pattern_predicate)).
/// - **Full-query form** (`full_query` is `Some`): `EXISTS { MATCH ... [WITH ...] RETURN ... }` — the
///   braces hold a complete, **read-only** Cypher query (openCypher `RegularQuery`); the subquery is
///   true iff that query yields at least one row. The interior is **correlated**: outer-scope
///   variables are visible and constrain it, while variables it introduces do not escape. A writing
///   clause (`CREATE`/`MERGE`/`SET`/`DELETE`/`REMOVE`) inside it is a compile-time
///   `InvalidClauseComposition`. In this arm [`pattern`](Self::pattern) is empty,
///   [`predicate`](Self::predicate) is `None`, and [`from_pattern_predicate`](Self::from_pattern_predicate)
///   is `false`; the query lives in [`full_query`](Self::full_query).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct ExistsSubquery {
    /// The pattern parts (comma-separated), at least one — **pattern form only** (empty in the
    /// full-query form).
    pub pattern: Vec<PatternPart>,
    /// The optional `WHERE` predicate over the pattern's bindings — **pattern form only** (`None` in
    /// the full-query form).
    pub predicate: Option<Box<Expr>>,
    /// `true` when this node was synthesized from a bare **pattern predicate** (`(n)-[]->()` written
    /// directly as a boolean expression) rather than an explicit `EXISTS { ... }`.
    ///
    /// The two share evaluation semantics (existential over the pattern) but differ in their static
    /// rules: a pattern predicate (a) may **not** introduce fresh variables — every named variable
    /// must already be bound in the outer scope (openCypher `UndefinedVariable`; TCK
    /// `expressions/pattern/Pattern1` [10]) — and (b) is only valid in a **predicate position**, not
    /// inside a projection / `SET` right-hand side / function argument (openCypher `UnexpectedSyntax`;
    /// TCK `expressions/pattern/Pattern1` [22]–[24], `expressions/list/List6` [6]). An explicit
    /// `EXISTS { ... }` has neither restriction.
    pub from_pattern_predicate: bool,
    /// The **full-query form**: when `Some`, the braces held a complete read-only Cypher query
    /// (`EXISTS { MATCH ... RETURN ... }`) rather than a bare pattern. The other three fields are
    /// then inert (`pattern` empty, `predicate` `None`, `from_pattern_predicate` `false`).
    pub full_query: Option<Box<Query>>,
}

/// The body of a [`COUNT`](ExprKind::CountSubquery) / [`COLLECT`](ExprKind::CollectSubquery)
/// subquery expression: a bare pattern (`COUNT` only) or a full inner query.
///
/// Structurally mirrors the read-only, correlated shape of [`ExistsSubquery`] (the two are siblings —
/// all three see the outer scope implicitly and reject writing clauses), but with different result
/// semantics: `COUNT` yields the row count and `COLLECT` yields the list of a single returned column.
///
/// - **Pattern form** (`COUNT { (a)-->(b) [WHERE p] }`): [`pattern`](Self::pattern) is non-empty,
///   [`predicate`](Self::predicate) is the optional `WHERE`, and [`full_query`](Self::full_query) is
///   `None`. `COLLECT` never uses this form (its `RETURN` is mandatory).
/// - **Full-query form** (`COUNT { MATCH ... RETURN ... }`, `COLLECT { MATCH ... RETURN x }`):
///   [`full_query`](Self::full_query) is `Some` and the other two fields are inert.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct SubqueryExpr {
    /// The pattern parts (comma-separated) — **pattern form only** (empty in the full-query form).
    pub pattern: Vec<PatternPart>,
    /// The optional `WHERE` predicate over the pattern's bindings — **pattern form only**.
    pub predicate: Option<Box<Expr>>,
    /// The **full-query form**: when `Some`, the braces held a complete Cypher query.
    pub full_query: Option<Box<Query>>,
}

impl SubqueryExpr {
    /// Whether this is the **full-query** arm rather than the bare-pattern arm.
    #[must_use]
    pub fn is_full_query(&self) -> bool {
        self.full_query.is_some()
    }
}

impl ExistsSubquery {
    /// Whether this is the **full-query** arm (`EXISTS { MATCH ... RETURN ... }`) rather than the
    /// pattern arm (`EXISTS { (a)-->(b) }` / a bare pattern predicate).
    #[must_use]
    pub fn is_full_query(&self) -> bool {
        self.full_query.is_some()
    }
}
