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
    /// The body of the query.
    pub body: QueryBody,
    /// The byte span covering the whole statement (excluding any trailing `;`).
    pub span: Span,
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
    /// The (possibly empty) label list.
    pub labels: Vec<Label>,
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
    /// The (possibly empty) relationship type alternatives (`:A|B|C`).
    pub types: Vec<RelType>,
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
            ExprKind::Unary { operand, .. } | ExprKind::HasLabels { operand, .. } => {
                operand.zero_spans_in_place();
            }
            ExprKind::Predicate { operand, rhs, .. } => {
                operand.zero_spans_in_place();
                if let Some(rhs) = rhs {
                    rhs.zero_spans_in_place();
                }
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
            link.node.zero_expr_spans_in_place();
        }
    }
}

impl NodePattern {
    fn zero_expr_spans_in_place(&mut self) {
        if let Some(props) = &mut self.properties {
            props.zero_spans_in_place();
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
    /// A label predicate `expr:Label1:Label2` (openCypher `NonArithmeticOperatorExpression` trailing
    /// `NodeLabels`) — tests whether the entity has all the listed labels.
    HasLabels {
        /// The base expression.
        operand: Box<Expr>,
        /// The labels tested.
        labels: Vec<Label>,
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
    /// An existential subquery `EXISTS { [MATCH] pattern [WHERE p] }` (openCypher
    /// `ExistentialSubquery`). Boxed for the same embedded-pattern reason as
    /// [`PatternComprehension`](Self::PatternComprehension).
    ExistsSubquery(Box<ExistsSubquery>),
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

impl ExistsSubquery {
    /// Whether this is the **full-query** arm (`EXISTS { MATCH ... RETURN ... }`) rather than the
    /// pattern arm (`EXISTS { (a)-->(b) }` / a bare pattern predicate).
    #[must_use]
    pub fn is_full_query(&self) -> bool {
        self.full_query.is_some()
    }
}
