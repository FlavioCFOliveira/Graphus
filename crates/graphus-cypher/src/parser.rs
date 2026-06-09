//! The Cypher **parser**: a hand-written recursive-descent clause/statement parser with a Pratt
//! expression parser, consuming the [`lexer`](crate::lexer)'s token stream and producing an
//! [`ast::Query`](crate::ast::Query).
//!
//! `04-technical-design.md` §7.1 mandates *"parser (hand-written recursive descent / Pratt) → AST"*
//! and §7.3 splits compile-time errors into a **syntax** phase (this parser) and a **semantic** phase
//! (the next sub-task). This parser therefore raises **only** [`SyntaxError`]s with **precise byte
//! positions** — the offending token's [`Span`] — because the openCypher TCK asserts the offset of
//! every `SyntaxError`. It does **not** perform name resolution, type checking, clause-ordering
//! validation, arity checking, or integer-range checking; those are semantic and belong to the next
//! phase (`04 §7.3`).
//!
//! # Grammar grounding
//!
//! Productions follow the openCypher EBNF (M23, mirrored at
//! <https://s3.amazonaws.com/artifacts.opencypher.org/M23/cypher.ebnf>), the same artifact the
//! [`lexer`](crate::lexer) cites. Each parse routine names the production it implements. Where
//! Graphus targets the broader 2024.x line (`D-cypher-line`) the deviations are called out.
//!
//! # Expression precedence (from the openCypher EBNF, lowest → highest binding)
//!
//! The EBNF expresses precedence by **production nesting**: the outermost production binds loosest.
//! Read top-to-bottom, each row binds tighter than the one above. (Production: M23 `Expression` and
//! descendants.)
//!
//! | Level | Operators | Assoc. | EBNF production |
//! |------:|-----------|--------|-----------------|
//! | 1 (loosest) | `OR` | left | `OrExpression` |
//! | 2 | `XOR` | left | `XorExpression` |
//! | 3 | `AND` | left | `AndExpression` |
//! | 4 | `NOT` (prefix) | — | `NotExpression` |
//! | 5 | `=` `<>` `<` `>` `<=` `>=` | left (chained) | `ComparisonExpression` |
//! | 6 | `STARTS WITH` `ENDS WITH` `CONTAINS` `IN` `=~`* `IS [NOT] NULL` | left (postfix) | `StringListNullPredicateExpression` |
//! | 7 | `+` `-` | left | `AddOrSubtractExpression` |
//! | 8 | `*` `/` `%` | left | `MultiplyDivideModuloExpression` |
//! | 9 | `^` | **right** | `PowerOfExpression` |
//! | 10 | unary `+` `-` (prefix) | — | `UnaryAddOrSubtractExpression` |
//! | 11 | `.` `[]` `[..]` `:Label` (postfix) | left | `NonArithmeticOperatorExpression` |
//! | 12 (tightest) | atoms: literals, `$p`, vars, `f(...)`, `count(*)`, `[...]`, `{...}`, `CASE`, comprehensions, `(...)` | — | `Atom` |
//!
//! \* `=~` is, in the M23 EBNF, a *function-like* construct in some lines; Graphus places it at the
//! string/list/null predicate level (binding tighter than comparison, looser than `+`), which is the
//! conventional, TCK-observed precedence for a regex match — documented here as a deliberate, cited
//! resolution (see the module note below).
//!
//! ## One grammar ambiguity resolved (cited)
//!
//! The M23 EBNF folds `STARTS WITH`/`ENDS WITH`/`CONTAINS`/`IN`/`IS NULL` into
//! `StringListNullPredicateExpression`, which sits **inside** `ComparisonExpression` — i.e. these
//! predicates bind **tighter** than `=`/`<`/`>`. So `a = b IN c` parses as `a = (b IN c)`. We follow
//! the EBNF nesting exactly (the predicate is parsed as the operand of the comparison). `=~` has no
//! dedicated production in M23 (it is realized through the regex function in that line); we model it
//! as a binary operator at the *predicate* level so `a =~ b` round-trips and binds like the other
//! string predicates — this is the precedence Neo4j's Cypher and the TCK exhibit, and is recorded as
//! an explicit decision here.

use crate::ast::{
    BinaryOp, CallClause, CaseAlternative, CaseExpr, Clause, CreateClause, DeleteClause, Expr,
    ExprKind, Label, ListComprehension, Literal, MapKey, MatchClause, MergeAction, MergeClause,
    NodePattern, PatternChainLink, PatternComprehension, PatternElement, PatternPart, PredicateOp,
    ProcedureCall, ProjectionBody, ProjectionItem, Query, QueryBody, RelDirection, RelType,
    RelationshipPattern, RemoveClause, RemoveItem, ReturnClause, SetClause, SetItem, SingleQuery,
    SortDirection, SortItem, StandaloneCall, StandaloneYield, UnaryOp, UnionPart, UnwindClause,
    VarLengthRange, Variable, WithClause, YieldItem,
};
use crate::lexer::{IntLiteral, Span, Token, TokenKind, tokenize};
use graphus_core::GraphusError;
use std::fmt;

/// A compile-time **syntax** error (`04 §7.3`), carrying the byte [`Span`] of the offending region.
///
/// This is the parser's analogue of the lexer's [`LexError`](crate::lexer::LexError). Like it,
/// [`SyntaxError`] converts into the crate-wide [`GraphusError::Compile`] at the engine boundary,
/// preserving the span in the message so the connectivity layer can surface a positional error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct SyntaxError {
    /// The classified cause.
    pub kind: SyntaxErrorKind,
    /// The byte range of the offending token / region.
    pub span: Span,
}

impl SyntaxError {
    /// Builds a [`SyntaxError`].
    pub fn new(kind: SyntaxErrorKind, span: Span) -> Self {
        Self { kind, span }
    }
}

impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "syntax error at bytes {}: {}", self.span, self.kind)
    }
}

impl std::error::Error for SyntaxError {}

impl From<SyntaxError> for GraphusError {
    /// Parser errors are compile-time `SyntaxError`s (`04 §7.3`); they map onto the crate-wide
    /// [`GraphusError::Compile`] variant, carrying the positional message.
    fn from(e: SyntaxError) -> Self {
        GraphusError::Compile(e.to_string())
    }
}

/// What went wrong while parsing, paired with a byte [`Span`] by [`SyntaxError`].
///
/// Every variant is the compile-time `SyntaxError` class (`04 §7.3`); the distinct variants let the
/// TCK error-classification table and diagnostics describe the fault precisely while keeping the
/// "expected X, found Y" shape the TCK's positional scenarios assert.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyntaxErrorKind {
    /// A token of a different kind than required was found. `expected` is a human description of
    /// what the grammar required at that position; `found` describes the offending token (or
    /// `"end of input"`).
    Expected {
        /// What the grammar required (e.g. `"')'"`, `"a variable"`, `"RETURN"`).
        expected: String,
        /// What was actually there.
        found: String,
    },
    /// Input ended before the construct was complete.
    UnexpectedEof {
        /// What the grammar required next.
        expected: String,
    },
    /// Trailing tokens remained after a complete statement (and optional `;`).
    TrailingInput,
    /// A construct was structurally well-formed at the token level but is not a legal start of any
    /// expression / clause here (e.g. an operator where an operand was required).
    UnexpectedToken {
        /// A description of the offending token.
        found: String,
    },
}

impl fmt::Display for SyntaxErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expected { expected, found } => {
                write!(f, "expected {expected}, found {found}")
            }
            Self::UnexpectedEof { expected } => {
                write!(f, "expected {expected}, found end of input")
            }
            Self::TrailingInput => f.write_str("unexpected trailing input after statement"),
            Self::UnexpectedToken { found } => write!(f, "unexpected {found}"),
        }
    }
}

/// Parses a complete Cypher statement from `input`, returning its [`Query`] AST.
///
/// This is the parser's public entry point (`04 §7.1`): it lexes `input` (so a malformed token is a
/// lexer [`LexError`](crate::lexer::LexError) converted to a [`SyntaxError`]-equivalent message via
/// [`GraphusError::Compile`]) and then parses the token stream into an AST. The optional trailing
/// `;` is accepted; any tokens after a complete statement are a [`SyntaxErrorKind::TrailingInput`].
///
/// # Errors
///
/// Returns a [`GraphusError::Compile`] (the compile-time `SyntaxError` class, `04 §7.3`) for any
/// lexing or parsing failure. The message embeds the offending byte [`Span`] so positions survive to
/// the client. To inspect the structured [`SyntaxError`] (with its [`Span`]) directly — e.g. in tests
/// that assert exact positions — use [`parse_tokens`] on a pre-lexed token slice plus its source.
///
/// # Examples
///
/// ```
/// use graphus_cypher::parser::parse;
///
/// // MATCH (with its inline WHERE) and RETURN are the two clauses; WHERE is part of MATCH.
/// let q = parse("MATCH (n:Person) WHERE n.age > 18 RETURN n.name AS name").expect("valid");
/// assert_eq!(q.body_single_query().clauses.len(), 2);
/// ```
pub fn parse(input: &str) -> Result<Query, GraphusError> {
    let tokens = tokenize(input)?;
    parse_tokens(&tokens, input).map_err(GraphusError::from)
}

/// Parses a pre-lexed token slice into a [`Query`], returning the structured [`SyntaxError`]
/// (with its byte [`Span`]) on failure.
///
/// `source` is the original query text the `tokens` were lexed from; the parser uses it to position
/// end-of-input errors (their span is the empty range `source.len()..source.len()`) and to recover
/// the **original case** of keyword-spelled schema names (e.g. a label `:order` written lowercase),
/// since the lexer normalizes keyword recognition case-insensitively. `tokens` must be the exact
/// output of [`tokenize`]`(source)`. Use [`parse`] for the convenient
/// string-in / [`GraphusError`]-out form.
///
/// # Errors
///
/// Returns a [`SyntaxError`] (compile-time `SyntaxError` class, `04 §7.3`) carrying the byte span of
/// the first offending token or region.
pub fn parse_tokens(tokens: &[Token], source: &str) -> Result<Query, SyntaxError> {
    let mut p = Parser::new(tokens, source);
    let query = p.parse_query()?;
    // Accept an optional trailing `;` (openCypher `Cypher = ..., [';'], EOI`).
    p.eat(&TokenKind::Semicolon);
    if let Some(tok) = p.peek() {
        return Err(SyntaxError::new(SyntaxErrorKind::TrailingInput, tok.span));
    }
    Ok(query)
}

impl Query {
    /// Returns the single query when `self` is a regular query with no `UNION`.
    ///
    /// # Panics
    ///
    /// Panics if `self` is a `UNION` chain or a standalone `CALL`. This is a **test/doc
    /// convenience** for the common single-query case; production code should match on
    /// [`QueryBody`] explicitly. The panic message names the actual shape.
    pub fn body_single_query(&self) -> &SingleQuery {
        match &self.body {
            QueryBody::Regular { head, unions } if unions.is_empty() => head,
            QueryBody::Regular { .. } => {
                panic!("body_single_query called on a UNION chain; match on QueryBody instead")
            }
            QueryBody::StandaloneCall(_) => {
                panic!("body_single_query called on a standalone CALL; match on QueryBody instead")
            }
        }
    }
}

/// The recursive-descent + Pratt parser state: a cursor over a token slice.
struct Parser<'t, 's> {
    /// The tokens to parse.
    tokens: &'t [Token],
    /// The original source text (for end-of-input spans and keyword-name case recovery).
    source: &'s str,
    /// The current token index.
    pos: usize,
}

impl<'t, 's> Parser<'t, 's> {
    /// Creates a parser over `tokens` lexed from `source`.
    fn new(tokens: &'t [Token], source: &'s str) -> Self {
        Self {
            tokens,
            source,
            pos: 0,
        }
    }

    // --- cursor primitives -----------------------------------------------------------------------

    /// Peeks the current token without consuming it.
    fn peek(&self) -> Option<&'t Token> {
        self.tokens.get(self.pos)
    }

    /// Peeks the token `n` ahead without consuming.
    fn peek_at(&self, n: usize) -> Option<&'t Token> {
        self.tokens.get(self.pos + n)
    }

    /// Peeks the current token's kind.
    fn peek_kind(&self) -> Option<&'t TokenKind> {
        self.peek().map(|t| &t.kind)
    }

    /// Consumes and returns the current token.
    fn bump(&mut self) -> Option<&'t Token> {
        let t = self.tokens.get(self.pos);
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    /// The span to attribute to an end-of-input error: the empty range at the source end.
    fn eof_span(&self) -> Span {
        Span::new(self.source.len(), self.source.len())
    }

    /// The span of the current token, or the end-of-input span if exhausted.
    fn here_span(&self) -> Span {
        self.peek().map_or_else(|| self.eof_span(), |t| t.span)
    }

    /// Returns `true` (without consuming) if the current token matches `kind` exactly.
    fn at(&self, kind: &TokenKind) -> bool {
        self.peek_kind() == Some(kind)
    }

    /// Consumes the current token iff it matches `kind`; returns whether it did.
    fn eat(&mut self, kind: &TokenKind) -> bool {
        if self.at(kind) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Consumes a token that must equal `kind`, or errors with an "expected {desc}" message
    /// positioned at the offending token (or end of input).
    fn expect(&mut self, kind: &TokenKind, desc: &str) -> Result<&'t Token, SyntaxError> {
        match self.peek() {
            Some(t) if &t.kind == kind => {
                self.pos += 1;
                Ok(t)
            }
            Some(t) => Err(SyntaxError::new(
                SyntaxErrorKind::Expected {
                    expected: desc.to_owned(),
                    found: describe(&t.kind),
                },
                t.span,
            )),
            None => Err(SyntaxError::new(
                SyntaxErrorKind::UnexpectedEof {
                    expected: desc.to_owned(),
                },
                self.eof_span(),
            )),
        }
    }

    /// Builds an "expected {desc}, found {current}" error at the current position (or EOF).
    fn expected_here(&self, desc: &str) -> SyntaxError {
        match self.peek() {
            Some(t) => SyntaxError::new(
                SyntaxErrorKind::Expected {
                    expected: desc.to_owned(),
                    found: describe(&t.kind),
                },
                t.span,
            ),
            None => SyntaxError::new(
                SyntaxErrorKind::UnexpectedEof {
                    expected: desc.to_owned(),
                },
                self.eof_span(),
            ),
        }
    }

    // --- top level -------------------------------------------------------------------------------

    /// Parses `Query = RegularQuery | StandaloneCall`.
    fn parse_query(&mut self) -> Result<Query, SyntaxError> {
        let start = self.here_span().start;
        // A standalone CALL is recognized by a leading `CALL` that is *not* part of a longer single
        // query (i.e. it is the whole statement). The grammar distinguishes `StandaloneCall` (no
        // surrounding clauses) from an `InQueryCall`. We parse a standalone call only when `CALL` is
        // the very first clause AND there is no other clause; the simplest faithful approach is: a
        // leading CALL that yields `*`, or a CALL followed by end/`;`, is standalone. To keep the
        // phase split clean we parse the first single query and, if it consists of exactly one CALL
        // clause whose YIELD is `*` or absent, surface it as a StandaloneCall.
        if self.at(&TokenKind::Call) {
            if let Some(call) = self.try_parse_standalone_call()? {
                let end = call.span.end;
                return Ok(Query {
                    body: QueryBody::StandaloneCall(call),
                    span: Span::new(start, end),
                });
            }
        }

        let head = self.parse_single_query()?;
        let mut unions = Vec::new();
        while self.at(&TokenKind::Union) {
            unions.push(self.parse_union_part()?);
        }
        let end = unions
            .last()
            .map_or(head.span.end, |u: &UnionPart| u.span.end);
        Ok(Query {
            body: QueryBody::Regular { head, unions },
            span: Span::new(start, end),
        })
    }

    /// Parses `Union = 'UNION', ['ALL'], SingleQuery`.
    fn parse_union_part(&mut self) -> Result<UnionPart, SyntaxError> {
        let start = self.here_span().start;
        self.expect(&TokenKind::Union, "UNION")?;
        let all = self.eat(&TokenKind::All);
        let query = self.parse_single_query()?;
        let end = query.span.end;
        Ok(UnionPart {
            all,
            query,
            span: Span::new(start, end),
        })
    }

    /// Parses a `SingleQuery` as a flat list of clauses (clause-ordering is a semantic check).
    fn parse_single_query(&mut self) -> Result<SingleQuery, SyntaxError> {
        let start = self.here_span().start;
        let mut clauses = Vec::new();
        while let Some(clause) = self.try_parse_clause()? {
            clauses.push(clause);
        }
        if clauses.is_empty() {
            return Err(self.expected_here("a query clause (MATCH, CREATE, RETURN, …)"));
        }
        let end = clauses.last().map_or(start, |c: &Clause| c.span().end);
        Ok(SingleQuery {
            clauses,
            span: Span::new(start, end),
        })
    }

    /// Parses one clause if the current token begins one; returns `None` at a clause boundary
    /// (`UNION`, `;`, EOF, or a token that cannot start a clause — left for the caller / trailing
    /// check).
    fn try_parse_clause(&mut self) -> Result<Option<Clause>, SyntaxError> {
        let kind = match self.peek_kind() {
            Some(k) => k,
            None => return Ok(None),
        };
        let clause = match kind {
            TokenKind::Optional | TokenKind::Match => Clause::Match(self.parse_match()?),
            TokenKind::Unwind => Clause::Unwind(self.parse_unwind()?),
            TokenKind::Call => Clause::Call(self.parse_in_query_call()?),
            TokenKind::Create => Clause::Create(self.parse_create()?),
            TokenKind::Merge => Clause::Merge(self.parse_merge()?),
            TokenKind::Set => Clause::Set(self.parse_set()?),
            TokenKind::Detach | TokenKind::Delete => Clause::Delete(self.parse_delete()?),
            TokenKind::Remove => Clause::Remove(self.parse_remove()?),
            TokenKind::With => Clause::With(self.parse_with()?),
            TokenKind::Return => Clause::Return(self.parse_return()?),
            // Not a clause start: `UNION`, `;`, or trailing garbage. Stop the clause loop.
            _ => return Ok(None),
        };
        Ok(Some(clause))
    }

    // --- reading clauses -------------------------------------------------------------------------

    /// Parses `Match = ['OPTIONAL'], 'MATCH', Pattern, ['WHERE', Expression]`.
    fn parse_match(&mut self) -> Result<MatchClause, SyntaxError> {
        let start = self.here_span().start;
        let optional = self.eat(&TokenKind::Optional);
        self.expect(&TokenKind::Match, "MATCH")?;
        let pattern = self.parse_pattern()?;
        let where_clause = self.parse_optional_where()?;
        let end = where_clause
            .as_ref()
            .map(|e| e.span.end)
            .or_else(|| pattern.last().map(|p| p.span.end))
            .unwrap_or(start);
        Ok(MatchClause {
            optional,
            pattern,
            where_clause,
            span: Span::new(start, end),
        })
    }

    /// Parses `Unwind = 'UNWIND', Expression, 'AS', Variable`.
    fn parse_unwind(&mut self) -> Result<UnwindClause, SyntaxError> {
        let start = self.here_span().start;
        self.expect(&TokenKind::Unwind, "UNWIND")?;
        let expr = self.parse_expr()?;
        self.expect(&TokenKind::As, "AS")?;
        let alias = self.parse_variable()?;
        let end = alias.span.end;
        Ok(UnwindClause {
            expr,
            alias,
            span: Span::new(start, end),
        })
    }

    /// Parses `InQueryCall = 'CALL', ExplicitProcedureInvocation, ['YIELD', YieldItems]`.
    fn parse_in_query_call(&mut self) -> Result<CallClause, SyntaxError> {
        let start = self.here_span().start;
        self.expect(&TokenKind::Call, "CALL")?;
        let call = self.parse_procedure_call(/* allow_implicit */ false)?;
        let mut end = call.span.end;
        let (yield_items, where_clause) = if self.eat(&TokenKind::Yield) {
            let (items, where_clause, y_end) = self.parse_yield_items()?;
            end = y_end;
            (Some(items), where_clause)
        } else {
            (None, None)
        };
        Ok(CallClause {
            call,
            yield_items,
            where_clause,
            span: Span::new(start, end),
        })
    }

    /// Attempts to parse a `StandaloneCall`. Returns `Some` only if this `CALL` is the entire
    /// statement (no further clauses follow). Restores the cursor and returns `None` otherwise, so
    /// the caller can re-parse it as an in-query `CALL`.
    ///
    /// openCypher `StandaloneCall = 'CALL', (Explicit | Implicit)ProcedureInvocation,
    /// ['YIELD', ('*' | YieldItems)]`. The `YIELD *` form is *only* legal standalone.
    fn try_parse_standalone_call(&mut self) -> Result<Option<StandaloneCall>, SyntaxError> {
        let checkpoint = self.pos;
        let start = self.here_span().start;
        self.expect(&TokenKind::Call, "CALL")?;
        let call = self.parse_procedure_call(/* allow_implicit */ true)?;
        let mut end = call.span.end;

        let yield_clause = if self.eat(&TokenKind::Yield) {
            if self.eat(&TokenKind::Star) {
                end = self.tokens[self.pos - 1].span.end;
                Some(StandaloneYield::Star)
            } else {
                let (items, where_clause, y_end) = self.parse_yield_items()?;
                end = y_end;
                Some(StandaloneYield::Items {
                    items,
                    where_clause,
                })
            }
        } else {
            None
        };

        // Standalone only if nothing else follows (optional `;` then EOF).
        let mut lookahead = self.pos;
        if matches!(
            self.tokens.get(lookahead).map(|t| &t.kind),
            Some(TokenKind::Semicolon)
        ) {
            lookahead += 1;
        }
        if lookahead >= self.tokens.len() {
            return Ok(Some(StandaloneCall {
                call,
                yield_clause,
                span: Span::new(start, end),
            }));
        }

        // Other clauses follow → this is an in-query CALL; rewind for the normal path.
        self.pos = checkpoint;
        Ok(None)
    }

    /// Parses `YieldItems = YieldItem, { ',', YieldItem }, [Where]`, returning the items, the
    /// optional trailing `WHERE`, and the end offset.
    fn parse_yield_items(&mut self) -> Result<(Vec<YieldItem>, Option<Expr>, usize), SyntaxError> {
        let mut items = vec![self.parse_yield_item()?];
        while self.eat(&TokenKind::Comma) {
            items.push(self.parse_yield_item()?);
        }
        let mut end = items.last().map_or(0, |i| i.span.end);
        let where_clause = self.parse_optional_where()?;
        if let Some(w) = &where_clause {
            end = w.span.end;
        }
        Ok((items, where_clause, end))
    }

    /// Parses `YieldItem = [ProcedureResultField, 'AS'], Variable`.
    fn parse_yield_item(&mut self) -> Result<YieldItem, SyntaxError> {
        let start = self.here_span().start;
        // `field AS var` vs bare `var`: a leading identifier followed by `AS` is the field form.
        if matches!(self.peek_kind(), Some(TokenKind::Identifier(_)))
            && matches!(self.peek_at(1).map(|t| &t.kind), Some(TokenKind::As))
        {
            let field = self.parse_symbolic_name("a YIELD result field")?;
            self.expect(&TokenKind::As, "AS")?;
            let alias = self.parse_variable()?;
            let end = alias.span.end;
            Ok(YieldItem {
                field: Some(field),
                alias,
                span: Span::new(start, end),
            })
        } else {
            let alias = self.parse_variable()?;
            let end = alias.span.end;
            Ok(YieldItem {
                field: None,
                alias,
                span: Span::new(start, end),
            })
        }
    }

    // --- updating clauses ------------------------------------------------------------------------

    /// Parses `Create = 'CREATE', Pattern`.
    fn parse_create(&mut self) -> Result<CreateClause, SyntaxError> {
        let start = self.here_span().start;
        self.expect(&TokenKind::Create, "CREATE")?;
        let pattern = self.parse_pattern()?;
        let end = pattern.last().map_or(start, |p| p.span.end);
        Ok(CreateClause {
            pattern,
            span: Span::new(start, end),
        })
    }

    /// Parses `Merge = 'MERGE', PatternPart, { MergeAction }`.
    fn parse_merge(&mut self) -> Result<MergeClause, SyntaxError> {
        let start = self.here_span().start;
        self.expect(&TokenKind::Merge, "MERGE")?;
        let pattern = self.parse_pattern_part()?;
        let mut end = pattern.span.end;
        let mut actions = Vec::new();
        while self.at(&TokenKind::On) {
            let (action, a_end) = self.parse_merge_action()?;
            actions.push(action);
            end = a_end;
        }
        Ok(MergeClause {
            pattern,
            actions,
            span: Span::new(start, end),
        })
    }

    /// Parses `MergeAction = ('ON', 'CREATE', Set) | ('ON', 'MATCH', Set)`, returning the action and
    /// its end offset.
    fn parse_merge_action(&mut self) -> Result<(MergeAction, usize), SyntaxError> {
        self.expect(&TokenKind::On, "ON")?;
        // After ON, expect CREATE or MATCH.
        let on_create = match self.peek_kind() {
            Some(TokenKind::Create) => true,
            Some(TokenKind::Match) => false,
            _ => return Err(self.expected_here("CREATE or MATCH after ON")),
        };
        self.bump(); // consume CREATE / MATCH
        let set = self.parse_set()?;
        let end = set.span.end;
        let action = if on_create {
            MergeAction::OnCreate(set.items)
        } else {
            MergeAction::OnMatch(set.items)
        };
        Ok((action, end))
    }

    /// Parses `Set = 'SET', SetItem, { ',', SetItem }`.
    fn parse_set(&mut self) -> Result<SetClause, SyntaxError> {
        let start = self.here_span().start;
        self.expect(&TokenKind::Set, "SET")?;
        let mut items = vec![self.parse_set_item()?];
        while self.eat(&TokenKind::Comma) {
            items.push(self.parse_set_item()?);
        }
        let end = self.prev_end(start);
        Ok(SetClause {
            items,
            span: Span::new(start, end),
        })
    }

    /// Parses one `SetItem`:
    /// `PropertyExpression '=' Expression` | `Variable '=' Expression` | `Variable '+=' Expression`
    /// | `Variable NodeLabels`.
    ///
    /// We parse a postfix expression for the target, then dispatch on the following operator. A
    /// `Variable` target for `=`/`+=` is distinguished from a `PropertyExpression` target by whether
    /// the parsed target is a bare variable or a property chain.
    fn parse_set_item(&mut self) -> Result<SetItem, SyntaxError> {
        // `n:Label` label-set form: a bare variable immediately followed by `:`.
        if matches!(self.peek_kind(), Some(TokenKind::Identifier(_)))
            && matches!(self.peek_at(1).map(|t| &t.kind), Some(TokenKind::Colon))
        {
            let target = self.parse_variable()?;
            let labels = self.parse_node_labels()?;
            return Ok(SetItem::Labels { target, labels });
        }

        let target = self.parse_postfix_expr()?;
        if self.eat(&TokenKind::PlusEq) {
            let value = self.parse_expr()?;
            let var = self.expect_variable_target(target, "+=")?;
            Ok(SetItem::Merge { target: var, value })
        } else if self.eat(&TokenKind::Eq) {
            let value = self.parse_expr()?;
            match target.kind {
                ExprKind::Variable(name) => Ok(SetItem::Replace {
                    target: Variable {
                        name,
                        span: target.span,
                    },
                    value,
                }),
                // Any property-access (or other) target is the property-assignment form.
                _ => Ok(SetItem::Property { target, value }),
            }
        } else {
            Err(self.expected_here("'=', '+=', or a label after a SET target"))
        }
    }

    /// Requires that a parsed target expression is a bare variable (for `+=`), erroring otherwise.
    fn expect_variable_target(&self, target: Expr, op: &str) -> Result<Variable, SyntaxError> {
        match target.kind {
            ExprKind::Variable(name) => Ok(Variable {
                name,
                span: target.span,
            }),
            _ => Err(SyntaxError::new(
                SyntaxErrorKind::Expected {
                    expected: format!("a variable on the left of '{op}'"),
                    found: "a non-variable expression".to_owned(),
                },
                target.span,
            )),
        }
    }

    /// Parses `Delete = ['DETACH'], 'DELETE', Expression, { ',', Expression }`.
    fn parse_delete(&mut self) -> Result<DeleteClause, SyntaxError> {
        let start = self.here_span().start;
        let detach = self.eat(&TokenKind::Detach);
        self.expect(&TokenKind::Delete, "DELETE")?;
        let mut exprs = vec![self.parse_expr()?];
        while self.eat(&TokenKind::Comma) {
            exprs.push(self.parse_expr()?);
        }
        let end = exprs.last().map_or(start, |e| e.span.end);
        Ok(DeleteClause {
            detach,
            exprs,
            span: Span::new(start, end),
        })
    }

    /// Parses `Remove = 'REMOVE', RemoveItem, { ',', RemoveItem }`.
    fn parse_remove(&mut self) -> Result<RemoveClause, SyntaxError> {
        let start = self.here_span().start;
        self.expect(&TokenKind::Remove, "REMOVE")?;
        let mut items = vec![self.parse_remove_item()?];
        while self.eat(&TokenKind::Comma) {
            items.push(self.parse_remove_item()?);
        }
        let end = self.prev_end(start);
        Ok(RemoveClause {
            items,
            span: Span::new(start, end),
        })
    }

    /// Parses `RemoveItem = (Variable, NodeLabels) | PropertyExpression`.
    fn parse_remove_item(&mut self) -> Result<RemoveItem, SyntaxError> {
        if matches!(self.peek_kind(), Some(TokenKind::Identifier(_)))
            && matches!(self.peek_at(1).map(|t| &t.kind), Some(TokenKind::Colon))
        {
            let target = self.parse_variable()?;
            let labels = self.parse_node_labels()?;
            Ok(RemoveItem::Labels { target, labels })
        } else {
            let expr = self.parse_postfix_expr()?;
            Ok(RemoveItem::Property(expr))
        }
    }

    // --- projection clauses ----------------------------------------------------------------------

    /// Parses `With = 'WITH', ProjectionBody, [Where]`.
    fn parse_with(&mut self) -> Result<WithClause, SyntaxError> {
        let start = self.here_span().start;
        self.expect(&TokenKind::With, "WITH")?;
        let body = self.parse_projection_body()?;
        let where_clause = self.parse_optional_where()?;
        let end = self.prev_end(start);
        Ok(WithClause {
            body,
            where_clause,
            span: Span::new(start, end),
        })
    }

    /// Parses `Return = 'RETURN', ProjectionBody`.
    fn parse_return(&mut self) -> Result<ReturnClause, SyntaxError> {
        let start = self.here_span().start;
        self.expect(&TokenKind::Return, "RETURN")?;
        let body = self.parse_projection_body()?;
        let end = self.prev_end(start);
        Ok(ReturnClause {
            body,
            span: Span::new(start, end),
        })
    }

    /// Parses `ProjectionBody = ['DISTINCT'], ProjectionItems, [Order], [Skip], [Limit]`.
    ///
    /// `ProjectionItems = ('*', { ',', ProjectionItem }) | (ProjectionItem, { ',', ProjectionItem })`.
    fn parse_projection_body(&mut self) -> Result<ProjectionBody, SyntaxError> {
        let distinct = self.eat(&TokenKind::Distinct);

        let mut star = false;
        let mut items = Vec::new();
        if self.eat(&TokenKind::Star) {
            star = true;
            while self.eat(&TokenKind::Comma) {
                items.push(self.parse_projection_item()?);
            }
        } else {
            items.push(self.parse_projection_item()?);
            while self.eat(&TokenKind::Comma) {
                items.push(self.parse_projection_item()?);
            }
        }

        let order_by = if self.at(&TokenKind::Order) {
            self.parse_order_by()?
        } else {
            Vec::new()
        };
        let skip = if self.eat(&TokenKind::Skip) {
            Some(self.parse_expr()?)
        } else {
            None
        };
        let limit = if self.eat(&TokenKind::Limit) {
            Some(self.parse_expr()?)
        } else {
            None
        };

        Ok(ProjectionBody {
            distinct,
            star,
            items,
            order_by,
            skip,
            limit,
        })
    }

    /// Parses `ProjectionItem = (Expression, 'AS', Variable) | Expression`.
    fn parse_projection_item(&mut self) -> Result<ProjectionItem, SyntaxError> {
        let expr = self.parse_expr()?;
        let start = expr.span.start;
        let (alias, end) = if self.eat(&TokenKind::As) {
            let v = self.parse_variable()?;
            let e = v.span.end;
            (Some(v), e)
        } else {
            (None, expr.span.end)
        };
        Ok(ProjectionItem {
            expr,
            alias,
            span: Span::new(start, end),
        })
    }

    /// Parses `Order = 'ORDER', 'BY', SortItem, { ',', SortItem }`.
    fn parse_order_by(&mut self) -> Result<Vec<SortItem>, SyntaxError> {
        self.expect(&TokenKind::Order, "ORDER")?;
        self.expect(&TokenKind::By, "BY")?;
        let mut items = vec![self.parse_sort_item()?];
        while self.eat(&TokenKind::Comma) {
            items.push(self.parse_sort_item()?);
        }
        Ok(items)
    }

    /// Parses `SortItem = Expression, [ASC | ASCENDING | DESC | DESCENDING]`.
    fn parse_sort_item(&mut self) -> Result<SortItem, SyntaxError> {
        let expr = self.parse_expr()?;
        let start = expr.span.start;
        let (direction, end) = match self.peek_kind() {
            Some(TokenKind::Asc | TokenKind::Ascending) => {
                let e = self.here_span().end;
                self.bump();
                (SortDirection::Ascending, e)
            }
            Some(TokenKind::Desc | TokenKind::Descending) => {
                let e = self.here_span().end;
                self.bump();
                (SortDirection::Descending, e)
            }
            _ => (SortDirection::Ascending, expr.span.end),
        };
        Ok(SortItem {
            expr,
            direction,
            span: Span::new(start, end),
        })
    }

    /// Parses an optional `Where = 'WHERE', Expression`, returning the predicate if present.
    fn parse_optional_where(&mut self) -> Result<Option<Expr>, SyntaxError> {
        if self.eat(&TokenKind::Where) {
            Ok(Some(self.parse_expr()?))
        } else {
            Ok(None)
        }
    }

    // --- patterns --------------------------------------------------------------------------------

    /// Parses `Pattern = PatternPart, { ',', PatternPart }`.
    fn parse_pattern(&mut self) -> Result<Vec<PatternPart>, SyntaxError> {
        let mut parts = vec![self.parse_pattern_part()?];
        while self.eat(&TokenKind::Comma) {
            parts.push(self.parse_pattern_part()?);
        }
        Ok(parts)
    }

    /// Parses `PatternPart = (Variable, '=', AnonymousPatternPart) | AnonymousPatternPart`.
    fn parse_pattern_part(&mut self) -> Result<PatternPart, SyntaxError> {
        let start = self.here_span().start;
        // Named path: `var = (...)`. A leading identifier followed by `=` is the named-path form.
        let var = if matches!(self.peek_kind(), Some(TokenKind::Identifier(_)))
            && matches!(self.peek_at(1).map(|t| &t.kind), Some(TokenKind::Eq))
        {
            let v = self.parse_variable()?;
            self.expect(&TokenKind::Eq, "'='")?;
            Some(v)
        } else {
            None
        };
        let element = self.parse_pattern_element()?;
        let end = element.span.end;
        Ok(PatternPart {
            var,
            element,
            span: Span::new(start, end),
        })
    }

    /// Parses `PatternElement = NodePattern, { PatternElementChain }`.
    fn parse_pattern_element(&mut self) -> Result<PatternElement, SyntaxError> {
        let start = self.here_span().start;
        let node = self.parse_node_pattern()?;
        let mut chain = Vec::new();
        // A chain link begins with a relationship: an arrow head (`<`) or a dash (`-`/`--`).
        while self.at_relationship_start() {
            let relationship = self.parse_relationship_pattern()?;
            let node = self.parse_node_pattern()?;
            chain.push(PatternChainLink { relationship, node });
        }
        let end = chain.last().map_or(node.span.end, |l| l.node.span.end);
        Ok(PatternElement {
            start: node,
            chain,
            span: Span::new(start, end),
        })
    }

    /// Whether the current token begins a relationship pattern (`<-`, `-`, `--`).
    fn at_relationship_start(&self) -> bool {
        matches!(
            self.peek_kind(),
            Some(TokenKind::ArrowLeft | TokenKind::Minus | TokenKind::DashDash)
        )
    }

    /// Parses `NodePattern = '(', [Variable], [NodeLabels], [Properties], ')'`.
    fn parse_node_pattern(&mut self) -> Result<NodePattern, SyntaxError> {
        let lparen = self.expect(&TokenKind::LParen, "'(' to begin a node pattern")?;
        let start = lparen.span.start;

        let variable = if matches!(self.peek_kind(), Some(TokenKind::Identifier(_))) {
            Some(self.parse_variable()?)
        } else {
            None
        };
        let labels = if self.at(&TokenKind::Colon) {
            self.parse_node_labels()?
        } else {
            Vec::new()
        };
        let properties = if self.at(&TokenKind::LBrace) || self.is_parameter() {
            Some(self.parse_properties()?)
        } else {
            None
        };

        let rparen = self.expect(&TokenKind::RParen, "')' to close the node pattern")?;
        Ok(NodePattern {
            variable,
            labels,
            properties,
            span: Span::new(start, rparen.span.end),
        })
    }

    /// Parses a `RelationshipPattern`: a left/right/undirected arrow with an optional
    /// `RelationshipDetail` bracket `[var :T1|T2 *1..2 {props}]`.
    ///
    /// openCypher `RelationshipPattern = (LeftArrowHead? Dash Detail? Dash RightArrowHead?)` in four
    /// arrow shapes. The [`lexer`](crate::lexer) tokenizes the arrow glyphs greedily, so the leading
    /// side appears as `<-` ([`ArrowLeft`](TokenKind::ArrowLeft), dash included), `-`
    /// ([`Minus`](TokenKind::Minus)), or `--` ([`DashDash`](TokenKind::DashDash), both dashes), and
    /// the trailing side as `->` ([`ArrowRight`](TokenKind::ArrowRight)), `-`, or a bare `>`
    /// ([`Gt`](TokenKind::Gt)) when the leading side already ate both dashes as `--`. The direction
    /// is derived from the (incoming arrow head?, outgoing arrow head?) pair. Concretely the eight
    /// well-formed glyph spellings reduce to:
    ///
    /// | spelling | tokens | direction |
    /// |----------|--------|-----------|
    /// | `-[..]->` | `Minus` … `ArrowRight` | left→right |
    /// | `-->` (no detail) | `DashDash` `Gt` | left→right |
    /// | `<-[..]-` | `ArrowLeft` … `Minus` | right→left |
    /// | `<--` (no detail) | `ArrowLeft` `Minus` | right→left |
    /// | `-[..]-` | `Minus` … `Minus` | undirected |
    /// | `--` (no detail) | `DashDash` | undirected |
    fn parse_relationship_pattern(&mut self) -> Result<RelationshipPattern, SyntaxError> {
        let start = self.here_span().start;

        // --- leading side: did we see an incoming `<` arrow head, and are both dashes consumed? ---
        let incoming_head;
        let mut dashes_consumed; // how many of the two structural dashes the leading token ate
        match self.peek_kind() {
            Some(TokenKind::ArrowLeft) => {
                // `<-`: incoming head + first dash.
                self.bump();
                incoming_head = true;
                dashes_consumed = 1;
            }
            Some(TokenKind::DashDash) => {
                // `--`: both dashes, no head (yet); a trailing `>` may still make it left→right.
                self.bump();
                incoming_head = false;
                dashes_consumed = 2;
            }
            Some(TokenKind::Minus) => {
                // `-`: first dash, no head.
                self.bump();
                incoming_head = false;
                dashes_consumed = 1;
            }
            _ => return Err(self.expected_here("'-', '--', or '<-' to begin a relationship")),
        }

        // --- optional detail bracket (only legal when at most one dash has been consumed) ---------
        let (mut variable, mut types, mut range, mut properties) = (None, Vec::new(), None, None);
        if dashes_consumed == 1 && self.at(&TokenKind::LBracket) {
            let detail = self.parse_relationship_detail()?;
            variable = detail.0;
            types = detail.1;
            range = detail.2;
            properties = detail.3;
        }

        // --- trailing side: a second dash and/or an outgoing `>` arrow head ----------------------
        // After a detail bracket (or a single leading dash with no bracket) we still owe the second
        // structural dash unless `--`/`<-` already covered both.
        let mut outgoing_head = false;
        let mut end;
        if dashes_consumed == 2 {
            // `--`/`<-` form: both dashes already consumed. An optional trailing `>` (from `-->`)
            // makes it outgoing; otherwise the relationship ends here.
            end = self.tokens[self.pos - 1].span.end;
            if !incoming_head && self.at(&TokenKind::Gt) {
                outgoing_head = true;
                end = self.here_span().end;
                self.bump();
            }
        } else {
            // One dash consumed so far; consume the closing side.
            match self.peek_kind() {
                Some(TokenKind::ArrowRight) => {
                    // `->`: second dash + outgoing head.
                    end = self.here_span().end;
                    self.bump();
                    outgoing_head = true;
                    dashes_consumed = 2;
                }
                Some(TokenKind::Minus) => {
                    // `-`: the second dash, no head.
                    end = self.here_span().end;
                    self.bump();
                    dashes_consumed = 2;
                }
                _ => return Err(self.expected_here("'-' or '->' to close the relationship")),
            }
        }
        debug_assert_eq!(
            dashes_consumed, 2,
            "a relationship pattern needs exactly two dashes"
        );

        // --- direction from the (incoming, outgoing) head pair -----------------------------------
        let direction = match (incoming_head, outgoing_head) {
            (true, false) => RelDirection::RightToLeft,
            (false, true) => RelDirection::LeftToRight,
            (false, false) => RelDirection::Undirected,
            // `<-...->` is not a well-formed Cypher relationship.
            (true, true) => {
                return Err(SyntaxError::new(
                    SyntaxErrorKind::UnexpectedToken {
                        found: "a relationship with arrow heads on both ends".to_owned(),
                    },
                    Span::new(start, end),
                ));
            }
        };

        Ok(RelationshipPattern {
            direction,
            variable,
            types,
            range,
            properties,
            span: Span::new(start, end),
        })
    }

    /// Parses `RelationshipDetail = '[', [Variable], [RelationshipTypes], [RangeLiteral],
    /// [Properties], ']'`, returning its components.
    #[allow(clippy::type_complexity)]
    fn parse_relationship_detail(
        &mut self,
    ) -> Result<
        (
            Option<Variable>,
            Vec<RelType>,
            Option<VarLengthRange>,
            Option<Expr>,
        ),
        SyntaxError,
    > {
        self.expect(&TokenKind::LBracket, "'[' to begin a relationship detail")?;
        let variable = if matches!(self.peek_kind(), Some(TokenKind::Identifier(_))) {
            Some(self.parse_variable()?)
        } else {
            None
        };
        let types = if self.at(&TokenKind::Colon) {
            self.parse_relationship_types()?
        } else {
            Vec::new()
        };
        let range = if self.at(&TokenKind::Star) {
            Some(self.parse_range_literal()?)
        } else {
            None
        };
        let properties = if self.at(&TokenKind::LBrace) || self.is_parameter() {
            Some(self.parse_properties()?)
        } else {
            None
        };
        self.expect(&TokenKind::RBracket, "']' to close the relationship detail")?;
        Ok((variable, types, range, properties))
    }

    /// Parses `RelationshipTypes = ':', RelTypeName, { '|', [':'], RelTypeName }`.
    fn parse_relationship_types(&mut self) -> Result<Vec<RelType>, SyntaxError> {
        self.expect(&TokenKind::Colon, "':' to begin relationship types")?;
        let mut types = vec![self.parse_rel_type_name()?];
        while self.eat(&TokenKind::Pipe) {
            // The optional `:` after `|` (openCypher `'|', [':']`).
            self.eat(&TokenKind::Colon);
            types.push(self.parse_rel_type_name()?);
        }
        Ok(types)
    }

    /// Parses one relationship type name (`SchemaName`); accepts identifiers and keyword-spelled
    /// names (a `SchemaName` may be a `ReservedWord`).
    fn parse_rel_type_name(&mut self) -> Result<RelType, SyntaxError> {
        let span = self.here_span();
        let name = self.parse_schema_name("a relationship type name")?;
        Ok(RelType { name, span })
    }

    /// Parses `RangeLiteral = '*', [IntegerLiteral], ['..', [IntegerLiteral]]`.
    fn parse_range_literal(&mut self) -> Result<VarLengthRange, SyntaxError> {
        self.expect(&TokenKind::Star, "'*' to begin a variable-length range")?;
        let min = self.try_parse_small_int()?;
        if self.eat(&TokenKind::DotDot) {
            let max = self.try_parse_small_int()?;
            Ok(VarLengthRange {
                min,
                max,
                exact: false,
            })
        } else {
            // `*` or `*n`: no `..`. `*n` means exactly n; bare `*` means unbounded.
            match min {
                Some(n) => Ok(VarLengthRange {
                    min: Some(n),
                    max: Some(n),
                    exact: true,
                }),
                None => Ok(VarLengthRange {
                    min: None,
                    max: None,
                    exact: false,
                }),
            }
        }
    }

    /// Parses an optional non-negative integer literal for a range bound, as `u64`. A literal that
    /// does not fit `u64` is a syntax-level overflow here (range bounds are bounded counts, not
    /// arbitrary Cypher integers); reported at the literal's span.
    fn try_parse_small_int(&mut self) -> Result<Option<u64>, SyntaxError> {
        if let Some(TokenKind::Integer(IntLiteral { value, .. })) = self.peek_kind() {
            let v = *value;
            let span = self.here_span();
            self.bump();
            let n = u64::try_from(v).map_err(|_| {
                SyntaxError::new(
                    SyntaxErrorKind::Expected {
                        expected: "a variable-length bound that fits in 64 bits".to_owned(),
                        found: "an out-of-range integer".to_owned(),
                    },
                    span,
                )
            })?;
            Ok(Some(n))
        } else {
            Ok(None)
        }
    }

    /// Parses `NodeLabels = NodeLabel, { NodeLabel }`, each `NodeLabel = ':', LabelName`.
    fn parse_node_labels(&mut self) -> Result<Vec<Label>, SyntaxError> {
        let mut labels = Vec::new();
        while self.at(&TokenKind::Colon) {
            let colon = self.here_span();
            self.bump(); // consume ':'
            let name_span = self.here_span();
            let name = self.parse_schema_name("a label name")?;
            labels.push(Label {
                name,
                span: Span::new(colon.start, name_span.end),
            });
        }
        if labels.is_empty() {
            return Err(self.expected_here("at least one ':Label'"));
        }
        Ok(labels)
    }

    /// Parses `Properties = MapLiteral | Parameter` as an [`Expr`] (a map literal or a parameter).
    fn parse_properties(&mut self) -> Result<Expr, SyntaxError> {
        if self.is_parameter() {
            self.parse_atom()
        } else {
            self.parse_map_literal()
        }
    }

    // --- expressions (Pratt over the EBNF precedence ladder) -------------------------------------

    /// Parses a full `Expression` (the precedence ladder starts at `OrExpression`).
    fn parse_expr(&mut self) -> Result<Expr, SyntaxError> {
        self.parse_or()
    }

    /// `OrExpression = XorExpression, { 'OR', XorExpression }` (left-assoc).
    fn parse_or(&mut self) -> Result<Expr, SyntaxError> {
        let mut lhs = self.parse_xor()?;
        while self.at(&TokenKind::Or) {
            self.bump();
            let rhs = self.parse_xor()?;
            lhs = Self::binary(BinaryOp::Or, lhs, rhs);
        }
        Ok(lhs)
    }

    /// `XorExpression = AndExpression, { 'XOR', AndExpression }` (left-assoc).
    fn parse_xor(&mut self) -> Result<Expr, SyntaxError> {
        let mut lhs = self.parse_and()?;
        while self.at(&TokenKind::Xor) {
            self.bump();
            let rhs = self.parse_and()?;
            lhs = Self::binary(BinaryOp::Xor, lhs, rhs);
        }
        Ok(lhs)
    }

    /// `AndExpression = NotExpression, { 'AND', NotExpression }` (left-assoc).
    fn parse_and(&mut self) -> Result<Expr, SyntaxError> {
        let mut lhs = self.parse_not()?;
        while self.at(&TokenKind::And) {
            self.bump();
            let rhs = self.parse_not()?;
            lhs = Self::binary(BinaryOp::And, lhs, rhs);
        }
        Ok(lhs)
    }

    /// `NotExpression = { 'NOT' }, ComparisonExpression` (prefix, stacks).
    fn parse_not(&mut self) -> Result<Expr, SyntaxError> {
        if self.at(&TokenKind::Not) {
            let start = self.here_span().start;
            self.bump();
            let operand = self.parse_not()?;
            let span = Span::new(start, operand.span.end);
            Ok(Expr::new(
                ExprKind::Unary {
                    op: UnaryOp::Not,
                    operand: Box::new(operand),
                },
                span,
            ))
        } else {
            self.parse_comparison()
        }
    }

    /// `ComparisonExpression = StringListNullPredicateExpression, { PartialComparisonExpression }`.
    ///
    /// Comparisons chain left-associatively in M23 (`a < b < c` parses as `(a < b) < c` structurally;
    /// the *chained-comparison* semantics are a later concern). Each comparison's right operand is a
    /// full predicate expression (so predicates bind tighter than comparison, per the EBNF nesting).
    fn parse_comparison(&mut self) -> Result<Expr, SyntaxError> {
        let mut lhs = self.parse_predicate()?;
        while let Some(op) = self.peek_comparison_op() {
            self.bump();
            let rhs = self.parse_predicate()?;
            lhs = Self::binary(op, lhs, rhs);
        }
        Ok(lhs)
    }

    /// Maps the current token to a comparison [`BinaryOp`] if it is one.
    fn peek_comparison_op(&self) -> Option<BinaryOp> {
        match self.peek_kind()? {
            TokenKind::Eq => Some(BinaryOp::Eq),
            TokenKind::Neq => Some(BinaryOp::Neq),
            TokenKind::Lt => Some(BinaryOp::Lt),
            TokenKind::Gt => Some(BinaryOp::Gt),
            TokenKind::Lte => Some(BinaryOp::Lte),
            TokenKind::Gte => Some(BinaryOp::Gte),
            _ => None,
        }
    }

    /// `StringListNullPredicateExpression = AddOrSubtractExpression,
    ///   { StringPredicate | ListPredicate | NullPredicate | '=~' AddOrSubtract }`.
    ///
    /// The postfix predicates (`STARTS WITH`, `ENDS WITH`, `CONTAINS`, `IN`, `IS [NOT] NULL`) and
    /// `=~` all attach here, binding tighter than comparison and looser than `+`/`-`.
    fn parse_predicate(&mut self) -> Result<Expr, SyntaxError> {
        let mut expr = self.parse_additive()?;
        loop {
            match self.peek_kind() {
                Some(TokenKind::In) => {
                    self.bump();
                    let rhs = self.parse_additive()?;
                    let span = Span::new(expr.span.start, rhs.span.end);
                    expr = Expr::new(
                        ExprKind::Predicate {
                            op: PredicateOp::In,
                            operand: Box::new(expr),
                            rhs: Some(Box::new(rhs)),
                        },
                        span,
                    );
                }
                Some(TokenKind::Starts) => {
                    self.bump();
                    self.expect_keyword_with()?;
                    let rhs = self.parse_additive()?;
                    expr = Self::predicate(PredicateOp::StartsWith, expr, Some(rhs));
                }
                Some(TokenKind::Ends) => {
                    self.bump();
                    self.expect_keyword_with()?;
                    let rhs = self.parse_additive()?;
                    expr = Self::predicate(PredicateOp::EndsWith, expr, Some(rhs));
                }
                Some(TokenKind::Contains) => {
                    self.bump();
                    let rhs = self.parse_additive()?;
                    expr = Self::predicate(PredicateOp::Contains, expr, Some(rhs));
                }
                Some(TokenKind::RegexMatch) => {
                    self.bump();
                    let rhs = self.parse_additive()?;
                    let span = Span::new(expr.span.start, rhs.span.end);
                    expr = Expr::new(
                        ExprKind::Binary {
                            op: BinaryOp::RegexMatch,
                            lhs: Box::new(expr),
                            rhs: Box::new(rhs),
                        },
                        span,
                    );
                }
                Some(TokenKind::Is) => {
                    // `IS NULL` / `IS NOT NULL`.
                    self.bump();
                    let not = self.eat(&TokenKind::Not);
                    let null_tok = self.expect(&TokenKind::Null, "NULL after IS")?;
                    let span = Span::new(expr.span.start, null_tok.span.end);
                    let op = if not {
                        PredicateOp::IsNotNull
                    } else {
                        PredicateOp::IsNull
                    };
                    expr = Expr::new(
                        ExprKind::Predicate {
                            op,
                            operand: Box::new(expr),
                            rhs: None,
                        },
                        span,
                    );
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    /// Consumes the `WITH` keyword that completes `STARTS WITH` / `ENDS WITH`.
    fn expect_keyword_with(&mut self) -> Result<(), SyntaxError> {
        self.expect(&TokenKind::With, "WITH (in STARTS WITH / ENDS WITH)")?;
        Ok(())
    }

    /// `AddOrSubtractExpression = MultiplyDivideModuloExpression, { ('+'|'-') MulDivMod }`
    /// (left-assoc).
    fn parse_additive(&mut self) -> Result<Expr, SyntaxError> {
        let mut lhs = self.parse_multiplicative()?;
        loop {
            let op = match self.peek_kind() {
                Some(TokenKind::Plus) => BinaryOp::Add,
                Some(TokenKind::Minus) => BinaryOp::Sub,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_multiplicative()?;
            lhs = Self::binary(op, lhs, rhs);
        }
        Ok(lhs)
    }

    /// `MultiplyDivideModuloExpression = PowerOfExpression, { ('*'|'/'|'%') PowerOf }` (left-assoc).
    fn parse_multiplicative(&mut self) -> Result<Expr, SyntaxError> {
        let mut lhs = self.parse_power()?;
        loop {
            let op = match self.peek_kind() {
                Some(TokenKind::Star) => BinaryOp::Mul,
                Some(TokenKind::Slash) => BinaryOp::Div,
                Some(TokenKind::Percent) => BinaryOp::Mod,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_power()?;
            lhs = Self::binary(op, lhs, rhs);
        }
        Ok(lhs)
    }

    /// `PowerOfExpression = UnaryAddOrSubtractExpression, { '^', UnaryAddOrSubtract }`.
    ///
    /// Exponentiation is **right-associative** (`2 ^ 3 ^ 2 = 2 ^ (3 ^ 2)`); we recurse on the right
    /// operand to build the right-leaning tree. The EBNF writes it left-iterative, but the standard
    /// Cypher semantics (and the TCK) treat `^` as right-associative — resolved here, see the module
    /// precedence note.
    fn parse_power(&mut self) -> Result<Expr, SyntaxError> {
        let lhs = self.parse_unary()?;
        if self.at(&TokenKind::Caret) {
            self.bump();
            let rhs = self.parse_power()?; // right-assoc: recurse
            Ok(Self::binary(BinaryOp::Pow, lhs, rhs))
        } else {
            Ok(lhs)
        }
    }

    /// `UnaryAddOrSubtractExpression = [('+'|'-')], NonArithmeticOperatorExpression` (prefix).
    fn parse_unary(&mut self) -> Result<Expr, SyntaxError> {
        let op = match self.peek_kind() {
            Some(TokenKind::Plus) => Some(UnaryOp::Plus),
            Some(TokenKind::Minus) => Some(UnaryOp::Minus),
            _ => None,
        };
        if let Some(op) = op {
            let start = self.here_span().start;
            self.bump();
            let operand = self.parse_unary()?; // stacked unary `- -x` is fine
            let span = Span::new(start, operand.span.end);
            Ok(Expr::new(
                ExprKind::Unary {
                    op,
                    operand: Box::new(operand),
                },
                span,
            ))
        } else {
            self.parse_postfix_expr()
        }
    }

    /// `NonArithmeticOperatorExpression = Atom, { ListOperator | PropertyLookup }, [NodeLabels]`.
    ///
    /// Parses an atom and then a postfix chain of `.key`, `[index]`, `[lo..hi]`, followed by an
    /// optional trailing `:Label...` label predicate.
    fn parse_postfix_expr(&mut self) -> Result<Expr, SyntaxError> {
        let mut expr = self.parse_atom()?;
        loop {
            match self.peek_kind() {
                Some(TokenKind::Dot) => {
                    self.bump();
                    let key_span = self.here_span();
                    let key = self.parse_property_key("a property name after '.'")?;
                    let span = Span::new(expr.span.start, key_span.end);
                    expr = Expr::new(
                        ExprKind::Property {
                            base: Box::new(expr),
                            key,
                        },
                        span,
                    );
                }
                Some(TokenKind::LBracket) => {
                    expr = self.parse_index_or_slice(expr)?;
                }
                _ => break,
            }
        }
        // Optional trailing label predicate `:L1:L2`.
        if self.at(&TokenKind::Colon) {
            let labels = self.parse_node_labels()?;
            let end = labels.last().map_or(expr.span.end, |l| l.span.end);
            let span = Span::new(expr.span.start, end);
            expr = Expr::new(
                ExprKind::HasLabels {
                    operand: Box::new(expr),
                    labels,
                },
                span,
            );
        }
        Ok(expr)
    }

    /// Parses `'[' Expression ']'` (index) or `'[' [Expression] '..' [Expression] ']'` (slice) onto
    /// `base`.
    fn parse_index_or_slice(&mut self, base: Expr) -> Result<Expr, SyntaxError> {
        let lbracket = self.expect(&TokenKind::LBracket, "'['")?;
        let start = base.span.start;
        let _ = lbracket;

        // Slice with empty lower bound: `[..hi]`.
        if self.at(&TokenKind::DotDot) {
            self.bump();
            let high = if self.at(&TokenKind::RBracket) {
                None
            } else {
                Some(Box::new(self.parse_expr()?))
            };
            let rb = self.expect(&TokenKind::RBracket, "']' to close the slice")?;
            return Ok(Expr::new(
                ExprKind::Slice {
                    base: Box::new(base),
                    low: None,
                    high,
                },
                Span::new(start, rb.span.end),
            ));
        }

        let first = self.parse_expr()?;
        if self.eat(&TokenKind::DotDot) {
            // Slice `[lo..]` or `[lo..hi]`.
            let high = if self.at(&TokenKind::RBracket) {
                None
            } else {
                Some(Box::new(self.parse_expr()?))
            };
            let rb = self.expect(&TokenKind::RBracket, "']' to close the slice")?;
            Ok(Expr::new(
                ExprKind::Slice {
                    base: Box::new(base),
                    low: Some(Box::new(first)),
                    high,
                },
                Span::new(start, rb.span.end),
            ))
        } else {
            // Single-index `[expr]`.
            let rb = self.expect(&TokenKind::RBracket, "']' to close the index")?;
            Ok(Expr::new(
                ExprKind::Index {
                    base: Box::new(base),
                    index: Box::new(first),
                },
                Span::new(start, rb.span.end),
            ))
        }
    }

    /// Parses an `Atom`: literals, parameters, variables, function calls, `count(*)`,
    /// list / map literals, `CASE`, list / pattern comprehensions, and parenthesized expressions.
    fn parse_atom(&mut self) -> Result<Expr, SyntaxError> {
        let tok = self
            .peek()
            .ok_or_else(|| self.expected_here("an expression"))?;
        let span = tok.span;
        match &tok.kind {
            TokenKind::Integer(lit) => {
                let lit = *lit;
                self.bump();
                Ok(Expr::new(ExprKind::Literal(Literal::Integer(lit)), span))
            }
            TokenKind::Float(f) => {
                let f = *f;
                self.bump();
                Ok(Expr::new(ExprKind::Literal(Literal::Float(f)), span))
            }
            TokenKind::String(s) => {
                let s = s.clone();
                self.bump();
                Ok(Expr::new(ExprKind::Literal(Literal::String(s)), span))
            }
            TokenKind::Boolean(b) => {
                let b = *b;
                self.bump();
                Ok(Expr::new(ExprKind::Literal(Literal::Boolean(b)), span))
            }
            TokenKind::Null => {
                self.bump();
                Ok(Expr::new(ExprKind::Literal(Literal::Null), span))
            }
            TokenKind::Parameter(name) => {
                let name = name.clone();
                self.bump();
                Ok(Expr::new(ExprKind::Parameter(name), span))
            }
            TokenKind::Case => self.parse_case(),
            TokenKind::LBracket => self.parse_list_or_comprehension(),
            TokenKind::LBrace => self.parse_map_literal(),
            TokenKind::LParen => {
                self.bump();
                let inner = self.parse_expr()?;
                let rp = self.expect(
                    &TokenKind::RParen,
                    "')' to close a parenthesized expression",
                )?;
                // Preserve the outer parentheses span but keep the inner node (parentheses do not
                // change semantics; the span widening is enough for diagnostics).
                Ok(Expr::new(inner.kind, Span::new(span.start, rp.span.end)))
            }
            TokenKind::Identifier(_) => self.parse_variable_or_call(),
            // `count(*)` — `count` lexes as an identifier, so it is handled in
            // `parse_variable_or_call`. Any other token cannot start an atom.
            _ => Err(SyntaxError::new(
                SyntaxErrorKind::UnexpectedToken {
                    found: describe(&tok.kind),
                },
                span,
            )),
        }
    }

    /// Parses a variable, a function call, or the `count(*)` atom — all of which begin with an
    /// identifier (possibly dotted, for namespaced functions).
    fn parse_variable_or_call(&mut self) -> Result<Expr, SyntaxError> {
        let start_span = self.here_span();
        let first = self.parse_symbolic_name("a variable or function name")?;

        // Dotted name: a function in a namespace (`ns.fn(...)`). Only treat dots as part of a
        // function name when a `(` ultimately follows; otherwise a `.` is property access handled by
        // the postfix layer. We look ahead: collect `.name` segments only if they lead to `(`.
        if self.at(&TokenKind::Dot) && self.dotted_name_leads_to_call() {
            let mut name = vec![first];
            while self.eat(&TokenKind::Dot) {
                name.push(self.parse_symbolic_name("a function name segment after '.'")?);
            }
            return self.finish_function_call(name, start_span.start);
        }

        // `count(*)` special-case (case-insensitive `count` already normalized by identifier text).
        if first.eq_ignore_ascii_case("count")
            && self.at(&TokenKind::LParen)
            && matches!(self.peek_at(1).map(|t| &t.kind), Some(TokenKind::Star))
            && matches!(self.peek_at(2).map(|t| &t.kind), Some(TokenKind::RParen))
        {
            self.bump(); // (
            self.bump(); // *
            let rp = self.bump().expect("RParen confirmed by lookahead");
            return Ok(Expr::new(
                ExprKind::CountStar,
                Span::new(start_span.start, rp.span.end),
            ));
        }

        // Plain function call `f(...)`.
        if self.at(&TokenKind::LParen) {
            return self.finish_function_call(vec![first], start_span.start);
        }

        // Otherwise: a variable reference.
        Ok(Expr::new(ExprKind::Variable(first), start_span))
    }

    /// Looks ahead from a `.` to decide whether a dotted name is a namespaced function call
    /// (`a.b.c(`) rather than property access (`a.b`). Scans `. name` pairs; returns `true` iff the
    /// run ends at a `(`.
    fn dotted_name_leads_to_call(&self) -> bool {
        let mut i = self.pos;
        loop {
            // Expect `.`
            if !matches!(self.tokens.get(i).map(|t| &t.kind), Some(TokenKind::Dot)) {
                return false;
            }
            i += 1;
            // Expect a name segment (identifier or keyword-as-name).
            match self.tokens.get(i).map(|t| &t.kind) {
                Some(TokenKind::Identifier(_)) => i += 1,
                Some(k) if keyword_as_name(k).is_some() => i += 1,
                _ => return false,
            }
            match self.tokens.get(i).map(|t| &t.kind) {
                Some(TokenKind::Dot) => continue,
                Some(TokenKind::LParen) => return true,
                _ => return false,
            }
        }
    }

    /// Finishes a `FunctionInvocation`: `'(' [DISTINCT] [Expression { ',' Expression }] ')'`.
    fn finish_function_call(
        &mut self,
        name: Vec<String>,
        start: usize,
    ) -> Result<Expr, SyntaxError> {
        self.expect(
            &TokenKind::LParen,
            "'(' to begin a function-call argument list",
        )?;
        let distinct = self.eat(&TokenKind::Distinct);
        let mut args = Vec::new();
        if !self.at(&TokenKind::RParen) {
            args.push(self.parse_expr()?);
            while self.eat(&TokenKind::Comma) {
                args.push(self.parse_expr()?);
            }
        }
        let rp = self.expect(
            &TokenKind::RParen,
            "')' to close the function-call argument list",
        )?;
        Ok(Expr::new(
            ExprKind::FunctionCall {
                name,
                distinct,
                args,
            },
            Span::new(start, rp.span.end),
        ))
    }

    /// Parses a `CaseExpression`, simple (`CASE expr WHEN v THEN r ...`) or searched
    /// (`CASE WHEN cond THEN r ...`), with optional `ELSE` and required `END`.
    fn parse_case(&mut self) -> Result<Expr, SyntaxError> {
        let case_tok = self.expect(&TokenKind::Case, "CASE")?;
        let start = case_tok.span.start;
        // Simple form has a subject expression before the first WHEN.
        let subject = if self.at(&TokenKind::When) {
            None
        } else {
            Some(Box::new(self.parse_expr()?))
        };
        let mut alternatives = Vec::new();
        while self.at(&TokenKind::When) {
            self.bump();
            let when = self.parse_expr()?;
            self.expect(&TokenKind::Then, "THEN after a CASE WHEN")?;
            let then = self.parse_expr()?;
            alternatives.push(CaseAlternative { when, then });
        }
        if alternatives.is_empty() {
            return Err(self.expected_here("at least one WHEN ... THEN ... in CASE"));
        }
        let else_expr = if self.eat(&TokenKind::Else) {
            Some(Box::new(self.parse_expr()?))
        } else {
            None
        };
        let end_tok = self.expect(&TokenKind::End, "END to close CASE")?;
        Ok(Expr::new(
            ExprKind::Case(CaseExpr {
                subject,
                alternatives,
                else_expr,
            }),
            Span::new(start, end_tok.span.end),
        ))
    }

    /// Parses a `'[' ... ']'` atom: a list literal, a list comprehension, or a pattern
    /// comprehension. Disambiguated by lookahead after the `[`.
    fn parse_list_or_comprehension(&mut self) -> Result<Expr, SyntaxError> {
        let lb = self.expect(&TokenKind::LBracket, "'['")?;
        let start = lb.span.start;

        // Empty list `[]`.
        if self.at(&TokenKind::RBracket) {
            let rb = self.bump().expect("RBracket confirmed");
            return Ok(Expr::new(
                ExprKind::List(Vec::new()),
                Span::new(start, rb.span.end),
            ));
        }

        // Pattern comprehension: `[ p = (a)-->(b) ... ]` or `[ (a)-->(b) ... ]`.
        // Recognized by a named-path `var =` followed by `(`, or a leading `(` that begins a
        // RelationshipsPattern (a node with at least one relationship). We detect the named-path
        // form and the bare leading-`(` form.
        if self.at_pattern_comprehension_start() {
            return self.finish_pattern_comprehension(start);
        }

        // Otherwise parse the first expression, then decide list vs list-comprehension by the token
        // that follows: `IN` after a bare variable signals a comprehension (`x IN list ...`).
        if self.at_list_comprehension_start() {
            return self.finish_list_comprehension(start);
        }

        // Plain list literal.
        let mut items = vec![self.parse_expr()?];
        while self.eat(&TokenKind::Comma) {
            items.push(self.parse_expr()?);
        }
        let rb = self.expect(&TokenKind::RBracket, "']' to close the list")?;
        Ok(Expr::new(
            ExprKind::List(items),
            Span::new(start, rb.span.end),
        ))
    }

    /// Whether the tokens just after `[` begin a pattern comprehension.
    fn at_pattern_comprehension_start(&self) -> bool {
        // `[ var = ( ...` — named path.
        if matches!(self.peek_kind(), Some(TokenKind::Identifier(_)))
            && matches!(self.peek_at(1).map(|t| &t.kind), Some(TokenKind::Eq))
            && matches!(self.peek_at(2).map(|t| &t.kind), Some(TokenKind::LParen))
        {
            return true;
        }
        // `[ ( ...` that is a relationship pattern (node then a relationship) rather than a
        // parenthesized expression. We require a `(` followed eventually by a relationship arrow at
        // the same bracket depth. A cheap, correct-enough heuristic: a `(` immediately starting the
        // bracket where the matching `)` is followed by a relationship start token.
        if self.at(&TokenKind::LParen) {
            return self.paren_group_is_node_then_rel();
        }
        false
    }

    /// Scans a balanced parenthesized group starting at the current `(` and reports whether it is a
    /// node pattern immediately followed by a relationship (`-`/`--`/`<-`/`->`), i.e. the start of a
    /// `RelationshipsPattern`. Used to tell `[(a)-->(b)|...]` (pattern comprehension) from
    /// `[(expr), ...]` (a list of parenthesized expressions).
    fn paren_group_is_node_then_rel(&self) -> bool {
        let mut depth = 0usize;
        let mut i = self.pos;
        while let Some(tok) = self.tokens.get(i) {
            match &tok.kind {
                TokenKind::LParen => depth += 1,
                TokenKind::RParen => {
                    depth -= 1;
                    if depth == 0 {
                        // The token after the closing `)` decides it.
                        return matches!(
                            self.tokens.get(i + 1).map(|t| &t.kind),
                            Some(TokenKind::Minus | TokenKind::DashDash | TokenKind::ArrowLeft)
                        );
                    }
                }
                // A comma at the top bracket level means it's a list, not a pattern.
                TokenKind::Comma if depth == 0 => return false,
                TokenKind::RBracket if depth == 0 => return false,
                _ => {}
            }
            i += 1;
        }
        false
    }

    /// Whether the tokens just after `[` begin a list comprehension `x IN list ...`.
    fn at_list_comprehension_start(&self) -> bool {
        matches!(self.peek_kind(), Some(TokenKind::Identifier(_)))
            && matches!(self.peek_at(1).map(|t| &t.kind), Some(TokenKind::In))
    }

    /// Finishes `ListComprehension = '[', FilterExpression, ['|', Expression], ']'`, where
    /// `FilterExpression = IdInColl, [Where]` and `IdInColl = Variable, 'IN', Expression`. The `[`
    /// is already consumed; `start` is its offset.
    fn finish_list_comprehension(&mut self, start: usize) -> Result<Expr, SyntaxError> {
        let variable = self.parse_variable()?;
        self.expect(&TokenKind::In, "IN in a list comprehension")?;
        let list = self.parse_expr()?;
        let predicate = if self.eat(&TokenKind::Where) {
            Some(Box::new(self.parse_expr()?))
        } else {
            None
        };
        let projection = if self.eat(&TokenKind::Pipe) {
            Some(Box::new(self.parse_expr()?))
        } else {
            None
        };
        let rb = self.expect(&TokenKind::RBracket, "']' to close the list comprehension")?;
        Ok(Expr::new(
            ExprKind::ListComprehension(ListComprehension {
                variable,
                list: Box::new(list),
                predicate,
                projection,
            }),
            Span::new(start, rb.span.end),
        ))
    }

    /// Finishes `PatternComprehension = '[', [Variable '='], RelationshipsPattern, [Where], '|',
    /// Expression, ']'`. The `[` is already consumed; `start` is its offset.
    fn finish_pattern_comprehension(&mut self, start: usize) -> Result<Expr, SyntaxError> {
        let var = if matches!(self.peek_kind(), Some(TokenKind::Identifier(_)))
            && matches!(self.peek_at(1).map(|t| &t.kind), Some(TokenKind::Eq))
        {
            let v = self.parse_variable()?;
            self.expect(&TokenKind::Eq, "'=' in a named pattern comprehension")?;
            Some(v)
        } else {
            None
        };
        let element = self.parse_pattern_element()?;
        let predicate = if self.eat(&TokenKind::Where) {
            Some(Box::new(self.parse_expr()?))
        } else {
            None
        };
        self.expect(
            &TokenKind::Pipe,
            "'|' before a pattern-comprehension projection",
        )?;
        let projection = self.parse_expr()?;
        let rb = self.expect(
            &TokenKind::RBracket,
            "']' to close the pattern comprehension",
        )?;
        Ok(Expr::new(
            ExprKind::PatternComprehension(Box::new(PatternComprehension {
                var,
                element,
                predicate,
                projection: Box::new(projection),
            })),
            Span::new(start, rb.span.end),
        ))
    }

    /// Parses `MapLiteral = '{', [ key ':' expr { ',' key ':' expr } ], '}'`.
    fn parse_map_literal(&mut self) -> Result<Expr, SyntaxError> {
        let lb = self.expect(&TokenKind::LBrace, "'{' to begin a map")?;
        let start = lb.span.start;
        let mut entries = Vec::new();
        if !self.at(&TokenKind::RBrace) {
            entries.push(self.parse_map_entry()?);
            while self.eat(&TokenKind::Comma) {
                entries.push(self.parse_map_entry()?);
            }
        }
        let rb = self.expect(&TokenKind::RBrace, "'}' to close the map")?;
        Ok(Expr::new(
            ExprKind::Map(entries),
            Span::new(start, rb.span.end),
        ))
    }

    /// Parses one `key ':' Expression` map entry.
    fn parse_map_entry(&mut self) -> Result<(MapKey, Expr), SyntaxError> {
        let key_span = self.here_span();
        let name = self.parse_property_key("a map key")?;
        let key = MapKey {
            name,
            span: key_span,
        };
        self.expect(&TokenKind::Colon, "':' after a map key")?;
        let value = self.parse_expr()?;
        Ok((key, value))
    }

    // --- name / procedure helpers ----------------------------------------------------------------

    /// Parses a `Variable = SymbolicName`.
    fn parse_variable(&mut self) -> Result<Variable, SyntaxError> {
        let span = self.here_span();
        let name = self.parse_symbolic_name("a variable")?;
        Ok(Variable { name, span })
    }

    /// Parses a procedure invocation name + (optional) argument list.
    ///
    /// `allow_implicit` permits the parenthesis-less `ImplicitProcedureInvocation` form (only legal
    /// in a `StandaloneCall`); when `false`, parentheses are required (`ExplicitProcedureInvocation`).
    fn parse_procedure_call(&mut self, allow_implicit: bool) -> Result<ProcedureCall, SyntaxError> {
        let start = self.here_span().start;
        let mut name = vec![self.parse_symbolic_name("a procedure name")?];
        while self.eat(&TokenKind::Dot) {
            name.push(self.parse_symbolic_name("a procedure name segment after '.'")?);
        }

        if self.at(&TokenKind::LParen) {
            self.bump(); // (
            let mut args = Vec::new();
            if !self.at(&TokenKind::RParen) {
                args.push(self.parse_expr()?);
                while self.eat(&TokenKind::Comma) {
                    args.push(self.parse_expr()?);
                }
            }
            let rp = self.expect(&TokenKind::RParen, "')' to close the procedure arguments")?;
            Ok(ProcedureCall {
                name,
                args: Some(args),
                span: Span::new(start, rp.span.end),
            })
        } else if allow_implicit {
            let end = self.prev_end(start);
            Ok(ProcedureCall {
                name,
                args: None,
                span: Span::new(start, end),
            })
        } else {
            Err(self.expected_here("'(' for the procedure argument list"))
        }
    }

    /// Parses a `SymbolicName` (an identifier; backticks already stripped by the lexer). Used where
    /// the grammar requires a plain name (variable, function/procedure segment).
    fn parse_symbolic_name(&mut self, what: &str) -> Result<String, SyntaxError> {
        match self.peek() {
            Some(Token {
                kind: TokenKind::Identifier(name),
                ..
            }) => {
                let name = name.clone();
                self.bump();
                Ok(name)
            }
            _ => Err(self.expected_here(what)),
        }
    }

    /// Parses a `SchemaName` (label / type / property key): a `SymbolicName` **or** a `ReservedWord`
    /// (openCypher `SchemaName = SymbolicName | ReservedWord`), so keyword-spelled labels like
    /// `:IN` or property keys like `order` are accepted.
    fn parse_schema_name(&mut self, what: &str) -> Result<String, SyntaxError> {
        match self.peek() {
            Some(Token {
                kind: TokenKind::Identifier(name),
                ..
            }) => {
                let name = name.clone();
                self.bump();
                Ok(name)
            }
            Some(tok) => {
                if keyword_as_name(&tok.kind).is_some() {
                    // Preserve the *original* source spelling (the lexer recognizes keywords
                    // case-insensitively, so the canonical token text would lose the writer's
                    // casing for a keyword-spelled schema name like `:order`).
                    let text = self.source[tok.span.start..tok.span.end].to_owned();
                    self.bump();
                    Ok(text)
                } else {
                    Err(self.expected_here(what))
                }
            }
            None => Err(self.expected_here(what)),
        }
    }

    /// Parses a property key (`PropertyKeyName = SchemaName`) — identical to [`Self::parse_schema_name`].
    fn parse_property_key(&mut self, what: &str) -> Result<String, SyntaxError> {
        self.parse_schema_name(what)
    }

    /// Whether the current token is a query parameter (`$name` / `$0`).
    fn is_parameter(&self) -> bool {
        matches!(self.peek_kind(), Some(TokenKind::Parameter(_)))
    }

    /// The end offset of the previously-consumed token, or `default` if none was consumed yet.
    fn prev_end(&self, default: usize) -> usize {
        if self.pos == 0 {
            default
        } else {
            self.tokens[self.pos - 1].span.end
        }
    }

    // --- node constructors -----------------------------------------------------------------------

    /// Builds a binary [`Expr`] spanning both operands.
    fn binary(op: BinaryOp, lhs: Expr, rhs: Expr) -> Expr {
        let span = Span::new(lhs.span.start, rhs.span.end);
        Expr::new(
            ExprKind::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            },
            span,
        )
    }

    /// Builds a postfix [`Expr::Predicate`] spanning the operand to the right operand (or to the
    /// operand itself for nullary predicates).
    fn predicate(op: PredicateOp, operand: Expr, rhs: Option<Expr>) -> Expr {
        let end = rhs.as_ref().map_or(operand.span.end, |r| r.span.end);
        let span = Span::new(operand.span.start, end);
        Expr::new(
            ExprKind::Predicate {
                op,
                operand: Box::new(operand),
                rhs: rhs.map(Box::new),
            },
            span,
        )
    }
}

/// Describes a [`TokenKind`] for "found X" error messages.
fn describe(kind: &TokenKind) -> String {
    match kind {
        TokenKind::Integer(_) => "an integer literal".to_owned(),
        TokenKind::Float(_) => "a float literal".to_owned(),
        TokenKind::String(_) => "a string literal".to_owned(),
        TokenKind::Boolean(b) => format!("`{b}`"),
        TokenKind::Null => "`null`".to_owned(),
        TokenKind::Identifier(name) => format!("identifier `{name}`"),
        TokenKind::Parameter(name) => format!("parameter `${name}`"),
        other => format!("`{}`", token_text(other)),
    }
}

/// The canonical source text of a structural / keyword [`TokenKind`] (for diagnostics).
fn token_text(kind: &TokenKind) -> &'static str {
    match kind {
        TokenKind::Match => "MATCH",
        TokenKind::Optional => "OPTIONAL",
        TokenKind::Where => "WHERE",
        TokenKind::Return => "RETURN",
        TokenKind::With => "WITH",
        TokenKind::Create => "CREATE",
        TokenKind::Merge => "MERGE",
        TokenKind::Set => "SET",
        TokenKind::Delete => "DELETE",
        TokenKind::Detach => "DETACH",
        TokenKind::Remove => "REMOVE",
        TokenKind::Unwind => "UNWIND",
        TokenKind::Call => "CALL",
        TokenKind::Yield => "YIELD",
        TokenKind::Order => "ORDER",
        TokenKind::By => "BY",
        TokenKind::Skip => "SKIP",
        TokenKind::Limit => "LIMIT",
        TokenKind::Union => "UNION",
        TokenKind::All => "ALL",
        TokenKind::Distinct => "DISTINCT",
        TokenKind::As => "AS",
        TokenKind::And => "AND",
        TokenKind::Or => "OR",
        TokenKind::Xor => "XOR",
        TokenKind::Not => "NOT",
        TokenKind::In => "IN",
        TokenKind::Is => "IS",
        TokenKind::Starts => "STARTS",
        TokenKind::Ends => "ENDS",
        TokenKind::Contains => "CONTAINS",
        TokenKind::Case => "CASE",
        TokenKind::When => "WHEN",
        TokenKind::Then => "THEN",
        TokenKind::Else => "ELSE",
        TokenKind::End => "END",
        TokenKind::Asc => "ASC",
        TokenKind::Ascending => "ASCENDING",
        TokenKind::Desc => "DESC",
        TokenKind::Descending => "DESCENDING",
        TokenKind::On => "ON",
        TokenKind::Constraint => "CONSTRAINT",
        TokenKind::Index => "INDEX",
        TokenKind::Exists => "EXISTS",
        TokenKind::Unique => "UNIQUE",
        TokenKind::Drop => "DROP",
        TokenKind::Plus => "+",
        TokenKind::Minus => "-",
        TokenKind::Star => "*",
        TokenKind::Slash => "/",
        TokenKind::Percent => "%",
        TokenKind::Caret => "^",
        TokenKind::Eq => "=",
        TokenKind::Neq => "<>",
        TokenKind::Lt => "<",
        TokenKind::Gt => ">",
        TokenKind::Lte => "<=",
        TokenKind::Gte => ">=",
        TokenKind::RegexMatch => "=~",
        TokenKind::PlusEq => "+=",
        TokenKind::Colon => ":",
        TokenKind::DoubleColon => "::",
        TokenKind::Dot => ".",
        TokenKind::DotDot => "..",
        TokenKind::Comma => ",",
        TokenKind::Semicolon => ";",
        TokenKind::LParen => "(",
        TokenKind::RParen => ")",
        TokenKind::LBracket => "[",
        TokenKind::RBracket => "]",
        TokenKind::LBrace => "{",
        TokenKind::RBrace => "}",
        TokenKind::Pipe => "|",
        TokenKind::ArrowRight => "->",
        TokenKind::ArrowLeft => "<-",
        TokenKind::DashDash => "--",
        // Payload-carrying kinds are described by `describe`, never reach here.
        TokenKind::Integer(_)
        | TokenKind::Float(_)
        | TokenKind::String(_)
        | TokenKind::Boolean(_)
        | TokenKind::Null
        | TokenKind::Identifier(_)
        | TokenKind::Parameter(_) => "<literal>",
    }
}

/// If `kind` is a keyword token that may also be used as a `SchemaName` (`ReservedWord`), returns
/// its canonical spelling. openCypher `SchemaName = SymbolicName | ReservedWord`, so a label / type
/// / property-key / function-name segment may be a reserved word (e.g. `:IN`, `.order`,
/// `db.index(...)`). Literals (`true`/`false`/`null`) are **not** schema names. This keeps such
/// keyword-spelled names parseable while the role check (whether it's *valid* in context) is
/// semantic.
fn keyword_as_name(kind: &TokenKind) -> Option<&'static str> {
    match kind {
        TokenKind::Boolean(_) | TokenKind::Null => None,
        TokenKind::Integer(_)
        | TokenKind::Float(_)
        | TokenKind::String(_)
        | TokenKind::Identifier(_)
        | TokenKind::Parameter(_) => None,
        // Operators / punctuation are not names.
        TokenKind::Plus
        | TokenKind::Minus
        | TokenKind::Star
        | TokenKind::Slash
        | TokenKind::Percent
        | TokenKind::Caret
        | TokenKind::Eq
        | TokenKind::Neq
        | TokenKind::Lt
        | TokenKind::Gt
        | TokenKind::Lte
        | TokenKind::Gte
        | TokenKind::RegexMatch
        | TokenKind::PlusEq
        | TokenKind::Colon
        | TokenKind::DoubleColon
        | TokenKind::Dot
        | TokenKind::DotDot
        | TokenKind::Comma
        | TokenKind::Semicolon
        | TokenKind::LParen
        | TokenKind::RParen
        | TokenKind::LBracket
        | TokenKind::RBracket
        | TokenKind::LBrace
        | TokenKind::RBrace
        | TokenKind::Pipe
        | TokenKind::ArrowRight
        | TokenKind::ArrowLeft
        | TokenKind::DashDash => None,
        // Everything else is a reserved keyword usable as a schema name.
        other => Some(token_text(other)),
    }
}

#[cfg(test)]
mod tests;
