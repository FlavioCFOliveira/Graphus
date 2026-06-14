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
//! | 9 | `^` | **left** | `PowerOfExpression` |
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
    BinaryOp, CallClause, CaseAlternative, CaseExpr, Clause, CreateClause, DeleteClause,
    ExistsSubquery, Expr, ExprKind, ForeachClause, Label, ListComprehension, Literal,
    LoadCsvClause, MapKey, MatchClause, MergeAction, MergeClause, NodePattern, PatternChainLink,
    PatternComprehension, PatternElement, PatternPart, PatternPartKind, PredicateOp, ProcedureCall,
    ProjectionBody, ProjectionItem, QuantifierExpr, QuantifierKind, Query, QueryBody, RelDirection,
    RelType, RelationshipPattern, RemoveClause, RemoveItem, ReturnClause, SetClause, SetItem,
    SingleQuery, SortDirection, SortItem, StandaloneCall, StandaloneYield, UnaryOp, UnionPart,
    UnwindClause, VarLengthRange, Variable, WithClause, YieldItem,
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
    /// The expression grammar nested deeper than [`MAX_EXPR_DEPTH`] (e.g. thousands of nested
    /// parentheses, brackets, or stacked `NOT`s). Bounding the recursion converts what would be a
    /// native stack overflow (SIGABRT) into a recoverable compile-time `SyntaxError`. This also
    /// protects every later pass that recurses over the same AST (semantic analysis, type checking,
    /// evaluation), since the AST can no longer be arbitrarily deep.
    NestingTooDeep,
    /// A construct was structurally well-formed at the token level but is not a legal start of any
    /// expression / clause here (e.g. an operator where an operand was required).
    UnexpectedToken {
        /// A description of the offending token.
        found: String,
    },
    /// An integer literal (decimal/hex/octal) whose value does not fit Cypher's signed 64-bit integer
    /// range (`i64::MIN..=i64::MAX`). openCypher classifies this as a compile-time `SyntaxError`
    /// (TCK detail `IntegerOverflow`; `tck/.../literals/Literals2`/`Literals3`/`Literals4`).
    IntegerOverflow,
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
            Self::IntegerOverflow => {
                f.write_str("integer literal out of range (does not fit a 64-bit signed integer)")
            }
            Self::NestingTooDeep => f.write_str("expression nests too deeply"),
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
/// The maximum expression-nesting depth the parser will accept before raising
/// [`SyntaxErrorKind::NestingTooDeep`]. Each level of parentheses, brackets, or stacked `NOT`
/// consumes one unit.
///
/// The limit is comfortably above any hand-written query yet bounds the recursive descent — and
/// every later pass that recurses over the same AST (semantic analysis, type checking, evaluation)
/// — so an adversarially deep query is rejected as a `SyntaxError` instead of overflowing the
/// stack. Each nesting level descends the whole precedence ladder, so the engine runs queries on a
/// large dedicated stack (the server's worker / the TCK harness's 128 MiB threads); 1 000 levels is
/// safe there with a wide margin, while still aligning with the low-thousands guard Neo4j's Cypher
/// parser applies. (Callers on a small default stack should likewise isolate parsing on a worker.)
const MAX_EXPR_DEPTH: usize = 1_000;

struct Parser<'t, 's> {
    /// The tokens to parse.
    tokens: &'t [Token],
    /// The original source text (for end-of-input spans and keyword-name case recovery).
    source: &'s str,
    /// The current token index.
    pos: usize,
    /// The current expression-recursion depth, bounded by [`MAX_EXPR_DEPTH`]. Incremented on entry
    /// to each recursive expression rule and decremented on exit by [`DepthGuard`], so an
    /// adversarially deep query is rejected as a `SyntaxError` instead of overflowing the stack.
    depth: usize,
}

/// An RAII guard that decrements [`Parser::depth`] when it is dropped, so the depth is restored on
/// every exit path (including the `?` error propagation that unwinds the recursive descent).
struct DepthGuard<'p, 't, 's> {
    parser: &'p mut Parser<'t, 's>,
}

impl Drop for DepthGuard<'_, '_, '_> {
    fn drop(&mut self) {
        self.parser.depth -= 1;
    }
}

impl<'p, 't, 's> std::ops::Deref for DepthGuard<'p, 't, 's> {
    type Target = Parser<'t, 's>;
    fn deref(&self) -> &Self::Target {
        self.parser
    }
}

impl std::ops::DerefMut for DepthGuard<'_, '_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.parser
    }
}

impl<'t, 's> Parser<'t, 's> {
    /// Creates a parser over `tokens` lexed from `source`.
    fn new(tokens: &'t [Token], source: &'s str) -> Self {
        Self {
            tokens,
            source,
            pos: 0,
            depth: 0,
        }
    }

    /// Enters one level of expression recursion, returning a [`DepthGuard`] that restores the depth
    /// on drop. Errors with [`SyntaxErrorKind::NestingTooDeep`] once [`MAX_EXPR_DEPTH`] is exceeded,
    /// turning a would-be stack overflow into a recoverable `SyntaxError`.
    fn enter_recursion(&mut self) -> Result<DepthGuard<'_, 't, 's>, SyntaxError> {
        self.depth += 1;
        if self.depth > MAX_EXPR_DEPTH {
            // Restore the depth before erroring so a caller that recovers sees a consistent state.
            self.depth -= 1;
            return Err(SyntaxError::new(
                SyntaxErrorKind::NestingTooDeep,
                self.here_span(),
            ));
        }
        Ok(DepthGuard { parser: self })
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

    /// Whether the token at offset `ahead` from the cursor is an [`TokenKind::Identifier`] whose text
    /// equals `word` (ASCII case-insensitive). Used to recognise **contextual** keywords (e.g. the
    /// `LOAD CSV` clause words) that are not reserved and so lex as identifiers.
    fn peek_keyword_ident_at(&self, ahead: usize, word: &str) -> bool {
        matches!(
            self.tokens.get(self.pos + ahead).map(|t| &t.kind),
            Some(TokenKind::Identifier(name)) if name.eq_ignore_ascii_case(word)
        )
    }

    /// Whether the current token is the contextual keyword `word` (an identifier spelled `word`,
    /// case-insensitive).
    fn at_keyword_ident(&self, word: &str) -> bool {
        self.peek_keyword_ident_at(0, word)
    }

    /// Consumes the current token iff it is the contextual keyword `word`; returns whether it did.
    fn eat_keyword_ident(&mut self, word: &str) -> bool {
        if self.at_keyword_ident(word) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Consumes the current token, which must be the contextual keyword `word`, or errors with
    /// "expected {desc}" positioned at the offending token. `desc` is the canonical (upper-case)
    /// spelling for the diagnostic.
    fn expect_keyword_ident(&mut self, word: &str, desc: &str) -> Result<(), SyntaxError> {
        if self.at_keyword_ident(word) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.expected_here(desc))
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
        // `LOAD CSV` is a contextual-keyword clause: `LOAD`/`CSV`/… are not reserved words (so they
        // stay usable as identifiers), so the dispatch recognises the clause by the `LOAD CSV`
        // identifier *spelling* rather than a token kind. A bare identifier `load` not followed by
        // `csv` is left to the normal expression/clause handling.
        if self.at_keyword_ident("load") && self.peek_keyword_ident_at(1, "csv") {
            return Ok(Some(Clause::LoadCsv(self.parse_load_csv()?)));
        }
        let clause = match kind {
            TokenKind::Optional | TokenKind::Match => Clause::Match(self.parse_match()?),
            TokenKind::Unwind => Clause::Unwind(self.parse_unwind()?),
            TokenKind::Call => Clause::Call(self.parse_in_query_call()?),
            TokenKind::Create => Clause::Create(self.parse_create()?),
            TokenKind::Merge => Clause::Merge(self.parse_merge()?),
            TokenKind::Set => Clause::Set(self.parse_set()?),
            TokenKind::Detach | TokenKind::Delete => Clause::Delete(self.parse_delete()?),
            TokenKind::Remove => Clause::Remove(self.parse_remove()?),
            TokenKind::Foreach => Clause::Foreach(self.parse_foreach()?),
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

    /// Parses
    /// `Foreach = 'FOREACH', '(', Variable, 'IN', Expression, '|', { UpdatingClause }, ')'`.
    ///
    /// The body is restricted to **updating** clauses only — `CREATE`, `SET`, `[DETACH] DELETE`,
    /// `REMOVE`, `MERGE`, and a nested `FOREACH`. Any reading / projection clause (`MATCH`,
    /// `OPTIONAL MATCH`, `WITH`, `RETURN`, `UNWIND`, `CALL`, `LOAD CSV`) at the inner-clause position
    /// is a [`SyntaxError`] (`SyntaxErrorKind::Expected`). At least one update clause is required —
    /// an empty body is a syntax error.
    fn parse_foreach(&mut self) -> Result<ForeachClause, SyntaxError> {
        let start = self.here_span().start;
        self.expect(&TokenKind::Foreach, "FOREACH")?;
        self.expect(&TokenKind::LParen, "'(' to begin a FOREACH")?;
        let variable = self.parse_variable()?;
        self.expect(&TokenKind::In, "IN in a FOREACH")?;
        let list = self.parse_expr()?;
        self.expect(&TokenKind::Pipe, "'|' before the FOREACH update clauses")?;

        let mut body = Vec::new();
        while !self.at(&TokenKind::RParen) {
            let kind = self
                .peek_kind()
                .ok_or_else(|| self.expected_here("an update clause inside FOREACH"))?;
            let clause = match kind {
                TokenKind::Create => Clause::Create(self.parse_create()?),
                TokenKind::Merge => Clause::Merge(self.parse_merge()?),
                TokenKind::Set => Clause::Set(self.parse_set()?),
                TokenKind::Detach | TokenKind::Delete => Clause::Delete(self.parse_delete()?),
                TokenKind::Remove => Clause::Remove(self.parse_remove()?),
                TokenKind::Foreach => Clause::Foreach(self.parse_foreach()?),
                // Only updating clauses are legal inside FOREACH; anything else (MATCH, WITH,
                // RETURN, UNWIND, CALL, …) is a syntax error.
                _ => return Err(self.expected_here("an update clause inside FOREACH")),
            };
            body.push(clause);
        }
        if body.is_empty() {
            return Err(self.expected_here("an update clause inside FOREACH"));
        }
        let rparen = self.expect(&TokenKind::RParen, "')' to close the FOREACH")?;
        let end = rparen.span.end;
        Ok(ForeachClause {
            variable,
            list,
            body,
            span: Span::new(start, end),
        })
    }

    /// Parses
    /// `LoadCSV = 'LOAD', 'CSV', ['WITH', 'HEADERS'], 'FROM', Expression, 'AS', Variable,
    /// ['FIELDTERMINATOR', StringLiteral]` (openCypher `LoadCSV`).
    ///
    /// `LOAD`, `CSV`, `FROM`, `HEADERS` and `FIELDTERMINATOR` are **contextual** keywords (not
    /// reserved words — see [`keyword_or_identifier`](crate::lexer)), so they arrive as
    /// [`TokenKind::Identifier`] and are matched here by their (case-insensitive) spelling. `WITH` and
    /// `AS` are genuine reserved keywords. The `FIELDTERMINATOR` argument must be a
    /// **single-character** string literal (openCypher constrains the field terminator to one
    /// character); a non-string or a multi-character string is a [`SyntaxErrorKind::Expected`].
    fn parse_load_csv(&mut self) -> Result<LoadCsvClause, SyntaxError> {
        let start = self.here_span().start;
        self.expect_keyword_ident("load", "LOAD")?;
        self.expect_keyword_ident("csv", "CSV")?;
        let with_headers = if self.eat(&TokenKind::With) {
            self.expect_keyword_ident("headers", "HEADERS")?;
            true
        } else {
            false
        };
        self.expect_keyword_ident("from", "FROM")?;
        let url = self.parse_expr()?;
        self.expect(&TokenKind::As, "AS")?;
        let alias = self.parse_variable()?;
        let mut end = alias.span.end;
        let field_terminator = if self.eat_keyword_ident("fieldterminator") {
            let span = self.here_span();
            match self.peek_kind() {
                Some(TokenKind::String(s)) => {
                    let mut chars = s.chars();
                    match (chars.next(), chars.next()) {
                        // Exactly one character: accept it.
                        (Some(c), None) => {
                            self.bump();
                            end = span.end;
                            Some(c)
                        }
                        // Empty or multi-character string: not a single-character terminator.
                        _ => {
                            return Err(SyntaxError::new(
                                SyntaxErrorKind::Expected {
                                    expected: "a single-character FIELDTERMINATOR string"
                                        .to_owned(),
                                    found: describe(&TokenKind::String(s.clone())),
                                },
                                span,
                            ));
                        }
                    }
                }
                _ => {
                    return Err(self.expected_here("a single-character FIELDTERMINATOR string"));
                }
            }
        } else {
            None
        };
        Ok(LoadCsvClause {
            with_headers,
            url,
            alias,
            field_terminator,
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
        // The un-aliased column name is the expression's exact source text (openCypher); capture
        // it here while the source is in reach (spans are byte-accurate, so this slice is exact).
        let verbatim = self.source[expr.span.start..expr.span.end].to_owned();
        Ok(ProjectionItem {
            expr,
            alias,
            verbatim,
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
    ///
    /// The anonymous part is either an ordinary pattern element or a `shortestPath(...)` /
    /// `allShortestPaths(...)` search function wrapping a single inner pattern.
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
        let (kind, element) = self.parse_pattern_part_body()?;
        let end = element.span.end;
        Ok(PatternPart {
            var,
            kind,
            element,
            span: Span::new(start, end),
        })
    }

    /// Parses the body of a pattern part: either an ordinary [`PatternElement`] or a
    /// `shortestPath(<pattern>)` / `allShortestPaths(<pattern>)` search function.
    ///
    /// The two search functions are recognised as a leading identifier (case-insensitively
    /// `shortestPath` / `allShortestPaths`) immediately followed by `(`; the inner pattern is an
    /// ordinary [`PatternElement`] parsed between the parentheses. Anything else is parsed as a
    /// plain pattern element, so an ordinary node named `shortestPath` (`(shortestPath)-[...]`) is
    /// unaffected — the disambiguator is the function-call `(` with no node-pattern shape inside.
    fn parse_pattern_part_body(
        &mut self,
    ) -> Result<(PatternPartKind, PatternElement), SyntaxError> {
        if let Some(TokenKind::Identifier(name)) = self.peek_kind() {
            let kind = if name.eq_ignore_ascii_case("shortestPath") {
                Some(PatternPartKind::ShortestPath)
            } else if name.eq_ignore_ascii_case("allShortestPaths") {
                Some(PatternPartKind::AllShortestPaths)
            } else {
                None
            };
            if let Some(kind) = kind {
                if matches!(self.peek_at(1).map(|t| &t.kind), Some(TokenKind::LParen)) {
                    self.bump(); // the search-function name
                    self.expect(
                        &TokenKind::LParen,
                        "'(' to begin the shortest-path search pattern",
                    )?;
                    let element = self.parse_pattern_element()?;
                    self.expect(
                        &TokenKind::RParen,
                        "')' to close the shortest-path search pattern",
                    )?;
                    return Ok((kind, element));
                }
            }
        }
        Ok((PatternPartKind::Normal, self.parse_pattern_element()?))
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
        // Per the openCypher grammar, a relationship may carry *both* a left and a right arrow head
        // (`<-->`, `<-[r]->`). The first `RelationshipPattern` grammar alternative
        // (`LeftArrowHead Dash [Detail] Dash RightArrowHead`) is well-formed and, like the
        // no-arrow-head form, denotes an **undirected** ("both ways") relationship — it matches an
        // edge in either direction (TCK `Match3` [19], `Match6` [12]/[13]).
        let direction = match (incoming_head, outgoing_head) {
            (true, false) => RelDirection::RightToLeft,
            (false, true) => RelDirection::LeftToRight,
            // Both no arrow heads and both arrow heads mean undirected.
            (false, false) | (true, true) => RelDirection::Undirected,
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
    ///
    /// Every nested expression — a parenthesised group, a list/map literal element, a function
    /// argument, a comprehension body — re-enters here, so a single depth guard at this choke point
    /// bounds the overall recursion (stacked `NOT`, which recurses directly, is guarded separately).
    fn parse_expr(&mut self) -> Result<Expr, SyntaxError> {
        let mut guard = self.enter_recursion()?;
        guard.parse_or()
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
            // Stacked `NOT NOT … x` recurses directly here (bypassing `parse_expr`), so it needs its
            // own depth guard to stay bounded.
            let mut guard = self.enter_recursion()?;
            let start = guard.here_span().start;
            guard.bump();
            let operand = guard.parse_not()?;
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
        let first = self.parse_predicate()?;
        let Some(op) = self.peek_comparison_op() else {
            return Ok(first);
        };
        self.bump();
        let second = self.parse_predicate()?;

        // A single comparison `a OP b` is left as-is.
        if self.peek_comparison_op().is_none() {
            return Ok(Self::binary(op, first, second));
        }

        // A *chained* comparison `a OP1 b OP2 c …` desugars to the conjunction of its adjacent
        // pairwise comparisons sharing the middle operands: `(a OP1 b) AND (b OP2 c) AND …`
        // (openCypher; pinned by the TCK `expressions/comparison/Comparison3` range scenarios, e.g.
        // `1 < n < 3` ≡ `1 < n AND n < 3`). Operands in expression position are side-effect-free, so
        // re-using the shared operand by `clone` is semantically exact.
        //
        // `prev` holds the right operand of the comparison just emitted; it becomes the left operand
        // of the next link. `acc` accumulates the running conjunction.
        let mut prev = second.clone();
        let mut acc = Self::binary(op, first, second);
        while let Some(next_op) = self.peek_comparison_op() {
            self.bump();
            let rhs = self.parse_predicate()?;
            let link = Self::binary(next_op, prev, rhs.clone());
            prev = rhs;
            acc = Self::binary(BinaryOp::And, acc, link);
        }
        Ok(acc)
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
    /// Exponentiation is **left-associative** in openCypher, per the M23 EBNF's left-iterative form
    /// `{ '^', … }` and pinned empirically by the TCK: `tck/.../precedence/Precedence2` [2]/[3] assert
    /// `4 ^ (3 * 2) ^ 3 = (4 ^ 6) ^ 3 = 4 ^ 18 = 68719476736` (the left-associative grouping), not the
    /// mathematical right-associative `4 ^ (6 ^ 3)`. We therefore iterate left, folding each `^` into
    /// the accumulated left operand. (This differs from Python/maths convention, which is
    /// right-associative; the TCK is authoritative here — see the module precedence note.)
    fn parse_power(&mut self) -> Result<Expr, SyntaxError> {
        let mut lhs = self.parse_unary()?;
        while self.at(&TokenKind::Caret) {
            self.bump();
            let rhs = self.parse_unary()?; // left-assoc: iterate
            lhs = Self::binary(BinaryOp::Pow, lhs, rhs);
        }
        Ok(lhs)
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
            // Fold a `-` directly in front of an integer literal into a single signed literal, so
            // `-9223372036854775808` (i64::MIN) is admitted as one in-range value. Without folding,
            // the magnitude `2^63` would fail the positive `i64::MAX` check before negation, and the
            // smallest integer would be unrepresentable. Only a *bare* integer token folds (a `-(…)`
            // or `-x` keeps the runtime unary-minus path).
            if op == UnaryOp::Minus {
                if let Some(TokenKind::Integer(lit)) = self.peek_kind() {
                    let value = lit.value;
                    let lit_span = self.here_span();
                    self.bump();
                    let span = Span::new(start, lit_span.end);
                    let n = Self::resolve_int_magnitude(value, true, span)?;
                    return Ok(Expr::new(ExprKind::Literal(Literal::Integer(n)), span));
                }
            }
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

    /// Resolves a decoded integer literal magnitude into a signed `i64`, applying `negative` and
    /// range-checking at compile time.
    ///
    /// The Cypher integer range is `i64::MIN..=i64::MAX`. A positive literal admits magnitudes up to
    /// `i64::MAX` (`2^63 - 1`); a negative literal admits magnitudes up to `2^63` (so `i64::MIN` is
    /// representable). Anything larger is a compile-time `SyntaxError`
    /// ([`SyntaxErrorKind::IntegerOverflow`], openCypher detail `IntegerOverflow`).
    fn resolve_int_magnitude(value: u128, negative: bool, span: Span) -> Result<i64, SyntaxError> {
        const MIN_MAGNITUDE: u128 = (i64::MAX as u128) + 1; // 2^63 == -i64::MIN
        let resolved = if negative {
            if value == MIN_MAGNITUDE {
                Some(i64::MIN)
            } else {
                i64::try_from(value).ok().map(|n| -n)
            }
        } else {
            i64::try_from(value).ok()
        };
        resolved.ok_or_else(|| SyntaxError::new(SyntaxErrorKind::IntegerOverflow, span))
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
                let value = lit.value;
                self.bump();
                // A bare (unsigned) integer literal must fit `i64::MAX`; a negative literal is folded
                // by `parse_unary` before reaching here, so this arm only ever sees the positive case.
                let n = Self::resolve_int_magnitude(value, false, span)?;
                Ok(Expr::new(ExprKind::Literal(Literal::Integer(n)), span))
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
            // `ALL` lexes as a keyword; as an atom it can only begin the `all(x IN xs WHERE p)`
            // quantifier. The other three quantifiers lex as identifiers (see
            // `parse_variable_or_call`).
            TokenKind::All => {
                let start = self.bump().expect("ALL peeked").span.start;
                self.finish_quantifier(QuantifierKind::All, start)
            }
            // `EXISTS` heads either the `EXISTS { ... }` subquery or the `exists(expr)` function.
            TokenKind::Exists => self.parse_exists(),
            TokenKind::LBracket => self.parse_list_or_comprehension(),
            TokenKind::LBrace => self.parse_map_literal(),
            TokenKind::LParen => {
                // Disambiguate a *pattern predicate* `(n)-[]->()` (openCypher
                // `PatternPredicate = RelationshipsPattern`, used as a boolean expression) from an
                // ordinary parenthesized expression `(1 + 2)`. A pattern predicate begins with a
                // node pattern whose closing `)` is immediately followed by a relationship connector
                // (`-`, `--`, `<-`). `paren_group_is_node_then_rel` performs exactly that lookahead
                // (it is shared with the pattern-comprehension disambiguation).
                if self.at_pattern_predicate_start() {
                    return self.parse_pattern_predicate();
                }
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

        // Quantifier predicates `any/none/single(x IN list WHERE p)` — recognised by the name plus
        // the `( name IN` lookahead (`all` lexes as a keyword and is handled in `parse_atom`).
        // Anything else with these names falls through to a regular function call.
        if self.at(&TokenKind::LParen)
            && matches!(
                self.peek_at(1).map(|t| &t.kind),
                Some(TokenKind::Identifier(_))
            )
            && matches!(self.peek_at(2).map(|t| &t.kind), Some(TokenKind::In))
        {
            let kind = match first.to_ascii_lowercase().as_str() {
                "any" => Some(QuantifierKind::Any),
                "none" => Some(QuantifierKind::None),
                "single" => Some(QuantifierKind::Single),
                _ => None,
            };
            if let Some(kind) = kind {
                return self.finish_quantifier(kind, start_span.start);
            }
        }

        // Plain function call `f(...)`.
        if self.at(&TokenKind::LParen) {
            return self.finish_function_call(vec![first], start_span.start);
        }

        // Otherwise: a variable reference.
        Ok(Expr::new(ExprKind::Variable(first), start_span))
    }

    /// Finishes a quantifier predicate after its head keyword/name:
    /// `'(' Variable IN Expression WHERE Expression ')'`. The `WHERE` predicate is required
    /// (openCypher rejects a quantifier without one).
    fn finish_quantifier(
        &mut self,
        kind: QuantifierKind,
        start: usize,
    ) -> Result<Expr, SyntaxError> {
        self.expect(&TokenKind::LParen, "'(' to begin a quantifier")?;
        let variable = self.parse_variable()?;
        self.expect(&TokenKind::In, "IN in a quantifier")?;
        let list = Box::new(self.parse_expr()?);
        self.expect(
            &TokenKind::Where,
            "WHERE in a quantifier (the predicate is required)",
        )?;
        let predicate = Box::new(self.parse_expr()?);
        let rp = self.expect(&TokenKind::RParen, "')' to close the quantifier")?;
        Ok(Expr::new(
            ExprKind::Quantifier(Box::new(QuantifierExpr {
                kind,
                variable,
                list,
                predicate,
            })),
            Span::new(start, rp.span.end),
        ))
    }

    /// Parses the `EXISTS` atom: the `EXISTS { [MATCH] pattern [WHERE p] }` existential subquery,
    /// or the `exists(expr)` function form when a `(` follows.
    fn parse_exists(&mut self) -> Result<Expr, SyntaxError> {
        let tok = self.bump().expect("caller saw EXISTS");
        let start = tok.span.start;
        if self.at(&TokenKind::LBrace) {
            self.bump();
            // The pattern form optionally writes a leading MATCH (Neo4j accepts both). We parse the
            // (optional-MATCH) pattern and optional WHERE exactly as the pattern form always has,
            // then disambiguate on the *following* token:
            //   - a closing `}`        => the **pattern form** (`EXISTS { (a)-->(b) [WHERE p] }`),
            //                             byte-identical to before this task; or
            //   - anything else (a     => the **full-query form**: more clauses follow (`RETURN` /
            //     trailing clause)        `WITH` / …), so the parsed pattern was actually the leading
            //                             MATCH of a full read-only query (`EXISTS { MATCH ... RETURN ... }`).
            let pattern_start = self.here_span().start;
            self.eat(&TokenKind::Match);
            let pattern = self.parse_pattern()?;
            let predicate = if self.eat(&TokenKind::Where) {
                Some(Box::new(self.parse_expr()?))
            } else {
                None
            };
            if self.at(&TokenKind::RBrace) {
                // Pattern form.
                let rb = self.expect(&TokenKind::RBrace, "'}' to close an EXISTS subquery")?;
                return Ok(Expr::new(
                    ExprKind::ExistsSubquery(Box::new(ExistsSubquery {
                        pattern,
                        predicate,
                        from_pattern_predicate: false,
                        full_query: None,
                    })),
                    Span::new(start, rb.span.end),
                ));
            }
            // Full-query form. The pattern + optional WHERE we just parsed are the leading
            // `MATCH <pattern> [WHERE <pred>]` clause of an inner read-only query; synthesize that
            // MATCH, then drive the normal clause loop to parse the remaining clauses up to `}`.
            let query = self.parse_exists_full_query(pattern, predicate, pattern_start, start)?;
            let rb = self.expect(&TokenKind::RBrace, "'}' to close an EXISTS subquery")?;
            return Ok(Expr::new(
                ExprKind::ExistsSubquery(Box::new(ExistsSubquery {
                    pattern: vec![],
                    predicate: None,
                    from_pattern_predicate: false,
                    full_query: Some(Box::new(query)),
                })),
                Span::new(start, rb.span.end),
            ));
        }
        // Function form `exists(expr)`.
        self.finish_function_call(vec!["exists".to_owned()], start)
    }

    /// Completes the **full-query form** of an `EXISTS { ... }` subquery once disambiguation in
    /// [`parse_exists`](Self::parse_exists) has decided that clauses follow the leading pattern.
    ///
    /// The already-parsed `pattern` (+ optional `predicate`) become the synthesized leading
    /// `MATCH <pattern> [WHERE <pred>]` clause; the remaining clauses are parsed with the **same**
    /// clause-loop subroutine the top-level parser uses ([`try_parse_clause`](Self::try_parse_clause)),
    /// so every clause kind, ordering rule and `UNION` chain is handled identically to a free-standing
    /// query (the closing `}` ends the loop, since `}` cannot start a clause). The composed inner
    /// [`Query`] is returned **without** consuming the `}` — the caller expects and consumes it.
    ///
    /// `pattern_start` is the byte offset of the leading pattern/MATCH (for the synthesized MATCH
    /// span); `exists_start` is the offset of the `EXISTS` keyword (for the inner query span).
    fn parse_exists_full_query(
        &mut self,
        pattern: Vec<PatternPart>,
        predicate: Option<Box<Expr>>,
        pattern_start: usize,
        exists_start: usize,
    ) -> Result<Query, SyntaxError> {
        // Synthesize the leading `MATCH <pattern> [WHERE <pred>]`. The EXISTS predicate is
        // `Option<Box<Expr>>` while a `MATCH` `where_clause` is `Option<Expr>`, so unbox it.
        let match_end = predicate
            .as_ref()
            .map(|p| p.span.end)
            .or_else(|| pattern.last().map(|p| p.span.end))
            .unwrap_or(pattern_start);
        let leading = Clause::Match(MatchClause {
            optional: false,
            pattern,
            where_clause: predicate.map(|b| *b),
            span: Span::new(pattern_start, match_end),
        });

        // Drive the normal clause loop for the remaining clauses (RETURN / WITH / …) until `}`.
        let mut clauses = vec![leading];
        while let Some(clause) = self.try_parse_clause()? {
            clauses.push(clause);
        }
        let head_end = clauses.last().map_or(match_end, |c| c.span().end);
        let head = SingleQuery {
            clauses,
            span: Span::new(pattern_start, head_end),
        };

        // A `UNION` chain inside the subquery is parsed with the same subroutine the top level uses.
        let mut unions = Vec::new();
        while self.at(&TokenKind::Union) {
            unions.push(self.parse_union_part()?);
        }
        let query_end = unions.last().map_or(head_end, |u| u.span.end);
        Ok(Query {
            body: QueryBody::Regular { head, unions },
            span: Span::new(exists_start, query_end),
        })
    }

    /// Whether the current `(` begins a *pattern predicate* (`(n)-[]->()`) rather than a
    /// parenthesized expression (`(1 + 2)`, `(n) - 1`).
    ///
    /// This is a stricter cousin of [`paren_group_is_node_then_rel`](Self::paren_group_is_node_then_rel)
    /// (which suffices inside `[...]`, where a leading `(` can only be a node pattern). In a general
    /// expression position the leading `(` is overwhelmingly a parenthesized subexpression, so the
    /// lookahead must be precise to avoid mis-parsing arithmetic such as `(a)-1` or `(1+2)-[3,4]` as
    /// a relationship. It requires **both**:
    ///
    /// 1. the parenthesized group to have **node-pattern shape** — an optional variable, an optional
    ///    `:`-label list, and an optional inline property map / parameter, with **no** operators,
    ///    literals, or other expression tokens at parenthesis depth 1; and
    /// 2. the closing `)` to be **immediately followed by a relationship connector**: `--`
    ///    ([`DashDash`](TokenKind::DashDash)), `<-` ([`ArrowLeft`](TokenKind::ArrowLeft)), or a `-`
    ///    ([`Minus`](TokenKind::Minus)) that itself heads a detail bracket `-[`
    ///    ([`LBracket`](TokenKind::LBracket)).
    ///
    /// A bare `-` followed by anything other than `[` is subtraction, never a relationship, so it is
    /// rejected here (openCypher spells an undirected relationship `--` / `-[..]-`, never a single
    /// `-` between two nodes).
    fn at_pattern_predicate_start(&self) -> bool {
        debug_assert!(self.at(&TokenKind::LParen));
        // Scan the node-pattern shape from `(` to its matching `)`; reject anything that is not part
        // of a `NodePattern` at depth 1. `end` ends up at the index of the closing `)`.
        let mut i = self.pos + 1; // first token inside the parens
        // Optional variable.
        if matches!(
            self.tokens.get(i).map(|t| &t.kind),
            Some(TokenKind::Identifier(_))
        ) {
            i += 1;
        }
        // Optional `:`-label list: `: Name (: Name)*` (label conjunction is colon-separated here).
        while matches!(self.tokens.get(i).map(|t| &t.kind), Some(TokenKind::Colon)) {
            i += 1;
            match self.tokens.get(i).map(|t| &t.kind) {
                Some(TokenKind::Identifier(_)) => i += 1,
                Some(k) if keyword_as_name(k).is_some() => i += 1,
                _ => return false,
            }
        }
        // Optional inline properties: a `{ ... }` map literal or a parameter `$p`.
        match self.tokens.get(i).map(|t| &t.kind) {
            Some(TokenKind::LBrace) => {
                // Skip a balanced `{ ... }` group.
                let mut depth = 0usize;
                loop {
                    match self.tokens.get(i).map(|t| &t.kind) {
                        Some(TokenKind::LBrace) => depth += 1,
                        Some(TokenKind::RBrace) => {
                            depth -= 1;
                            if depth == 0 {
                                i += 1;
                                break;
                            }
                        }
                        None => return false,
                        _ => {}
                    }
                    i += 1;
                }
            }
            Some(TokenKind::Parameter(_)) => i += 1,
            _ => {}
        }
        // The very next token must be the closing `)` — anything else means the group held an
        // expression, not a bare node pattern.
        if !matches!(self.tokens.get(i).map(|t| &t.kind), Some(TokenKind::RParen)) {
            return false;
        }
        i += 1;
        // The token after `)` must begin a relationship connector.
        match self.tokens.get(i).map(|t| &t.kind) {
            Some(TokenKind::DashDash | TokenKind::ArrowLeft) => true,
            // A single `-` is a relationship only when it heads a detail bracket `-[`.
            Some(TokenKind::Minus) => {
                matches!(
                    self.tokens.get(i + 1).map(|t| &t.kind),
                    Some(TokenKind::LBracket)
                )
            }
            _ => false,
        }
    }

    /// Parses a *pattern predicate* — a relationship pattern used directly as a boolean expression
    /// (openCypher `PatternPredicate = RelationshipsPattern`), e.g. `(n)-[]->()` in
    /// `MATCH (n) WHERE (n)-[]->() RETURN n`.
    ///
    /// A pattern predicate is semantically an existential over the pattern: it is true iff the
    /// pattern matches at least once given the outer row's bindings. Rather than introduce a new
    /// evaluation path, it desugars to the already-supported [`ExprKind::ExistsSubquery`] (the
    /// `EXISTS { pattern }` form), so the binding/semantic/lowering/eval phases reuse the existential
    /// machinery unchanged. Variables already bound in the outer scope constrain the pattern; fresh
    /// variables inside it are existentially quantified and do not escape — exactly the `EXISTS`
    /// semantics.
    ///
    /// The grammar restricts a pattern predicate to a single `RelationshipsPattern` (one
    /// [`PatternElement`]: a node followed by at least one chain link), with no comma-separated parts
    /// and no named-path variable — those forms are only valid inside an explicit `EXISTS { ... }`.
    fn parse_pattern_predicate(&mut self) -> Result<Expr, SyntaxError> {
        let element = self.parse_pattern_element()?;
        let span = element.span;
        let part = PatternPart {
            var: None,
            kind: PatternPartKind::Normal,
            element,
            span,
        };
        Ok(Expr::new(
            ExprKind::ExistsSubquery(Box::new(ExistsSubquery {
                pattern: vec![part],
                predicate: None,
                from_pattern_predicate: true,
                full_query: None,
            })),
            span,
        ))
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
        // A procedure name's segments accept a `SchemaName` (a `SymbolicName` **or** a reserved
        // word), not just a plain identifier, so a namespaced procedure whose segment collides with a
        // Cypher keyword parses — e.g. Neo4j's `db.index.fulltext.queryNodes` (`index` is a keyword).
        // This mirrors how labels / property keys already accept keyword spellings
        // ([`parse_schema_name`]) and matches the driver-ecosystem procedure names (`rmp` task #72).
        let mut name = vec![self.parse_schema_name("a procedure name")?];
        while self.eat(&TokenKind::Dot) {
            name.push(self.parse_schema_name("a procedure name segment after '.'")?);
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

    /// Parses a property key (`PropertyKeyName = SchemaName`).
    ///
    /// In addition to a `SymbolicName` or `ReservedWord` (via [`Self::parse_schema_name`]), this
    /// accepts the literal keywords `null`, `true` and `false` **as a key name** — openCypher allows
    /// them as (non-reserved) property/schema key names, so a map literal like
    /// `{null: 'Mats', NULL: 'Pontus'}` is valid (`expressions/map/Map1.feature` [5],
    /// `Map2.feature` [5]). The *original source spelling* is preserved, so `null` and `NULL` stay
    /// **distinct keys** (the lexer recognises these keywords case-insensitively, which would
    /// otherwise collapse the two).
    fn parse_property_key(&mut self, what: &str) -> Result<String, SyntaxError> {
        if let Some(tok) = self.peek()
            && matches!(tok.kind, TokenKind::Null | TokenKind::Boolean(_))
        {
            let text = self.source[tok.span.start..tok.span.end].to_owned();
            self.bump();
            return Ok(text);
        }
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
        TokenKind::Foreach => "FOREACH",
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
