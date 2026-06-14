//! The Cypher lexer: query text → token stream with **byte-accurate source spans**
//! (`04-technical-design.md` §7.1 — *"lexer → token stream"*; §7.3 — lexer errors are the
//! compile-time `SyntaxError` class and must carry **precise positions**, because the openCypher
//! TCK asserts the offset of every `SyntaxError`).
//!
//! # Why a hand-written scanner (not `logos`)
//!
//! `04 §7.1` names `logos` as a candidate. We chose a **hand-written scanner** instead, for the
//! single inviolable reason this sub-task exists: **byte-accurate error positions**. `logos`
//! recognizes valid tokens efficiently, but on malformed input it can only emit a catch-all error
//! token holding the matched slice — it does not distinguish *unterminated string* from *bad escape*
//! from *unterminated block comment*, nor does it report the exact offset *inside* a token where the
//! fault lies. The openCypher string-literal escape rules (`\uXXXX` vs `\uXXXXXXXX` vs the
//! `\u{...}` brace extension) and the TCK's positional `SyntaxError` scenarios need that control. A
//! hand-written scanner also: keeps [`#![forbid(unsafe_code)]`](super), adds **zero dependencies**
//! (matching the house style of the sibling value-model modules), and is the natural companion to
//! the hand-written recursive-descent parser the design mandates for the next sub-task (`04 §7.1`).
//!
//! # Grounding in the openCypher grammar
//!
//! Token shapes follow the openCypher EBNF (`cypher.ebnf`, M-series; mirrored at
//! <https://s3.amazonaws.com/artifacts.opencypher.org/M23/cypher.ebnf>). The relevant productions
//! are cited inline where they are non-obvious (string escapes, number bases, symbolic names,
//! parameters). Where Graphus targets the broader 2024.x Cypher line (`D-cypher-line`), the few
//! superset additions over M-series are called out in the code (e.g. the `\u{...}` brace escape and
//! a signed `+` exponent).
//!
//! # Spans
//!
//! Every [`Token`] carries a [`Span`] of **byte offsets** `start..end` into the original input,
//! half-open (`end` is exclusive), so `&input[span.start..span.end]` slices the exact source text of
//! the token. Whitespace and comments are skipped but never shift the offsets of surrounding tokens.
//! On error, [`LexError`] carries the byte [`Span`] of the offending region (see
//! [`LexErrorKind`]); for single-character faults the span is one byte wide, for an unterminated
//! construct it spans from the opening delimiter to end-of-input.
//!
//! # What the lexer does *not* do
//!
//! - **Negative numbers.** `-1` lexes as [`TokenKind::Minus`] followed by an integer literal; the
//!   sign is resolved by the parser as unary minus (openCypher: `NumberLiteral` has no leading sign;
//!   the minus is the unary `-` operator). This keeps `a-1` and `a - 1` lexing identically.
//! - **Numeric overflow.** An integer/float literal is tokenized by *shape*; whether it fits `i64`
//!   / `f64` is a parser/semantic concern. The lexer guarantees only that the slice is a
//!   well-formed numeral of its base.
//! - **Keyword vs identifier *role*.** The lexer classifies a reserved word as its keyword
//!   [`TokenKind`] (case-insensitively) and preserves the original text in the [`Span`] for error
//!   messages; whether a given keyword is *also* legal as an identifier in a position is the
//!   parser's call.

use std::fmt;

use graphus_core::GraphusError;

/// A half-open range of **byte** offsets `[start, end)` into the lexer's input.
///
/// `end` is exclusive, so the source text of a token `t` is exactly `&input[t.span.start..t.span.end]`
/// and `span.len()` is the token's byte length. Spans never overlap and, together with the skipped
/// whitespace/comment gaps, tile the whole input (asserted by the lexer's property tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub struct Span {
    /// Inclusive start byte offset.
    pub start: usize,
    /// Exclusive end byte offset.
    pub end: usize,
}

impl Span {
    /// Builds a span from a half-open byte range.
    ///
    /// # Panics
    ///
    /// Never panics, but callers are expected to pass `start <= end`; the lexer always does.
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// The byte length of the span (`end - start`).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the span is empty (`start == end`). A real token never has an empty span; this is a
    /// convenience for callers inspecting derived spans.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

/// A single lexed token: its classification ([`TokenKind`]) plus its byte [`Span`] in the input.
///
/// The token does **not** own its source text; recover it with `&input[token.span.start..token.span.end]`.
/// For literals whose decoded value differs from their source spelling (strings with escapes,
/// hex/octal integers), [`TokenKind`] carries the decoded payload while the [`Span`] still covers
/// the original spelling for diagnostics.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct Token {
    /// What kind of token this is (and any decoded payload).
    pub kind: TokenKind,
    /// The byte range of this token's source spelling.
    pub span: Span,
}

impl Token {
    /// Convenience constructor.
    pub fn new(kind: TokenKind, span: Span) -> Self {
        Self { kind, span }
    }
}

/// The classification of a [`Token`], plus decoded payloads for literals and identifiers.
///
/// Keyword variants are matched **case-insensitively** by the lexer (openCypher keywords are
/// case-insensitive); the original casing is recoverable from the token's [`Span`]. Operator and
/// punctuation variants are spelled out individually so the parser never re-scans bytes.
///
/// Literal payloads:
/// - [`TokenKind::Integer`] holds an [`IntLiteral`]: the decoded magnitude plus the base it was
///   written in. The magnitude is a `u128` (headroom for the parser's `i64` range check); range
///   validation is the parser's job, keeping the compile-time *syntax* vs *semantic* phases cleanly
///   split (`04 §7.3`). See [`IntLiteral`].
/// - [`TokenKind::Float`] holds the decoded `f64`.
/// - [`TokenKind::String`] holds the **unescaped** string contents (escapes resolved).
/// - [`TokenKind::Identifier`] holds the identifier text (backticks stripped, doubled backticks
///   collapsed for the escaped form).
/// - [`TokenKind::Parameter`] holds the parameter name without the leading `$`.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum TokenKind {
    // ---- literals & identifiers -------------------------------------------------------------
    /// An integer literal (decimal, `0x` hex, or `0o` octal), decoded.
    Integer(IntLiteral),
    /// A floating-point literal, decoded to `f64`.
    Float(f64),
    /// A string literal, with escape sequences resolved to their characters.
    String(String),
    /// A boolean literal keyword (`true` / `false`, case-insensitive).
    Boolean(bool),
    /// The `null` literal keyword (case-insensitive).
    Null,
    /// An identifier (variable / label / type / property-key name). For the backtick-escaped form
    /// the surrounding backticks are removed and doubled backticks `` `` `` are collapsed to one.
    Identifier(String),
    /// A query parameter: the leading `$` is stripped; the payload is the name (`$foo` → `foo`) or
    /// the decimal index (`$0` → `0`).
    Parameter(String),

    // ---- keywords (case-insensitive) --------------------------------------------------------
    /// `MATCH`
    Match,
    /// `OPTIONAL`
    Optional,
    /// `WHERE`
    Where,
    /// `RETURN`
    Return,
    /// `WITH`
    With,
    /// `CREATE`
    Create,
    /// `MERGE`
    Merge,
    /// `SET`
    Set,
    /// `DELETE`
    Delete,
    /// `DETACH`
    Detach,
    /// `REMOVE`
    Remove,
    /// `UNWIND`
    Unwind,
    /// `FOREACH`
    Foreach,
    /// `CALL`
    Call,
    /// `YIELD`
    Yield,
    /// `ORDER`
    Order,
    /// `BY`
    By,
    /// `SKIP`
    Skip,
    /// `LIMIT`
    Limit,
    /// `UNION`
    Union,
    /// `ALL`
    All,
    /// `DISTINCT`
    Distinct,
    /// `AS`
    As,
    /// `AND`
    And,
    /// `OR`
    Or,
    /// `XOR`
    Xor,
    /// `NOT`
    Not,
    /// `IN`
    In,
    /// `IS`
    Is,
    /// `STARTS`
    Starts,
    /// `ENDS`
    Ends,
    /// `CONTAINS`
    Contains,
    /// `CASE`
    Case,
    /// `WHEN`
    When,
    /// `THEN`
    Then,
    /// `ELSE`
    Else,
    /// `END`
    End,
    /// `ASC`
    Asc,
    /// `ASCENDING`
    Ascending,
    /// `DESC`
    Desc,
    /// `DESCENDING`
    Descending,
    /// `ON`
    On,
    /// `CONSTRAINT`
    Constraint,
    /// `INDEX`
    Index,
    /// `EXISTS`
    Exists,
    /// `UNIQUE`
    Unique,
    /// `DROP`
    Drop,

    // ---- operators & punctuation ------------------------------------------------------------
    /// `+`
    Plus,
    /// `-` (single dash; note `--` and `->`/`<-` are distinct, see below)
    Minus,
    /// `*`
    Star,
    /// `/`
    Slash,
    /// `%`
    Percent,
    /// `^`
    Caret,
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
    /// `+=` (map-merge mutation, used by `SET n += {…}`)
    PlusEq,
    /// `:`
    Colon,
    /// `::` (type-coercion / qualified name)
    DoubleColon,
    /// `.`
    Dot,
    /// `..` (range, used in list slices and quantified path ranges)
    DotDot,
    /// `,`
    Comma,
    /// `;`
    Semicolon,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `|`
    Pipe,
    /// `->` (right relationship arrow)
    ArrowRight,
    /// `<-` (left relationship arrow)
    ArrowLeft,
    /// `--` (undirected double-dash, e.g. `(a)--(b)`)
    DashDash,
}

/// A decoded integer literal: its magnitude and the base it was written in.
///
/// openCypher integers are 64-bit signed, but the lexer stores the **magnitude** in a `u128` so an
/// out-of-range literal still lexes (the parser does the `i64` range check, keeping the syntax vs
/// semantic phase split clean — `04 §7.3`). The sign is never part of the literal: `-1` lexes as
/// [`TokenKind::Minus`] then this literal. Keeping the [`IntBase`] lets diagnostics echo the
/// original `0x` / `0o` / decimal form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub struct IntLiteral {
    /// The decoded value, as a `u128` to hold any in-range literal plus headroom for the parser's
    /// own range check. (The lexer never rejects an in-base numeral for being large; that is the
    /// parser's job, keeping the compile-time *syntax* vs *semantic* phases cleanly split, `04 §7.3`.)
    pub value: u128,
    /// The base the literal was written in.
    pub base: IntBase,
}

/// The numeric base a [`IntLiteral`] was written in (openCypher `IntegerLiteral`: decimal, `0x`
/// hex, `0o` octal; note openCypher does **not** define C-style bare-leading-zero octal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum IntBase {
    /// Base-10 (`DecimalInteger`).
    Decimal,
    /// Base-16 with a `0x` / `0X` prefix (`HexInteger`).
    Hex,
    /// Base-8 with a `0o` / `0O` prefix (`OctalInteger`).
    Octal,
}

/// What went wrong while lexing, paired with the byte [`Span`] of the offending region by
/// [`LexError`].
///
/// Every kind maps to the compile-time `SyntaxError` class (`04 §7.3`); the distinct variants let
/// diagnostics and the TCK error-classification table describe the fault precisely.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LexErrorKind {
    /// A character that cannot begin any token (e.g. a stray `@` or `#`).
    UnexpectedChar(char),
    /// A string literal whose closing quote was never found before end-of-input. The span runs from
    /// the opening quote to EOF.
    UnterminatedString,
    /// A block comment `/* … */` whose closing `*/` was never found. Span runs from `/*` to EOF.
    UnterminatedBlockComment,
    /// A backtick-escaped identifier `` `…` `` whose closing backtick was never found. Span runs
    /// from the opening backtick to EOF.
    UnterminatedEscapedName,
    /// An empty backtick-escaped identifier ```` `` ```` is not a valid name (openCypher
    /// `EscapedSymbolicName` requires at least one inner character per backtick pair).
    EmptyEscapedName,
    /// An invalid string escape sequence (e.g. `\q`). The span covers the backslash and the
    /// offending escape character.
    InvalidEscape,
    /// A `\uXXXX` / `\uXXXXXXXX` / `\u{…}` escape with too few hex digits, a non-hex digit, or a
    /// code point that is not a valid Unicode scalar value (surrogate or out of range).
    InvalidUnicodeEscape,
    /// A numeric literal prefix (`0x` / `0o`) with no following digits, or a malformed numeral.
    MalformedNumber,
    /// A floating-point literal whose magnitude exceeds the `f64` range (e.g. `1.34E999`), which
    /// `f64::from_str` parses to infinity rather than rejecting. openCypher classifies this as a
    /// compile-time `SyntaxError` (TCK detail `FloatingPointOverflow`,
    /// `tck/features/expressions/literals/Literals5` [27]).
    FloatOverflow,
    /// A `$` not followed by a valid parameter name or decimal index.
    MalformedParameter,
}

impl fmt::Display for LexErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedChar(c) => write!(f, "unexpected character {c:?}"),
            Self::UnterminatedString => f.write_str("unterminated string literal"),
            Self::UnterminatedBlockComment => f.write_str("unterminated block comment"),
            Self::UnterminatedEscapedName => f.write_str("unterminated backtick-escaped name"),
            Self::EmptyEscapedName => f.write_str("empty backtick-escaped name"),
            Self::InvalidEscape => f.write_str("invalid string escape sequence"),
            Self::InvalidUnicodeEscape => f.write_str("invalid unicode escape sequence"),
            Self::MalformedNumber => f.write_str("malformed numeric literal"),
            Self::FloatOverflow => f.write_str("floating-point literal out of range"),
            Self::MalformedParameter => f.write_str("malformed parameter"),
        }
    }
}

/// A lexing failure: a [`LexErrorKind`] plus the byte [`Span`] it occurred at.
///
/// This is the compile-time `SyntaxError` carrier (`04 §7.3`). It converts into the crate-wide
/// [`GraphusError::Compile`] at the engine boundary via [`From`], preserving the span in the
/// message so the connectivity layer can surface a positional error to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct LexError {
    /// The classified cause.
    pub kind: LexErrorKind,
    /// The byte range of the offending source region.
    pub span: Span,
}

impl LexError {
    /// Builds a [`LexError`] from a kind and span.
    pub fn new(kind: LexErrorKind, span: Span) -> Self {
        Self { kind, span }
    }
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "syntax error at bytes {}: {}", self.span, self.kind)
    }
}

impl std::error::Error for LexError {}

impl From<LexError> for GraphusError {
    /// Lexer errors are compile-time `SyntaxError`s (`04 §7.3`); they map onto the crate-wide
    /// [`GraphusError::Compile`] variant, carrying the positional message.
    fn from(e: LexError) -> Self {
        GraphusError::Compile(e.to_string())
    }
}

/// Tokenizes `input` into a [`Vec`] of [`Token`]s with byte-accurate spans, skipping whitespace and
/// comments.
///
/// This is the crate's public lexing entry point (`04 §7.1`). The returned tokens are in source
/// order; whitespace and `//` line / `/* */` block comments are removed but do not perturb the byte
/// offsets recorded on the surrounding tokens.
///
/// # Errors
///
/// Returns a [`LexError`] (compile-time `SyntaxError`, `04 §7.3`) at the first malformed construct:
/// an unexpected character, an unterminated string / block comment / backtick name, an invalid
/// escape (including bad `\u` unicode escapes), a malformed numeric literal, or a malformed
/// parameter. The error's [`Span`] is the byte range of the offending region.
///
/// # Examples
///
/// ```
/// use graphus_cypher::lexer::{tokenize, TokenKind};
///
/// let tokens = tokenize("MATCH (n) RETURN n").expect("valid query");
/// assert_eq!(tokens[0].kind, TokenKind::Match);
/// assert_eq!(tokens[0].span.start, 0);
/// assert_eq!(tokens[0].span.end, 5); // "MATCH"
/// // The `(` keeps its true offset even though a space was skipped before it.
/// assert_eq!(tokens[1].kind, TokenKind::LParen);
/// assert_eq!(tokens[1].span.start, 6);
/// ```
pub fn tokenize(input: &str) -> Result<Vec<Token>, LexError> {
    Lexer::new(input).run()
}

/// A single-pass byte-offset scanner over a UTF-8 `&str`.
///
/// The lexer walks `bytes` (the input's UTF-8 bytes) by index, which is what makes every span a
/// true byte offset. Multi-byte UTF-8 is handled by decoding `char`s only where a token may legally
/// contain non-ASCII (identifiers, string contents); the structural ASCII of Cypher (keywords,
/// operators, punctuation, number/parameter prefixes) is matched byte-wise. All offsets are byte
/// offsets, never `char` indices.
#[derive(Debug)]
struct Lexer<'a> {
    /// The original source, retained for `char` decoding of identifier / string runs.
    src: &'a str,
    /// The source as raw bytes; the cursor `pos` indexes into this.
    bytes: &'a [u8],
    /// The current byte offset.
    pos: usize,
}

impl<'a> Lexer<'a> {
    /// Creates a lexer over `input`.
    fn new(input: &'a str) -> Self {
        Self {
            src: input,
            bytes: input.as_bytes(),
            pos: 0,
        }
    }

    /// Drives the scan to completion, returning all tokens or the first error.
    fn run(mut self) -> Result<Vec<Token>, LexError> {
        let mut out = Vec::new();
        loop {
            self.skip_trivia()?;
            if self.pos >= self.bytes.len() {
                return Ok(out);
            }
            out.push(self.next_token()?);
        }
    }

    /// Peeks the byte at the current cursor, or `None` at end-of-input.
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Peeks the byte `n` positions ahead of the cursor.
    fn peek_at(&self, n: usize) -> Option<u8> {
        self.bytes.get(self.pos + n).copied()
    }

    /// Skips whitespace and comments. Returns an error only for an unterminated block comment (its
    /// span is recorded from the opening `/*`).
    fn skip_trivia(&mut self) -> Result<(), LexError> {
        loop {
            match self.peek() {
                // ASCII whitespace plus the Unicode whitespace that openCypher permits between
                // tokens. We treat any `char::is_whitespace` as trivia; ASCII fast-path first.
                Some(b) if b.is_ascii_whitespace() => self.pos += 1,
                Some(b'/') if self.peek_at(1) == Some(b'/') => self.skip_line_comment(),
                Some(b'/') if self.peek_at(1) == Some(b'*') => self.skip_block_comment()?,
                Some(b) if b >= 0x80 => {
                    // Possible multi-byte Unicode whitespace (e.g. U+00A0, U+2028). Decode one char.
                    let ch = self.char_at(self.pos);
                    if ch.is_whitespace() {
                        self.pos += ch.len_utf8();
                    } else {
                        return Ok(());
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    /// Skips a `//` line comment up to (not including) the line terminator.
    fn skip_line_comment(&mut self) {
        self.pos += 2; // consume "//"
        while let Some(b) = self.peek() {
            if b == b'\n' || b == b'\r' {
                break;
            }
            self.pos += 1;
        }
    }

    /// Skips a `/* … */` block comment. Cypher block comments do **not** nest (openCypher follows
    /// SQL-style non-nesting comments), so the first `*/` closes it.
    ///
    /// # Errors
    ///
    /// [`LexErrorKind::UnterminatedBlockComment`] spanning `/*`..EOF if no `*/` is found.
    fn skip_block_comment(&mut self) -> Result<(), LexError> {
        let start = self.pos;
        self.pos += 2; // consume "/*"
        while self.pos < self.bytes.len() {
            if self.peek() == Some(b'*') && self.peek_at(1) == Some(b'/') {
                self.pos += 2; // consume "*/"
                return Ok(());
            }
            self.pos += 1;
        }
        Err(LexError::new(
            LexErrorKind::UnterminatedBlockComment,
            Span::new(start, self.bytes.len()),
        ))
    }

    /// Scans the single token beginning at the cursor (trivia already skipped, cursor on a real
    /// byte).
    fn next_token(&mut self) -> Result<Token, LexError> {
        let start = self.pos;
        let b = self.peek().unwrap_or(b'\0'); // run() guarantees a byte here; default is unreachable.
        match b {
            b'"' | b'\'' => self.scan_string(),
            b'`' => self.scan_escaped_name(),
            b'$' => self.scan_parameter(),
            b'0'..=b'9' => self.scan_number(),
            b'.' if matches!(self.peek_at(1), Some(b'0'..=b'9')) => self.scan_number(),
            _ if is_ident_start(b) => Ok(self.scan_word()),
            _ if b >= 0x80 && is_ident_start_char(self.char_at(start)) => Ok(self.scan_word()),
            _ => self.scan_operator(start),
        }
    }

    /// Scans an operator or punctuation token, choosing the longest match. `start` is the token's
    /// byte offset.
    ///
    /// # Errors
    ///
    /// [`LexErrorKind::UnexpectedChar`] (one-byte/one-char span) for any byte that begins no token.
    fn scan_operator(&mut self, start: usize) -> Result<Token, LexError> {
        // Multi-byte operators are matched before their single-byte prefixes.
        let two = (self.peek(), self.peek_at(1));
        let kind = match two {
            (Some(b'<'), Some(b'>')) => self.emit2(TokenKind::Neq),
            (Some(b'<'), Some(b'=')) => self.emit2(TokenKind::Lte),
            (Some(b'>'), Some(b'=')) => self.emit2(TokenKind::Gte),
            (Some(b'='), Some(b'~')) => self.emit2(TokenKind::RegexMatch),
            (Some(b'+'), Some(b'=')) => self.emit2(TokenKind::PlusEq),
            (Some(b':'), Some(b':')) => self.emit2(TokenKind::DoubleColon),
            (Some(b'.'), Some(b'.')) => self.emit2(TokenKind::DotDot),
            (Some(b'-'), Some(b'>')) => self.emit2(TokenKind::ArrowRight),
            (Some(b'<'), Some(b'-')) => self.emit2(TokenKind::ArrowLeft),
            (Some(b'-'), Some(b'-')) => self.emit2(TokenKind::DashDash),
            _ => {
                let single = match self.peek() {
                    Some(b'+') => TokenKind::Plus,
                    Some(b'-') => TokenKind::Minus,
                    Some(b'*') => TokenKind::Star,
                    Some(b'/') => TokenKind::Slash,
                    Some(b'%') => TokenKind::Percent,
                    Some(b'^') => TokenKind::Caret,
                    Some(b'=') => TokenKind::Eq,
                    Some(b'<') => TokenKind::Lt,
                    Some(b'>') => TokenKind::Gt,
                    Some(b':') => TokenKind::Colon,
                    Some(b'.') => TokenKind::Dot,
                    Some(b',') => TokenKind::Comma,
                    Some(b';') => TokenKind::Semicolon,
                    Some(b'(') => TokenKind::LParen,
                    Some(b')') => TokenKind::RParen,
                    Some(b'[') => TokenKind::LBracket,
                    Some(b']') => TokenKind::RBracket,
                    Some(b'{') => TokenKind::LBrace,
                    Some(b'}') => TokenKind::RBrace,
                    Some(b'|') => TokenKind::Pipe,
                    _ => {
                        // Unknown byte: report the offending *character* (decode it for the span /
                        // message so a multi-byte stray char gets its full byte span).
                        let ch = self.char_at(start);
                        let end = start + ch.len_utf8();
                        self.pos = end;
                        return Err(LexError::new(
                            LexErrorKind::UnexpectedChar(ch),
                            Span::new(start, end),
                        ));
                    }
                };
                self.pos += 1;
                single
            }
        };
        Ok(Token::new(kind, Span::new(start, self.pos)))
    }

    /// Consumes two bytes and returns `kind` (helper for two-byte operators).
    fn emit2(&mut self, kind: TokenKind) -> TokenKind {
        self.pos += 2;
        kind
    }

    /// Scans an identifier or keyword (`UnescapedSymbolicName`): an identifier-start char followed
    /// by identifier-part chars. Keywords are recognized case-insensitively; everything else is an
    /// [`TokenKind::Identifier`]. `true`/`false`/`null` are recognized as their literal kinds.
    fn scan_word(&mut self) -> Token {
        let start = self.pos;
        // Advance over identifier-part characters (ASCII fast path, with Unicode fallback).
        while let Some(b) = self.peek() {
            if b < 0x80 {
                if is_ident_part(b) {
                    self.pos += 1;
                } else {
                    break;
                }
            } else {
                let ch = self.char_at(self.pos);
                if is_ident_part_char(ch) {
                    self.pos += ch.len_utf8();
                } else {
                    break;
                }
            }
        }
        let text = &self.src[start..self.pos];
        let kind = keyword_or_identifier(text);
        Token::new(kind, Span::new(start, self.pos))
    }

    /// Scans a query parameter `$name` or `$0` (openCypher `Parameter = '$', (SymbolicName |
    /// DecimalInteger)`).
    ///
    /// # Errors
    ///
    /// [`LexErrorKind::MalformedParameter`] if `$` is not followed by an identifier-start char or a
    /// decimal digit. The span covers `$` plus the offending byte (or just `$` at EOF).
    fn scan_parameter(&mut self) -> Result<Token, LexError> {
        let start = self.pos;
        self.pos += 1; // consume '$'
        match self.peek() {
            // Numeric parameter index: one or more decimal digits.
            Some(b'0'..=b'9') => {
                let name_start = self.pos;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
                let name = self.src[name_start..self.pos].to_owned();
                Ok(Token::new(
                    TokenKind::Parameter(name),
                    Span::new(start, self.pos),
                ))
            }
            // Named parameter: a symbolic name.
            Some(b) if is_ident_start(b) => self.finish_named_parameter(start),
            Some(b) if b >= 0x80 && is_ident_start_char(self.char_at(self.pos)) => {
                self.finish_named_parameter(start)
            }
            // Anything else (incl. EOF): malformed. The span pinpoints the fault: at EOF or
            // whitespace the `$` itself is the whole problem (no name follows), so span just `$`;
            // a non-whitespace stray byte (e.g. `$-`) is included so the diagnostic points at the
            // bad name-start character.
            other => {
                let end = match other {
                    Some(b) if b < 0x80 && b.is_ascii_whitespace() => self.pos,
                    Some(b) if b < 0x80 => self.pos + 1,
                    Some(b) if b >= 0x80 && self.char_at(self.pos).is_whitespace() => self.pos,
                    Some(_) => self.pos + self.char_at(self.pos).len_utf8(),
                    None => self.pos,
                };
                Err(LexError::new(
                    LexErrorKind::MalformedParameter,
                    Span::new(start, end),
                ))
            }
        }
    }

    /// Completes a named parameter once the first name char is confirmed at the cursor. `start` is
    /// the offset of the `$`.
    fn finish_named_parameter(&mut self, start: usize) -> Result<Token, LexError> {
        let name_start = self.pos;
        while let Some(b) = self.peek() {
            if b < 0x80 {
                if is_ident_part(b) {
                    self.pos += 1;
                } else {
                    break;
                }
            } else {
                let ch = self.char_at(self.pos);
                if is_ident_part_char(ch) {
                    self.pos += ch.len_utf8();
                } else {
                    break;
                }
            }
        }
        let name = self.src[name_start..self.pos].to_owned();
        Ok(Token::new(
            TokenKind::Parameter(name),
            Span::new(start, self.pos),
        ))
    }

    /// Scans a backtick-escaped identifier `` `…` `` (openCypher `EscapedSymbolicName`). Doubled
    /// backticks ```` `` ```` inside the name denote a single literal backtick.
    ///
    /// # Errors
    ///
    /// - [`LexErrorKind::UnterminatedEscapedName`] (span `` ` ``..EOF) if the closing backtick is
    ///   missing.
    /// - [`LexErrorKind::EmptyEscapedName`] if the name is ```` `` ```` with no content.
    fn scan_escaped_name(&mut self) -> Result<Token, LexError> {
        let start = self.pos;
        self.pos += 1; // consume opening '`'
        let mut name = String::new();
        loop {
            match self.peek() {
                None => {
                    return Err(LexError::new(
                        LexErrorKind::UnterminatedEscapedName,
                        Span::new(start, self.bytes.len()),
                    ));
                }
                Some(b'`') => {
                    // A doubled backtick is an escaped literal backtick; otherwise this closes the
                    // name.
                    if self.peek_at(1) == Some(b'`') {
                        name.push('`');
                        self.pos += 2;
                    } else {
                        self.pos += 1; // consume closing '`'
                        if name.is_empty() {
                            return Err(LexError::new(
                                LexErrorKind::EmptyEscapedName,
                                Span::new(start, self.pos),
                            ));
                        }
                        return Ok(Token::new(
                            TokenKind::Identifier(name),
                            Span::new(start, self.pos),
                        ));
                    }
                }
                Some(b) if b < 0x80 => {
                    name.push(b as char);
                    self.pos += 1;
                }
                Some(_) => {
                    let ch = self.char_at(self.pos);
                    name.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    /// Scans a string literal in single or double quotes, resolving escape sequences (openCypher
    /// `StringLiteral` / `EscapedChar`).
    ///
    /// # Errors
    ///
    /// - [`LexErrorKind::UnterminatedString`] (span quote..EOF) if the closing quote is missing.
    /// - [`LexErrorKind::InvalidEscape`] for an unknown escape (span of `\` + char).
    /// - [`LexErrorKind::InvalidUnicodeEscape`] for a bad `\u` escape.
    fn scan_string(&mut self) -> Result<Token, LexError> {
        let start = self.pos;
        let quote = self.peek().unwrap_or(b'"');
        self.pos += 1; // consume opening quote
        let mut value = String::new();
        loop {
            match self.peek() {
                None => {
                    return Err(LexError::new(
                        LexErrorKind::UnterminatedString,
                        Span::new(start, self.bytes.len()),
                    ));
                }
                Some(b) if b == quote => {
                    self.pos += 1; // consume closing quote
                    return Ok(Token::new(
                        TokenKind::String(value),
                        Span::new(start, self.pos),
                    ));
                }
                Some(b'\\') => {
                    self.scan_escape(&mut value)?;
                }
                Some(b) if b < 0x80 => {
                    value.push(b as char);
                    self.pos += 1;
                }
                Some(_) => {
                    let ch = self.char_at(self.pos);
                    value.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    /// Resolves a single backslash escape, pushing the decoded char(s) onto `value`. The cursor is
    /// on the `\` on entry.
    ///
    /// openCypher `EscapedChar`: `\\ \' \" \b \f \n \r \t \uXXXX (4 hex) \uXXXXXXXX (8 hex)`. We
    /// additionally accept the `\u{…}` brace form used by the broader Cypher line (`D-cypher-line`);
    /// the EBNF M-series form (fixed 4 / 8 hex digits) remains the primary, and is what the TCK
    /// asserts.
    ///
    /// # Errors
    ///
    /// [`LexErrorKind::InvalidEscape`] / [`LexErrorKind::InvalidUnicodeEscape`] with the precise
    /// span of the offending escape.
    fn scan_escape(&mut self, value: &mut String) -> Result<(), LexError> {
        let esc_start = self.pos;
        self.pos += 1; // consume '\'
        let Some(b) = self.peek() else {
            // A trailing backslash at EOF: the string is unterminated, but the more specific fault
            // is the dangling escape. Report it spanning the backslash to EOF.
            return Err(LexError::new(
                LexErrorKind::InvalidEscape,
                Span::new(esc_start, self.bytes.len()),
            ));
        };
        let decoded = match b {
            b'\\' => '\\',
            b'\'' => '\'',
            b'"' => '"',
            b'b' => '\u{0008}',
            b'f' => '\u{000C}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                self.pos += 1; // consume 'u'
                let ch = self.scan_unicode_escape(esc_start)?;
                value.push(ch);
                return Ok(());
            }
            _ => {
                // Unknown escape: span covers `\` and the offending char (decoded so multi-byte
                // chars get their full span).
                let ch = self.char_at(self.pos);
                let end = self.pos + ch.len_utf8();
                self.pos = end;
                return Err(LexError::new(
                    LexErrorKind::InvalidEscape,
                    Span::new(esc_start, end),
                ));
            }
        };
        self.pos += 1; // consume the single escape char
        value.push(decoded);
        Ok(())
    }

    /// Resolves a `\u` unicode escape. On entry the cursor is just past `\u`; `esc_start` is the
    /// offset of the `\` (for the error span). Accepts three forms:
    ///
    /// - `\uXXXX` — exactly 4 hex digits (openCypher M-series, primary).
    /// - `\uXXXXXXXX` — exactly 8 hex digits (openCypher M-series).
    /// - `\u{…}` — 1..=6 hex digits in braces (broader Cypher line, `D-cypher-line`).
    ///
    /// # Errors
    ///
    /// [`LexErrorKind::InvalidUnicodeEscape`] for missing/short/non-hex digits or a code point that
    /// is not a Unicode scalar value (surrogate `D800..=DFFF` or `> 10FFFF`).
    fn scan_unicode_escape(&mut self, esc_start: usize) -> Result<char, LexError> {
        if self.peek() == Some(b'{') {
            self.pos += 1; // consume '{'
            let digits_start = self.pos;
            while matches!(self.peek(), Some(c) if c.is_ascii_hexdigit()) {
                self.pos += 1;
            }
            let digits = &self.src[digits_start..self.pos];
            // Require the closing brace and a non-empty, not-too-long digit run.
            if self.peek() != Some(b'}') || digits.is_empty() || digits.len() > 6 {
                // Span to the brace if present, else to current cursor.
                let end = if self.peek() == Some(b'}') {
                    self.pos + 1
                } else {
                    self.pos
                };
                return Err(LexError::new(
                    LexErrorKind::InvalidUnicodeEscape,
                    Span::new(esc_start, end),
                ));
            }
            self.pos += 1; // consume '}'
            return self.code_point_to_char(digits, Span::new(esc_start, self.pos));
        }

        // Fixed-width form: try 8 hex digits, else 4 (openCypher EBNF: `(U, 4*HexDigit) | (U,
        // 8*HexDigit)`). We greedily prefer 8 when 8 hex digits are present, matching the longest
        // EscapedChar; otherwise require exactly 4.
        let avail = self.count_hex_run();
        let take = if avail >= 8 {
            8
        } else if avail >= 4 {
            4
        } else {
            let end = self.pos + avail;
            return Err(LexError::new(
                LexErrorKind::InvalidUnicodeEscape,
                Span::new(esc_start, end),
            ));
        };
        let digits = &self.src[self.pos..self.pos + take];
        self.pos += take;
        self.code_point_to_char(digits, Span::new(esc_start, self.pos))
    }

    /// Counts the run of ASCII hex digits starting at the cursor (does not advance).
    fn count_hex_run(&self) -> usize {
        let mut n = 0;
        while matches!(self.bytes.get(self.pos + n), Some(c) if c.is_ascii_hexdigit()) {
            n += 1;
        }
        n
    }

    /// Parses `digits` (validated hex) as a Unicode scalar value, erroring on surrogates / overflow.
    fn code_point_to_char(&self, digits: &str, span: Span) -> Result<char, LexError> {
        // `digits` is guaranteed non-empty ASCII hex by the callers; parse as u32. A >6-digit run is
        // impossible here (brace form caps at 6, fixed form at 8 but 8 hex ≤ u32::MAX), but guard
        // the `from_str_radix` result regardless to avoid any panic path.
        let cp = u32::from_str_radix(digits, 16)
            .map_err(|_| LexError::new(LexErrorKind::InvalidUnicodeEscape, span))?;
        char::from_u32(cp).ok_or_else(|| LexError::new(LexErrorKind::InvalidUnicodeEscape, span))
    }

    /// Scans a numeric literal: hex `0x…`, octal `0o…`, or a decimal integer / float (openCypher
    /// `NumberLiteral`). Leading `+`/`-` is **not** consumed here (it is the unary operator); a
    /// literal beginning `.5` is a float.
    ///
    /// # Errors
    ///
    /// [`LexErrorKind::MalformedNumber`] for an empty `0x` / `0o`, or a `.`-only / malformed shape.
    fn scan_number(&mut self) -> Result<Token, LexError> {
        let start = self.pos;

        // Base-prefixed integers: 0x / 0X (hex), 0o / 0O (octal).
        if self.peek() == Some(b'0') {
            match self.peek_at(1) {
                Some(b'x' | b'X') => return self.scan_radix_int(start, IntBase::Hex),
                Some(b'o' | b'O') => return self.scan_radix_int(start, IntBase::Octal),
                _ => {}
            }
        }

        // Decimal integer or float. Consume the integer part.
        let mut is_float = false;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }

        // Fractional part: a `.` *followed by a digit* (so `1..2` range and `1.foo` property access
        // are not eaten as floats). A leading `.5` enters here with no integer digits consumed; the
        // dispatch in `next_token` only routes a bare `.` here when a digit follows, so the same
        // rule covers it.
        if self.peek() == Some(b'.') && matches!(self.peek_at(1), Some(b'0'..=b'9')) {
            is_float = true;
            self.pos += 1; // consume '.'
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }

        // Exponent: e / E, optional sign (EBNF M-series allows only '-'; the broader Cypher line and
        // common drivers also accept '+', so we accept both and document it), then >=1 digit.
        if matches!(self.peek(), Some(b'e' | b'E')) {
            let exp_marker = self.pos;
            let mut probe = self.pos + 1;
            if matches!(self.bytes.get(probe), Some(b'+' | b'-')) {
                probe += 1;
            }
            if matches!(self.bytes.get(probe), Some(b'0'..=b'9')) {
                is_float = true;
                self.pos = probe;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            } else {
                // `1e` with no exponent digits: not part of the number. Leave the cursor before
                // `e` so it lexes as a following identifier. (We did not advance past exp_marker.)
                debug_assert_eq!(self.pos, exp_marker);
            }
        }

        let text = &self.src[start..self.pos];
        if is_float {
            // The shape is a valid float per the grammar above; `f64::from_str` accepts it.
            let value = text.parse::<f64>().map_err(|_| {
                LexError::new(LexErrorKind::MalformedNumber, Span::new(start, self.pos))
            })?;
            // `f64::from_str` maps an out-of-range magnitude (e.g. `1.34E999`) to infinity rather
            // than erroring. The grammar above never admits literal `inf`/`nan` text, so an infinite
            // result can only mean the written value overflowed `f64` — a compile-time `SyntaxError`
            // (openCypher; `tck/.../Literals5` [27], detail `FloatingPointOverflow`).
            if value.is_infinite() {
                return Err(LexError::new(
                    LexErrorKind::FloatOverflow,
                    Span::new(start, self.pos),
                ));
            }
            Ok(Token::new(
                TokenKind::Float(value),
                Span::new(start, self.pos),
            ))
        } else {
            // Pure decimal integer. The slice is all ASCII digits.
            let value = text.parse::<u128>().map_err(|_| {
                LexError::new(LexErrorKind::MalformedNumber, Span::new(start, self.pos))
            })?;
            Ok(Token::new(
                TokenKind::Integer(IntLiteral {
                    value,
                    base: IntBase::Decimal,
                }),
                Span::new(start, self.pos),
            ))
        }
    }

    /// Scans the body of a `0x` / `0o` prefixed integer. `start` is the `0`; `base` selects the
    /// digit class. The prefix (`0x` / `0o`) is consumed here.
    ///
    /// # Errors
    ///
    /// [`LexErrorKind::MalformedNumber`] if no valid digit follows the prefix (openCypher
    /// `HexInteger = '0x', {HexDigit}-` and `OctalInteger = '0o', {OctDigit}-` both require ≥1
    /// digit), spanning the prefix plus any stray following identifier-part char.
    fn scan_radix_int(&mut self, start: usize, base: IntBase) -> Result<Token, LexError> {
        self.pos += 2; // consume "0x" / "0o"
        let digits_start = self.pos;
        let radix = match base {
            IntBase::Hex => 16,
            IntBase::Octal => 8,
            IntBase::Decimal => unreachable!("scan_radix_int is only called for hex/octal"),
        };
        while let Some(b) = self.peek() {
            let is_digit = match base {
                IntBase::Hex => b.is_ascii_hexdigit(),
                IntBase::Octal => (b'0'..=b'7').contains(&b),
                IntBase::Decimal => false,
            };
            if is_digit {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == digits_start {
            // No digits after the prefix. Extend the error span over any trailing identifier-part
            // bytes so e.g. `0xZ` reports the whole bad token, not just `0x`.
            while matches!(self.peek(), Some(b) if is_ident_part(b)) {
                self.pos += 1;
            }
            return Err(LexError::new(
                LexErrorKind::MalformedNumber,
                Span::new(start, self.pos),
            ));
        }
        let digits = &self.src[digits_start..self.pos];
        let value = u128::from_str_radix(digits, radix).map_err(|_| {
            LexError::new(LexErrorKind::MalformedNumber, Span::new(start, self.pos))
        })?;
        Ok(Token::new(
            TokenKind::Integer(IntLiteral { value, base }),
            Span::new(start, self.pos),
        ))
    }

    /// Decodes the `char` at byte offset `at`.
    ///
    /// `at` must be a UTF-8 char boundary inside `src`; all callers index at boundaries (token
    /// starts, after fully-consumed chars). If `src[at..]` were empty this would have no char, but
    /// callers only invoke it when a byte is known present.
    fn char_at(&self, at: usize) -> char {
        // `chars().next()` on a valid char-boundary slice yields the char. The fallback char is
        // unreachable for in-bounds boundary offsets; it avoids any unwrap in non-test code.
        self.src[at..].chars().next().unwrap_or('\u{FFFD}')
    }
}

/// Identifier-start for an ASCII byte: a letter or underscore (openCypher `IdentifierStart`).
fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

/// Identifier-part for an ASCII byte: a letter, digit, or underscore.
fn is_ident_part(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Identifier-start for a full `char` (covers non-ASCII letters; openCypher permits Unicode
/// identifier characters via the Java-identifier rules its grammar references). We accept any
/// alphabetic Unicode char or `_`.
fn is_ident_start_char(c: char) -> bool {
    c == '_' || c.is_alphabetic()
}

/// Identifier-part for a full `char`: alphanumeric Unicode or `_`.
fn is_ident_part_char(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

/// Classifies a scanned word: an exact (ASCII-case-insensitive) reserved-word match becomes its
/// keyword [`TokenKind`]; `true`/`false`/`null` become their literal kinds; anything else is an
/// identifier.
///
/// openCypher keywords are **case-insensitive**, so we match on the lowercased ASCII form. Because
/// the keyword set is pure ASCII, lowercasing only ASCII letters is sufficient and avoids allocation
/// for the common (identifier) case by using `eq_ignore_ascii_case`.
///
/// The `LOAD CSV` clause words (`LOAD`, `CSV`, `FROM`, `HEADERS`, `FIELDTERMINATOR`) are deliberately
/// **not** in this table: they are *contextual* keywords recognised by spelling in the parser (see
/// `Parser::parse_load_csv`). Reserving them globally would break their long-standing use as ordinary
/// identifiers (e.g. `RETURN a AS from`), which the openCypher grammar permits — `FROM` et al. are
/// not reserved words. Recognising them only in the `LOAD CSV` position keeps that compatibility.
fn keyword_or_identifier(text: &str) -> TokenKind {
    // The reserved-word table (openCypher EBNF `ReservedWord`, plus the 2024.x line additions named
    // in the task: YIELD, CALL, INDEX, ASCENDING/DESCENDING, DISTINCT, …). Each entry pairs the
    // canonical spelling with its token kind. Matching is ASCII-case-insensitive.
    macro_rules! kw {
        ($($lit:literal => $kind:expr),+ $(,)?) => {
            $(if text.eq_ignore_ascii_case($lit) { return $kind; })+
        };
    }
    kw! {
        "match" => TokenKind::Match,
        "optional" => TokenKind::Optional,
        "where" => TokenKind::Where,
        "return" => TokenKind::Return,
        "with" => TokenKind::With,
        "create" => TokenKind::Create,
        "merge" => TokenKind::Merge,
        "set" => TokenKind::Set,
        "delete" => TokenKind::Delete,
        "detach" => TokenKind::Detach,
        "remove" => TokenKind::Remove,
        "unwind" => TokenKind::Unwind,
        "foreach" => TokenKind::Foreach,
        "call" => TokenKind::Call,
        "yield" => TokenKind::Yield,
        "order" => TokenKind::Order,
        "by" => TokenKind::By,
        "skip" => TokenKind::Skip,
        "limit" => TokenKind::Limit,
        "union" => TokenKind::Union,
        "all" => TokenKind::All,
        "distinct" => TokenKind::Distinct,
        "as" => TokenKind::As,
        "and" => TokenKind::And,
        "or" => TokenKind::Or,
        "xor" => TokenKind::Xor,
        "not" => TokenKind::Not,
        "in" => TokenKind::In,
        "is" => TokenKind::Is,
        "starts" => TokenKind::Starts,
        "ends" => TokenKind::Ends,
        "contains" => TokenKind::Contains,
        "case" => TokenKind::Case,
        "when" => TokenKind::When,
        "then" => TokenKind::Then,
        "else" => TokenKind::Else,
        "end" => TokenKind::End,
        "asc" => TokenKind::Asc,
        "ascending" => TokenKind::Ascending,
        "desc" => TokenKind::Desc,
        "descending" => TokenKind::Descending,
        "on" => TokenKind::On,
        "constraint" => TokenKind::Constraint,
        "index" => TokenKind::Index,
        "exists" => TokenKind::Exists,
        "unique" => TokenKind::Unique,
        "drop" => TokenKind::Drop,
        "true" => TokenKind::Boolean(true),
        "false" => TokenKind::Boolean(false),
        "null" => TokenKind::Null,
    }
    TokenKind::Identifier(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lexes `input`, asserting success, and returns the token kinds (dropping spans) for terse
    /// sequence assertions.
    fn kinds(input: &str) -> Vec<TokenKind> {
        tokenize(input)
            .expect("expected the input to lex without error")
            .into_iter()
            .map(|t| t.kind)
            .collect()
    }

    /// Lexes `input` expecting an error, returning it.
    fn lex_err(input: &str) -> LexError {
        tokenize(input).expect_err("expected the input to fail lexing")
    }

    fn int(value: u128, base: IntBase) -> TokenKind {
        TokenKind::Integer(IntLiteral { value, base })
    }

    fn ident(name: &str) -> TokenKind {
        TokenKind::Identifier(name.to_owned())
    }

    fn string(s: &str) -> TokenKind {
        TokenKind::String(s.to_owned())
    }

    fn param(s: &str) -> TokenKind {
        TokenKind::Parameter(s.to_owned())
    }

    // ----------------------------------------------------------------------------------------
    // Representative full queries
    // ----------------------------------------------------------------------------------------

    #[test]
    fn match_where_return_with_pattern_params_literals_operators() {
        let q =
            "MATCH (n:Person {age: 30}) WHERE n.name = $name AND n.age >= 18 RETURN n.name AS name";
        assert_eq!(
            kinds(q),
            vec![
                TokenKind::Match,
                TokenKind::LParen,
                ident("n"),
                TokenKind::Colon,
                ident("Person"),
                TokenKind::LBrace,
                ident("age"),
                TokenKind::Colon,
                int(30, IntBase::Decimal),
                TokenKind::RBrace,
                TokenKind::RParen,
                TokenKind::Where,
                ident("n"),
                TokenKind::Dot,
                ident("name"),
                TokenKind::Eq,
                param("name"),
                TokenKind::And,
                ident("n"),
                TokenKind::Dot,
                ident("age"),
                TokenKind::Gte,
                int(18, IntBase::Decimal),
                TokenKind::Return,
                ident("n"),
                TokenKind::Dot,
                ident("name"),
                TokenKind::As,
                ident("name"),
            ]
        );
    }

    #[test]
    fn relationship_pattern_arrows_and_dashes() {
        // Directed, undirected, and a typed variable-bound relationship.
        let q = "(a)-[r:KNOWS]->(b)<-(c)--(d)";
        assert_eq!(
            kinds(q),
            vec![
                TokenKind::LParen,
                ident("a"),
                TokenKind::RParen,
                TokenKind::Minus,
                TokenKind::LBracket,
                ident("r"),
                TokenKind::Colon,
                ident("KNOWS"),
                TokenKind::RBracket,
                TokenKind::ArrowRight,
                TokenKind::LParen,
                ident("b"),
                TokenKind::RParen,
                TokenKind::ArrowLeft,
                TokenKind::LParen,
                ident("c"),
                TokenKind::RParen,
                TokenKind::DashDash,
                TokenKind::LParen,
                ident("d"),
                TokenKind::RParen,
            ]
        );
    }

    #[test]
    fn create_merge_set_delete_clauses() {
        let q = "CREATE (n) MERGE (m) SET n += {x: 1} DETACH DELETE m";
        assert_eq!(
            kinds(q),
            vec![
                TokenKind::Create,
                TokenKind::LParen,
                ident("n"),
                TokenKind::RParen,
                TokenKind::Merge,
                TokenKind::LParen,
                ident("m"),
                TokenKind::RParen,
                TokenKind::Set,
                ident("n"),
                TokenKind::PlusEq,
                TokenKind::LBrace,
                ident("x"),
                TokenKind::Colon,
                int(1, IntBase::Decimal),
                TokenKind::RBrace,
                TokenKind::Detach,
                TokenKind::Delete,
                ident("m"),
            ]
        );
    }

    // ----------------------------------------------------------------------------------------
    // Integer literals: decimal / hex / octal
    // ----------------------------------------------------------------------------------------

    #[test]
    fn integer_literals_all_bases() {
        assert_eq!(kinds("0"), vec![int(0, IntBase::Decimal)]);
        assert_eq!(kinds("42"), vec![int(42, IntBase::Decimal)]);
        assert_eq!(
            kinds("1234567890"),
            vec![int(1_234_567_890, IntBase::Decimal)]
        );
        assert_eq!(kinds("0xFF"), vec![int(255, IntBase::Hex)]);
        assert_eq!(kinds("0Xff"), vec![int(255, IntBase::Hex)]);
        assert_eq!(kinds("0x0"), vec![int(0, IntBase::Hex)]);
        assert_eq!(kinds("0o17"), vec![int(15, IntBase::Octal)]);
        assert_eq!(kinds("0O7"), vec![int(7, IntBase::Octal)]);
    }

    #[test]
    fn negative_number_lexes_as_minus_then_integer() {
        // The sign is the unary-minus operator, resolved at parse time (documented).
        assert_eq!(
            kinds("-7"),
            vec![TokenKind::Minus, int(7, IntBase::Decimal)]
        );
        assert_eq!(
            kinds("a-1"),
            vec![ident("a"), TokenKind::Minus, int(1, IntBase::Decimal)]
        );
    }

    #[test]
    fn large_integer_is_lexed_not_rejected() {
        // Beyond i64; the lexer accepts the *shape*, the parser does range checking (04 §7.3).
        let beyond_i64 = "99999999999999999999"; // > i64::MAX
        assert_eq!(
            kinds(beyond_i64),
            vec![int(99_999_999_999_999_999_999_u128, IntBase::Decimal)]
        );
    }

    // ----------------------------------------------------------------------------------------
    // Float literals
    // ----------------------------------------------------------------------------------------

    #[test]
    fn float_literals_forms() {
        match &kinds("2.5")[0] {
            TokenKind::Float(f) => assert!((f - 2.5).abs() < 1e-12),
            other => panic!("expected float, got {other:?}"),
        }
        match &kinds(".5")[0] {
            TokenKind::Float(f) => assert!((f - 0.5).abs() < 1e-12),
            other => panic!("expected float, got {other:?}"),
        }
        match &kinds("1e10")[0] {
            TokenKind::Float(f) => assert!((f - 1e10).abs() < 1.0),
            other => panic!("expected float, got {other:?}"),
        }
        match &kinds("6.022e23")[0] {
            TokenKind::Float(f) => assert!((f - 6.022e23).abs() / 6.022e23 < 1e-12),
            other => panic!("expected float, got {other:?}"),
        }
        match &kinds("1.5E-3")[0] {
            TokenKind::Float(f) => assert!((f - 1.5e-3).abs() < 1e-12),
            other => panic!("expected float, got {other:?}"),
        }
        match &kinds("2e+8")[0] {
            TokenKind::Float(f) => assert!((f - 2e8).abs() < 1.0),
            other => panic!("expected float, got {other:?}"),
        }
    }

    #[test]
    fn dot_dot_range_is_not_eaten_by_float() {
        // `1..2` is integer, DotDot, integer — not `1.` `.2`.
        assert_eq!(
            kinds("1..2"),
            vec![
                int(1, IntBase::Decimal),
                TokenKind::DotDot,
                int(2, IntBase::Decimal)
            ]
        );
    }

    #[test]
    fn integer_dot_property_access_is_not_a_float() {
        // `n.prop` after an integer-looking thing: ensure `1.foo` does not eat the dot as a float.
        assert_eq!(kinds("x.y"), vec![ident("x"), TokenKind::Dot, ident("y")]);
    }

    #[test]
    fn exponent_without_digits_is_not_part_of_number() {
        // `1e` is integer `1` then identifier `e` (no exponent digits).
        assert_eq!(kinds("1e"), vec![int(1, IntBase::Decimal), ident("e")]);
    }

    // ----------------------------------------------------------------------------------------
    // String literals & escapes
    // ----------------------------------------------------------------------------------------

    #[test]
    fn strings_single_and_double_quoted() {
        assert_eq!(kinds("'hello'"), vec![string("hello")]);
        assert_eq!(kinds("\"hello\""), vec![string("hello")]);
        assert_eq!(kinds("''"), vec![string("")]); // empty string is valid
    }

    #[test]
    fn string_simple_escapes() {
        assert_eq!(kinds(r"'\\'"), vec![string("\\")]);
        assert_eq!(kinds(r"'\''"), vec![string("'")]);
        assert_eq!(kinds("\"\\\"\""), vec![string("\"")]);
        assert_eq!(kinds(r"'\n'"), vec![string("\n")]);
        assert_eq!(kinds(r"'\t'"), vec![string("\t")]);
        assert_eq!(kinds(r"'\r'"), vec![string("\r")]);
        assert_eq!(kinds(r"'\b'"), vec![string("\u{0008}")]);
        assert_eq!(kinds(r"'\f'"), vec![string("\u{000C}")]);
    }

    #[test]
    fn string_unicode_escapes_all_three_forms() {
        // We build the inputs at runtime so the source file never contains a literal
        // backslash-u-hex adjacency (which is brittle to tooling). `bs` is a single backslash.
        let bs = '\\';
        // 4-hex form `\uXXXX` (openCypher M-series primary): U+0041 = 'A'.
        let four_hex = format!("'{bs}u0041'");
        assert_eq!(kinds(&four_hex), vec![string("A")]);
        // 8-hex form `\uXXXXXXXX` (openCypher M-series): U+0001F600 = grinning face.
        let eight_hex = format!("'{bs}u0001F600'");
        assert_eq!(kinds(&eight_hex), vec![string("\u{1F600}")]);
        // brace form `\u{...}` (broader Cypher line, D-cypher-line).
        let brace = format!("'{bs}u{{1F600}}'");
        assert_eq!(kinds(&brace), vec![string("\u{1F600}")]);
        let brace_a = format!("'{bs}u{{41}}'");
        assert_eq!(kinds(&brace_a), vec![string("A")]);
        // A 4-hex escape immediately followed by more hex text must only consume 4 digits:
        // `A1` is U+0041 ('A') then the literal character '1'. (hex run = 5, not >= 8, so
        // take exactly 4.)
        let four_then_text = format!("'{bs}u00411'");
        assert_eq!(kinds(&four_then_text), vec![string("A1")]);
    }

    #[test]
    fn string_with_unicode_content_and_mixed_escapes() {
        assert_eq!(
            kinds(r"'café!'"),
            vec![string("café!")] // U+0021 = '!'
        );
        // A literal multi-byte char in the source keeps the value intact.
        assert_eq!(kinds("'naïve 日本語'"), vec![string("naïve 日本語")]);
    }

    // ----------------------------------------------------------------------------------------
    // Booleans, null
    // ----------------------------------------------------------------------------------------

    #[test]
    fn boolean_and_null_literals_case_insensitive() {
        assert_eq!(kinds("true"), vec![TokenKind::Boolean(true)]);
        assert_eq!(kinds("TRUE"), vec![TokenKind::Boolean(true)]);
        assert_eq!(kinds("False"), vec![TokenKind::Boolean(false)]);
        assert_eq!(kinds("null"), vec![TokenKind::Null]);
        assert_eq!(kinds("NULL"), vec![TokenKind::Null]);
        assert_eq!(kinds("Null"), vec![TokenKind::Null]);
    }

    // ----------------------------------------------------------------------------------------
    // Identifiers, including backtick-escaped
    // ----------------------------------------------------------------------------------------

    #[test]
    fn identifiers_unescaped() {
        assert_eq!(kinds("n"), vec![ident("n")]);
        assert_eq!(kinds("_private"), vec![ident("_private")]);
        assert_eq!(kinds("camelCase123"), vec![ident("camelCase123")]);
        assert_eq!(kinds("日本語"), vec![ident("日本語")]); // unicode identifier
    }

    #[test]
    fn keyword_lookalike_is_an_identifier() {
        // `matched` is NOT the keyword MATCH; `returns`, `wherever` likewise.
        assert_eq!(kinds("matched"), vec![ident("matched")]);
        assert_eq!(kinds("returns"), vec![ident("returns")]);
        assert_eq!(kinds("wherever"), vec![ident("wherever")]);
        // ...but the exact word (any case) is the keyword.
        assert_eq!(kinds("MaTcH"), vec![TokenKind::Match]);
    }

    #[test]
    fn foreach_is_a_reserved_keyword() {
        // `FOREACH` lexes as the reserved keyword (case-insensitive), and `|` as `Pipe`.
        assert_eq!(kinds("FOREACH"), vec![TokenKind::Foreach]);
        assert_eq!(kinds("foreach"), vec![TokenKind::Foreach]);
        assert_eq!(kinds("ForEach"), vec![TokenKind::Foreach]);
        // A lookalike is a plain identifier, not the keyword.
        assert_eq!(kinds("foreaches"), vec![ident("foreaches")]);
    }

    #[test]
    fn backtick_escaped_identifiers() {
        assert_eq!(kinds("`weird name`"), vec![ident("weird name")]);
        // Embedded escaped backtick: `` inside collapses to one `.
        assert_eq!(kinds("`a``b`"), vec![ident("a`b")]);
        // A backtick name may contain otherwise-illegal chars and keywords.
        assert_eq!(kinds("`MATCH`"), vec![ident("MATCH")]);
        assert_eq!(
            kinds("`with-dash.and space`"),
            vec![ident("with-dash.and space")]
        );
        // Unicode inside backticks.
        assert_eq!(kinds("`café`"), vec![ident("café")]);
    }

    // ----------------------------------------------------------------------------------------
    // Parameters
    // ----------------------------------------------------------------------------------------

    #[test]
    fn parameters_named_and_indexed() {
        assert_eq!(kinds("$name"), vec![param("name")]);
        assert_eq!(kinds("$_x1"), vec![param("_x1")]);
        assert_eq!(kinds("$0"), vec![param("0")]);
        assert_eq!(kinds("$42"), vec![param("42")]);
    }

    // ----------------------------------------------------------------------------------------
    // Operators & punctuation: longest-match coverage
    // ----------------------------------------------------------------------------------------

    #[test]
    fn operators_longest_match() {
        assert_eq!(
            kinds("= <> < > <= >= =~ + - * / % ^ += : :: . .. , ; | -> <- --"),
            vec![
                TokenKind::Eq,
                TokenKind::Neq,
                TokenKind::Lt,
                TokenKind::Gt,
                TokenKind::Lte,
                TokenKind::Gte,
                TokenKind::RegexMatch,
                TokenKind::Plus,
                TokenKind::Minus,
                TokenKind::Star,
                TokenKind::Slash,
                TokenKind::Percent,
                TokenKind::Caret,
                TokenKind::PlusEq,
                TokenKind::Colon,
                TokenKind::DoubleColon,
                TokenKind::Dot,
                TokenKind::DotDot,
                TokenKind::Comma,
                TokenKind::Semicolon,
                TokenKind::Pipe,
                TokenKind::ArrowRight,
                TokenKind::ArrowLeft,
                TokenKind::DashDash,
            ]
        );
    }

    #[test]
    fn brackets_and_braces() {
        assert_eq!(
            kinds("()[]{}"),
            vec![
                TokenKind::LParen,
                TokenKind::RParen,
                TokenKind::LBracket,
                TokenKind::RBracket,
                TokenKind::LBrace,
                TokenKind::RBrace,
            ]
        );
    }

    // ----------------------------------------------------------------------------------------
    // Comments & whitespace skipped; surrounding spans accurate
    // ----------------------------------------------------------------------------------------

    #[test]
    fn line_comment_skipped() {
        let toks = tokenize("RETURN // trailing\n1").expect("valid");
        assert_eq!(toks[0].kind, TokenKind::Return);
        assert_eq!(toks[1].kind, int(1, IntBase::Decimal));
        // `1` sits after "RETURN // trailing\n" = 19 bytes.
        assert_eq!(toks[1].span, Span::new(19, 20));
    }

    #[test]
    fn block_comment_skipped() {
        let toks = tokenize("RETURN /* a\nb */ 1").expect("valid");
        assert_eq!(toks[0].kind, TokenKind::Return);
        assert_eq!(toks[1].kind, int(1, IntBase::Decimal));
        // "RETURN /* a\nb */ " = 17 bytes, so `1` is at [17,18).
        assert_eq!(toks[1].span, Span::new(17, 18));
    }

    #[test]
    fn whitespace_does_not_perturb_spans() {
        let toks = tokenize("   MATCH    n   ").expect("valid");
        assert_eq!(toks[0].span, Span::new(3, 8)); // MATCH
        assert_eq!(toks[1].span, Span::new(12, 13)); // n
    }

    #[test]
    fn spans_are_byte_accurate_with_multibyte_prefix() {
        // A multi-byte char before a token must shift its byte offset correctly.
        let input = "café x"; // 'é' is 2 bytes (U+00E9): café = 5 bytes, space at 5, x at 6.
        let toks = tokenize(input).expect("valid");
        assert_eq!(toks[0].kind, ident("café"));
        assert_eq!(toks[0].span, Span::new(0, 5));
        assert_eq!(toks[1].kind, ident("x"));
        assert_eq!(toks[1].span, Span::new(6, 7));
    }

    // ----------------------------------------------------------------------------------------
    // Error cases: exact byte spans asserted
    // ----------------------------------------------------------------------------------------

    #[test]
    fn unterminated_string_double() {
        let e = lex_err("\"abc");
        assert_eq!(e.kind, LexErrorKind::UnterminatedString);
        assert_eq!(e.span, Span::new(0, 4)); // opening quote .. EOF
    }

    #[test]
    fn unterminated_string_after_tokens() {
        let e = lex_err("RETURN 'oops");
        assert_eq!(e.kind, LexErrorKind::UnterminatedString);
        assert_eq!(e.span, Span::new(7, 12)); // the "'oops" region
    }

    #[test]
    fn invalid_string_escape() {
        let e = lex_err(r"'\q'");
        assert_eq!(e.kind, LexErrorKind::InvalidEscape);
        // `\q` occupies bytes [1,3): backslash at 1, 'q' at 2.
        assert_eq!(e.span, Span::new(1, 3));
    }

    #[test]
    fn invalid_unicode_escape_too_few_digits() {
        let e = lex_err(r"'\u12'");
        assert_eq!(e.kind, LexErrorKind::InvalidUnicodeEscape);
        // `\u12` then closing quote stops the hex run at 2 digits: span [1,5) = `\u12`.
        assert_eq!(e.span, Span::new(1, 5));
    }

    #[test]
    fn invalid_unicode_escape_surrogate() {
        // U+D800 is a lone surrogate — not a Unicode scalar value.
        let e = lex_err(r"'\uD800'");
        assert_eq!(e.kind, LexErrorKind::InvalidUnicodeEscape);
        assert_eq!(e.span, Span::new(1, 7)); // `\uD800`
    }

    #[test]
    fn invalid_unicode_escape_brace_unterminated() {
        let e = lex_err(r"'\u{41'");
        assert_eq!(e.kind, LexErrorKind::InvalidUnicodeEscape);
        // `\u{41` with no closing brace: span [1,6) (backslash .. last hex digit before the quote).
        assert_eq!(e.span, Span::new(1, 6));
    }

    #[test]
    fn invalid_unicode_escape_brace_too_long() {
        let e = lex_err(r"'\u{1234567}'");
        assert_eq!(e.kind, LexErrorKind::InvalidUnicodeEscape);
        // 7 hex digits > 6 cap; span covers `\u{1234567}` = [1,12).
        assert_eq!(e.span, Span::new(1, 12));
    }

    #[test]
    fn unterminated_block_comment() {
        let e = lex_err("RETURN /* never closes");
        assert_eq!(e.kind, LexErrorKind::UnterminatedBlockComment);
        assert_eq!(e.span, Span::new(7, 22)); // `/*` .. EOF
    }

    #[test]
    fn unterminated_escaped_name() {
        let e = lex_err("`open");
        assert_eq!(e.kind, LexErrorKind::UnterminatedEscapedName);
        assert_eq!(e.span, Span::new(0, 5)); // backtick .. EOF
    }

    #[test]
    fn empty_escaped_name() {
        let e = lex_err("``");
        assert_eq!(e.kind, LexErrorKind::EmptyEscapedName);
        assert_eq!(e.span, Span::new(0, 2));
    }

    #[test]
    fn stray_character() {
        let e = lex_err("RETURN @");
        assert_eq!(e.kind, LexErrorKind::UnexpectedChar('@'));
        assert_eq!(e.span, Span::new(7, 8));
    }

    #[test]
    fn stray_multibyte_character_full_span() {
        // A non-ident, non-whitespace multi-byte char (e.g. U+00A1 '¡', 2 bytes) gets its full span.
        let e = lex_err("¡");
        assert_eq!(e.kind, LexErrorKind::UnexpectedChar('\u{A1}'));
        assert_eq!(e.span, Span::new(0, 2));
    }

    #[test]
    fn malformed_hex_no_digits() {
        let e = lex_err("0xZ");
        assert_eq!(e.kind, LexErrorKind::MalformedNumber);
        // Error span extends over the trailing ident-part char: `0xZ` = [0,3).
        assert_eq!(e.span, Span::new(0, 3));
    }

    #[test]
    fn malformed_octal_no_digits() {
        let e = lex_err("0o");
        assert_eq!(e.kind, LexErrorKind::MalformedNumber);
        assert_eq!(e.span, Span::new(0, 2));
    }

    #[test]
    fn malformed_parameter_no_name() {
        let e = lex_err("$ ");
        assert_eq!(e.kind, LexErrorKind::MalformedParameter);
        assert_eq!(e.span, Span::new(0, 1)); // just `$` (next is space)
    }

    #[test]
    fn malformed_parameter_bad_char() {
        let e = lex_err("$-");
        assert_eq!(e.kind, LexErrorKind::MalformedParameter);
        assert_eq!(e.span, Span::new(0, 2)); // `$` + the bad `-`
    }

    // ----------------------------------------------------------------------------------------
    // Error conversion to the crate-wide GraphusError::Compile (compile-time SyntaxError, 04 §7.3)
    // ----------------------------------------------------------------------------------------

    #[test]
    fn lex_error_converts_to_compile_error() {
        let e = lex_err("\"abc");
        let g: GraphusError = e.into();
        match g {
            GraphusError::Compile(msg) => {
                assert!(msg.contains("syntax error"), "message was: {msg}");
                assert!(msg.contains("0..4"), "span missing from message: {msg}");
            }
            other => panic!("expected Compile, got {other:?}"),
        }
    }

    // ----------------------------------------------------------------------------------------
    // Span invariants: non-overlapping, in-order, within bounds
    // ----------------------------------------------------------------------------------------

    #[test]
    fn spans_are_ordered_non_overlapping_and_in_bounds() {
        let q = "MATCH (n:L {k:1.5})-[r]->(m) WHERE n.x =~ 'a.*' RETURN $p, [1,2,3]";
        let toks = tokenize(q).expect("valid");
        let mut prev_end = 0usize;
        for t in &toks {
            assert!(t.span.start >= prev_end, "overlap/disorder at {:?}", t);
            assert!(t.span.end <= q.len(), "span past EOF at {:?}", t);
            assert!(t.span.start < t.span.end, "empty/inverted span at {:?}", t);
            // The span must slice a valid sub-str (char boundary correctness).
            let _ = &q[t.span.start..t.span.end];
            prev_end = t.span.end;
        }
    }

    #[test]
    fn empty_and_whitespace_only_inputs_yield_no_tokens() {
        assert!(tokenize("").expect("ok").is_empty());
        assert!(tokenize("   \t\n  ").expect("ok").is_empty());
        assert!(tokenize("// just a comment").expect("ok").is_empty());
        assert!(
            tokenize("/* just a block comment */")
                .expect("ok")
                .is_empty()
        );
    }
}
