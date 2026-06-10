//! The TCK **expected-result value mini-language** (`tck/README.adoc` §"Format of the expected
//! results").
//!
//! Every cell in a `Then the result should be …` / `And parameters are:` table is written in a
//! small, well-defined surface syntax that mirrors Cypher literals but is **not** Cypher: it adds
//! graph-element literals (`(:L {…})`, `[:T {…}]`, `<(n)-[r]->(m)>`) that have no Cypher literal
//! form, and it pins floats/strings/nulls to exact textual conventions. This module parses that
//! surface into an [`ExpectedValue`] tree; [`crate::compare`] then matches an [`ExpectedValue`]
//! against a value the engine actually produced, using the openCypher equivalence semantics the
//! engine already implements.
//!
//! # The grammar (from the README, verbatim semantics)
//!
//! ```text
//! value      := integer | float | string | bool | null | list | map | node | rel | path
//! integer    := '-'? DIGIT+
//! float      := decimal | scientific | 'NaN' | 'Inf' | '-Inf'
//! string     := "'" ( escape | <any char except '> )* "'"          (single-quoted)
//! bool       := 'true' | 'false'
//! null       := 'null'
//! list       := '[' (value (',' value)*)? ']'
//! map        := '{' (key ':' value (',' key ':' value)*)? '}'      (key bare or `backtick`-quoted)
//! node       := '(' (':' Label)* (map)? ')'
//! rel        := '[' ':' Type (map)? ']'
//! path       := '<' node ( ('-' rel '->' | '<-' rel '-') node )* '>'
//! ```
//!
//! The grammar is parsed by a small hand-rolled recursive-descent parser (the corpus nests maps
//! dozens of levels deep — `tck/features/expressions/…` has a 39-level-deep map literal — so a
//! regex is out of the question, and the parser must be genuinely recursive). Whitespace between
//! tokens is insignificant.

use std::fmt;

/// A parsed expected value from a TCK result/parameter table cell (`tck/README.adoc`).
///
/// This is the *target* of a comparison: [`crate::compare`] checks a value the engine produced
/// against an `ExpectedValue` using openCypher equivalence. Graph-element variants
/// ([`Self::Node`]/[`Self::Relationship`]/[`Self::Path`]) carry **no identity** — the TCK never
/// writes entity ids — so they are matched structurally (labels/type + properties + path shape),
/// never by id.
#[derive(Debug, Clone, PartialEq)]
pub enum ExpectedValue {
    /// `null`.
    Null,
    /// A boolean (`true` / `false`).
    Boolean(bool),
    /// A 64-bit signed integer.
    Integer(i64),
    /// An IEEE-754 double, including the special values `NaN`, `Inf`, `-Inf`.
    Float(f64),
    /// A single-quoted string (escapes already decoded).
    String(String),
    /// An ordered list `[v0, v1, …]`.
    List(Vec<ExpectedValue>),
    /// A map `{k0: v0, …}` (keys in written order).
    Map(Vec<(String, ExpectedValue)>),
    /// A node literal `(:L1:L2 {k: v, …})` — labels (possibly none) and properties (possibly none).
    Node(ExpectedNode),
    /// A relationship literal `[:T {k: v, …}]` — exactly one type and properties (possibly none).
    Relationship(ExpectedRel),
    /// A path literal `<(n0)-[r1]->(n1)…>` — an alternating node/relationship sequence with the
    /// per-step traversal direction.
    Path(ExpectedPath),
}

/// A node literal `(:L1:L2 {…})` with no identity (`tck/README.adoc` graph elements).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ExpectedNode {
    /// The node's labels, in written order. The comparison treats them as a set.
    pub labels: Vec<String>,
    /// The node's properties, in written order. The comparison treats them as a map.
    pub properties: Vec<(String, ExpectedValue)>,
}

/// A relationship literal `[:T {…}]` with no identity (`tck/README.adoc` graph elements).
#[derive(Debug, Clone, PartialEq)]
pub struct ExpectedRel {
    /// The relationship's single type.
    pub rel_type: String,
    /// The relationship's properties, in written order. The comparison treats them as a map.
    pub properties: Vec<(String, ExpectedValue)>,
}

/// One hop of a path literal: a relationship plus the node it leads to, and the traversal direction.
#[derive(Debug, Clone, PartialEq)]
pub struct ExpectedPathStep {
    /// `true` if the step is written left-to-right (`-[r]->`), `false` if right-to-left (`<-[r]-`).
    pub forward: bool,
    /// The relationship traversed in this step.
    pub rel: ExpectedRel,
    /// The node reached by this step.
    pub node: ExpectedNode,
}

/// A path literal `<(n0) step1 step2 …>` (`tck/README.adoc` graph elements).
///
/// A zero-length path is just `<(n0)>` (one node, no steps).
#[derive(Debug, Clone, PartialEq)]
pub struct ExpectedPath {
    /// The path's first node.
    pub start: ExpectedNode,
    /// The subsequent hops, each a `(direction, relationship, node)` triple.
    pub steps: Vec<ExpectedPathStep>,
}

// `ExpectedValue` contains `f64`, so it cannot derive `Eq`. The sub-structs transitively hold
// `ExpectedValue` in their property lists, so they likewise derive only `PartialEq` (a `Vec<(String,
// ExpectedValue)>` is not `Eq` because `ExpectedValue` is not). `Default` is only on `ExpectedNode`
// for ergonomic construction. We keep `Eq` off all value-bearing types deliberately — `f64::NaN`
// has no reflexive equality, which is exactly why the *equivalence* relation (not `Eq`) is the right
// comparison for these (see `crate::compare`).

/// An error parsing a TCK expected-value cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseValueError {
    /// A human description of what went wrong and where (byte offset into the cell).
    pub message: String,
    /// The byte offset into the cell text where the error was detected.
    pub at: usize,
}

impl fmt::Display for ParseValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid expected value at byte {}: {}",
            self.at, self.message
        )
    }
}

impl std::error::Error for ParseValueError {}

/// Parses a complete TCK expected-value cell into an [`ExpectedValue`].
///
/// # Errors
///
/// Returns [`ParseValueError`] if the cell is not a single well-formed value in the TCK mini-language
/// (`tck/README.adoc`), including trailing junk after an otherwise-valid value.
pub fn parse_expected(input: &str) -> Result<ExpectedValue, ParseValueError> {
    let mut p = ValueParser::new(input);
    p.skip_ws();
    let v = p.parse_value()?;
    p.skip_ws();
    if p.pos < p.bytes.len() {
        return Err(p.err("unexpected trailing input after value"));
    }
    Ok(v)
}

/// A recursive-descent parser over a single expected-value cell.
struct ValueParser<'a> {
    bytes: &'a [u8],
    src: &'a str,
    pos: usize,
}

impl<'a> ValueParser<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            bytes: src.as_bytes(),
            src,
            pos: 0,
        }
    }

    fn err(&self, message: &str) -> ParseValueError {
        ParseValueError {
            message: message.to_owned(),
            at: self.pos,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    /// Consumes `lit` if it appears next (case-sensitive), returning whether it matched.
    fn eat(&mut self, lit: &str) -> bool {
        if self.src[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            true
        } else {
            false
        }
    }

    /// Parses any value at the current position.
    fn parse_value(&mut self) -> Result<ExpectedValue, ParseValueError> {
        self.skip_ws();
        match self.peek() {
            None => Err(self.err("expected a value, found end of input")),
            Some(b'\'') => self.parse_string().map(ExpectedValue::String),
            Some(b'[') => self.parse_list_or_rel(),
            Some(b'{') => self.parse_map().map(ExpectedValue::Map),
            Some(b'(') => self.parse_node().map(ExpectedValue::Node),
            Some(b'<') => self.parse_path().map(ExpectedValue::Path),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.parse_number(),
            Some(_) => self.parse_keyword_value(),
        }
    }

    /// Parses `null`, `true`, `false`, or the float keywords `NaN`/`Inf` that begin with a letter.
    fn parse_keyword_value(&mut self) -> Result<ExpectedValue, ParseValueError> {
        if self.eat("null") {
            Ok(ExpectedValue::Null)
        } else if self.eat("true") {
            Ok(ExpectedValue::Boolean(true))
        } else if self.eat("false") {
            Ok(ExpectedValue::Boolean(false))
        } else if self.eat("NaN") {
            Ok(ExpectedValue::Float(f64::NAN))
        } else if self.eat("Inf") || self.eat("Infinity") {
            Ok(ExpectedValue::Float(f64::INFINITY))
        } else {
            Err(self.err("expected a value (null/true/false/NaN/Inf or a literal)"))
        }
    }

    /// Parses an integer or float, including `-Inf` and scientific notation.
    fn parse_number(&mut self) -> Result<ExpectedValue, ParseValueError> {
        let start = self.pos;
        // Leading sign.
        let negative = self.peek() == Some(b'-');
        if negative {
            self.pos += 1;
            // `-Inf` / `-Infinity`.
            if self.eat("Inf") || self.eat("Infinity") {
                return Ok(ExpectedValue::Float(f64::NEG_INFINITY));
            }
        }
        let mut is_float = false;
        while let Some(c) = self.peek() {
            match c {
                b'0'..=b'9' => self.pos += 1,
                b'.' => {
                    is_float = true;
                    self.pos += 1;
                }
                b'e' | b'E' => {
                    is_float = true;
                    self.pos += 1;
                    if matches!(self.peek(), Some(b'+' | b'-')) {
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
        let text = &self.src[start..self.pos];
        if text.is_empty() || text == "-" {
            return Err(self.err("malformed number"));
        }
        if is_float {
            text.parse::<f64>()
                .map(ExpectedValue::Float)
                .map_err(|_| self.err("malformed float literal"))
        } else {
            match text.parse::<i64>() {
                Ok(n) => Ok(ExpectedValue::Integer(n)),
                // An integer literal that overflows i64 is still a valid *expected* number; keep it
                // as a float so the comparison can at least attempt a numeric match (the engine would
                // have rejected it at compile time, so such cells only appear in error scenarios).
                Err(_) => text
                    .parse::<f64>()
                    .map(ExpectedValue::Float)
                    .map_err(|_| self.err("integer literal out of range")),
            }
        }
    }

    /// Parses a single-quoted string, decoding the escape sequences the TCK uses.
    fn parse_string(&mut self) -> Result<String, ParseValueError> {
        debug_assert_eq!(self.peek(), Some(b'\''));
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(self.err("unterminated string literal")),
                Some(b'\'') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(b'\'') => {
                            out.push('\'');
                            self.pos += 1;
                        }
                        Some(b'"') => {
                            out.push('"');
                            self.pos += 1;
                        }
                        Some(b'\\') => {
                            out.push('\\');
                            self.pos += 1;
                        }
                        Some(b'/') => {
                            out.push('/');
                            self.pos += 1;
                        }
                        Some(b'b') => {
                            out.push('\u{0008}');
                            self.pos += 1;
                        }
                        Some(b'f') => {
                            out.push('\u{000C}');
                            self.pos += 1;
                        }
                        Some(b'n') => {
                            out.push('\n');
                            self.pos += 1;
                        }
                        Some(b'r') => {
                            out.push('\r');
                            self.pos += 1;
                        }
                        Some(b't') => {
                            out.push('\t');
                            self.pos += 1;
                        }
                        Some(b'u') => {
                            self.pos += 1;
                            out.push(self.parse_unicode_escape()?);
                        }
                        // Unknown escape: keep the character literally (lenient — the TCK only uses
                        // the escapes above, so this is a safety net, not a path the corpus hits).
                        Some(_) => {
                            let ch = self.current_char();
                            out.push(ch);
                            self.pos += ch.len_utf8();
                        }
                        None => return Err(self.err("dangling escape at end of string")),
                    }
                }
                Some(_) => {
                    let ch = self.current_char();
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    /// Decodes a `\uXXXX` escape (already past the `u`).
    fn parse_unicode_escape(&mut self) -> Result<char, ParseValueError> {
        let start = self.pos;
        for _ in 0..4 {
            match self.peek() {
                Some(c) if c.is_ascii_hexdigit() => self.pos += 1,
                _ => return Err(self.err("malformed \\u escape (expected four hex digits)")),
            }
        }
        let code = u32::from_str_radix(&self.src[start..self.pos], 16)
            .map_err(|_| self.err("invalid hex in \\u escape"))?;
        char::from_u32(code).ok_or_else(|| self.err("\\u escape is not a valid code point"))
    }

    /// Returns the full UTF-8 char at the cursor (the cursor may be mid-multibyte after ASCII work,
    /// but we only call this when positioned at a char boundary).
    fn current_char(&self) -> char {
        self.src[self.pos..].chars().next().unwrap_or('\u{FFFD}')
    }

    /// Parses either a list `[…]` or a relationship literal `[:T {…}]`. A `[` followed (after
    /// optional whitespace) by `:` is a relationship; otherwise it is a list.
    fn parse_list_or_rel(&mut self) -> Result<ExpectedValue, ParseValueError> {
        debug_assert_eq!(self.peek(), Some(b'['));
        // Look past the `[` and whitespace for a `:`.
        let save = self.pos;
        self.pos += 1;
        self.skip_ws();
        if self.peek() == Some(b':') {
            self.pos = save;
            return self.parse_rel().map(ExpectedValue::Relationship);
        }
        // It is a list. (We already consumed `[` and the leading whitespace.)
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(ExpectedValue::List(items));
        }
        loop {
            let v = self.parse_value()?;
            items.push(v);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(ExpectedValue::List(items));
                }
                _ => return Err(self.err("expected ',' or ']' in list")),
            }
        }
    }

    /// Parses a map `{k: v, …}` (keys bare or backtick-quoted).
    fn parse_map(&mut self) -> Result<Vec<(String, ExpectedValue)>, ParseValueError> {
        debug_assert_eq!(self.peek(), Some(b'{'));
        self.pos += 1;
        let mut entries = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(entries);
        }
        loop {
            self.skip_ws();
            let key = self.parse_map_key()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(self.err("expected ':' after map key"));
            }
            self.pos += 1;
            let value = self.parse_value()?;
            entries.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(entries);
                }
                _ => return Err(self.err("expected ',' or '}' in map")),
            }
        }
    }

    /// Parses a map key: a backtick-quoted key `` `…` `` or a bare identifier.
    fn parse_map_key(&mut self) -> Result<String, ParseValueError> {
        if self.peek() == Some(b'`') {
            self.pos += 1;
            let start = self.pos;
            while let Some(c) = self.peek() {
                if c == b'`' {
                    break;
                }
                let ch = self.current_char();
                self.pos += ch.len_utf8();
            }
            if self.peek() != Some(b'`') {
                return Err(self.err("unterminated backtick-quoted map key"));
            }
            let key = self.src[start..self.pos].to_owned();
            self.pos += 1; // closing backtick
            Ok(key)
        } else {
            let start = self.pos;
            while let Some(c) = self.peek() {
                if c.is_ascii_alphanumeric() || c == b'_' {
                    self.pos += 1;
                } else if c >= 0x80 {
                    let ch = self.current_char();
                    self.pos += ch.len_utf8();
                } else {
                    break;
                }
            }
            if self.pos == start {
                return Err(self.err("expected a map key"));
            }
            Ok(self.src[start..self.pos].to_owned())
        }
    }

    /// Parses a node literal `(:L1:L2 {…})`.
    fn parse_node(&mut self) -> Result<ExpectedNode, ParseValueError> {
        debug_assert_eq!(self.peek(), Some(b'('));
        self.pos += 1;
        let mut node = ExpectedNode::default();
        // Labels: zero or more `:Label`.
        loop {
            self.skip_ws();
            if self.peek() == Some(b':') {
                self.pos += 1;
                node.labels.push(self.parse_symbol()?);
            } else {
                break;
            }
        }
        self.skip_ws();
        if self.peek() == Some(b'{') {
            node.properties = self.parse_map()?;
            self.skip_ws();
        }
        if self.peek() != Some(b')') {
            return Err(self.err("expected ')' to close node literal"));
        }
        self.pos += 1;
        Ok(node)
    }

    /// Parses a relationship literal `[:T {…}]`.
    fn parse_rel(&mut self) -> Result<ExpectedRel, ParseValueError> {
        debug_assert_eq!(self.peek(), Some(b'['));
        self.pos += 1;
        self.skip_ws();
        if self.peek() != Some(b':') {
            return Err(self.err("relationship literal must start with ':Type'"));
        }
        self.pos += 1;
        let rel_type = self.parse_symbol()?;
        self.skip_ws();
        let mut properties = Vec::new();
        if self.peek() == Some(b'{') {
            properties = self.parse_map()?;
            self.skip_ws();
        }
        if self.peek() != Some(b']') {
            return Err(self.err("expected ']' to close relationship literal"));
        }
        self.pos += 1;
        Ok(ExpectedRel {
            rel_type,
            properties,
        })
    }

    /// Parses a path literal `<(n0) (-[r]->(n) | <-[r]-(n))* >`.
    fn parse_path(&mut self) -> Result<ExpectedPath, ParseValueError> {
        debug_assert_eq!(self.peek(), Some(b'<'));
        self.pos += 1;
        self.skip_ws();
        let start = self.parse_node()?;
        let mut steps = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                Some(b'>') => {
                    self.pos += 1;
                    return Ok(ExpectedPath { start, steps });
                }
                Some(b'-') => {
                    // `-[:T]->(n)` : forward.
                    self.pos += 1; // '-'
                    self.skip_ws();
                    let rel = self.parse_rel()?;
                    self.skip_ws();
                    if !self.eat("->") {
                        return Err(self.err("expected '->' after forward relationship in path"));
                    }
                    self.skip_ws();
                    let node = self.parse_node()?;
                    steps.push(ExpectedPathStep {
                        forward: true,
                        rel,
                        node,
                    });
                }
                Some(b'<') => {
                    // `<-[:T]-(n)` : backward.
                    self.pos += 1; // '<'
                    if !self.eat("-") {
                        return Err(self.err("expected '<-' before backward relationship in path"));
                    }
                    self.skip_ws();
                    let rel = self.parse_rel()?;
                    self.skip_ws();
                    if !self.eat("-") {
                        return Err(self.err("expected '-' after backward relationship in path"));
                    }
                    self.skip_ws();
                    let node = self.parse_node()?;
                    steps.push(ExpectedPathStep {
                        forward: false,
                        rel,
                        node,
                    });
                }
                _ => return Err(self.err("expected '>', '-' or '<' in path literal")),
            }
        }
    }

    /// Parses a label / relationship-type symbol: a backtick-quoted name or a bare identifier.
    fn parse_symbol(&mut self) -> Result<String, ParseValueError> {
        self.skip_ws();
        if self.peek() == Some(b'`') {
            return self.parse_map_key(); // identical lexical rule
        }
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == b'_' {
                self.pos += 1;
            } else if c >= 0x80 {
                let ch = self.current_char();
                self.pos += ch.len_utf8();
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(self.err("expected a label or relationship-type name"));
        }
        Ok(self.src[start..self.pos].to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> ExpectedValue {
        parse_expected(s).unwrap_or_else(|e| panic!("parse {s:?}: {e}"))
    }

    #[test]
    fn primitives() {
        assert_eq!(p("0"), ExpectedValue::Integer(0));
        assert_eq!(p("-42"), ExpectedValue::Integer(-42));
        assert_eq!(p("1.5"), ExpectedValue::Float(1.5));
        assert_eq!(p("1.0e10"), ExpectedValue::Float(1.0e10));
        assert_eq!(p("-2.5E-3"), ExpectedValue::Float(-2.5e-3));
        assert_eq!(p("true"), ExpectedValue::Boolean(true));
        assert_eq!(p("false"), ExpectedValue::Boolean(false));
        assert_eq!(p("null"), ExpectedValue::Null);
    }

    #[test]
    fn special_floats() {
        assert!(matches!(p("NaN"), ExpectedValue::Float(f) if f.is_nan()));
        assert_eq!(p("Inf"), ExpectedValue::Float(f64::INFINITY));
        assert_eq!(p("-Inf"), ExpectedValue::Float(f64::NEG_INFINITY));
    }

    #[test]
    fn strings_with_escapes() {
        assert_eq!(p("''"), ExpectedValue::String(String::new()));
        assert_eq!(p("'abc'"), ExpectedValue::String("abc".to_owned()));
        // The corpus's `'\''` cell: an escaped single quote inside a string.
        assert_eq!(p("'\\''"), ExpectedValue::String("'".to_owned()));
        assert_eq!(p("'a\\nb'"), ExpectedValue::String("a\nb".to_owned()));
        assert_eq!(p("'\\u0041'"), ExpectedValue::String("A".to_owned()));
        assert_eq!(
            p("'héllo 世界 🌍'"),
            ExpectedValue::String("héllo 世界 🌍".to_owned())
        );
    }

    #[test]
    fn lists_including_empty_and_nested() {
        assert_eq!(p("[]"), ExpectedValue::List(vec![]));
        assert_eq!(
            p("[1, 2, 3]"),
            ExpectedValue::List(vec![
                ExpectedValue::Integer(1),
                ExpectedValue::Integer(2),
                ExpectedValue::Integer(3),
            ])
        );
        assert_eq!(
            p("[[1], []]"),
            ExpectedValue::List(vec![
                ExpectedValue::List(vec![ExpectedValue::Integer(1)]),
                ExpectedValue::List(vec![]),
            ])
        );
    }

    #[test]
    fn maps_bare_and_backtick_keys() {
        assert_eq!(p("{}"), ExpectedValue::Map(vec![]));
        assert_eq!(
            p("{a: 1, b: true}"),
            ExpectedValue::Map(vec![
                ("a".to_owned(), ExpectedValue::Integer(1)),
                ("b".to_owned(), ExpectedValue::Boolean(true)),
            ])
        );
        // A backtick-quoted empty key with an empty-string value: `{``: ''}`.
        assert_eq!(
            p("{``: ''}"),
            ExpectedValue::Map(vec![(String::new(), ExpectedValue::String(String::new()))])
        );
    }

    #[test]
    fn deeply_nested_map_does_not_overflow_a_reasonable_stack() {
        // The corpus has a 39-deep nested map; build one and confirm it round-trips.
        let mut s = String::new();
        let depth = 39;
        for i in 0..depth {
            s.push_str(&format!("{{a{i}: "));
        }
        s.push_str("{}");
        for _ in 0..depth {
            s.push('}');
        }
        let v = p(&s);
        // Walk down `depth` maps to the empty terminal.
        let mut cur = &v;
        for _ in 0..depth {
            match cur {
                ExpectedValue::Map(entries) => {
                    assert_eq!(entries.len(), 1);
                    cur = &entries[0].1;
                }
                other => panic!("expected nested map, got {other:?}"),
            }
        }
        assert_eq!(*cur, ExpectedValue::Map(vec![]));
    }

    #[test]
    fn node_literals() {
        assert_eq!(p("()"), ExpectedValue::Node(ExpectedNode::default()));
        assert_eq!(
            p("(:A)"),
            ExpectedValue::Node(ExpectedNode {
                labels: vec!["A".to_owned()],
                properties: vec![],
            })
        );
        assert_eq!(
            p("(:A:B {p: 0, q: 'string'})"),
            ExpectedValue::Node(ExpectedNode {
                labels: vec!["A".to_owned(), "B".to_owned()],
                properties: vec![
                    ("p".to_owned(), ExpectedValue::Integer(0)),
                    ("q".to_owned(), ExpectedValue::String("string".to_owned())),
                ],
            })
        );
        assert_eq!(
            p("({numbers: [1, 2, 3]})"),
            ExpectedValue::Node(ExpectedNode {
                labels: vec![],
                properties: vec![(
                    "numbers".to_owned(),
                    ExpectedValue::List(vec![
                        ExpectedValue::Integer(1),
                        ExpectedValue::Integer(2),
                        ExpectedValue::Integer(3),
                    ])
                )],
            })
        );
    }

    #[test]
    fn relationship_literals() {
        assert_eq!(
            p("[:T]"),
            ExpectedValue::Relationship(ExpectedRel {
                rel_type: "T".to_owned(),
                properties: vec![],
            })
        );
        assert_eq!(
            p("[:KNOWS {since: 1999}]"),
            ExpectedValue::Relationship(ExpectedRel {
                rel_type: "KNOWS".to_owned(),
                properties: vec![("since".to_owned(), ExpectedValue::Integer(1999))],
            })
        );
        // A list of relationship literals (e.g. `relationships(p)` result).
        assert_eq!(
            p("[[:T], [:T]]"),
            ExpectedValue::List(vec![
                ExpectedValue::Relationship(ExpectedRel {
                    rel_type: "T".to_owned(),
                    properties: vec![],
                }),
                ExpectedValue::Relationship(ExpectedRel {
                    rel_type: "T".to_owned(),
                    properties: vec![],
                }),
            ])
        );
    }

    #[test]
    fn paths_forward_backward_and_zero_length() {
        // Zero-length path: a single node.
        assert_eq!(
            p("<(:A)>"),
            ExpectedValue::Path(ExpectedPath {
                start: ExpectedNode {
                    labels: vec!["A".to_owned()],
                    properties: vec![],
                },
                steps: vec![],
            })
        );
        // A mixed-direction path: <(:B)<-[:T1]-(:A)<-[:T2]-(:B)>
        let path = p("<(:B)<-[:T1]-(:A)<-[:T2]-(:B)>");
        let ExpectedValue::Path(pp) = path else {
            panic!("expected a path");
        };
        assert_eq!(pp.start.labels, vec!["B".to_owned()]);
        assert_eq!(pp.steps.len(), 2);
        assert!(!pp.steps[0].forward);
        assert_eq!(pp.steps[0].rel.rel_type, "T1");
        assert_eq!(pp.steps[0].node.labels, vec!["A".to_owned()]);
        assert!(!pp.steps[1].forward);
        assert_eq!(pp.steps[1].rel.rel_type, "T2");
    }

    #[test]
    fn forward_path_with_properties() {
        let path = p("<(:A {name: 'A'})-[:KNOWS {num: 1}]->(:B)>");
        let ExpectedValue::Path(pp) = path else {
            panic!("expected a path");
        };
        assert_eq!(
            pp.start.properties,
            vec![("name".to_owned(), ExpectedValue::String("A".to_owned()))]
        );
        assert_eq!(pp.steps.len(), 1);
        assert!(pp.steps[0].forward);
        assert_eq!(
            pp.steps[0].rel.properties,
            vec![("num".to_owned(), ExpectedValue::Integer(1))]
        );
    }

    #[test]
    fn trailing_junk_is_rejected() {
        assert!(parse_expected("1 2").is_err());
        assert!(parse_expected("[1, 2]extra").is_err());
        assert!(parse_expected("").is_err());
    }
}
