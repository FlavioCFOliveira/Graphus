//! Unit tests for the Cypher parser.
//!
//! Coverage is organized by concern:
//! - **Clauses**: each clause type parses to the expected AST shape, plus realistic multi-clause
//!   combinations.
//! - **Expressions**: operator precedence and associativity (grounded in the openCypher EBNF
//!   precedence ladder documented on the parent module), plus every atom kind.
//! - **Patterns**: node/relationship patterns, directions, labels, multiple rel types,
//!   variable-length ranges, inline properties, named paths.
//! - **Syntax errors**: exact byte [`Span`]s are asserted for missing/unexpected tokens, unclosed
//!   brackets, and trailing input — the compile-time `SyntaxError` phase (`04 §7.3`).
//! - **Spans**: composite-node spans cover their full extent.

use super::*;
use crate::ast::*;
use crate::lexer::tokenize;

// =================================================================================================
// Test helpers
// =================================================================================================

/// Parses `q`, asserting success, and returns the [`Query`]. Surfaces the parse error verbatim on
/// failure for a useful test message.
fn ok(q: &str) -> Query {
    match parse(q) {
        Ok(query) => query,
        Err(e) => panic!("expected `{q}` to parse, but got: {e}"),
    }
}

/// Parses `q` expecting a [`SyntaxError`], returning it with its byte span. Uses [`parse_tokens`] so
/// the structured error (with `kind` + `span`) is available, not just the `GraphusError` message.
fn err(q: &str) -> SyntaxError {
    let tokens = tokenize(q).expect("test inputs lex cleanly; the fault is syntactic");
    parse_tokens(&tokens, q).expect_err("expected a syntax error")
}

/// The clauses of a single (non-UNION, non-standalone) query.
fn clauses(q: &Query) -> &[Clause] {
    &q.body_single_query().clauses
}

/// Extracts the sole `RETURN` projection-item expressions of a single-clause-ish query, panicking if
/// the first clause is not a `RETURN`. A terse accessor for expression-shape tests.
fn return_exprs(q: &str) -> Vec<Expr> {
    let query = ok(q);
    for c in clauses(&query) {
        if let Clause::Return(r) = c {
            return r.body.items.iter().map(|i| i.expr.clone()).collect();
        }
    }
    panic!("query `{q}` has no RETURN clause");
}

/// The single returned expression's [`ExprKind`] (panics unless `RETURN <one expr>`).
fn return_kind(q: &str) -> ExprKind {
    let mut es = return_exprs(q);
    assert_eq!(es.len(), 1, "expected exactly one RETURN item in `{q}`");
    es.remove(0).kind
}

// =================================================================================================
// Clauses — happy paths with AST-shape assertions
// =================================================================================================

#[test]
fn match_where_return_with_alias() {
    let q = "MATCH (n:Person) WHERE n.age > 18 RETURN n.name AS name";
    let query = ok(q);
    let cs = clauses(&query);
    // Two clauses: MATCH (with its inline WHERE) and RETURN. WHERE is *part of* MATCH, not a clause.
    assert_eq!(cs.len(), 2);

    // MATCH
    let Clause::Match(m) = &cs[0] else {
        panic!("clause 0 should be MATCH")
    };
    assert!(!m.optional);
    assert_eq!(m.pattern.len(), 1);
    let start = &m.pattern[0].element.start;
    assert_eq!(start.variable.as_ref().unwrap().name, "n");
    assert_eq!(start.labels.len(), 1);
    assert_eq!(start.labels[0].name, "Person");
    // WHERE n.age > 18
    let where_e = m.where_clause.as_ref().expect("WHERE present");
    let ExprKind::Binary {
        op: BinaryOp::Gt, ..
    } = &where_e.kind
    else {
        panic!("WHERE should be a `>` comparison, got {:?}", where_e.kind)
    };

    // RETURN n.name AS name
    let Clause::Return(r) = &cs[1] else {
        panic!("clause 1 should be RETURN")
    };
    assert!(!r.body.distinct);
    assert!(!r.body.star);
    assert_eq!(r.body.items.len(), 1);
    let item = &r.body.items[0];
    assert_eq!(item.alias.as_ref().unwrap().name, "name");
    let ExprKind::Property { key, .. } = &item.expr.kind else {
        panic!("RETURN item should be a property access")
    };
    assert_eq!(key, "name");
}

#[test]
fn optional_match_sets_flag() {
    let query = ok("OPTIONAL MATCH (n) RETURN n");
    let Clause::Match(m) = &clauses(&query)[0] else {
        panic!("expected OPTIONAL MATCH")
    };
    assert!(m.optional);
}

#[test]
fn return_distinct_star_order_skip_limit() {
    let q = "MATCH (n) RETURN DISTINCT * ORDER BY n.a ASC, n.b DESC SKIP 5 LIMIT 10";
    let query = ok(q);
    let Clause::Return(r) = clauses(&query).last().unwrap() else {
        panic!("expected RETURN")
    };
    assert!(r.body.distinct);
    assert!(r.body.star);
    assert!(r.body.items.is_empty());
    assert_eq!(r.body.order_by.len(), 2);
    assert_eq!(r.body.order_by[0].direction, SortDirection::Ascending);
    assert_eq!(r.body.order_by[1].direction, SortDirection::Descending);
    assert!(r.body.skip.is_some());
    assert!(r.body.limit.is_some());
}

#[test]
fn sort_item_default_direction_is_ascending() {
    let query = ok("MATCH (n) RETURN n ORDER BY n.x");
    let Clause::Return(r) = clauses(&query).last().unwrap() else {
        panic!("expected RETURN")
    };
    assert_eq!(r.body.order_by[0].direction, SortDirection::Ascending);
}

#[test]
fn with_carries_where_and_modifiers() {
    let q = "MATCH (n) WITH n, count(*) AS c WHERE c > 1 RETURN n";
    let query = ok(q);
    let Clause::With(w) = &clauses(&query)[1] else {
        panic!("clause 1 should be WITH")
    };
    assert_eq!(w.body.items.len(), 2);
    assert_eq!(w.body.items[1].alias.as_ref().unwrap().name, "c");
    assert!(matches!(w.body.items[1].expr.kind, ExprKind::CountStar));
    let where_e = w.where_clause.as_ref().expect("WITH ... WHERE present");
    assert!(matches!(
        where_e.kind,
        ExprKind::Binary {
            op: BinaryOp::Gt,
            ..
        }
    ));
}

#[test]
fn unwind_binds_alias() {
    let query = ok("UNWIND [1, 2, 3] AS x RETURN x");
    let Clause::Unwind(u) = &clauses(&query)[0] else {
        panic!("expected UNWIND")
    };
    assert_eq!(u.alias.name, "x");
    assert!(matches!(u.expr.kind, ExprKind::List(_)));
}

#[test]
fn create_pattern() {
    let query = ok("CREATE (a:A)-[:R]->(b:B)");
    let Clause::Create(c) = &clauses(&query)[0] else {
        panic!("expected CREATE")
    };
    assert_eq!(c.pattern.len(), 1);
    let el = &c.pattern[0].element;
    assert_eq!(el.chain.len(), 1);
    assert_eq!(
        el.chain[0].relationship.direction,
        RelDirection::LeftToRight
    );
}

#[test]
fn merge_with_on_create_and_on_match() {
    let q = "MERGE (n:P {id: 1}) ON CREATE SET n.created = true ON MATCH SET n.seen = n.seen + 1";
    let query = ok(q);
    let Clause::Merge(m) = &clauses(&query)[0] else {
        panic!("expected MERGE")
    };
    assert!(m.pattern.element.start.properties.is_some());
    assert_eq!(m.actions.len(), 2);
    let MergeAction::OnCreate(items0) = &m.actions[0] else {
        panic!("first action should be ON CREATE SET")
    };
    assert_eq!(items0.len(), 1);
    assert!(matches!(m.actions[1], MergeAction::OnMatch(_)));
}

#[test]
fn set_property_replace_merge_and_labels() {
    let q = "MATCH (n) SET n.p = 1, n = {a: 1}, n += {b: 2}, n:Label1:Label2";
    let query = ok(q);
    let Clause::Set(s) = &clauses(&query)[1] else {
        panic!("expected SET")
    };
    assert_eq!(s.items.len(), 4);
    assert!(matches!(s.items[0], SetItem::Property { .. }));
    assert!(matches!(s.items[1], SetItem::Replace { .. }));
    assert!(matches!(s.items[2], SetItem::Merge { .. }));
    let SetItem::Labels { labels, .. } = &s.items[3] else {
        panic!("item 3 should be a label set")
    };
    assert_eq!(labels.len(), 2);
    assert_eq!(labels[0].name, "Label1");
    assert_eq!(labels[1].name, "Label2");
}

#[test]
fn detach_delete_and_plain_delete() {
    let query = ok("MATCH (n) DETACH DELETE n, m");
    let Clause::Delete(d) = &clauses(&query)[1] else {
        panic!("expected DELETE")
    };
    assert!(d.detach);
    assert_eq!(d.exprs.len(), 2);

    let query2 = ok("MATCH (n) DELETE n");
    let Clause::Delete(d2) = &clauses(&query2)[1] else {
        panic!("expected DELETE")
    };
    assert!(!d2.detach);
}

#[test]
fn remove_labels_and_property() {
    let query = ok("MATCH (n) REMOVE n:Label, n.prop");
    let Clause::Remove(r) = &clauses(&query)[1] else {
        panic!("expected REMOVE")
    };
    assert_eq!(r.items.len(), 2);
    assert!(matches!(r.items[0], RemoveItem::Labels { .. }));
    assert!(matches!(r.items[1], RemoveItem::Property(_)));
}

#[test]
fn in_query_call_with_yield() {
    let q = "CALL db.labels() YIELD label AS l RETURN l";
    let query = ok(q);
    let Clause::Call(c) = &clauses(&query)[0] else {
        panic!("expected CALL")
    };
    assert_eq!(c.call.name, vec!["db".to_owned(), "labels".to_owned()]);
    assert_eq!(c.call.args.as_ref().unwrap().len(), 0);
    let items = c.yield_items.as_ref().expect("YIELD present");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].field.as_deref(), Some("label"));
    assert_eq!(items[0].alias.name, "l");
}

#[test]
fn in_query_call_yield_with_where() {
    let q = "CALL db.x() YIELD a, b WHERE a > 1 RETURN a";
    let query = ok(q);
    let Clause::Call(c) = &clauses(&query)[0] else {
        panic!("expected CALL")
    };
    assert_eq!(c.yield_items.as_ref().unwrap().len(), 2);
    assert!(c.where_clause.is_some());
}

#[test]
fn standalone_call_explicit_with_yield() {
    let query = ok("CALL db.labels() YIELD label");
    let QueryBody::StandaloneCall(c) = &query.body else {
        panic!("expected a standalone CALL")
    };
    assert!(c.call.args.is_some());
    let StandaloneYield::Items { items, .. } = c.yield_clause.as_ref().unwrap() else {
        panic!("expected YIELD items")
    };
    assert_eq!(items.len(), 1);
}

#[test]
fn standalone_call_yield_star() {
    let query = ok("CALL db.labels() YIELD *");
    let QueryBody::StandaloneCall(c) = &query.body else {
        panic!("expected a standalone CALL")
    };
    assert!(matches!(c.yield_clause, Some(StandaloneYield::Star)));
}

#[test]
fn standalone_call_implicit_no_parens() {
    // Implicit (parenthesis-less) form is only legal standalone.
    let query = ok("CALL db.labels");
    let QueryBody::StandaloneCall(c) = &query.body else {
        panic!("expected a standalone CALL")
    };
    assert!(c.call.args.is_none());
    assert!(c.yield_clause.is_none());
}

#[test]
fn call_followed_by_clause_is_in_query_not_standalone() {
    // A CALL with a trailing RETURN must be an in-query call inside a regular query.
    let query = ok("CALL db.labels() YIELD label RETURN label");
    let QueryBody::Regular { head, .. } = &query.body else {
        panic!("expected a regular query")
    };
    assert!(matches!(head.clauses[0], Clause::Call(_)));
    assert!(matches!(head.clauses[1], Clause::Return(_)));
}

// =================================================================================================
// UNION
// =================================================================================================

#[test]
fn union_all_and_plain_union() {
    let query = ok("MATCH (n) RETURN n UNION ALL MATCH (m) RETURN m UNION MATCH (k) RETURN k");
    let QueryBody::Regular { head, unions } = &query.body else {
        panic!("expected a regular query")
    };
    assert_eq!(head.clauses.len(), 2);
    assert_eq!(unions.len(), 2);
    assert!(unions[0].all, "first UNION is ALL");
    assert!(!unions[1].all, "second UNION is plain");
}

// =================================================================================================
// Multi-clause realistic query
// =================================================================================================

#[test]
fn full_read_query_all_modifiers() {
    let q = "MATCH (n:Person)-[:KNOWS]->(m) \
             WHERE n.age > 18 \
             WITH n, m \
             RETURN n.name AS name, m.name \
             ORDER BY name DESC \
             LIMIT 10";
    let query = ok(q);
    let cs = clauses(&query);
    // MATCH (with inline WHERE) + WITH + RETURN = 3 clauses.
    assert_eq!(cs.len(), 3);
    assert!(matches!(cs[0], Clause::Match(_)));
    assert!(matches!(cs[1], Clause::With(_)));
    let Clause::Return(r) = &cs[2] else {
        panic!("last clause should be RETURN")
    };
    assert_eq!(r.body.items.len(), 2);
    assert_eq!(r.body.order_by.len(), 1);
    assert_eq!(r.body.order_by[0].direction, SortDirection::Descending);
    assert!(r.body.limit.is_some());
}

// =================================================================================================
// Expression precedence & associativity (EBNF ladder; see parent-module precedence table)
// =================================================================================================

/// Asserts a binary op at the root with a given left/right shape predicate.
fn assert_binary_root(kind: &ExprKind, expect: BinaryOp) -> (&Expr, &Expr) {
    match kind {
        ExprKind::Binary { op, lhs, rhs } if *op == expect => (lhs, rhs),
        other => panic!("expected a {expect:?} at the root, got {other:?}"),
    }
}

#[test]
fn mul_binds_tighter_than_add() {
    // 1 + 2 * 3  ==  1 + (2 * 3)
    let kind = return_kind("RETURN 1 + 2 * 3");
    let (_, rhs) = assert_binary_root(&kind, BinaryOp::Add);
    assert_binary_root(&rhs.kind, BinaryOp::Mul);
}

#[test]
fn sub_is_left_associative() {
    // 1 - 2 - 3  ==  (1 - 2) - 3
    let kind = return_kind("RETURN 1 - 2 - 3");
    let (lhs, _) = assert_binary_root(&kind, BinaryOp::Sub);
    assert_binary_root(&lhs.kind, BinaryOp::Sub);
}

#[test]
fn power_is_left_associative() {
    // openCypher: `^` is left-associative — `2 ^ 3 ^ 2 == (2 ^ 3) ^ 2`. Pinned by
    // `tck/.../precedence/Precedence2` [2]/[3] (`4 ^ (3*2) ^ 3 == (4 ^ 6) ^ 3 == 4 ^ 18`). The
    // *left* operand of the root `^` is therefore the nested `^`.
    let kind = return_kind("RETURN 2 ^ 3 ^ 2");
    let (lhs, _) = assert_binary_root(&kind, BinaryOp::Pow);
    assert_binary_root(&lhs.kind, BinaryOp::Pow);
}

#[test]
fn power_binds_tighter_than_mul() {
    // 2 * 3 ^ 2  ==  2 * (3 ^ 2)
    let kind = return_kind("RETURN 2 * 3 ^ 2");
    let (_, rhs) = assert_binary_root(&kind, BinaryOp::Mul);
    assert_binary_root(&rhs.kind, BinaryOp::Pow);
}

#[test]
fn power_binds_tighter_than_add() {
    // 2 + 3 ^ 2  ==  2 + (3 ^ 2)
    let kind = return_kind("RETURN 2 + 3 ^ 2");
    let (_, rhs) = assert_binary_root(&kind, BinaryOp::Add);
    assert_binary_root(&rhs.kind, BinaryOp::Pow);
}

#[test]
fn unary_minus_folds_into_power_base() {
    // `-3 ^ 2` parses as `(-3) ^ 2` (unary minus binds tighter than `^` in openCypher;
    // `tck/.../precedence/Precedence2` [4] expects `9.0`). The folded literal is the *base*.
    let kind = return_kind("RETURN -3 ^ 2");
    let (lhs, _) = assert_binary_root(&kind, BinaryOp::Pow);
    assert!(
        matches!(&lhs.kind, ExprKind::Literal(Literal::Integer(-3))),
        "expected folded -3 as the power base, got {:?}",
        lhs.kind
    );
}

#[test]
fn and_binds_tighter_than_or() {
    // a OR b AND c  ==  a OR (b AND c)
    let kind = return_kind("RETURN a OR b AND c");
    let (_, rhs) = assert_binary_root(&kind, BinaryOp::Or);
    assert_binary_root(&rhs.kind, BinaryOp::And);
}

#[test]
fn xor_sits_between_or_and_and() {
    // a OR b XOR c AND d  ==  a OR (b XOR (c AND d))
    let kind = return_kind("RETURN a OR b XOR c AND d");
    let (_, or_rhs) = assert_binary_root(&kind, BinaryOp::Or);
    let (_, xor_rhs) = assert_binary_root(&or_rhs.kind, BinaryOp::Xor);
    assert_binary_root(&xor_rhs.kind, BinaryOp::And);
}

#[test]
fn not_is_looser_than_comparison() {
    // NOT a = b  ==  NOT (a = b)
    let kind = return_kind("RETURN NOT a = b");
    let ExprKind::Unary {
        op: UnaryOp::Not,
        operand,
    } = &kind
    else {
        panic!("expected NOT at the root, got {kind:?}")
    };
    assert_binary_root(&operand.kind, BinaryOp::Eq);
}

#[test]
fn comparison_is_looser_than_arithmetic() {
    // a + b < c  ==  (a + b) < c
    let kind = return_kind("RETURN a + b < c");
    let (lhs, _) = assert_binary_root(&kind, BinaryOp::Lt);
    assert_binary_root(&lhs.kind, BinaryOp::Add);
}

#[test]
fn predicate_in_binds_tighter_than_comparison() {
    // a = b IN c  ==  a = (b IN c)  (EBNF: StringListNullPredicate nests inside Comparison)
    let kind = return_kind("RETURN a = b IN c");
    let (_, rhs) = assert_binary_root(&kind, BinaryOp::Eq);
    let ExprKind::Predicate {
        op: PredicateOp::In,
        ..
    } = &rhs.kind
    else {
        panic!("RHS should be an IN predicate, got {:?}", rhs.kind)
    };
}

#[test]
fn in_and_is_not_null_combined() {
    // x IN [1, 2] AND y IS NOT NULL  ==  (x IN [..]) AND (y IS NOT NULL)
    let kind = return_kind("RETURN x IN [1, 2] AND y IS NOT NULL");
    let (lhs, rhs) = assert_binary_root(&kind, BinaryOp::And);
    assert!(matches!(
        lhs.kind,
        ExprKind::Predicate {
            op: PredicateOp::In,
            ..
        }
    ));
    assert!(matches!(
        rhs.kind,
        ExprKind::Predicate {
            op: PredicateOp::IsNotNull,
            rhs: None,
            ..
        }
    ));
}

#[test]
fn string_predicates_starts_ends_contains() {
    assert!(matches!(
        return_kind("RETURN s STARTS WITH 'a'"),
        ExprKind::Predicate {
            op: PredicateOp::StartsWith,
            ..
        }
    ));
    assert!(matches!(
        return_kind("RETURN s ENDS WITH 'z'"),
        ExprKind::Predicate {
            op: PredicateOp::EndsWith,
            ..
        }
    ));
    assert!(matches!(
        return_kind("RETURN s CONTAINS 'm'"),
        ExprKind::Predicate {
            op: PredicateOp::Contains,
            ..
        }
    ));
}

#[test]
fn is_null_predicate() {
    assert!(matches!(
        return_kind("RETURN n.p IS NULL"),
        ExprKind::Predicate {
            op: PredicateOp::IsNull,
            rhs: None,
            ..
        }
    ));
}

#[test]
fn regex_match_operator() {
    let kind = return_kind("RETURN n.name =~ 'a.*'");
    assert!(matches!(
        kind,
        ExprKind::Binary {
            op: BinaryOp::RegexMatch,
            ..
        }
    ));
}

#[test]
fn unary_minus_then_postfix() {
    // -a.b[0]  ==  -( ((a.b)[0]) )  — postfix binds tighter than unary minus
    let kind = return_kind("RETURN -a.b[0]");
    let ExprKind::Unary {
        op: UnaryOp::Minus,
        operand,
    } = &kind
    else {
        panic!("expected unary minus at root, got {kind:?}")
    };
    let ExprKind::Index { base, .. } = &operand.kind else {
        panic!("under the minus should be an index, got {:?}", operand.kind)
    };
    assert!(matches!(base.kind, ExprKind::Property { .. }));
}

#[test]
fn label_predicate_on_variable() {
    // n:Label  ==  HasLabels(n, [Label])
    let kind = return_kind("RETURN n:Label");
    let ExprKind::HasLabels { operand, labels } = &kind else {
        panic!("expected a label predicate, got {kind:?}")
    };
    assert!(matches!(operand.kind, ExprKind::Variable(_)));
    assert_eq!(labels.len(), 1);
    assert_eq!(labels[0].name, "Label");
}

#[test]
fn parenthesized_overrides_precedence() {
    // (1 + 2) * 3  ==  (1 + 2) * 3
    let kind = return_kind("RETURN (1 + 2) * 3");
    let (lhs, _) = assert_binary_root(&kind, BinaryOp::Mul);
    assert_binary_root(&lhs.kind, BinaryOp::Add);
}

// =================================================================================================
// Atoms
// =================================================================================================

#[test]
fn literal_atoms() {
    assert!(matches!(
        return_kind("RETURN 42"),
        ExprKind::Literal(Literal::Integer(_))
    ));
    assert!(matches!(
        return_kind("RETURN 2.5"),
        ExprKind::Literal(Literal::Float(_))
    ));
    assert!(matches!(
        return_kind("RETURN 'hi'"),
        ExprKind::Literal(Literal::String(_))
    ));
    assert!(matches!(
        return_kind("RETURN true"),
        ExprKind::Literal(Literal::Boolean(true))
    ));
    assert!(matches!(
        return_kind("RETURN null"),
        ExprKind::Literal(Literal::Null)
    ));
}

#[test]
fn integer_literal_resolves_to_i64() {
    assert!(matches!(
        return_kind("RETURN 42"),
        ExprKind::Literal(Literal::Integer(42))
    ));
    // The largest positive integer (`i64::MAX`) parses, decimal and hex.
    assert!(matches!(
        return_kind("RETURN 9223372036854775807"),
        ExprKind::Literal(Literal::Integer(i64::MAX))
    ));
    assert!(matches!(
        return_kind("RETURN 0x7FFFFFFFFFFFFFFF"),
        ExprKind::Literal(Literal::Integer(i64::MAX))
    ));
}

#[test]
fn smallest_integer_folds_to_i64_min() {
    // `-9223372036854775808` (i64::MIN) is admitted as one folded negative literal
    // (`tck/.../literals/Literals2` [8]); the magnitude `2^63` is otherwise out of the positive range.
    assert!(matches!(
        return_kind("RETURN -9223372036854775808"),
        ExprKind::Literal(Literal::Integer(i64::MIN))
    ));
    // Hex and octal smallest, likewise.
    assert!(matches!(
        return_kind("RETURN -0x8000000000000000"),
        ExprKind::Literal(Literal::Integer(i64::MIN))
    ));
    assert!(matches!(
        return_kind("RETURN -0o1000000000000000000000"),
        ExprKind::Literal(Literal::Integer(i64::MIN))
    ));
}

#[test]
fn integer_overflow_is_a_compile_time_syntax_error() {
    // A too-large / too-small literal is a compile-time `SyntaxError` (`IntegerOverflow`), not a
    // runtime arithmetic error: decimal (`Literals2` [9]/[10]), hex (`Literals3` [16]/[17]), octal
    // (`Literals4` [9]/[10]).
    for q in [
        "RETURN 9223372036854775808",       // i64::MAX + 1
        "RETURN -9223372036854775809",      // i64::MIN - 1
        "RETURN 0x8000000000000000",        // hex i64::MAX + 1
        "RETURN -0x8000000000000001",       // hex i64::MIN - 1
        "RETURN 0o1000000000000000000000",  // octal i64::MAX + 1
        "RETURN -0o1000000000000000000001", // octal i64::MIN - 1
    ] {
        let e = err(q);
        assert_eq!(
            e.kind,
            SyntaxErrorKind::IntegerOverflow,
            "query {q:?} should be a compile-time IntegerOverflow"
        );
    }
}

#[test]
fn float_overflow_is_a_compile_time_syntax_error() {
    // `1.34E999` overflows `f64`; openCypher rejects it at compile time (`Literals5` [27]). The lexer
    // raises the error, surfaced through `parse`.
    let e = crate::parser::parse("RETURN 1.34E999").expect_err("float overflow must fail");
    assert!(
        matches!(e, graphus_core::GraphusError::Compile { .. }),
        "expected a compile-time error, got {e:?}"
    );
}

#[test]
fn string_predicate_binds_tighter_than_or() {
    // `'x' STARTS WITH a OR b` == `('x' STARTS WITH a) OR b` — the string predicate is the *left*
    // operand of `OR` (`tck/.../precedence/Precedence4` [4]).
    let kind = return_kind("RETURN 'x' STARTS WITH a OR b");
    let (lhs, _) = assert_binary_root(&kind, BinaryOp::Or);
    assert!(
        matches!(
            &lhs.kind,
            ExprKind::Predicate {
                op: PredicateOp::StartsWith,
                ..
            }
        ),
        "LHS of OR should be a STARTS WITH predicate, got {:?}",
        lhs.kind
    );
}

#[test]
fn string_predicate_binds_tighter_than_and() {
    // `a AND 'x' CONTAINS b` == `a AND ('x' CONTAINS b)` — the predicate is the *right* operand.
    let kind = return_kind("RETURN a AND 'x' CONTAINS b");
    let (_, rhs) = assert_binary_root(&kind, BinaryOp::And);
    assert!(
        matches!(
            &rhs.kind,
            ExprKind::Predicate {
                op: PredicateOp::Contains,
                ..
            }
        ),
        "RHS of AND should be a CONTAINS predicate, got {:?}",
        rhs.kind
    );
}

#[test]
fn parameter_atom() {
    let ExprKind::Parameter(name) = return_kind("RETURN $foo") else {
        panic!("expected a parameter")
    };
    assert_eq!(name, "foo");
}

#[test]
fn function_call_with_distinct_and_args() {
    let ExprKind::FunctionCall {
        name,
        distinct,
        args,
    } = return_kind("RETURN count(DISTINCT n.x)")
    else {
        panic!("expected a function call")
    };
    assert_eq!(name, vec!["count".to_owned()]);
    assert!(distinct);
    assert_eq!(args.len(), 1);
}

#[test]
fn namespaced_function_call() {
    let ExprKind::FunctionCall { name, args, .. } = return_kind("RETURN math.floor(1.5)") else {
        panic!("expected a namespaced function call")
    };
    assert_eq!(name, vec!["math".to_owned(), "floor".to_owned()]);
    assert_eq!(args.len(), 1);
}

#[test]
fn count_star_atom() {
    assert!(matches!(
        return_kind("RETURN count(*)"),
        ExprKind::CountStar
    ));
}

#[test]
fn list_literal_and_nesting() {
    let ExprKind::List(items) = return_kind("RETURN [1, [2, 3], 'x']") else {
        panic!("expected a list literal")
    };
    assert_eq!(items.len(), 3);
    assert!(matches!(items[1].kind, ExprKind::List(_)));
}

#[test]
fn empty_list_literal() {
    let ExprKind::List(items) = return_kind("RETURN []") else {
        panic!("expected an empty list")
    };
    assert!(items.is_empty());
}

#[test]
fn map_literal_with_nested_list() {
    let ExprKind::Map(entries) = return_kind("RETURN {a: 1, b: [2, 3]}") else {
        panic!("expected a map literal")
    };
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].0.name, "a");
    assert_eq!(entries[1].0.name, "b");
    assert!(matches!(entries[1].1.kind, ExprKind::List(_)));
}

#[test]
fn empty_map_literal() {
    let ExprKind::Map(entries) = return_kind("RETURN {}") else {
        panic!("expected an empty map")
    };
    assert!(entries.is_empty());
}

#[test]
fn searched_case_expression() {
    let ExprKind::Case(case) = return_kind("RETURN CASE WHEN x > 1 THEN 'big' ELSE 'small' END")
    else {
        panic!("expected a CASE")
    };
    assert!(case.subject.is_none(), "searched CASE has no subject");
    assert_eq!(case.alternatives.len(), 1);
    assert!(case.else_expr.is_some());
}

#[test]
fn simple_case_expression() {
    let ExprKind::Case(case) = return_kind("RETURN CASE x WHEN 1 THEN 'one' WHEN 2 THEN 'two' END")
    else {
        panic!("expected a CASE")
    };
    assert!(case.subject.is_some(), "simple CASE has a subject");
    assert_eq!(case.alternatives.len(), 2);
    assert!(case.else_expr.is_none());
}

#[test]
fn list_comprehension_full() {
    let ExprKind::ListComprehension(lc) =
        return_kind("RETURN [x IN [1, 2, 3] WHERE x > 1 | x * 2]")
    else {
        panic!("expected a list comprehension")
    };
    assert_eq!(lc.variable.name, "x");
    assert!(lc.predicate.is_some());
    assert!(lc.projection.is_some());
}

#[test]
fn list_comprehension_filter_only() {
    let ExprKind::ListComprehension(lc) = return_kind("RETURN [x IN xs WHERE x > 0]") else {
        panic!("expected a list comprehension")
    };
    assert!(lc.predicate.is_some());
    assert!(lc.projection.is_none());
}

#[test]
fn pattern_comprehension_named_and_anonymous() {
    let ExprKind::PatternComprehension(pc) = return_kind("RETURN [p = (a)-->(b) WHERE a.x | p]")
    else {
        panic!("expected a pattern comprehension")
    };
    assert!(pc.var.is_some());
    assert!(pc.predicate.is_some());

    let ExprKind::PatternComprehension(pc2) = return_kind("RETURN [(a)-->(b) | b]") else {
        panic!("expected an anonymous pattern comprehension")
    };
    assert!(pc2.var.is_none());
    assert!(pc2.predicate.is_none());
    assert_eq!(pc2.element.chain.len(), 1);
}

// =================================================================================================
// Patterns
// =================================================================================================

#[test]
fn node_pattern_multiple_labels_and_props() {
    let query = ok("MATCH (v:A:B:C {k: 1}) RETURN v");
    let Clause::Match(m) = &clauses(&query)[0] else {
        panic!("expected MATCH")
    };
    let node = &m.pattern[0].element.start;
    assert_eq!(node.variable.as_ref().unwrap().name, "v");
    assert_eq!(
        node.labels
            .iter()
            .map(|l| l.name.as_str())
            .collect::<Vec<_>>(),
        vec!["A", "B", "C"]
    );
    assert!(matches!(
        node.properties.as_ref().unwrap().kind,
        ExprKind::Map(_)
    ));
}

#[test]
fn anonymous_node_pattern() {
    let query = ok("MATCH () RETURN 1");
    let Clause::Match(m) = &clauses(&query)[0] else {
        panic!("expected MATCH")
    };
    let node = &m.pattern[0].element.start;
    assert!(node.variable.is_none());
    assert!(node.labels.is_empty());
    assert!(node.properties.is_none());
}

#[test]
fn relationship_directions() {
    let dir = |q: &str| -> RelDirection {
        let query = ok(q);
        let Clause::Match(m) = &clauses(&query)[0] else {
            panic!("expected MATCH")
        };
        m.pattern[0].element.chain[0].relationship.direction
    };
    assert_eq!(
        dir("MATCH (a)-[r]->(b) RETURN 1"),
        RelDirection::LeftToRight
    );
    assert_eq!(
        dir("MATCH (a)<-[r]-(b) RETURN 1"),
        RelDirection::RightToLeft
    );
    assert_eq!(dir("MATCH (a)-[r]-(b) RETURN 1"), RelDirection::Undirected);
    assert_eq!(dir("MATCH (a)-->(b) RETURN 1"), RelDirection::LeftToRight);
    assert_eq!(dir("MATCH (a)<--(b) RETURN 1"), RelDirection::RightToLeft);
    assert_eq!(dir("MATCH (a)--(b) RETURN 1"), RelDirection::Undirected);
}

#[test]
fn relationship_multiple_types() {
    let query = ok("MATCH (a)-[r:KNOWS|LIKES|FOLLOWS]->(b) RETURN r");
    let Clause::Match(m) = &clauses(&query)[0] else {
        panic!("expected MATCH")
    };
    let rel = &m.pattern[0].element.chain[0].relationship;
    assert_eq!(rel.variable.as_ref().unwrap().name, "r");
    assert_eq!(
        rel.types
            .iter()
            .map(|t| t.name.as_str())
            .collect::<Vec<_>>(),
        vec!["KNOWS", "LIKES", "FOLLOWS"]
    );
}

#[test]
fn relationship_inline_properties() {
    let query = ok("MATCH (a)-[r:R {since: 2020}]->(b) RETURN r");
    let Clause::Match(m) = &clauses(&query)[0] else {
        panic!("expected MATCH")
    };
    let rel = &m.pattern[0].element.chain[0].relationship;
    assert!(matches!(
        rel.properties.as_ref().unwrap().kind,
        ExprKind::Map(_)
    ));
}

#[test]
fn variable_length_ranges() {
    let range = |q: &str| -> VarLengthRange {
        let query = ok(q);
        let Clause::Match(m) = &clauses(&query)[0] else {
            panic!("expected MATCH")
        };
        m.pattern[0].element.chain[0]
            .relationship
            .range
            .expect("a range")
    };
    // `*` — unbounded
    let r = range("MATCH (a)-[*]->(b) RETURN 1");
    assert_eq!((r.min, r.max), (None, None));
    // `*2` — exact
    let r = range("MATCH (a)-[*2]->(b) RETURN 1");
    assert_eq!((r.min, r.max, r.exact), (Some(2), Some(2), true));
    // `*1..3` — bounded both sides
    let r = range("MATCH (a)-[*1..3]->(b) RETURN 1");
    assert_eq!((r.min, r.max, r.exact), (Some(1), Some(3), false));
    // `*..5` — bounded above only
    let r = range("MATCH (a)-[*..5]->(b) RETURN 1");
    assert_eq!((r.min, r.max), (None, Some(5)));
    // `*2..` — bounded below only
    let r = range("MATCH (a)-[*2..]->(b) RETURN 1");
    assert_eq!((r.min, r.max), (Some(2), None));
}

#[test]
fn named_path() {
    let query = ok("MATCH p = (a)-[:R]->(b) RETURN p");
    let Clause::Match(m) = &clauses(&query)[0] else {
        panic!("expected MATCH")
    };
    let part = &m.pattern[0];
    assert_eq!(part.var.as_ref().unwrap().name, "p");
    assert_eq!(part.element.chain.len(), 1);
}

#[test]
fn multi_part_pattern_chain() {
    let query = ok("MATCH (a)-[:R1]->(b)-[:R2]->(c) RETURN a, c");
    let Clause::Match(m) = &clauses(&query)[0] else {
        panic!("expected MATCH")
    };
    assert_eq!(m.pattern[0].element.chain.len(), 2);
}

#[test]
fn comma_separated_patterns() {
    let query = ok("MATCH (a), (b), (c) RETURN a");
    let Clause::Match(m) = &clauses(&query)[0] else {
        panic!("expected MATCH")
    };
    assert_eq!(m.pattern.len(), 3);
}

#[test]
fn node_properties_from_parameter() {
    let query = ok("MATCH (n $props) RETURN n");
    let Clause::Match(m) = &clauses(&query)[0] else {
        panic!("expected MATCH")
    };
    assert!(matches!(
        m.pattern[0].element.start.properties.as_ref().unwrap().kind,
        ExprKind::Parameter(_)
    ));
}

#[test]
fn keyword_spelled_label_is_accepted() {
    // `SchemaName = SymbolicName | ReservedWord`, so a label may be a reserved word like `INDEX`.
    let query = ok("MATCH (n:INDEX) RETURN n");
    let Clause::Match(m) = &clauses(&query)[0] else {
        panic!("expected MATCH")
    };
    assert_eq!(m.pattern[0].element.start.labels[0].name, "INDEX");
}

#[test]
fn keyword_spelled_property_key_is_accepted() {
    let ExprKind::Map(entries) = return_kind("RETURN {order: 1, index: 2}") else {
        panic!("expected a map")
    };
    assert_eq!(entries[0].0.name, "order");
    assert_eq!(entries[1].0.name, "index");
}

// =================================================================================================
// Syntax errors — exact byte spans (compile-time SyntaxError phase, 04 §7.3)
// =================================================================================================

#[test]
fn error_missing_closing_paren_in_node() {
    // `MATCH (n RETURN n` — the `)` is missing; the parser expects it where RETURN appears.
    let e = err("MATCH (n RETURN n");
    assert!(
        matches!(&e.kind, SyntaxErrorKind::Expected { expected, .. } if expected.contains(')')),
        "kind was {:?}",
        e.kind
    );
    // `RETURN` starts at byte 9.
    assert_eq!(e.span, Span::new(9, 15));
}

#[test]
fn error_unexpected_token_for_operand() {
    // `RETURN +` — a `+` then EOF: the unary operand is missing (end of input).
    let e = err("RETURN +");
    assert!(matches!(e.kind, SyntaxErrorKind::UnexpectedEof { .. }));
    assert_eq!(e.span, Span::new(8, 8)); // empty span at EOF
}

#[test]
fn error_unclosed_list_bracket() {
    // `RETURN [1, 2` — the `]` never arrives; error at EOF.
    let e = err("RETURN [1, 2");
    assert!(matches!(e.kind, SyntaxErrorKind::UnexpectedEof { .. }));
    assert_eq!(e.span, Span::new(12, 12));
}

#[test]
fn error_trailing_input_after_statement() {
    // A complete `RETURN 1` followed by a stray `2`.
    let e = err("RETURN 1 2");
    assert_eq!(e.kind, SyntaxErrorKind::TrailingInput);
    // The stray `2` is at byte 9.
    assert_eq!(e.span, Span::new(9, 10));
}

#[test]
fn error_trailing_input_after_semicolon() {
    let e = err("RETURN 1 ; RETURN 2");
    assert_eq!(e.kind, SyntaxErrorKind::TrailingInput);
    // The second `RETURN` begins at byte 11.
    assert_eq!(e.span, Span::new(11, 17));
}

#[test]
fn error_expected_x_found_y_with_span() {
    // `MATCH (n) RETURN ORDER` — after RETURN, an expression is required but `ORDER` (a keyword)
    // appears. This is the "expected X, found Y" shape the TCK exercises, with the offending token's
    // span.
    let e = err("MATCH (n) RETURN ORDER");
    match &e.kind {
        SyntaxErrorKind::Expected { found, .. } | SyntaxErrorKind::UnexpectedToken { found } => {
            assert!(found.contains("ORDER"), "found description was {found:?}");
        }
        other => panic!("unexpected error kind {other:?}"),
    }
    // `ORDER` starts at byte 17.
    assert_eq!(e.span, Span::new(17, 22));
}

#[test]
fn error_match_requires_pattern() {
    // `MATCH RETURN n` — MATCH needs a `(` to begin a node pattern; RETURN is at byte 6.
    let e = err("MATCH RETURN n");
    assert!(matches!(e.kind, SyntaxErrorKind::Expected { .. }));
    assert_eq!(e.span, Span::new(6, 12));
}

#[test]
fn error_unwind_requires_as() {
    // `UNWIND xs x` — missing `AS`; `x` is at byte 10.
    let e = err("UNWIND xs x");
    assert!(
        matches!(&e.kind, SyntaxErrorKind::Expected { expected, .. } if expected == "AS"),
        "kind was {:?}",
        e.kind
    );
    assert_eq!(e.span, Span::new(10, 11));
}

#[test]
fn error_case_requires_then() {
    // `RETURN CASE WHEN x 'y' END` — missing THEN; `'y'` (string) is the offending token.
    let e = err("RETURN CASE WHEN x 'y' END");
    assert!(
        matches!(&e.kind, SyntaxErrorKind::Expected { expected, .. } if expected.contains("THEN")),
        "kind was {:?}",
        e.kind
    );
    // `'y'` starts at byte 19.
    assert_eq!(e.span, Span::new(19, 22));
}

#[test]
fn error_is_requires_null() {
    // `RETURN x IS 1` — IS must be followed by NULL (the parser only handles IS [NOT] NULL).
    let e = err("RETURN x IS 1");
    assert!(
        matches!(&e.kind, SyntaxErrorKind::Expected { expected, .. } if expected.contains("NULL")),
        "kind was {:?}",
        e.kind
    );
    assert_eq!(e.span, Span::new(12, 13)); // the `1`
}

#[test]
fn error_empty_input() {
    // No clauses at all.
    let e = err("");
    assert!(matches!(e.kind, SyntaxErrorKind::UnexpectedEof { .. }));
    assert_eq!(e.span, Span::new(0, 0));
}

#[test]
fn error_starts_without_with_keyword() {
    // `RETURN s STARTS 'a'` — STARTS must be followed by WITH.
    let e = err("RETURN s STARTS 'a'");
    assert!(
        matches!(&e.kind, SyntaxErrorKind::Expected { expected, .. } if expected.contains("WITH")),
        "kind was {:?}",
        e.kind
    );
    // `'a'` starts at byte 16.
    assert_eq!(e.span, Span::new(16, 19));
}

// =================================================================================================
// Span coverage — composite nodes cover their full extent
// =================================================================================================

#[test]
fn query_span_covers_whole_statement() {
    let q = "MATCH (n) RETURN n";
    let query = ok(q);
    assert_eq!(query.span, Span::new(0, q.len()));
}

#[test]
fn trailing_semicolon_is_accepted_and_excluded_from_span() {
    let q = "RETURN 1 ;";
    let query = ok(q);
    // The span ends at `1`, not the `;`.
    assert_eq!(query.span.end, 8);
}

#[test]
fn binary_expr_span_covers_both_operands() {
    let kind = return_kind("RETURN 10 + 20");
    let ExprKind::Binary { lhs, rhs, .. } = &kind else {
        panic!("expected binary")
    };
    assert_eq!(lhs.span, Span::new(7, 9)); // `10`
    assert_eq!(rhs.span, Span::new(12, 14)); // `20`
}

#[test]
fn node_pattern_span_covers_parens() {
    let query = ok("MATCH (n:L) RETURN n");
    let Clause::Match(m) = &clauses(&query)[0] else {
        panic!("expected MATCH")
    };
    // `(n:L)` is bytes 6..11.
    assert_eq!(m.pattern[0].element.start.span, Span::new(6, 11));
}

// =================================================================================================
// GraphusError boundary conversion
// =================================================================================================

#[test]
fn parse_returns_compile_error_on_syntax_fault() {
    use graphus_core::GraphusError;
    let e = parse("RETURN 1 2").expect_err("should fail");
    match e {
        GraphusError::Compile(msg) => {
            assert!(msg.contains("syntax error"), "message: {msg}");
            assert!(msg.contains("trailing"), "message: {msg}");
        }
        other => panic!("expected Compile, got {other:?}"),
    }
}

#[test]
fn parse_propagates_lexer_error_as_compile_error() {
    use graphus_core::GraphusError;
    // An unterminated string is a *lexer* error; `parse` must surface it as a Compile error too.
    let e = parse("RETURN 'oops").expect_err("should fail to lex");
    assert!(matches!(e, GraphusError::Compile(_)));
}

// =================================================================================================
// A small grammar-oracle-style set drawn from openCypher example queries
// =================================================================================================

/// A handful of representative queries lifted from the openCypher documentation / TCK style; each
/// must parse without error. This is a lightweight "grammar oracle" smoke set per `04 §7.1`
/// (*"A grammar test oracle cross-checks against the openCypher grammar artifacts"*); the full TCK
/// harness (#25) is the exhaustive oracle.
#[test]
fn opencypher_example_queries_parse() {
    let examples = [
        "MATCH (n) RETURN n",
        "MATCH (n:Person) RETURN n.name, n.age",
        "MATCH (n:Person)-[:KNOWS]->(friend) RETURN friend.name",
        "MATCH (n) WHERE n.name = 'Alice' RETURN n",
        "CREATE (n:Person {name: 'Alice', age: 30})",
        "MERGE (n:Person {name: 'Alice'}) RETURN n",
        "MATCH (n:Person {name: 'Alice'}) SET n.age = 31 RETURN n",
        "MATCH (n) DETACH DELETE n",
        "UNWIND [1, 2, 3] AS x RETURN x * x AS square",
        "MATCH (a)-[r*1..3]->(b) RETURN length(r)",
        "MATCH (n) RETURN n ORDER BY n.name DESC SKIP 1 LIMIT 5",
        "MATCH (n) RETURN DISTINCT n.dept",
        "MATCH (n) RETURN count(*) AS total",
        "MATCH (n) WITH n WHERE n.x > 1 RETURN n",
        "MATCH (n) RETURN n UNION MATCH (m) RETURN m",
        "RETURN CASE WHEN 1 < 2 THEN 'yes' ELSE 'no' END AS answer",
        "WITH [1, 2, 3] AS xs RETURN [x IN xs WHERE x > 1 | x * 10] AS ys",
        "MATCH (a:Person) RETURN a.name STARTS WITH 'A' AS startsWithA",
        "CALL db.labels() YIELD label RETURN label ORDER BY label",
        "MATCH p = (a)-[:KNOWS*]->(b) WHERE a.name = 'Alice' RETURN p",
        "MATCH (n) WHERE n.age IN [20, 30, 40] AND n.active IS NOT NULL RETURN n",
    ];
    for q in examples {
        assert!(parse(q).is_ok(), "openCypher example failed to parse: {q}");
    }
}

// =================================================================================================
// Pattern predicates (rmp #126): a relationship pattern used directly as a boolean expression,
// `(n)-[]->()`, desugars to an `EXISTS { pattern }` existential (openCypher
// `PatternPredicate = RelationshipsPattern`).
// =================================================================================================

/// The `WHERE` expression of the first `MATCH` clause of `q` (panics if absent).
fn match_where(q: &str) -> Expr {
    let query = ok(q);
    for c in clauses(&query) {
        if let Clause::Match(m) = c {
            return m
                .where_clause
                .clone()
                .unwrap_or_else(|| panic!("query `{q}` has no MATCH ... WHERE"));
        }
    }
    panic!("query `{q}` has no MATCH clause");
}

/// Unwraps a pattern-predicate [`ExprKind::ExistsSubquery`] (asserting it came from a bare pattern
/// predicate, not an explicit `EXISTS {{ ... }}`), returning its single pattern element.
fn pattern_predicate_element(expr: &Expr) -> PatternElement {
    let ExprKind::ExistsSubquery(ex) = &expr.kind else {
        panic!(
            "expected a pattern-predicate ExistsSubquery, got {:?}",
            expr.kind
        );
    };
    assert!(
        ex.from_pattern_predicate,
        "expected from_pattern_predicate = true"
    );
    assert!(
        ex.predicate.is_none(),
        "a bare pattern predicate has no WHERE"
    );
    assert_eq!(
        ex.pattern.len(),
        1,
        "a pattern predicate is one pattern part"
    );
    let part = &ex.pattern[0];
    assert!(
        part.var.is_none(),
        "a pattern predicate has no path variable"
    );
    part.element.clone()
}

#[test]
fn pattern_predicate_simple_outgoing() {
    let where_e = match_where("MATCH (n) WHERE (n)-[]->() RETURN n");
    let element = pattern_predicate_element(&where_e);
    assert_eq!(
        element.start.variable.as_ref().map(|v| v.name.as_str()),
        Some("n")
    );
    assert_eq!(element.chain.len(), 1);
    assert_eq!(
        element.chain[0].relationship.direction,
        RelDirection::LeftToRight
    );
}

#[test]
fn pattern_predicate_directions() {
    // Undirected `-[]-`.
    let e = match_where("MATCH (n) WHERE (n)-[]-() RETURN n");
    assert_eq!(
        pattern_predicate_element(&e).chain[0]
            .relationship
            .direction,
        RelDirection::Undirected
    );
    // Incoming `<-[]-`.
    let e = match_where("MATCH (n) WHERE (n)<-[]-() RETURN n");
    assert_eq!(
        pattern_predicate_element(&e).chain[0]
            .relationship
            .direction,
        RelDirection::RightToLeft
    );
    // Arrow shorthands without a detail bracket: `-->`, `<--`, `--`.
    for (q, dir) in [
        (
            "MATCH (n) WHERE (n)-->() RETURN n",
            RelDirection::LeftToRight,
        ),
        (
            "MATCH (n) WHERE (n)<--() RETURN n",
            RelDirection::RightToLeft,
        ),
        ("MATCH (n) WHERE (n)--() RETURN n", RelDirection::Undirected),
    ] {
        let e = match_where(q);
        assert_eq!(
            pattern_predicate_element(&e).chain[0]
                .relationship
                .direction,
            dir,
            "wrong direction for `{q}`"
        );
    }
}

#[test]
fn pattern_predicate_with_type_and_var_length() {
    // Relationship type.
    let e = match_where("MATCH (n) WHERE (n)-[:REL1]->() RETURN n");
    let rel = &pattern_predicate_element(&e).chain[0].relationship;
    assert_eq!(rel.types.len(), 1);
    assert!(rel.range.is_none());
    // Type alternatives + variable length.
    let e = match_where("MATCH (n), (m) WHERE (n)-[:REL1|REL2*]-(m) RETURN n, m");
    let rel = &pattern_predicate_element(&e).chain[0].relationship;
    assert_eq!(rel.types.len(), 2);
    assert!(rel.range.is_some());
}

#[test]
fn pattern_predicate_multi_hop() {
    let e = match_where("MATCH (a) WHERE (a)-[:T]->(:C)<-[:T]-(a {num: 5}) RETURN a");
    let element = pattern_predicate_element(&e);
    assert_eq!(element.chain.len(), 2, "two relationship hops");
}

#[test]
fn pattern_predicate_combines_with_not_and_or() {
    // NOT (pattern).
    let e = match_where("MATCH (a) WHERE NOT (a)-[:T]->() RETURN a");
    let ExprKind::Unary {
        op: UnaryOp::Not,
        operand,
    } = &e.kind
    else {
        panic!("expected NOT, got {:?}", e.kind);
    };
    let _ = pattern_predicate_element(operand); // asserts the operand is a pattern predicate.

    // (pattern) AND (pattern): both operands are pattern predicates.
    let e = match_where("MATCH (n) WHERE (n)-[:A]-() AND (n)-[:B]-() RETURN n");
    let ExprKind::Binary {
        op: BinaryOp::And,
        lhs,
        rhs,
    } = &e.kind
    else {
        panic!("expected AND, got {:?}", e.kind);
    };
    let _ = pattern_predicate_element(lhs);
    let _ = pattern_predicate_element(rhs);
}

#[test]
fn disambiguation_parenthesized_arithmetic_is_not_a_pattern() {
    // The classic ambiguity: `(1 + 2) * 3` is arithmetic, never a pattern predicate.
    let k = return_kind("RETURN (1 + 2) * 3");
    let ExprKind::Binary {
        op: BinaryOp::Mul, ..
    } = k
    else {
        panic!("expected multiplication, got {k:?}");
    };
    // A parenthesized variable followed by subtraction stays arithmetic.
    let k = return_kind("RETURN (a) - 1");
    let ExprKind::Binary {
        op: BinaryOp::Sub, ..
    } = k
    else {
        panic!("expected subtraction, got {k:?}");
    };
    // A bare parenthesized expression is unwrapped, not turned into a pattern.
    assert!(matches!(return_kind("RETURN (n)"), ExprKind::Variable(_)));
}

#[test]
fn pattern_predicate_in_general_expression_position_parses() {
    // The parser accepts a pattern predicate anywhere an expression may appear; the *placement*
    // restriction (only valid in a predicate position) is a semantic concern, not a syntactic one.
    assert!(parse("MATCH (n) RETURN (n)-[]->()").is_ok());
    assert!(parse("MATCH (n) WITH (n)-[]->() AS x RETURN x").is_ok());
}

// =================================================================================================
// EXISTS subquery: pattern-form vs full-query-form disambiguation (rmp #123)
// =================================================================================================

/// Unwraps the sole `WHERE`-position [`ExprKind::ExistsSubquery`] of a `MATCH ... WHERE exists{...}`
/// query.
fn exists_subquery(q: &str) -> ExistsSubquery {
    let where_e = match_where(q);
    let ExprKind::ExistsSubquery(ex) = where_e.kind else {
        panic!(
            "expected an ExistsSubquery in `{q}`, got {:?}",
            where_e.kind
        );
    };
    *ex
}

#[test]
fn parse_exists_disambiguation_pattern_only() {
    // A bare pattern, an explicit MATCH, and a MATCH + WHERE — all the pattern form: `full_query`
    // is None and `pattern` is populated. The closing `}` immediately follows the pattern/WHERE.
    for q in [
        "MATCH (a) WHERE exists { (a)-->(b) } RETURN a",
        "MATCH (a) WHERE exists { MATCH (a)-->(b) } RETURN a",
        "MATCH (a) WHERE exists { MATCH (a)-->(b) WHERE a.x = 1 } RETURN a",
    ] {
        let ex = exists_subquery(q);
        assert!(
            ex.full_query.is_none(),
            "`{q}` must be the pattern form (full_query None)"
        );
        assert_eq!(ex.pattern.len(), 1, "`{q}` must carry its pattern part");
        assert!(
            !ex.from_pattern_predicate,
            "an explicit EXISTS is not a pattern predicate"
        );
    }
}

#[test]
fn parse_exists_disambiguation_full_query() {
    // Clauses following the leading pattern (RETURN / WITH) flip it to the full-query form:
    // `full_query` is Some, `pattern` is empty, and the synthesized first clause is a MATCH over the
    // leading pattern.
    for q in [
        "MATCH (a) WHERE exists { MATCH (a)-->(b) RETURN true } RETURN a",
        "MATCH (a) WHERE exists { MATCH (a)-->(b) WITH a RETURN a } RETURN a",
        // The leading MATCH keyword is optional even in the full-query form.
        "MATCH (a) WHERE exists { (a)-->(b) RETURN true } RETURN a",
    ] {
        let ex = exists_subquery(q);
        let inner = ex
            .full_query
            .as_ref()
            .unwrap_or_else(|| panic!("`{q}` must be the full-query form (full_query Some)"));
        assert!(ex.pattern.is_empty(), "full-query form has empty pattern");
        assert!(ex.predicate.is_none(), "full-query form has no predicate");

        let QueryBody::Regular { head, .. } = &inner.body else {
            panic!("`{q}` inner query should be a regular query");
        };
        let Clause::Match(first) = &head.clauses[0] else {
            panic!(
                "`{q}` synthesized first clause should be a MATCH, got {:?}",
                head.clauses[0]
            );
        };
        assert!(!first.optional, "synthesized MATCH is not OPTIONAL");
        assert_eq!(
            first.pattern.len(),
            1,
            "`{q}` synthesized MATCH carries the leading pattern (a)-->(b)"
        );
        // The leading pattern is (a)-->(b): a node `a` with one outgoing hop to `b`.
        let element = &first.pattern[0].element;
        assert_eq!(
            element.start.variable.as_ref().map(|v| v.name.as_str()),
            Some("a")
        );
        assert_eq!(
            element.chain.len(),
            1,
            "one relationship hop in the lead pattern"
        );
        // A RETURN closes the inner query.
        assert!(
            matches!(head.clauses.last(), Some(Clause::Return(_))),
            "`{q}` inner query ends in RETURN"
        );
    }
}

#[test]
fn parse_exists_full_query_with_aggregation_and_where() {
    // The aggregation scenario (TCK ExistentialSubquery2 [2]) parses into MATCH / WITH / RETURN.
    let ex = exists_subquery(
        "MATCH (n) WHERE exists { MATCH (n)-->(m) WITH n, count(*) AS c WHERE c = 3 RETURN true } RETURN n",
    );
    let inner = ex.full_query.expect("full-query form");
    let QueryBody::Regular { head, .. } = &inner.body else {
        panic!("regular query expected");
    };
    assert!(matches!(head.clauses[0], Clause::Match(_)));
    assert!(matches!(head.clauses[1], Clause::With(_)));
    assert!(matches!(head.clauses[2], Clause::Return(_)));
}
