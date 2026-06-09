//! Integration tests for the Cypher **physical planner** (`graphus_cypher::physical`,
//! `04-technical-design.md` §7.1, §6.6).
//!
//! Each test compiles a query through the full front-end (`tokenize → parse → analyze → lower`),
//! then `plan_physical` against a purpose-built [`IndexCatalog`], and asserts the chosen physical
//! operator(s) and the recorded index dependencies. Assertions use structural pattern matching on
//! the [`PhysicalOp`] tree (the load-bearing shape) plus the golden [`Display`] rendering.
//!
//! Coverage map: index selection (equality seek / range seek / token-lookup scan / scan+filter
//! fallback / composite leading-key); expand-into vs expand-all; hash vs nested-loop join; Sort+Limit
//! → Top-N; Limit pushdown (and the negative cases where it must NOT push); index-dependency
//! recording for cache invalidation; residual-filter retention; carry-through of write/procedure
//! operators.

use graphus_cypher::catalog::{IndexCatalog, IndexKind};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalOp, PhysicalPlan, RangeBound, plan_physical};
use graphus_cypher::semantics::analyze;

/// Compiles `src` to a physical plan against `catalog`, panicking with context on any failure.
fn physical(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).unwrap_or_else(|e| panic!("lex `{src}`: {e:?}"));
    let ast = parse_tokens(&toks, src).unwrap_or_else(|e| panic!("parse `{src}`: {e:?}"));
    let validated = analyze(&ast).unwrap_or_else(|e| panic!("analyze `{src}`: {e:?}"));
    plan_physical(&lower(&validated), catalog)
}

/// The rendered physical plan string.
fn rendered(src: &str, catalog: &IndexCatalog) -> String {
    physical(src, catalog).to_string()
}

/// Walks the physical tree, returning the first operator satisfying `pred` (pre-order).
fn find<'a>(op: &'a PhysicalOp, pred: &dyn Fn(&PhysicalOp) -> bool) -> Option<&'a PhysicalOp> {
    if pred(op) {
        return Some(op);
    }
    for child in children(op) {
        if let Some(found) = find(child, pred) {
            return Some(found);
        }
    }
    None
}

/// The child operators of `op` (for the generic walker).
fn children(op: &PhysicalOp) -> Vec<&PhysicalOp> {
    match op {
        PhysicalOp::ExpandAll { input, .. }
        | PhysicalOp::ExpandInto { input, .. }
        | PhysicalOp::Filter { input, .. }
        | PhysicalOp::Projection { input, .. }
        | PhysicalOp::Aggregation { input, .. }
        | PhysicalOp::Sort { input, .. }
        | PhysicalOp::TopN { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Unwind { input, .. }
        | PhysicalOp::Optional { input, .. }
        | PhysicalOp::Create { input, .. }
        | PhysicalOp::Merge { input, .. }
        | PhysicalOp::SetClause { input, .. }
        | PhysicalOp::Delete { input, .. }
        | PhysicalOp::Remove { input, .. } => vec![input],
        PhysicalOp::NestedLoopJoin { left, right }
        | PhysicalOp::HashJoin { left, right, .. }
        | PhysicalOp::Union { left, right, .. } => vec![left, right],
        PhysicalOp::ProcedureCall { input, .. } => input.iter().map(Box::as_ref).collect(),
        _ => Vec::new(),
    }
}

// =================================================================================================
// Index selection
// =================================================================================================

#[test]
fn equality_on_indexed_property_becomes_index_seek() {
    let catalog = IndexCatalog::builder()
        .with_label_property("Person", "name")
        .build();
    let plan = physical("MATCH (n:Person {name: 'Ada'}) RETURN n", &catalog);
    let seek = find(&plan.root, &|op| {
        matches!(op, PhysicalOp::NodeIndexSeek { .. })
    })
    .expect("an index seek");
    match seek {
        PhysicalOp::NodeIndexSeek {
            variable,
            label,
            property,
            index,
            ..
        } => {
            assert_eq!(variable.name, "n");
            assert_eq!(label.name, "Person");
            assert_eq!(property, "name");
            // The plan records its dependency on exactly that index.
            assert!(plan.depends_on(*index));
        }
        _ => unreachable!(),
    }
    // Exactly one index dependency.
    assert_eq!(plan.index_dependencies().count(), 1);
}

#[test]
fn equality_via_explicit_where_becomes_index_seek() {
    let catalog = IndexCatalog::builder()
        .with_label_property("Person", "age")
        .build();
    let plan = physical("MATCH (n:Person) WHERE n.age = 30 RETURN n", &catalog);
    assert!(
        find(&plan.root, &|op| matches!(
            op,
            PhysicalOp::NodeIndexSeek { .. }
        ))
        .is_some(),
        "{plan}"
    );
}

#[test]
fn no_index_falls_back_to_label_scan_plus_filter() {
    let catalog = IndexCatalog::empty();
    let plan = physical("MATCH (n:Person {name: 'Ada'}) RETURN n", &catalog);
    let rendered = plan.to_string();
    assert!(rendered.contains("NodeByLabelScan(n:Person)"), "{rendered}");
    assert!(rendered.contains("Filter("), "{rendered}");
    assert!(!rendered.contains("Seek"), "{rendered}");
    assert_eq!(plan.index_dependencies().count(), 0);
}

#[test]
fn range_predicate_with_range_index_becomes_range_seek() {
    let catalog = IndexCatalog::builder()
        .with_label_property("Person", "age")
        .build();
    let plan = physical("MATCH (n:Person) WHERE n.age > 18 RETURN n", &catalog);
    let seek = find(&plan.root, &|op| {
        matches!(op, PhysicalOp::NodeIndexRangeSeek { .. })
    })
    .expect("a range seek");
    match seek {
        PhysicalOp::NodeIndexRangeSeek {
            property, bound, ..
        } => {
            assert_eq!(property, "age");
            assert_eq!(*bound, RangeBound::GreaterThan);
        }
        _ => unreachable!(),
    }
}

#[test]
fn range_predicate_mirrors_when_property_on_right() {
    // `18 < n.age` is the same as `n.age > 18`: the bound mirrors.
    let catalog = IndexCatalog::builder()
        .with_label_property("Person", "age")
        .build();
    let plan = physical("MATCH (n:Person) WHERE 18 < n.age RETURN n", &catalog);
    let seek = find(&plan.root, &|op| {
        matches!(op, PhysicalOp::NodeIndexRangeSeek { .. })
    })
    .expect("a range seek");
    if let PhysicalOp::NodeIndexRangeSeek { bound, .. } = seek {
        assert_eq!(*bound, RangeBound::GreaterThan);
    }
}

#[test]
fn bare_label_match_with_token_lookup_index_becomes_token_scan() {
    let catalog = IndexCatalog::builder().with_token_lookup("Person").build();
    let plan = physical("MATCH (n:Person) RETURN n", &catalog);
    let scan = find(&plan.root, &|op| {
        matches!(op, PhysicalOp::TokenLookupScan { .. })
    })
    .expect("a token-lookup scan");
    match scan {
        PhysicalOp::TokenLookupScan { label, index, .. } => {
            assert_eq!(label.name, "Person");
            assert!(plan.depends_on(*index));
        }
        _ => unreachable!(),
    }
    assert_eq!(plan.index_dependencies().count(), 1);
}

#[test]
fn bare_label_match_without_token_index_is_label_scan() {
    let catalog = IndexCatalog::empty();
    let plan = physical("MATCH (n:Person) RETURN n", &catalog);
    assert!(
        plan.to_string().contains("NodeByLabelScan(n:Person)"),
        "{plan}"
    );
    assert!(!plan.to_string().contains("TokenLookupScan"), "{plan}");
}

#[test]
fn composite_leading_key_equality_becomes_index_seek() {
    let catalog = IndexCatalog::builder()
        .with_label_composite("Person", ["name", "age"])
        .build();
    // A predicate on the leading composite key `name` is servable as a leading-prefix seek.
    let plan = physical("MATCH (n:Person) WHERE n.name = 'Ada' RETURN n", &catalog);
    let seek = find(&plan.root, &|op| {
        matches!(op, PhysicalOp::NodeIndexSeek { .. })
    })
    .expect("a composite leading-key seek");
    if let PhysicalOp::NodeIndexSeek { index, .. } = seek {
        assert_eq!(catalog.get(*index).unwrap().kind, IndexKind::Composite);
    }
}

#[test]
fn non_leading_composite_key_does_not_seek() {
    let catalog = IndexCatalog::builder()
        .with_label_composite("Person", ["name", "age"])
        .build();
    // A predicate on the non-leading key `age` cannot drive a single-predicate seek.
    let plan = physical("MATCH (n:Person) WHERE n.age = 30 RETURN n", &catalog);
    assert!(
        find(&plan.root, &|op| matches!(
            op,
            PhysicalOp::NodeIndexSeek { .. }
        ))
        .is_none(),
        "non-leading composite key must not seek: {plan}"
    );
    assert_eq!(plan.index_dependencies().count(), 0);
}

#[test]
fn one_conjunct_seeks_and_the_rest_stays_as_residual_filter() {
    let catalog = IndexCatalog::builder()
        .with_label_property("Person", "name")
        .build();
    // `name = 'Ada' AND age > 18`: name drives the seek; age stays a residual filter.
    let plan = physical(
        "MATCH (n:Person) WHERE n.name = 'Ada' AND n.age > 18 RETURN n",
        &catalog,
    );
    assert!(
        find(&plan.root, &|op| matches!(
            op,
            PhysicalOp::NodeIndexSeek { .. }
        ))
        .is_some(),
        "{plan}"
    );
    assert!(
        find(&plan.root, &|op| matches!(op, PhysicalOp::Filter { .. })).is_some(),
        "a residual filter for the un-consumed conjunct: {plan}"
    );
    // The whole-plan rendering shows the age predicate retained as a residual filter and the name
    // equality consumed into the seek (`name = 'Ada'` appears in the seek, not the filter).
    let r = plan.to_string();
    assert!(r.contains("NodeIndexSeek"), "{r}");
    assert!(
        r.contains("age"),
        "the un-consumed age predicate is retained: {r}"
    );
    // The name equality must appear as a seek (`name = 'Ada' via …`), not inside the residual
    // Filter(...). It appears exactly once in the seek line.
    assert_eq!(
        r.matches("'Ada'").count(),
        1,
        "name equality consumed once into the seek: {r}"
    );
}

#[test]
fn index_seek_value_is_an_unevaluated_expression_not_a_bound_value() {
    // The seek carries the AST expression (parameter-independent); it does not bind a value.
    let catalog = IndexCatalog::builder()
        .with_label_property("Person", "age")
        .build();
    let plan = physical("MATCH (n:Person) WHERE n.age = $a RETURN n", &catalog);
    let seek = find(&plan.root, &|op| {
        matches!(op, PhysicalOp::NodeIndexSeek { .. })
    })
    .expect("a parameterised seek");
    if let PhysicalOp::NodeIndexSeek { value, .. } = seek {
        assert!(
            matches!(value.kind, graphus_cypher::ast::ExprKind::Parameter(_)),
            "seek value stays a parameter (binds at execution)"
        );
    }
}

// =================================================================================================
// Expand: into vs all
// =================================================================================================

#[test]
fn expand_with_one_bound_endpoint_is_expand_all() {
    // `(a)-[r]->(b)`: a is the anchor, b is new -> expand-all.
    let catalog = IndexCatalog::empty();
    let plan = physical("MATCH (a)-[r]->(b) RETURN a, b", &catalog);
    assert!(
        find(&plan.root, &|op| matches!(op, PhysicalOp::ExpandAll { .. })).is_some(),
        "{plan}"
    );
    assert!(
        find(&plan.root, &|op| matches!(
            op,
            PhysicalOp::ExpandInto { .. }
        ))
        .is_none(),
        "{plan}"
    );
}

#[test]
fn expand_with_both_endpoints_bound_is_expand_into() {
    // A triangle: `(a)-->(b)-->(c)-->(a)` binds `a` and the final hop's `to` is the already-bound
    // `a`, so the closing expand is an expand-into (a cycle/connection check).
    let catalog = IndexCatalog::empty();
    let plan = physical("MATCH (a)-->(b)-->(c)-->(a) RETURN a", &catalog);
    assert!(
        find(&plan.root, &|op| matches!(
            op,
            PhysicalOp::ExpandInto { .. }
        ))
        .is_some(),
        "the closing hop into the bound `a` must be expand-into: {plan}"
    );
}

#[test]
fn expand_into_endpoints_are_both_already_bound() {
    let catalog = IndexCatalog::empty();
    let plan = physical("MATCH (a)-->(b)-->(c)-->(a) RETURN a", &catalog);
    let into = find(&plan.root, &|op| {
        matches!(op, PhysicalOp::ExpandInto { .. })
    })
    .unwrap();
    if let PhysicalOp::ExpandInto { from, to, .. } = into {
        // `to` is `a` (the cycle close); `from` is `c`. Both already in scope from the input.
        assert_eq!(to.name, "a");
        assert_eq!(from.name, "c");
    }
}

// =================================================================================================
// Join heuristic: hash vs nested-loop
// =================================================================================================

#[test]
fn correlated_optional_match_is_nested_loop_join() {
    // OPTIONAL MATCH lowers to Apply(left, Optional(rhs-over-Argument)) — correlated -> nested loop.
    let catalog = IndexCatalog::empty();
    let plan = physical("MATCH (a) OPTIONAL MATCH (a)-->(b) RETURN a, b", &catalog);
    assert!(
        find(&plan.root, &|op| matches!(
            op,
            PhysicalOp::NestedLoopJoin { .. }
        ))
        .is_some(),
        "correlated apply must be a nested-loop join: {plan}"
    );
}

#[test]
fn equi_join_on_shared_variable_is_hash_join() {
    // Two comma-separated components sharing the node variable `a` give an equi-join on `a`.
    // The logical planner correlates a disconnected comma-component via Apply, but the right side
    // here re-uses `a` so the two independent scans share a join key -> hash join.
    let catalog = IndexCatalog::empty();
    // `MATCH (a), (a)` is degenerate; use a shared variable across two pattern parts where the
    // second part does NOT read the first through an Argument: `MATCH (a:A) MATCH (a:A)` re-binds
    // `a`. We instead exercise a genuine equi-join through UNION-free shared-key apply by checking
    // the join classifier directly on independent scans.
    use graphus_cypher::physical::choose_join;
    let left = PhysicalOp::NodeByLabelScan {
        variable: graphus_cypher::logical::Var::named("a"),
        label: graphus_cypher::ast::Label {
            name: "A".to_owned(),
            span: graphus_cypher::lexer::Span::new(0, 0),
        },
    };
    let right = PhysicalOp::NodeByLabelScan {
        variable: graphus_cypher::logical::Var::named("a"),
        label: graphus_cypher::ast::Label {
            name: "A".to_owned(),
            span: graphus_cypher::lexer::Span::new(0, 0),
        },
    };
    // An independent (non-correlated) right branch sharing the key `a`.
    let logical_right = graphus_cypher::logical::LogicalOp::NodeByLabelScan {
        variable: graphus_cypher::logical::Var::named("a"),
        label: graphus_cypher::ast::Label {
            name: "A".to_owned(),
            span: graphus_cypher::lexer::Span::new(0, 0),
        },
    };
    let joined = choose_join(left, right, &logical_right);
    match joined {
        PhysicalOp::HashJoin { join_keys, .. } => assert_eq!(join_keys, vec!["a".to_owned()]),
        other => panic!("expected a hash join on `a`, got {other}"),
    }
    let _ = catalog; // catalog unused for the direct-classifier portion.
}

#[test]
fn cartesian_product_with_no_shared_key_is_nested_loop_join() {
    use graphus_cypher::physical::choose_join;
    let left = PhysicalOp::AllNodesScan {
        variable: graphus_cypher::logical::Var::named("a"),
    };
    let right = PhysicalOp::AllNodesScan {
        variable: graphus_cypher::logical::Var::named("b"),
    };
    let logical_right = graphus_cypher::logical::LogicalOp::AllNodesScan {
        variable: graphus_cypher::logical::Var::named("b"),
    };
    // No shared key (`a` vs `b`) -> nested loop (cartesian product).
    match choose_join(left, right, &logical_right) {
        PhysicalOp::NestedLoopJoin { .. } => {}
        other => panic!("expected a nested-loop join, got {other}"),
    }
}

// =================================================================================================
// Sort / Limit pushdown
// =================================================================================================

#[test]
fn sort_then_limit_becomes_topn() {
    let catalog = IndexCatalog::empty();
    let plan = physical(
        "MATCH (n) RETURN n.age AS age ORDER BY age LIMIT 5",
        &catalog,
    );
    let topn = find(&plan.root, &|op| matches!(op, PhysicalOp::TopN { .. }))
        .expect("a Top-N from the fused Sort+Limit");
    if let PhysicalOp::TopN { keys, .. } = topn {
        assert_eq!(keys.len(), 1);
    }
    // No standalone Sort/Limit survive (they fused).
    assert!(
        find(&plan.root, &|op| matches!(op, PhysicalOp::Sort { .. })).is_none(),
        "the Sort fused into TopN: {plan}"
    );
}

#[test]
fn limit_is_pushed_below_a_row_preserving_projection() {
    let catalog = IndexCatalog::empty();
    let plan = physical("MATCH (n) RETURN n.age AS age LIMIT 5", &catalog);
    // The root is the projection; the Limit was pushed below it.
    match &plan.root {
        PhysicalOp::Projection {
            input, distinct, ..
        } => {
            assert!(!distinct);
            assert!(
                matches!(**input, PhysicalOp::Limit { .. }),
                "Limit must be pushed below the projection: {plan}"
            );
        }
        other => panic!("expected Projection root, got {other}"),
    }
}

#[test]
fn limit_is_not_pushed_below_a_distinct_projection() {
    // DISTINCT changes the row count; pushing the Limit below it would change results.
    let catalog = IndexCatalog::empty();
    let plan = physical("MATCH (n) RETURN DISTINCT n.age AS age LIMIT 5", &catalog);
    match &plan.root {
        PhysicalOp::Limit { input, .. } => {
            assert!(
                matches!(**input, PhysicalOp::Projection { distinct: true, .. }),
                "Limit stays ABOVE the DISTINCT projection: {plan}"
            );
        }
        other => panic!("expected a Limit root above the DISTINCT projection, got {other}"),
    }
}

#[test]
fn limit_is_not_pushed_below_an_aggregation() {
    // Aggregation collapses rows; the Limit must stay above it.
    let catalog = IndexCatalog::empty();
    let plan = physical(
        "MATCH (n) RETURN n.dept AS d, count(*) AS c LIMIT 3",
        &catalog,
    );
    match &plan.root {
        PhysicalOp::Limit { input, .. } => {
            assert!(
                matches!(**input, PhysicalOp::Aggregation { .. }),
                "Limit stays above the Aggregation: {plan}"
            );
        }
        other => panic!("expected a Limit above the Aggregation, got {other}"),
    }
}

#[test]
fn standalone_sort_without_limit_stays_a_sort() {
    let catalog = IndexCatalog::empty();
    let plan = physical("MATCH (n) RETURN n.age AS age ORDER BY age", &catalog);
    assert!(
        find(&plan.root, &|op| matches!(op, PhysicalOp::Sort { .. })).is_some(),
        "no Limit means no TopN fusion: {plan}"
    );
    assert!(
        find(&plan.root, &|op| matches!(op, PhysicalOp::TopN { .. })).is_none(),
        "{plan}"
    );
}

// =================================================================================================
// Carry-through and golden rendering
// =================================================================================================

#[test]
fn write_operators_carry_through_to_physical() {
    let catalog = IndexCatalog::empty();
    let plan = physical("CREATE (n:Person {name: 'Ada'})", &catalog);
    assert!(plan.to_string().contains("Create("), "{plan}");
}

#[test]
fn procedure_call_carries_through_to_physical() {
    let catalog = IndexCatalog::empty();
    let plan = physical("CALL db.labels()", &catalog);
    assert!(
        plan.to_string().contains("ProcedureCall(db.labels"),
        "{plan}"
    );
}

#[test]
fn golden_render_index_seek_plan() {
    let catalog = IndexCatalog::builder()
        .with_label_property("Person", "name")
        .build();
    // The whole plan renders stably, leaf-deepest-indented (matching the logical printer style).
    let r = rendered("MATCH (n:Person {name: 'Ada'}) RETURN n", &catalog);
    assert_eq!(
        r,
        "Projection(n AS n)\n  NodeIndexSeek(n:Person name = 'Ada' via idx#0)\n"
    );
}

#[test]
fn golden_render_topn_plan() {
    let catalog = IndexCatalog::empty();
    // `ORDER BY` sorts over the projection (lowering puts Sort above Projection), and the trailing
    // `LIMIT` over that Sort fuses into a Top-N at the root: `TopN ▸ Projection ▸ AllNodesScan`.
    let r = rendered(
        "MATCH (n) RETURN n.age AS age ORDER BY age DESC LIMIT 2",
        &catalog,
    );
    assert_eq!(
        r,
        "TopN(age DESC LIMIT 2)\n  Projection(n.age AS age)\n    AllNodesScan(n)\n"
    );
}
