//! Integration tests for the Cypher **logical planner** (`graphus_cypher::lower`,
//! `04-technical-design.md` §7.1).
//!
//! Each test lowers a representative query through the full front-end
//! (`tokenize → parse → analyze → lower`) and asserts the resulting [`LogicalOp`] tree, both by
//! **structural pattern matching** (the load-bearing shape and fields) and by **golden
//! [`Display`]** string (a stable, human-readable rendering of the whole tree). The two together
//! catch both shape regressions and field/ordering regressions.
//!
//! Coverage map (one or more tests each): simple MATCH-RETURN; MATCH-WHERE-RETURN (filter
//! placement); relationship expand (direction/type/var-length); 2-hop pattern; multi-clause WITH
//! boundary (scope reset); OPTIONAL MATCH (Apply/Optional left-outer); aggregation (group keys +
//! aggregates); ORDER BY/SKIP/LIMIT; UNWIND; CREATE/MERGE(+ON CREATE/MATCH SET)/SET/DELETE/REMOVE;
//! CALL YIELD; UNION ALL; the inline-property normalisation rule (fires adjacent to its scan) and a
//! companion test that a `WHERE` is *not* pushed below the pattern scans (semantics-preserving
//! boundary); the [`Display`] pretty-printer.

use graphus_cypher::ast::{ExprKind, RelDirection, SortDirection};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::logical::{CreatePart, LogicalOp, RemoveOp, SetOp};
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::semantics::analyze;

/// Lowers a query string to its logical plan, panicking with context on any front-end failure.
fn plan(src: &str) -> LogicalOp {
    let toks = tokenize(src).unwrap_or_else(|e| panic!("lex `{src}`: {e:?}"));
    let ast = parse_tokens(&toks, src).unwrap_or_else(|e| panic!("parse `{src}`: {e:?}"));
    let validated = analyze(&ast).unwrap_or_else(|e| panic!("analyze `{src}`: {e:?}"));
    lower(&validated)
}

/// Lowers a query and returns its golden [`Display`] rendering.
fn rendered(src: &str) -> String {
    plan(src).to_string()
}

// =================================================================================================
// Leaf reads and simple projections
// =================================================================================================

#[test]
fn simple_match_return_lowers_to_projection_over_all_nodes_scan() {
    let plan = plan("MATCH (n) RETURN n");
    // Root is the RETURN projection over an all-nodes scan.
    match &plan {
        LogicalOp::Projection {
            input,
            items,
            distinct,
        } => {
            assert!(!distinct, "no DISTINCT");
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].alias, "n");
            assert!(matches!(**input, LogicalOp::AllNodesScan { .. }));
        }
        other => panic!("expected Projection root, got: {other}"),
    }
    assert_eq!(
        rendered("MATCH (n) RETURN n"),
        "Projection(n AS n)\n  AllNodesScan(n)\n"
    );
}

#[test]
fn labelled_match_lowers_to_node_by_label_scan_not_index_seek() {
    // The logical plan stays index-agnostic: a labelled match is a *label* scan, never a seek.
    let plan = plan("MATCH (n:Person) RETURN n");
    match &plan {
        LogicalOp::Projection { input, .. } => match &**input {
            LogicalOp::NodeByLabelScan { variable, label } => {
                assert_eq!(variable.name, "n");
                assert_eq!(label.name, "Person");
            }
            other => panic!("expected NodeByLabelScan, got: {other}"),
        },
        other => panic!("expected Projection root, got: {other}"),
    }
}

#[test]
fn multiple_labels_lower_to_label_scan_plus_haslabels_filter() {
    // First label drives the scan; residual labels become a HasLabels filter (index-agnostic).
    assert_eq!(
        rendered("MATCH (a:A:B) RETURN a"),
        "Projection(a AS a)\n  Filter(a:B)\n    NodeByLabelScan(a:A)\n"
    );
}

#[test]
fn query_with_no_reading_clause_starts_from_empty() {
    // `RETURN 1` has one driving row (the Empty leaf), so it yields exactly one result row.
    assert_eq!(
        rendered("RETURN 1 AS one"),
        "Projection(1 AS one)\n  Empty\n"
    );
}

// =================================================================================================
// WHERE filter placement
// =================================================================================================

#[test]
fn where_lowers_to_filter_above_the_scan() {
    // The WHERE predicate becomes a Filter sitting directly above the (label) scan, below RETURN.
    let plan = plan("MATCH (n:Person) WHERE n.age > 18 RETURN n.name AS name");
    match &plan {
        LogicalOp::Projection { input, items, .. } => {
            assert_eq!(items[0].alias, "name");
            match &**input {
                LogicalOp::Filter { input, predicate } => {
                    // predicate is the `n.age > 18` comparison.
                    assert!(matches!(predicate.kind, ExprKind::Binary { .. }));
                    assert!(matches!(**input, LogicalOp::NodeByLabelScan { .. }));
                }
                other => panic!("expected Filter, got: {other}"),
            }
        }
        other => panic!("expected Projection root, got: {other}"),
    }
    assert_eq!(
        rendered("MATCH (n:Person) WHERE n.age > 18 RETURN n.name AS name"),
        "Projection(n.name AS name)\n  Filter((n.age > 18))\n    NodeByLabelScan(n:Person)\n"
    );
}

// =================================================================================================
// Relationship expansion
// =================================================================================================

#[test]
fn relationship_match_lowers_to_expand_over_scan() {
    let plan = plan("MATCH (a)-[r:KNOWS]->(b) RETURN b");
    match &plan {
        LogicalOp::Projection { input, .. } => match &**input {
            LogicalOp::Expand {
                input,
                from,
                relationship,
                to,
                direction,
                types,
                range,
                ..
            } => {
                assert_eq!(from.name, "a");
                assert_eq!(relationship.name, "r");
                assert_eq!(to.name, "b");
                assert_eq!(*direction, RelDirection::LeftToRight);
                assert_eq!(types.len(), 1);
                assert_eq!(types[0].name, "KNOWS");
                assert!(range.is_none(), "single hop has no range");
                assert!(matches!(**input, LogicalOp::AllNodesScan { .. }));
            }
            other => panic!("expected Expand, got: {other}"),
        },
        other => panic!("expected Projection root, got: {other}"),
    }
}

#[test]
fn right_to_left_relationship_keeps_direction() {
    let plan = plan("MATCH (a)<-[r:KNOWS]-(b) RETURN b");
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection");
    };
    let LogicalOp::Expand { direction, .. } = &**input else {
        panic!("expected Expand");
    };
    assert_eq!(*direction, RelDirection::RightToLeft);
}

#[test]
fn undirected_relationship_keeps_direction() {
    let plan = plan("MATCH (a)-[r:KNOWS]-(b) RETURN b");
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection");
    };
    let LogicalOp::Expand { direction, .. } = &**input else {
        panic!("expected Expand");
    };
    assert_eq!(*direction, RelDirection::Undirected);
}

#[test]
fn anonymous_relationship_gets_synthetic_variable() {
    // `MATCH (a)-->(b)` has an anonymous relationship; the planner generates a synthetic name.
    let plan = plan("MATCH (a)-->(b) RETURN b");
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection");
    };
    let LogicalOp::Expand { relationship, .. } = &**input else {
        panic!("expected Expand");
    };
    assert!(relationship.synthetic, "anonymous rel must be synthetic");
}

#[test]
fn two_hop_pattern_lowers_to_two_expands_with_correct_direction_and_types() {
    // 2-hop pattern lowers to scan + two stacked Expands, each carrying its direction/types.
    let plan = plan("MATCH (a)-[:KNOWS]->(b)-[:LIKES]->(c) RETURN c");
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection");
    };
    // Outer expand is the second hop b->c (LIKES); its input is the first hop a->b (KNOWS).
    let LogicalOp::Expand {
        input: inner,
        from,
        to,
        types,
        ..
    } = &**input
    else {
        panic!("expected outer Expand");
    };
    assert_eq!(from.name, "b");
    assert_eq!(to.name, "c");
    assert_eq!(types[0].name, "LIKES");
    let LogicalOp::Expand {
        input: scan,
        from,
        to,
        types,
        ..
    } = &**inner
    else {
        panic!("expected inner Expand");
    };
    assert_eq!(from.name, "a");
    assert_eq!(to.name, "b");
    assert_eq!(types[0].name, "KNOWS");
    assert!(matches!(**scan, LogicalOp::AllNodesScan { .. }));

    assert_eq!(
        rendered("MATCH (a)-[:KNOWS]->(b)-[:LIKES]->(c) RETURN c"),
        "Projection(c AS c)\n  \
         Expand(b)-[anon_1:LIKES]->(c)\n    \
         Expand(a)-[anon_0:KNOWS]->(b)\n      \
         AllNodesScan(a)\n"
    );
}

#[test]
fn variable_length_range_is_carried_onto_expand() {
    // `*1..3` is carried verbatim onto the Expand operator.
    let plan = plan("MATCH (a)-[r:KNOWS*1..3]->(b) RETURN b");
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection");
    };
    let LogicalOp::Expand { range, .. } = &**input else {
        panic!("expected Expand");
    };
    let range = range.expect("range present");
    assert_eq!(range.min, Some(1));
    assert_eq!(range.max, Some(3));
    assert!(rendered("MATCH (a)-[r:KNOWS*1..3]->(b) RETURN b").contains("*1..3"));
}

#[test]
fn unbounded_var_length_renders_star() {
    assert!(rendered("MATCH (a)-[r*]->(b) RETURN b").contains("-[r*]->"));
}

// =================================================================================================
// Multi-clause WITH boundary (scope reset)
// =================================================================================================

#[test]
fn with_is_a_projection_boundary() {
    // `WITH n AS m` becomes a Projection between the scan and the final RETURN; the trailing WHERE
    // sits above the WITH projection (post-projection scope) and references the reset name `m`.
    let plan = plan("MATCH (n) WITH n AS m WHERE m.x > 1 RETURN m");
    let LogicalOp::Projection { input: ret_in, .. } = &plan else {
        panic!("expected final Projection");
    };
    // The RETURN's input is the WITH's WHERE filter.
    let LogicalOp::Filter {
        input: with_proj,
        predicate,
    } = &**ret_in
    else {
        panic!("expected Filter (WITH...WHERE), got: {ret_in}");
    };
    // The filter references the reset name `m`, proving it is evaluated post-projection.
    assert!(matches!(predicate.kind, ExprKind::Binary { .. }));
    // Below the filter is the WITH projection (n AS m).
    let LogicalOp::Projection {
        input: scan, items, ..
    } = &**with_proj
    else {
        panic!("expected WITH Projection, got: {with_proj}");
    };
    assert_eq!(items[0].alias, "m");
    assert!(matches!(**scan, LogicalOp::AllNodesScan { .. }));

    assert_eq!(
        rendered("MATCH (n) WITH n AS m WHERE m.x > 1 RETURN m"),
        "Projection(m AS m)\n  \
         Filter((m.x > 1))\n    \
         Projection(n AS m)\n      \
         AllNodesScan(n)\n"
    );
}

#[test]
fn with_star_carries_bindings_through() {
    // `WITH *` projects each currently-bound variable as itself.
    let r = rendered("MATCH (n) WITH * RETURN n");
    // The WITH projection projects `n AS n`.
    assert!(r.contains("Projection(n AS n)"), "rendered:\n{r}");
}

// =================================================================================================
// OPTIONAL MATCH (left-outer via Apply/Optional)
// =================================================================================================

#[test]
fn optional_match_lowers_to_apply_over_optional() {
    // `MATCH (a) OPTIONAL MATCH (a)-[r]->(b)` is left-outer: Apply(left, Optional(expand/argument)).
    let plan = plan("MATCH (a) OPTIONAL MATCH (a)-[r]->(b) RETURN a, b");
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection root");
    };
    let LogicalOp::Apply { left, right } = &**input else {
        panic!("expected Apply, got: {input}");
    };
    // Left is the required MATCH (a).
    assert!(matches!(**left, LogicalOp::AllNodesScan { .. }));
    // Right is Optional over the correlated expand.
    let LogicalOp::Optional {
        input: opt_in,
        null_variables,
    } = &**right
    else {
        panic!("expected Optional, got: {right}");
    };
    // The newly-introduced optional variables (r, b) are null-filled; the carried `a` is not.
    let names: Vec<&str> = null_variables.iter().map(|v| v.name.as_str()).collect();
    assert!(names.contains(&"r") && names.contains(&"b"));
    assert!(
        !names.contains(&"a"),
        "carried variable must not be null-filled"
    );
    // The optional pattern reads from an Argument(a) leaf (correlated to the left binding).
    let LogicalOp::Expand { input: arg, .. } = &**opt_in else {
        panic!("expected Expand under Optional, got: {opt_in}");
    };
    match &**arg {
        LogicalOp::Argument { arguments } => {
            assert!(arguments.iter().any(|v| v.name == "a"));
        }
        other => panic!("expected Argument leaf, got: {other}"),
    }

    assert_eq!(
        rendered("MATCH (a) OPTIONAL MATCH (a)-[r]->(b) RETURN a, b"),
        "Projection(a AS a, b AS b)\n  \
         Apply\n    \
         AllNodesScan(a)\n    \
         Optional(nulls=[r, b])\n      \
         Expand(a)-[r]->(b)\n        \
         Argument(a)\n"
    );
}

#[test]
fn leading_optional_match_preserves_the_unit_driving_row() {
    // A leading OPTIONAL MATCH still has a driving row to preserve: the single empty unit row
    // (`LogicalOp::Empty`). Lowering it like a plain MATCH would drop to zero rows when the pattern
    // matches nothing, but openCypher mandates one all-`NULL` row
    // (`OPTIONAL MATCH (n:DoesNotExist) RETURN labels(n)` is a single `null`; `rmp` #132,
    // `expressions/graph/Graph3.feature` [7]). So it lowers to `Apply(Empty, Optional(scan))`.
    let plan = plan("OPTIONAL MATCH (n) RETURN n");
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection");
    };
    let LogicalOp::Apply { left, right } = &**input else {
        panic!("expected Apply, got: {input}");
    };
    assert!(
        matches!(**left, LogicalOp::Empty),
        "the driving side must be the single unit row, got: {left}"
    );
    assert!(
        matches!(**right, LogicalOp::Optional { .. }),
        "the optional pattern must be wrapped in Optional, got: {right}"
    );
}

// =================================================================================================
// Aggregation
// =================================================================================================

#[test]
fn aggregating_return_lowers_to_aggregation_with_group_keys() {
    // `RETURN n.dept AS d, count(*) AS c` partitions into group key `d` and aggregate `c`.
    let plan = plan("MATCH (n) RETURN n.dept AS d, count(*) AS c");
    match &plan {
        LogicalOp::Aggregation {
            input,
            group_keys,
            aggregates,
        } => {
            assert_eq!(group_keys.len(), 1);
            assert_eq!(group_keys[0].alias, "d");
            assert_eq!(aggregates.len(), 1);
            assert_eq!(aggregates[0].alias, "c");
            assert!(matches!(aggregates[0].expr.kind, ExprKind::CountStar));
            assert!(matches!(**input, LogicalOp::AllNodesScan { .. }));
        }
        other => panic!("expected Aggregation root, got: {other}"),
    }
    assert_eq!(
        rendered("MATCH (n) RETURN n.dept AS d, count(*) AS c"),
        "Aggregation(keys=[n.dept AS d], aggs=[count(*) AS c])\n  AllNodesScan(n)\n"
    );
}

#[test]
fn implicit_grouping_with_no_keys() {
    // `RETURN count(*)` aggregates the whole input as one group (no group keys).
    let plan = plan("MATCH (n) RETURN count(*) AS c");
    match &plan {
        LogicalOp::Aggregation {
            group_keys,
            aggregates,
            ..
        } => {
            assert!(group_keys.is_empty(), "no group keys → single group");
            assert_eq!(aggregates.len(), 1);
        }
        other => panic!("expected Aggregation root, got: {other}"),
    }
}

// =================================================================================================
// ORDER BY / SKIP / LIMIT / DISTINCT
// =================================================================================================

#[test]
fn order_by_skip_limit_stack_in_grammar_order() {
    // Evaluation order: project, then Sort, then Skip, then Limit (Limit is the outermost/root).
    assert_eq!(
        rendered("MATCH (n) RETURN n ORDER BY n.name DESC SKIP 5 LIMIT 10"),
        "Limit(10)\n  \
         Skip(5)\n    \
         Sort(n.name DESC)\n      \
         Projection(n AS n)\n        \
         AllNodesScan(n)\n"
    );
}

#[test]
fn sort_key_direction_is_preserved() {
    let plan = plan("MATCH (n) RETURN n ORDER BY n.a ASC, n.b DESC");
    let LogicalOp::Sort { keys, .. } = &plan else {
        panic!("expected Sort root, got: {plan}");
    };
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].direction, SortDirection::Ascending);
    assert_eq!(keys[1].direction, SortDirection::Descending);
}

#[test]
fn distinct_rides_on_the_projection() {
    let plan = plan("MATCH (n) RETURN DISTINCT n.x AS x");
    let LogicalOp::Projection { distinct, .. } = &plan else {
        panic!("expected Projection root, got: {plan}");
    };
    assert!(*distinct, "DISTINCT must be recorded on the Projection");
}

// =================================================================================================
// UNWIND
// =================================================================================================

#[test]
fn leading_unwind_lowers_over_empty() {
    let plan = plan("UNWIND [1, 2, 3] AS x RETURN x");
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection root");
    };
    match &**input {
        LogicalOp::Unwind {
            input,
            variable,
            list,
        } => {
            assert_eq!(variable.name, "x");
            assert!(matches!(list.kind, ExprKind::List(_)));
            assert!(matches!(**input, LogicalOp::Empty));
        }
        other => panic!("expected Unwind, got: {other}"),
    }
}

#[test]
fn correlated_unwind_lowers_over_prior_plan() {
    // `MATCH (n) UNWIND n.tags AS t` unwinds per matched row (input is the scan, not Empty).
    let plan = plan("MATCH (n) UNWIND n.tags AS t RETURN t");
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection root");
    };
    let LogicalOp::Unwind { input, .. } = &**input else {
        panic!("expected Unwind");
    };
    assert!(
        matches!(**input, LogicalOp::AllNodesScan { .. }),
        "correlated unwind drives off the prior plan, got: {input}"
    );
}

// =================================================================================================
// Write clauses
// =================================================================================================

#[test]
fn create_lowers_to_create_with_node_part() {
    let plan = plan("CREATE (n:Person {name: 'Ada'}) RETURN n");
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection root");
    };
    match &**input {
        LogicalOp::Create { input, pattern } => {
            assert!(matches!(**input, LogicalOp::Empty));
            assert_eq!(pattern.len(), 1);
            match &pattern[0] {
                CreatePart::Node {
                    variable,
                    labels,
                    properties,
                } => {
                    assert_eq!(variable.name, "n");
                    assert_eq!(labels[0].name, "Person");
                    assert!(
                        properties.is_some(),
                        "inline props carried onto Create node"
                    );
                }
                other => panic!("expected Node create part, got: {other:?}"),
            }
        }
        other => panic!("expected Create, got: {other}"),
    }
}

#[test]
fn create_relationship_lowers_three_parts() {
    // `CREATE (a)-[r:KNOWS]->(b)` lowers to node a, node b, relationship r.
    let plan = plan("CREATE (a)-[r:KNOWS]->(b)");
    let LogicalOp::Create { pattern, .. } = &plan else {
        panic!("expected Create root, got: {plan}");
    };
    assert_eq!(pattern.len(), 3);
    assert!(matches!(pattern[0], CreatePart::Node { .. }));
    assert!(matches!(pattern[1], CreatePart::Node { .. }));
    match &pattern[2] {
        CreatePart::Relationship {
            from,
            to,
            rel_type,
            direction,
            ..
        } => {
            assert_eq!(from.name, "a");
            assert_eq!(to.name, "b");
            assert_eq!(rel_type.name, "KNOWS");
            assert_eq!(*direction, RelDirection::LeftToRight);
        }
        other => panic!("expected Relationship part, got: {other:?}"),
    }
}

#[test]
fn merge_carries_on_create_and_on_match_actions() {
    let plan = plan(
        "MERGE (n:Person {name: 'Ada'}) ON CREATE SET n.created = true ON MATCH SET n.seen = true RETURN n",
    );
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection root");
    };
    match &**input {
        LogicalOp::Merge {
            pattern,
            on_create,
            on_match,
            ..
        } => {
            assert_eq!(pattern.len(), 1);
            assert_eq!(on_create.len(), 1);
            assert_eq!(on_match.len(), 1);
            assert!(matches!(on_create[0], SetOp::Property { .. }));
            assert!(matches!(on_match[0], SetOp::Property { .. }));
        }
        other => panic!("expected Merge, got: {other}"),
    }
    assert_eq!(
        rendered(
            "MERGE (n:Person {name: 'Ada'}) ON CREATE SET n.created = true ON MATCH SET n.seen = true RETURN n"
        ),
        "Projection(n AS n)\n  \
         Merge((n:Person) ON CREATE SET n.created = true ON MATCH SET n.seen = true)\n    \
         Empty\n"
    );
}

#[test]
fn set_lowers_to_set_clause_op() {
    let plan = plan("MATCH (n) SET n.x = 1 RETURN n");
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection root");
    };
    match &**input {
        LogicalOp::SetClause { input, ops } => {
            assert!(matches!(**input, LogicalOp::AllNodesScan { .. }));
            assert_eq!(ops.len(), 1);
            assert!(matches!(ops[0], SetOp::Property { .. }));
        }
        other => panic!("expected Set, got: {other}"),
    }
}

#[test]
fn set_replace_and_merge_props_and_labels() {
    // `SET n = {..}` (replace), `SET n += {..}` (merge), `SET n:Label` (add labels).
    let plan = plan("MATCH (n) SET n = {a: 1}, n += {b: 2}, n:Tagged RETURN n");
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection root");
    };
    let LogicalOp::SetClause { ops, .. } = &**input else {
        panic!("expected Set");
    };
    assert!(matches!(ops[0], SetOp::ReplaceProperties { .. }));
    assert!(matches!(ops[1], SetOp::MergeProperties { .. }));
    assert!(matches!(ops[2], SetOp::AddLabels { .. }));
}

#[test]
fn detach_delete_lowers_with_flag() {
    let plan = plan("MATCH (n) DETACH DELETE n");
    match &plan {
        LogicalOp::Delete {
            input,
            detach,
            exprs,
        } => {
            assert!(*detach);
            assert_eq!(exprs.len(), 1);
            assert!(matches!(**input, LogicalOp::AllNodesScan { .. }));
        }
        other => panic!("expected Delete root, got: {other}"),
    }
    assert_eq!(
        rendered("MATCH (n) DETACH DELETE n"),
        "DetachDelete(n)\n  AllNodesScan(n)\n"
    );
}

#[test]
fn plain_delete_has_no_detach_flag() {
    let plan = plan("MATCH (n) DELETE n");
    let LogicalOp::Delete { detach, .. } = &plan else {
        panic!("expected Delete root");
    };
    assert!(!detach);
}

#[test]
fn remove_lowers_labels_and_property() {
    let plan = plan("MATCH (n) REMOVE n:Temp, n.flag");
    match &plan {
        LogicalOp::Remove { input, ops } => {
            assert!(matches!(**input, LogicalOp::AllNodesScan { .. }));
            assert_eq!(ops.len(), 2);
            assert!(matches!(ops[0], RemoveOp::Labels { .. }));
            assert!(matches!(ops[1], RemoveOp::Property { .. }));
        }
        other => panic!("expected Remove root, got: {other}"),
    }
    assert_eq!(
        rendered("MATCH (n) REMOVE n:Temp, n.flag"),
        "Remove(n:Temp, n.flag)\n  AllNodesScan(n)\n"
    );
}

// =================================================================================================
// CALL ... YIELD
// =================================================================================================

#[test]
fn leading_call_yield_is_a_row_source() {
    let plan = plan("CALL db.labels() YIELD label RETURN label");
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection root");
    };
    match &**input {
        LogicalOp::ProcedureCall {
            input,
            name,
            args,
            yields,
        } => {
            assert!(input.is_none(), "leading CALL is a source (no input)");
            assert_eq!(name, &["db".to_owned(), "labels".to_owned()]);
            assert!(
                args.as_ref().is_some_and(std::vec::Vec::is_empty),
                "explicit empty args"
            );
            let yields = yields.as_ref().expect("YIELD present");
            assert_eq!(yields[0].variable.name, "label");
        }
        other => panic!("expected ProcedureCall, got: {other}"),
    }
    assert_eq!(
        rendered("CALL db.labels() YIELD label RETURN label"),
        "Projection(label AS label)\n  ProcedureCall(db.labels() YIELD label)\n"
    );
}

#[test]
fn correlated_call_after_match_is_wrapped_in_apply() {
    // A CALL after a MATCH is correlated: Apply(matchPlan, ProcedureCall(input = Argument)).
    let plan = plan("MATCH (n) CALL db.labels() YIELD label RETURN n, label");
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection root");
    };
    let LogicalOp::Apply { left, right } = &**input else {
        panic!("expected Apply, got: {input}");
    };
    assert!(matches!(**left, LogicalOp::AllNodesScan { .. }));
    let LogicalOp::ProcedureCall { input, .. } = &**right else {
        panic!("expected ProcedureCall on Apply right, got: {right}");
    };
    assert!(
        matches!(input.as_deref(), Some(LogicalOp::Argument { .. })),
        "correlated CALL reads from an Argument leaf"
    );
}

#[test]
fn standalone_call_lowers_to_procedure_call() {
    let plan = plan("CALL db.labels()");
    match &plan {
        LogicalOp::ProcedureCall { input, name, .. } => {
            assert!(input.is_none());
            assert_eq!(name, &["db".to_owned(), "labels".to_owned()]);
        }
        other => panic!("expected ProcedureCall root, got: {other}"),
    }
}

// =================================================================================================
// UNION
// =================================================================================================

#[test]
fn union_all_combines_branch_plans() {
    // Both branches must return the same column names (openCypher `DifferentColumnsInUnion`).
    let plan = plan("MATCH (n) RETURN n AS x UNION ALL MATCH (m) RETURN m AS x");
    match &plan {
        LogicalOp::Union { left, right, all } => {
            assert!(*all, "UNION ALL keeps duplicates");
            assert!(matches!(**left, LogicalOp::Projection { .. }));
            assert!(matches!(**right, LogicalOp::Projection { .. }));
        }
        other => panic!("expected Union root, got: {other}"),
    }
    assert_eq!(
        rendered("MATCH (n) RETURN n AS x UNION ALL MATCH (m) RETURN m AS x"),
        "Union ALL\n  \
         Projection(n AS x)\n    \
         AllNodesScan(n)\n  \
         Projection(m AS x)\n    \
         AllNodesScan(m)\n"
    );
}

#[test]
fn plain_union_is_distinct() {
    let plan = plan("MATCH (n) RETURN n AS x UNION MATCH (m) RETURN m AS x");
    let LogicalOp::Union { all, .. } = &plan else {
        panic!("expected Union root");
    };
    assert!(!all, "plain UNION de-duplicates");
}

#[test]
fn union_chain_folds_left_associatively() {
    // `a UNION b UNION c` → Union(Union(a, b), c).
    let plan =
        plan("MATCH (n) RETURN n AS x UNION MATCH (m) RETURN m AS x UNION MATCH (p) RETURN p AS x");
    let LogicalOp::Union { left, .. } = &plan else {
        panic!("expected outer Union");
    };
    assert!(
        matches!(**left, LogicalOp::Union { .. }),
        "the left of the outer Union is itself a Union (left-associative fold)"
    );
}

// =================================================================================================
// Normalisation: inline-property hoisting (fires), WHERE-not-pushed (does not fire)
// =================================================================================================

#[test]
fn inline_property_map_is_hoisted_to_filter_adjacent_to_its_scan() {
    // RULE FIRES: `MATCH (n {name: 'Ada'})` becomes `Filter(n.name = 'Ada')` directly above the
    // scan that binds `n` — pushed as close to the leaf as is sound (semantics-preserving:
    // an inline equality map is exactly `WHERE n.name = 'Ada'`).
    let plan = plan("MATCH (n {name: 'Ada'}) RETURN n");
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection root");
    };
    match &**input {
        LogicalOp::Filter { input, predicate } => {
            // The hoisted predicate is the property equality.
            match &predicate.kind {
                ExprKind::Binary { op, lhs, .. } => {
                    assert_eq!(*op, graphus_cypher::ast::BinaryOp::Eq);
                    assert!(matches!(lhs.kind, ExprKind::Property { .. }));
                }
                other => panic!("expected `n.name = 'Ada'` equality, got: {other:?}"),
            }
            // The filter sits *directly* above the scan that binds `n` (closest-to-leaf placement).
            assert!(
                matches!(**input, LogicalOp::AllNodesScan { .. }),
                "inline-property filter must be adjacent to its scan, got: {input}"
            );
        }
        other => panic!("expected Filter (hoisted inline prop), got: {other}"),
    }
    assert_eq!(
        rendered("MATCH (n {name: 'Ada'}) RETURN n"),
        "Projection(n AS n)\n  Filter((n.name = 'Ada'))\n    AllNodesScan(n)\n"
    );
}

#[test]
fn inline_property_on_expanded_node_is_filtered_adjacent_to_its_expand_not_the_anchor_scan() {
    // RULE FIRES, and placement is load-bearing: the inline prop on `b` filters directly above the
    // Expand that binds `b`, NOT above the anchor scan of `a` (where `b` is not yet bound — pushing
    // it there would reference an unbound variable and change/ break semantics).
    let plan = plan("MATCH (a)-[r]->(b {k: 1}) RETURN b");
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection root");
    };
    // Top of the pattern subtree is the inline-prop filter on `b`.
    let LogicalOp::Filter {
        input: expand,
        predicate,
    } = &**input
    else {
        panic!("expected Filter on b, got: {input}");
    };
    // The filter predicate references `b`.
    let ExprKind::Binary { lhs, .. } = &predicate.kind else {
        panic!("expected equality predicate");
    };
    let ExprKind::Property { base, .. } = &lhs.kind else {
        panic!("expected property access");
    };
    assert!(matches!(base.kind, ExprKind::Variable(ref n) if n == "b"));
    // Directly below the filter is the Expand that binds `b` (filter is adjacent to its binding).
    assert!(
        matches!(**expand, LogicalOp::Expand { .. }),
        "filter on `b` must sit directly above the Expand binding `b`, got: {expand}"
    );
}

#[test]
fn where_is_not_pushed_below_the_pattern_scans() {
    // RULE DOES NOT FIRE: a `WHERE` predicate referencing `b` (bound by the expand) is kept above
    // the whole pattern (the Expand), NOT pushed below the anchor scan of `a`. Pushing a WHERE that
    // may reference later-bound pattern variables toward a single scan would be unsound, so the
    // planner conservatively leaves WHERE above the full pattern.
    let plan = plan("MATCH (a)-[r]->(b) WHERE b.k = 1 RETURN b");
    let LogicalOp::Projection { input, .. } = &plan else {
        panic!("expected Projection root");
    };
    // The WHERE filter is the top of the pattern subtree, directly above the Expand (which binds
    // both `a`-anchored scan and `b`). It is NOT interleaved below the Expand.
    match &**input {
        LogicalOp::Filter { input, .. } => {
            assert!(
                matches!(**input, LogicalOp::Expand { .. }),
                "WHERE filter must sit above the whole pattern's Expand, got: {input}"
            );
        }
        other => panic!("expected WHERE Filter above the Expand, got: {other}"),
    }
    assert_eq!(
        rendered("MATCH (a)-[r]->(b) WHERE b.k = 1 RETURN b"),
        "Projection(b AS b)\n  \
         Filter((b.k = 1))\n    \
         Expand(a)-[r]->(b)\n      \
         AllNodesScan(a)\n"
    );
}

// =================================================================================================
// Display pretty-printer
// =================================================================================================

#[test]
fn display_indents_inputs_one_level_per_depth() {
    // Each input is indented two spaces deeper than its parent; the deepest leaf is most-indented.
    let r = rendered("MATCH (a)-[:R]->(b) WHERE b.x = 1 RETURN b");
    let lines: Vec<&str> = r.lines().collect();
    assert_eq!(lines[0], "Projection(b AS b)"); // depth 0
    assert_eq!(lines[1], "  Filter((b.x = 1))"); // depth 1
    assert_eq!(lines[2], "    Expand(a)-[anon_0:R]->(b)"); // depth 2
    assert_eq!(lines[3], "      AllNodesScan(a)"); // depth 3
}

#[test]
fn display_renders_binary_branches_at_same_depth() {
    // Union (and Apply) render both children at the same indentation depth.
    let r = rendered("MATCH (n) RETURN n AS x UNION ALL MATCH (m) RETURN m AS x");
    let lines: Vec<&str> = r.lines().collect();
    assert_eq!(lines[0], "Union ALL");
    // Both branch roots are at depth 1 (two-space indent).
    assert!(lines[1].starts_with("  Projection"));
    assert!(lines[3].starts_with("  Projection"));
}

#[test]
fn display_is_deterministic_for_the_same_query() {
    // The pretty-printer is stable: lowering the same source twice renders identically.
    let a = rendered("MATCH (n:Person) WHERE n.age > 18 RETURN n.name AS name");
    let b = rendered("MATCH (n:Person) WHERE n.age > 18 RETURN n.name AS name");
    assert_eq!(a, b);
}

// =================================================================================================
// Anchoring a pattern part on an already-bound node (`rmp` task #862)
// =================================================================================================
//
// A pattern part whose *leading* node is unbound but which shares a *later* node with the plan so
// far must expand from that bound node, not scan its leading label and connect afterwards. The
// re-anchored walk traverses the same links over the same relationship set from the other end, with
// each backward hop's arrow mirrored, so the result bag is unchanged — only the access path is.

#[test]
fn bound_trailing_node_anchors_the_part_instead_of_scanning_its_leading_node() {
    // `a` is bound by the first part; the second part is written leading-node-first but must be
    // walked from `a`, mirroring the arrow (`(v)-[:LIKES]->(a)` becomes `Expand(a)<-[…]-(v)`).
    let r = rendered("MATCH (u)-[:LIKES]->(a), (v)-[:LIKES]->(a) RETURN v");
    assert!(
        r.contains("Expand(a)<-[anon_1:LIKES]-(v)"),
        "second part must expand backwards from the bound `a`, got:\n{r}"
    );
    // ... and `v` is therefore never scanned, so no cartesian Apply is introduced for this part.
    assert!(
        !r.contains("AllNodesScan(v)"),
        "the re-anchored part must not scan its leading node, got:\n{r}"
    );
    assert!(
        !r.contains("Apply"),
        "a part sharing a bound node is a traversal, not a correlated join, got:\n{r}"
    );
}

#[test]
fn bound_middle_node_anchors_the_part_and_walks_both_ways() {
    // `b` sits in the MIDDLE of the second part: the walk goes backwards to `c` (arrow mirrored)
    // and then forwards to `d` (arrow as written).
    let r = rendered("MATCH (x)-[:A]->(b) MATCH (c)-[:B]->(b)-[:C]->(d) RETURN d");
    assert!(
        r.contains("Expand(b)<-[anon_1:B]-(c)"),
        "backward hop must mirror the written arrow, got:\n{r}"
    );
    assert!(
        r.contains("Expand(b)-[anon_2:C]->(d)"),
        "forward hop resumes at the anchor and keeps the written arrow, got:\n{r}"
    );
    assert!(
        !r.contains("AllNodesScan(c)"),
        "the re-anchored part must not scan its leading node, got:\n{r}"
    );
}

#[test]
fn undirected_link_walked_backwards_stays_undirected() {
    // An undirected link is symmetric: mirroring it is a no-op, so the rendering keeps `-[…]-`.
    let r = rendered("MATCH (u)-[:LIKES]->(a), (v)-[:KNOWS]-(a) RETURN v");
    assert!(
        r.contains("Expand(a)-[anon_1:KNOWS]-(v)"),
        "an undirected backward hop keeps its direction, got:\n{r}"
    );
}

#[test]
fn leading_node_already_bound_still_reuses_it_unchanged() {
    // The historical case: when the LEADING node is the shared one, nothing changes.
    let r = rendered("MATCH (u)-[:LIKES]->(a), (a)-[:TAGGED]->(t) RETURN t");
    assert!(
        r.contains("Expand(a)-[anon_1:TAGGED]->(t)"),
        "a bound leading node keeps the written forward walk, got:\n{r}"
    );
    assert!(!r.contains("AllNodesScan(a)"), "no re-scan of `a`:\n{r}");
}

#[test]
fn named_path_part_declines_reanchoring() {
    // `NamedPath` records the path's start and steps in WRITTEN order, which a re-anchored walk no
    // longer produces — so a part binding a path variable keeps the leading-node anchor.
    let r = rendered("MATCH (u)-[:LIKES]->(a) MATCH p = (v)-[:LIKES]->(a) RETURN p");
    assert!(
        r.contains("NamedPath(p = v,"),
        "the named path must still start at the written leading node, got:\n{r}"
    );
    assert!(
        r.contains("AllNodesScan(v)"),
        "declining re-anchoring keeps the leading-node scan, got:\n{r}"
    );
}

#[test]
fn quantified_path_part_declines_reanchoring() {
    // A QPP's interior repetition is not reversible by mirroring one arrow, so a part containing one
    // keeps the leading-node anchor.
    let r = rendered("MATCH (u)-[:LIKES]->(a) MATCH (v) ((s)-[:R]->(e)){1,2} (a) RETURN v");
    assert!(
        r.contains("AllNodesScan(v)"),
        "a QPP part keeps its written anchor, got:\n{r}"
    );
}

#[test]
fn disconnected_part_still_lowers_to_a_correlated_apply() {
    // A genuinely disconnected component shares no node, so it keeps the fresh scan + Apply.
    let r = rendered("MATCH (u:A)-[:LIKES]->(a:B), (x:C)-[:R]->(y:D) RETURN x");
    assert!(
        r.contains("Apply"),
        "a disconnected part is still a correlated join, got:\n{r}"
    );
    assert!(
        r.contains("NodeByLabelScan(x:C)"),
        "a disconnected part still scans its leading node, got:\n{r}"
    );
}

#[test]
fn constrained_leading_node_declines_reanchoring_inline_map() {
    // The leading node of the second part carries an inline property map, so it keeps its own scan
    // (which the physical planner can turn into an index seek). Expanding backwards from the bound
    // node to find one selective row would be the worse plan, and the cost-based anchor search
    // (`rmp` #858) is what will decide this by estimate.
    let r = rendered("MATCH (u)-[:LIKES]->(a), (v {uidn: 2})-[:LIKES]->(a) RETURN v");
    assert!(
        r.contains("AllNodesScan(v)"),
        "a constrained leading node keeps its scan, got:\n{r}"
    );
}

#[test]
fn constrained_leading_node_declines_reanchoring_where_clause() {
    // The same constraint written as a WHERE on the enclosing MATCH must decline identically —
    // otherwise the rewrite would depend on which of two equivalent spellings the user chose.
    let r = rendered("MATCH (u)-[:LIKES]->(a), (v)-[:LIKES]->(a) WHERE v.uidn = 2 RETURN v");
    assert!(
        r.contains("AllNodesScan(v)"),
        "a WHERE-constrained leading node keeps its scan, got:\n{r}"
    );
}

#[test]
fn where_on_another_variable_does_not_block_reanchoring() {
    // Only a constraint on the *leading node of the re-anchored part* blocks the rewrite; a WHERE
    // about some other variable must not suppress it.
    let r = rendered("MATCH (u)-[:LIKES]->(a), (v)-[:LIKES]->(a) WHERE u.uidn = 1 RETURN v");
    assert!(
        r.contains("Expand(a)<-[anon_1:LIKES]-(v)"),
        "an unconstrained leading node still re-anchors, got:\n{r}"
    );
}
