//! Integration tests for Cypher **semantic analysis** (`04-technical-design.md` §7.3).
//!
//! These exercise [`graphus_cypher::semantics::analyze`] over real parsed queries, asserting the
//! compile-time errors it raises (with their byte [`Span`] and TCK `(phase, type, detail)`
//! classification) and the valid queries it accepts. They are organised by concern:
//!
//! - **Scoping** — undefined variables, the `WITH`/`RETURN` projection-boundary reset, comprehension
//!   locals, type conflicts.
//! - **Aggregation** — placement, nesting, and the grouping-key rule.
//! - **Projection** — `RETURN *` empty scope, duplicate columns, `ORDER BY` scope, mandatory `WITH`
//!   aliasing.
//! - **Functions** — unknown name, wrong arity (against the built-in registry).
//! - **Write clauses** — `CREATE`/`MERGE` relationship well-formedness, `DELETE` of a non-entity.
//! - **Clause composition** — `RETURN` must be last.
//! - **Valid queries** — representative multi-clause queries analyse cleanly.
//! - **The compile-vs-runtime boundary** — runtime-only-erroneous queries are NOT rejected here.

use graphus_cypher::ast::Query;
use graphus_cypher::errors::{ErrorPhase, ErrorType, SemanticDetail, SemanticError};
use graphus_cypher::lexer::{Span, tokenize};
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::semantics::analyze;

// =================================================================================================
// Helpers
// =================================================================================================

/// Parses `src` (asserting it parses) and returns the AST.
fn ast(src: &str) -> Query {
    let toks = tokenize(src).expect("test inputs lex cleanly");
    parse_tokens(&toks, src).expect("test inputs parse cleanly; the fault under test is semantic")
}

/// Analyses `src`, asserting it is semantically **valid**.
fn ok(src: &str) {
    let q = ast(src);
    if let Err(e) = analyze(&q) {
        panic!("expected `{src}` to be semantically valid, but got: {e}");
    }
}

/// Analyses `src`, asserting it raises a [`SemanticError`], which is returned for inspection.
fn err(src: &str) -> SemanticError {
    let q = ast(src);
    analyze(&q).expect_err("expected a semantic error")
}

/// Asserts the error for `src` has the given TCK detail (and, implicitly, the compile-time phase).
fn assert_detail(src: &str, detail: SemanticDetail) {
    let e = err(src);
    assert_eq!(
        e.classification().detail,
        detail,
        "for `{src}`: expected detail {detail}, got {} ({e})",
        e.classification().detail
    );
    assert_eq!(
        e.classification().phase,
        ErrorPhase::CompileTime,
        "must be compile-time: `{src}`"
    );
}

/// The byte span of `needle`'s first occurrence in `src` (for span assertions).
fn span_of(src: &str, needle: &str) -> Span {
    let start = src
        .find(needle)
        .unwrap_or_else(|| panic!("`{needle}` not in `{src}`"));
    Span::new(start, start + needle.len())
}

// =================================================================================================
// Scoping — undefined variables & the WITH/RETURN reset
// =================================================================================================

#[test]
fn undefined_variable_in_return() {
    assert_detail("RETURN x", SemanticDetail::UndefinedVariable);
}

#[test]
fn undefined_variable_in_where() {
    // `m` is never bound; `n` is. The fault is `m` in the WHERE.
    let e = err("MATCH (n) WHERE m.age > 1 RETURN n");
    assert_eq!(e.classification().detail, SemanticDetail::UndefinedVariable);
    assert_eq!(e.span, span_of("MATCH (n) WHERE m.age > 1 RETURN n", "m"));
}

#[test]
fn undefined_variable_in_set() {
    assert_detail("MATCH (n) SET m.x = 1", SemanticDetail::UndefinedVariable);
}

#[test]
fn defined_variable_is_fine() {
    ok("MATCH (n) WHERE n.age > 18 RETURN n.name AS name");
}

#[test]
fn with_resets_scope_dropped_variable_is_undefined_afterwards() {
    // `n` is matched, but only `n.name AS name` is carried through WITH; `n` is gone afterwards.
    let src = "MATCH (n) WITH n.name AS name RETURN n";
    assert_detail(src, SemanticDetail::UndefinedVariable);
    let e = err(src);
    assert_eq!(e.span, span_of(src, "RETURN n").split_off_return());
}

#[test]
fn with_carries_aliased_variable_through() {
    // `n` IS carried through (aliased as itself's projection), so it remains usable.
    ok("MATCH (n) WITH n AS n RETURN n.name AS name");
    ok("MATCH (n) WITH n RETURN n");
}

#[test]
fn with_star_carries_everything_through() {
    ok("MATCH (n) WITH * RETURN n");
    ok("MATCH (a)-[r]->(b) WITH * RETURN a, r, b");
}

#[test]
fn variable_introduced_after_with_is_in_scope() {
    ok("WITH 1 AS x RETURN x");
    ok("UNWIND [1, 2, 3] AS n RETURN n");
}

#[test]
fn comprehension_variable_is_local_to_the_comprehension() {
    // `x` is bound only inside the list comprehension; it is undefined in the outer RETURN.
    ok("RETURN [x IN [1, 2, 3] WHERE x > 1 | x] AS ys");
    assert_detail(
        "RETURN [x IN [1, 2, 3] | x] AS ys, x",
        SemanticDetail::UndefinedVariable,
    );
}

#[test]
fn variable_type_conflict_node_vs_relationship() {
    // `r` is a relationship in the first MATCH, then re-used as a node — a type conflict.
    let e = err("MATCH ()-[r]->() MATCH (r) RETURN r");
    assert_eq!(
        e.classification().detail,
        SemanticDetail::VariableTypeConflict
    );
    // Every compile-time fault is a TCK SyntaxError (the corpus-wide classification rule).
    assert_eq!(e.classification().error_type, ErrorType::SyntaxError);
}

#[test]
fn same_kind_rebinding_is_allowed() {
    // `n` as a node in both MATCHes refers to the same node — not an error.
    ok("MATCH (n) MATCH (n) RETURN n");
}

// =================================================================================================
// Aggregation
// =================================================================================================

#[test]
fn plain_count_aggregation_is_valid() {
    ok("MATCH (n) RETURN count(n)");
    ok("MATCH (n) RETURN count(*)");
}

#[test]
fn grouping_aggregation_is_valid() {
    // `n.x` is the grouping key; `count(*)` aggregates within each group — valid.
    ok("MATCH (n) RETURN n.x, count(*)");
    ok("MATCH (n) RETURN n.x AS x, sum(n.y) AS total");
}

#[test]
fn ambiguous_aggregation_mixing_free_expression_with_aggregate() {
    // `n.y + 1` is neither a grouping key nor aggregated, alongside `count(*)` — ambiguous.
    assert_detail(
        "MATCH (n) RETURN n.y + 1, count(*)",
        SemanticDetail::AmbiguousAggregationExpression,
    );
}

#[test]
fn nested_aggregation_is_rejected() {
    assert_detail(
        "MATCH (n) RETURN sum(count(n))",
        SemanticDetail::NestedAggregation,
    );
}

#[test]
fn aggregation_in_where_is_rejected() {
    assert_detail(
        "MATCH (n) WHERE count(n) > 1 RETURN n",
        SemanticDetail::InvalidAggregation,
    );
}

#[test]
fn aggregation_in_order_by_of_non_aggregating_projection_is_rejected() {
    // No aggregate in the projection, but an aggregate in ORDER BY — invalid.
    assert_detail(
        "MATCH (n) RETURN n ORDER BY count(n)",
        SemanticDetail::InvalidAggregation,
    );
}

#[test]
fn aggregation_in_order_by_of_aggregating_projection_is_valid() {
    // The projection aggregates, so ORDER BY may sort the grouped rows by an aggregate.
    ok("MATCH (n) RETURN n.x, count(*) ORDER BY count(*)");
}

// =================================================================================================
// Projection — RETURN *, duplicate columns, ORDER BY scope, mandatory WITH alias
// =================================================================================================

#[test]
fn return_star_with_empty_scope_is_an_error() {
    let e = err("RETURN *");
    assert_eq!(e.classification().detail, SemanticDetail::UndefinedVariable);
    // The whole RETURN clause is the offending span (the `*` has no narrower span).
    assert_eq!(e.span, Span::new(0, "RETURN *".len()));
}

#[test]
fn return_star_with_variables_in_scope_is_valid() {
    ok("MATCH (n) RETURN *");
}

#[test]
fn duplicate_result_column_name_is_an_error() {
    assert_detail(
        "MATCH (n) RETURN n.a AS x, n.b AS x",
        SemanticDetail::ColumnNameConflict,
    );
}

#[test]
fn duplicate_column_against_star_expansion() {
    // `*` exposes `n`; aliasing another expression to `n` collides.
    assert_detail(
        "MATCH (n) RETURN *, n.a AS n",
        SemanticDetail::ColumnNameConflict,
    );
}

#[test]
fn order_by_may_reference_a_pre_projection_variable() {
    // `rmp` task #40: openCypher lets ORDER BY of a **non-aggregating, non-DISTINCT** projection
    // reference variables in scope *before* the projection (here `n`), not only the projected alias.
    // (This was previously rejected — an over-strict scoping bug, now relaxed to match the TCK.)
    ok("MATCH (n) RETURN n.name AS name ORDER BY n.age");
}

#[test]
fn order_by_cannot_reference_a_dropped_variable_under_aggregation() {
    // An aggregating projection drops the pre-projection variables; ORDER BY then sees only the
    // projected columns, so the dropped `n` is undefined.
    assert_detail(
        "MATCH (n) RETURN count(n) AS c ORDER BY n.age",
        SemanticDetail::UndefinedVariable,
    );
}

#[test]
fn order_by_cannot_reference_a_dropped_variable_under_distinct() {
    // DISTINCT likewise reduces to the projected values, so a pre-projection variable is gone.
    assert_detail(
        "MATCH (n) RETURN DISTINCT n.name AS name ORDER BY n.age",
        SemanticDetail::UndefinedVariable,
    );
}

#[test]
fn order_by_on_a_truly_undefined_name_is_still_an_error() {
    // A name bound nowhere — neither projected nor in the pre-projection scope — is undefined.
    assert_detail(
        "MATCH (n) RETURN n.name AS name ORDER BY zzz.age",
        SemanticDetail::UndefinedVariable,
    );
}

#[test]
fn order_by_on_projected_name_is_valid() {
    ok("MATCH (n) RETURN n.name AS name ORDER BY name");
}

#[test]
fn with_requires_alias_for_computed_expression() {
    // `n.age + 1` is a computed expression in WITH and must be aliased.
    assert_detail(
        "MATCH (n) WITH n.age + 1 RETURN 1",
        SemanticDetail::NoExpressionAlias,
    );
}

#[test]
fn with_allows_bare_variable_and_property() {
    // A bare variable / property has an inferable name, so no AS is required in WITH.
    ok("MATCH (n) WITH n RETURN n");
    // `WITH n.name` projects a column named `n.name`; the variable `n` itself is NOT carried
    // through, so a subsequent `RETURN n.name` (which references `n`) is undefined — real Cypher
    // requires aliasing it to a name. The non-aliased WITH itself is accepted (inferable name).
    ok("MATCH (n) WITH n.name AS name RETURN name");
    assert_detail(
        "MATCH (n) WITH n.name RETURN n.name",
        SemanticDetail::UndefinedVariable,
    );
}

#[test]
fn final_return_allows_unaliased_computed_expression() {
    // The final RETURN does not require aliasing (the column name is the source text).
    ok("MATCH (n) RETURN n.age + 1");
}

// =================================================================================================
// Functions — unknown name and arity (against the built-in registry)
// =================================================================================================

#[test]
fn unknown_function_is_an_error() {
    assert_detail(
        "RETURN no_such_function(1)",
        SemanticDetail::UnknownFunction,
    );
}

#[test]
fn known_function_with_correct_arity_is_valid() {
    ok("MATCH (n) RETURN size(labels(n))");
    ok("RETURN abs(-1)");
    ok("RETURN coalesce(1, 2, 3, 4)"); // variadic
    ok("RETURN round(1.5)"); // range 1..2
    ok("RETURN round(1.5, 2)");
}

#[test]
fn known_function_with_wrong_arity_is_an_error() {
    assert_detail("RETURN abs(1, 2)", SemanticDetail::InvalidNumberOfArguments);
    assert_detail("RETURN size()", SemanticDetail::InvalidNumberOfArguments);
}

#[test]
fn function_name_is_case_insensitive() {
    ok("MATCH (n) RETURN COUNT(n)");
    ok("MATCH (n) RETURN Size(labels(n))");
}

// =================================================================================================
// Write clauses — CREATE/MERGE relationship well-formedness, DELETE of a non-entity
// =================================================================================================

#[test]
fn create_directed_single_type_relationship_is_valid() {
    ok("CREATE (a)-[:KNOWS]->(b)");
    ok("CREATE (a)-[r:KNOWS]->(b)");
}

#[test]
fn create_relationship_without_type_is_an_error() {
    assert_detail(
        "CREATE (a)-[r]->(b)",
        SemanticDetail::NoSingleRelationshipType,
    );
}

#[test]
fn create_relationship_with_multiple_types_is_an_error() {
    assert_detail(
        "CREATE (a)-[:A|B]->(b)",
        SemanticDetail::NoSingleRelationshipType,
    );
}

#[test]
fn create_undirected_relationship_is_an_error() {
    assert_detail(
        "CREATE (a)-[:KNOWS]-(b)",
        SemanticDetail::RequiresDirectedRelationship,
    );
}

#[test]
fn create_var_length_relationship_is_an_error() {
    // Variable-length is rejected before the (also-failing) direction/type checks.
    assert_detail(
        "CREATE (a)-[:KNOWS*1..2]->(b)",
        SemanticDetail::CreatingVarLength,
    );
}

#[test]
fn merge_relationship_well_formedness_is_enforced() {
    ok("MERGE (a)-[:KNOWS]->(b)");
    assert_detail(
        "MERGE (a)-[r]->(b)",
        SemanticDetail::NoSingleRelationshipType,
    );
    assert_detail(
        "MERGE (a)-[:KNOWS]-(b)",
        SemanticDetail::RequiresDirectedRelationship,
    );
}

#[test]
fn create_rebinding_an_existing_relationship_variable_is_an_error() {
    // CREATE always makes a *new* relationship, so reusing an already-bound rel variable is illegal.
    // (The created relationship is otherwise well-formed — one type, directed — so the rebind, not
    // a well-formedness fault, is the error surfaced.)
    let src = "MATCH ()-[r]->() CREATE ()-[r:KNOWS]->()";
    let e = err(src);
    assert_eq!(
        e.classification().detail,
        SemanticDetail::VariableAlreadyBound
    );
    // The offending span is the *rebound* `r` in the CREATE (the second `r`), not the matched one.
    let first_r = src.find('r').expect("a first r");
    let second_r = first_r + 1 + src[first_r + 1..].find('r').expect("a second r");
    assert_eq!(e.span, Span::new(second_r, second_r + 1));
}

#[test]
fn create_reusing_a_matched_node_as_endpoint_is_valid() {
    // Reusing a *node* variable as a CREATE endpoint attaches to the existing node — allowed.
    ok("MATCH (a) CREATE (a)-[:KNOWS]->(b)");
}

#[test]
fn delete_of_a_literal_is_an_error() {
    assert_detail("DELETE 1", SemanticDetail::InvalidDelete);
    assert_detail("MATCH (n) DELETE n.age + 1", SemanticDetail::InvalidDelete);
}

#[test]
fn delete_of_a_variable_is_accepted() {
    // Whether the variable names a deletable entity is a runtime fact; static analysis accepts it.
    ok("MATCH (n) DELETE n");
    ok("MATCH (a)-[r]->(b) DELETE r");
    ok("MATCH (n) DETACH DELETE n");
}

// =================================================================================================
// Clause composition
// =================================================================================================

#[test]
fn return_must_be_the_last_clause() {
    // A RETURN that is not last is an illegal composition.
    assert_detail(
        "RETURN 1 MATCH (n) RETURN n",
        SemanticDetail::InvalidClauseComposition,
    );
}

// =================================================================================================
// Valid representative queries
// =================================================================================================

#[test]
fn multi_clause_match_with_return_is_valid() {
    ok(
        "MATCH (a)-[r:KNOWS]->(b) WHERE a.age > b.age WITH a, b, r WHERE r.since > 2000 RETURN a.name AS who, b.name AS friend",
    );
}

#[test]
fn merge_with_on_create_and_on_match_is_valid() {
    ok("MERGE (n:Person {name: 'x'}) ON CREATE SET n.created = 1 ON MATCH SET n.seen = 1 RETURN n");
}

#[test]
fn unwind_then_match_is_valid() {
    ok("UNWIND [1, 2, 3] AS id MATCH (n) WHERE n.id = id RETURN n");
}

#[test]
fn call_yield_binds_and_is_usable() {
    ok("CALL db.labels() YIELD label RETURN label");
    ok("CALL db.labels() YIELD label WHERE label <> 'x' RETURN label");
}

#[test]
fn standalone_call_is_valid() {
    ok("CALL db.labels()");
    ok("CALL db.labels() YIELD *");
}

#[test]
fn pattern_comprehension_binds_locally_and_is_valid() {
    ok("MATCH (a) RETURN [(a)-->(b) WHERE b.x > 1 | b.name] AS names");
}

#[test]
fn union_branches_are_scoped_independently() {
    ok("MATCH (n) RETURN n.x AS v UNION MATCH (m) RETURN m.y AS v");
    // An undefined variable in one branch is still caught.
    assert_detail(
        "MATCH (n) RETURN n.x AS v UNION RETURN z AS v",
        SemanticDetail::UndefinedVariable,
    );
}

// =================================================================================================
// The compile-vs-runtime boundary (load-bearing, `04 §7.3`)
// =================================================================================================

#[test]
fn division_by_zero_is_not_a_compile_time_error() {
    // `1/0` is a RUNTIME ArithmeticError by TCK design; semantic analysis must accept it.
    ok("RETURN 1 / 0");
    ok("MATCH (n) RETURN n.a / 0 AS x");
}

#[test]
fn value_type_mismatch_is_not_a_compile_time_error() {
    // Adding a string to an integer is a RUNTIME TypeError on actual values, not a static one.
    ok("RETURN 'a' + 1");
    ok("MATCH (n) WHERE n.age + 'x' RETURN n");
}

#[test]
fn missing_parameter_is_not_a_compile_time_error() {
    // Parameters bind at execution (`04 §7.5`); an unbound `$p` is a runtime ParameterMissing.
    ok("MATCH (n) WHERE n.id = $id RETURN n");
    ok("RETURN $p AS p");
}

#[test]
fn nonexistent_property_access_is_not_a_compile_time_error() {
    // Property presence is a runtime fact against the live graph.
    ok("MATCH (n) RETURN n.totally_made_up_property");
}

// =================================================================================================
// Error-classification fidelity (rmp #56)
// =================================================================================================

#[test]
fn create_of_a_bound_node_is_variable_already_bound() {
    // A standalone node part re-using a bound name (TCK Create1).
    assert_detail("MATCH (n) CREATE (n)", SemanticDetail::VariableAlreadyBound);
    // Adding a label to a bound node inside a CREATE pattern (TCK Create1).
    assert_detail(
        "MATCH (n) CREATE (n:Foo)-[:R]->(m)",
        SemanticDetail::VariableAlreadyBound,
    );
    // Bare endpoints of a relationship chain remain legal.
    ok("MATCH (a), (b) CREATE (a)-[:R]->(b)");
}

#[test]
fn create_of_a_bound_relationship_wins_over_well_formedness() {
    // The variable fault is reported even when the CREATE relationship also lacks a type
    // (TCK Create2 [23]).
    assert_detail(
        "MATCH ()-[r]->() CREATE ()-[r]->()",
        SemanticDetail::VariableAlreadyBound,
    );
}

#[test]
fn path_variable_reuse_is_variable_already_bound() {
    // A named path can never re-use a bound name (TCK Match6 [21]).
    assert_detail(
        "MATCH (p)-[]-() MATCH p = ()-[]-() RETURN p",
        SemanticDetail::VariableAlreadyBound,
    );
    // … including a re-use of the path's own name inside its own pattern (TCK Match6 [23]/[24]).
    assert_detail(
        "MATCH p = (p)-[]-() RETURN p",
        SemanticDetail::VariableAlreadyBound,
    );
    // A node/relationship cross-kind re-bind stays a VariableTypeConflict (TCK Match2 [9]).
    assert_detail(
        "MATCH (r) MATCH ()-[r]-() RETURN r",
        SemanticDetail::VariableTypeConflict,
    );
}

#[test]
fn union_branches_must_return_the_same_columns() {
    assert_detail(
        "RETURN 1 AS a UNION RETURN 2 AS b",
        SemanticDetail::DifferentColumnsInUnion,
    );
    assert_detail(
        "RETURN 1 AS a UNION ALL RETURN 2 AS b",
        SemanticDetail::DifferentColumnsInUnion,
    );
    ok("RETURN 1 AS a UNION RETURN 2 AS a");
}

// =================================================================================================
// A tiny helper used by the WITH-reset span assertion.
// =================================================================================================

trait SpanReturnExt {
    /// Narrows a `"RETURN <var>"` span to just the `<var>` part (the offending reference).
    fn split_off_return(self) -> Span;
}

impl SpanReturnExt for Span {
    fn split_off_return(self) -> Span {
        // "RETURN " is 7 bytes; the variable starts after it.
        Span::new(self.start + 7, self.end)
    }
}

// =================================================================================================
// Procedure calls (`CALL … [YIELD …]`, rmp #57; `tck/features/clauses/call/**`)
// =================================================================================================

mod procedures {
    use super::{assert_detail, ast, ok};
    use graphus_core::Value;
    use graphus_cypher::ast::{ExprKind, QueryBody};
    use graphus_cypher::binding::Parameters;
    use graphus_cypher::errors::{ErrorType, SemanticDetail, SemanticError};
    use graphus_cypher::procedure_registry::{
        FieldSpec, FieldType, ProcedureSet, ProcedureSignature, ValueClass,
    };
    use graphus_cypher::semantics::{analyze_with_procedures, check_implicit_call_parameters};

    /// A registry with `test.my.proc(name :: STRING?, id :: INTEGER?) :: (out :: STRING?)` and the
    /// no-input/no-output `test.doNothing() :: ()` (the shapes the TCK CALL features lean on).
    fn registry() -> ProcedureSet {
        let mut set = ProcedureSet::with_builtins();
        set.register_table(
            ProcedureSignature::new(
                "test.my.proc",
                vec![
                    FieldSpec::new("name", FieldType::nullable(ValueClass::String)),
                    FieldSpec::new("id", FieldType::nullable(ValueClass::Integer)),
                ],
                vec![FieldSpec::new(
                    "out",
                    FieldType::nullable(ValueClass::String),
                )],
            ),
            vec![(
                vec![Value::String("Stefan".into()), Value::Integer(1)],
                vec![Value::String("Berlin".into())],
            )],
        )
        .expect("well-formed fixture");
        set.register_table(
            ProcedureSignature::new("test.doNothing", Vec::new(), Vec::new()),
            Vec::new(),
        )
        .expect("well-formed fixture");
        set
    }

    fn ok_with(src: &str) {
        let q = ast(src);
        if let Err(e) = analyze_with_procedures(&q, &registry()) {
            panic!("expected `{src}` to be semantically valid, but got: {e}");
        }
    }

    fn err_with(src: &str) -> SemanticError {
        let q = ast(src);
        analyze_with_procedures(&q, &registry()).expect_err("expected a semantic error")
    }

    #[test]
    fn unknown_procedure_is_procedure_error_procedure_not_found() {
        // TCK Call1 [13]/[14]: type `ProcedureError`, detail `ProcedureNotFound`, compile time —
        // for both the standalone implicit form and the in-query form.
        for src in [
            "CALL no.such.proc",
            "CALL no.such.proc() YIELD out RETURN out",
        ] {
            let e = err_with(src);
            assert_eq!(
                e.classification().error_type,
                ErrorType::ProcedureError,
                "{src}"
            );
            assert_eq!(
                e.classification().detail,
                SemanticDetail::ProcedureNotFound,
                "{src}"
            );
        }
    }

    #[test]
    fn wrong_arity_is_invalid_number_of_arguments() {
        // TCK Call1 [7]–[10]: missing and surplus explicit arguments, standalone and in-query.
        for src in [
            "CALL test.my.proc('Dobby')",
            "CALL test.my.proc('Dobby') YIELD out RETURN out",
            "CALL test.my.proc('a', 1, 2, 3)",
        ] {
            let e = err_with(src);
            assert_eq!(
                e.classification().error_type,
                ErrorType::SyntaxError,
                "{src}"
            );
            assert_eq!(
                e.classification().detail,
                SemanticDetail::InvalidNumberOfArguments,
                "{src}"
            );
        }
    }

    #[test]
    fn literal_argument_type_mismatch_is_invalid_argument_type() {
        // TCK Call2 [5]/[6]: a BOOLEAN literal where INTEGER? is declared.
        for src in [
            "CALL test.my.proc('x', true)",
            "CALL test.my.proc('x', true) YIELD out RETURN out",
        ] {
            let e = err_with(src);
            assert_eq!(
                e.classification().error_type,
                ErrorType::SyntaxError,
                "{src}"
            );
            assert_eq!(
                e.classification().detail,
                SemanticDetail::InvalidArgumentType,
                "{src}"
            );
        }
        // Coercions are accepted: null where nullable, INTEGER where INTEGER.
        ok_with("CALL test.my.proc(null, null)");
    }

    #[test]
    fn in_query_call_with_outputs_requires_yield() {
        // TCK Call1 [12]: detail `UndefinedVariable` at compile time.
        let e = err_with("CALL test.my.proc('x', 1) RETURN out");
        assert_eq!(e.classification().detail, SemanticDetail::UndefinedVariable);
        // A void procedure needs no YIELD in-query (TCK Call1 [3]).
        ok_with("MATCH (n) CALL test.doNothing() RETURN n");
    }

    #[test]
    fn yield_rebinding_an_in_scope_name_is_variable_already_bound() {
        // TCK Call1 [15] and Call5 [5]/[6].
        for src in [
            "WITH 'Hi' AS out CALL test.my.proc('x', 1) YIELD out RETURN *",
            "CALL test.my.proc('x', 1) YIELD out, out AS out RETURN out",
        ] {
            let e = err_with(src);
            assert_eq!(
                e.classification().detail,
                SemanticDetail::VariableAlreadyBound,
                "{src}"
            );
        }
    }

    #[test]
    fn aggregation_in_call_arguments_is_invalid_aggregation() {
        // TCK Call1 [16].
        let e = err_with("MATCH (n) CALL test.my.proc('x', count(n)) YIELD out RETURN out");
        assert_eq!(
            e.classification().detail,
            SemanticDetail::InvalidAggregation
        );
    }

    #[test]
    fn implicit_call_arguments_are_resolved_to_parameters() {
        // openCypher `ImplicitProcedureInvocation`: `CALL test.my.proc` takes its arguments from
        // the query parameters by input name; analysis rewrites them to `$name`, `$id`.
        let q = ast("CALL test.my.proc");
        let validated = analyze_with_procedures(&q, &registry()).expect("valid");
        let QueryBody::StandaloneCall(call) = &validated.query().body else {
            panic!("expected a standalone call");
        };
        let args = call.call.args.as_ref().expect("args resolved");
        let names: Vec<&str> = args
            .iter()
            .map(|a| match &a.kind {
                ExprKind::Parameter(name) => name.as_str(),
                other => panic!("expected a parameter expression, got {other:?}"),
            })
            .collect();
        assert_eq!(names, ["name", "id"]);
    }

    #[test]
    fn implicit_call_missing_parameter_is_parameter_missing() {
        // TCK Call1 [11]: type `ParameterMissing`, detail `MissingParameter`, compile time.
        let q = ast("CALL test.my.proc");
        let mut params = Parameters::new();
        params.insert("name".to_owned(), Value::String("Stefan".into()));
        let e =
            check_implicit_call_parameters(&q, &params, &registry()).expect_err("`id` is missing");
        assert_eq!(e.classification().error_type, ErrorType::ParameterMissing);
        assert_eq!(e.classification().detail, SemanticDetail::MissingParameter);

        params.insert("id".to_owned(), Value::Integer(1));
        check_implicit_call_parameters(&q, &params, &registry()).expect("all inputs supplied");
        // Explicit calls and non-CALL queries are no-ops for this check.
        check_implicit_call_parameters(&ast("RETURN 1 AS x"), &Parameters::new(), &registry())
            .expect("not a standalone call");
    }

    #[test]
    fn builtin_procedures_resolve_through_the_default_registry() {
        // The registry-less `analyze` resolves the engine built-ins (regression pin for the
        // pre-existing `ok("CALL db.labels()")` behaviour, now registry-backed).
        ok("CALL db.relationshipTypes()");
        ok("CALL db.propertyKeys() YIELD propertyKey RETURN propertyKey");
        assert_detail(
            "CALL db.labels(1)",
            SemanticDetail::InvalidNumberOfArguments,
        );
    }
}
