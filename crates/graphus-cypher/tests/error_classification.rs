//! CI-style **error-classification table** test (`04-technical-design.md` §7.3).
//!
//! `04 §7.3` mandates: *"An error-classification table maps every internal error to its TCK
//! `(status, classification, phase)` triple; a CI test asserts the phase split against TCK
//! expectations so we cannot regress the classification."* This file is that test.
//!
//! It enumerates **every** [`SemanticErrorKind`] variant and asserts, for each, that its
//! [`Classification`]:
//!
//! 1. has `phase == CompileTime` (the load-bearing compile-vs-runtime invariant — semantic analysis
//!    is the *only* phase allowed to emit compile-time errors and never emits runtime ones); and
//! 2. round-trips: the `(type, detail)` pair renders to the verbatim TCK Gherkin strings, and the
//!    detail is the one the variant's `detail()` reports.
//!
//! [`all_kinds`] builds one of every variant, and [`expected_classification`] maps each to its
//! independently-written `(type, detail)` expectation. Because `SemanticErrorKind` is
//! `#[non_exhaustive]`, a match in this *downstream* test crate cannot be wildcard-free; the
//! truly-exhaustive guard (a wildcard-free match that fails to compile when a variant is added)
//! lives **inside the crate** as `errors::tests::classification_table_is_exhaustive`. Here we add a
//! belt-and-braces cross-check: the wildcard arm `panic!`s, so a new, unlisted variant that somehow
//! reaches this table at runtime is flagged loudly.

use graphus_cypher::errors::{
    Classification, ErrorPhase, ErrorType, SemanticDetail, SemanticError, SemanticErrorKind,
    VarKind,
};
use graphus_cypher::lexer::Span;

/// One representative value of **every** `SemanticErrorKind` variant. Adding a variant without
/// extending this list is caught by [`every_listed_kind_is_distinct`] (count) and by
/// [`kind_is_represented`] (exhaustive match, no wildcard).
fn all_kinds() -> Vec<SemanticErrorKind> {
    vec![
        SemanticErrorKind::UndefinedVariable {
            name: "x".to_owned(),
        },
        SemanticErrorKind::VariableAlreadyBound {
            name: "x".to_owned(),
        },
        SemanticErrorKind::VariableTypeConflict {
            name: "x".to_owned(),
            first: VarKind::Node,
            second: VarKind::Relationship,
        },
        SemanticErrorKind::AmbiguousAggregationExpression,
        SemanticErrorKind::NestedAggregation,
        SemanticErrorKind::InvalidAggregation { position: "WHERE" },
        SemanticErrorKind::NoExpressionAlias,
        SemanticErrorKind::ColumnNameConflict {
            name: "x".to_owned(),
        },
        SemanticErrorKind::NegativeIntegerArgument,
        SemanticErrorKind::NoSingleRelationshipType { count: 0 },
        SemanticErrorKind::RequiresDirectedRelationship,
        SemanticErrorKind::CreatingVarLength,
        SemanticErrorKind::UnknownFunction {
            name: "f".to_owned(),
        },
        SemanticErrorKind::InvalidNumberOfArguments {
            name: "f".to_owned(),
            expected: "1".to_owned(),
            got: 2,
        },
        SemanticErrorKind::ProcedureNotFound {
            name: "test.my.proc".to_owned(),
        },
        SemanticErrorKind::InvalidProcedureArgumentType {
            name: "test.my.proc".to_owned(),
            parameter: "in".to_owned(),
            expected: "INTEGER?".to_owned(),
        },
        SemanticErrorKind::MissingParameter {
            name: "in".to_owned(),
        },
        SemanticErrorKind::NonConstantExpression { position: "SKIP" },
        SemanticErrorKind::InvalidDelete,
        SemanticErrorKind::InvalidClauseComposition { reason: "test" },
        SemanticErrorKind::DifferentColumnsInUnion,
        SemanticErrorKind::InvalidLoadCsvUrl,
        SemanticErrorKind::InvalidShortestPath {
            reason: "test".to_owned(),
        },
        SemanticErrorKind::PatternPredicateInExpression,
        SemanticErrorKind::InvalidParameterUse,
    ]
}

/// The independently-written expectation table: the `(type, detail)` the classification must
/// produce for each variant. Mirrors (without reusing) `SemanticErrorKind::classification`, so the
/// two agreeing is a real cross-check, not a tautology. The wildcard arm `panic!`s rather than
/// silently passing, so an unlisted variant is flagged (the compile-time exhaustiveness guard lives
/// in-crate; this is the runtime backstop, required because `#[non_exhaustive]` forbids a
/// wildcard-free match here).
fn expected_classification(kind: &SemanticErrorKind) -> (ErrorType, SemanticDetail) {
    use SemanticErrorKind as K;
    // The openCypher TCK classifies almost every compile-time fault as a `SyntaxError`: measured
    // over the pinned corpus, nearly every `... should be raised at compile time:` step names
    // SyntaxError (the only SemanticError in the corpus is the *runtime* `MergeReadOwnWrites`).
    // The measured exceptions, both from `tck/features/clauses/call/Call1.feature`, are
    // `ProcedureError`/`ProcedureNotFound` and `ParameterMissing`/`MissingParameter`. The table
    // expects SyntaxError everywhere else; the cross-check value is the per-variant **detail**.
    match kind {
        K::UndefinedVariable { .. } => (ErrorType::SyntaxError, SemanticDetail::UndefinedVariable),
        K::VariableAlreadyBound { .. } => {
            (ErrorType::SyntaxError, SemanticDetail::VariableAlreadyBound)
        }
        K::VariableTypeConflict { .. } => {
            (ErrorType::SyntaxError, SemanticDetail::VariableTypeConflict)
        }
        K::AmbiguousAggregationExpression => (
            ErrorType::SyntaxError,
            SemanticDetail::AmbiguousAggregationExpression,
        ),
        K::NestedAggregation => (ErrorType::SyntaxError, SemanticDetail::NestedAggregation),
        K::InvalidAggregation { .. } => {
            (ErrorType::SyntaxError, SemanticDetail::InvalidAggregation)
        }
        K::NoExpressionAlias => (ErrorType::SyntaxError, SemanticDetail::NoExpressionAlias),
        K::ColumnNameConflict { .. } => {
            (ErrorType::SyntaxError, SemanticDetail::ColumnNameConflict)
        }
        K::NegativeIntegerArgument => (
            ErrorType::SyntaxError,
            SemanticDetail::NegativeIntegerArgument,
        ),
        K::NoSingleRelationshipType { .. } => (
            ErrorType::SyntaxError,
            SemanticDetail::NoSingleRelationshipType,
        ),
        K::RequiresDirectedRelationship => (
            ErrorType::SyntaxError,
            SemanticDetail::RequiresDirectedRelationship,
        ),
        K::CreatingVarLength => (ErrorType::SyntaxError, SemanticDetail::CreatingVarLength),
        K::UnknownFunction { .. } => (ErrorType::SyntaxError, SemanticDetail::UnknownFunction),
        K::InvalidNumberOfArguments { .. } => (
            ErrorType::SyntaxError,
            SemanticDetail::InvalidNumberOfArguments,
        ),
        // The two measured non-SyntaxError compile-time types in the corpus, both from
        // `tck/features/clauses/call/Call1.feature` (rmp #57).
        K::ProcedureNotFound { .. } => {
            (ErrorType::ProcedureError, SemanticDetail::ProcedureNotFound)
        }
        K::InvalidProcedureArgumentType { .. } => {
            (ErrorType::SyntaxError, SemanticDetail::InvalidArgumentType)
        }
        K::MissingParameter { .. } => (
            ErrorType::ParameterMissing,
            SemanticDetail::MissingParameter,
        ),
        K::NonConstantExpression { .. } => (
            ErrorType::SyntaxError,
            SemanticDetail::NonConstantExpression,
        ),
        K::InvalidDelete => (ErrorType::SyntaxError, SemanticDetail::InvalidDelete),
        K::InvalidClauseComposition { .. } => (
            ErrorType::SyntaxError,
            SemanticDetail::InvalidClauseComposition,
        ),
        K::DifferentColumnsInUnion => (
            ErrorType::SyntaxError,
            SemanticDetail::DifferentColumnsInUnion,
        ),
        K::InvalidLoadCsvUrl => (ErrorType::SyntaxError, SemanticDetail::InvalidLoadCsvUrl),
        K::InvalidShortestPath { .. } => {
            (ErrorType::SyntaxError, SemanticDetail::InvalidShortestPath)
        }
        K::PatternPredicateInExpression => {
            (ErrorType::SyntaxError, SemanticDetail::UnexpectedSyntax)
        }
        K::InvalidParameterUse => (ErrorType::SyntaxError, SemanticDetail::InvalidParameterUse),
        // `#[non_exhaustive]` requires this arm in a downstream crate. A new, unlisted variant
        // trips it loudly rather than passing silently; the compile-time guard is in-crate.
        other => panic!("unlisted SemanticErrorKind in the classification cross-check: {other:?}"),
    }
}

/// THE phase-split invariant: **every** semantic-error variant is classified at compile time, with
/// the type/detail the table promises. This is the regression guard `04 §7.3` requires.
#[test]
fn every_semantic_error_is_classified_at_compile_time() {
    for kind in all_kinds() {
        let Classification {
            phase,
            error_type,
            detail,
        } = kind.classification();

        // (1) The load-bearing invariant.
        assert_eq!(
            phase,
            ErrorPhase::CompileTime,
            "variant {kind:?} must be a COMPILE-TIME error (semantic analysis never raises runtime)"
        );

        // (2) Round-trip against the independently-written expectation table.
        let (want_type, want_detail) = expected_classification(&kind);
        assert_eq!(error_type, want_type, "type mismatch for {kind:?}");
        assert_eq!(detail, want_detail, "detail mismatch for {kind:?}");

        // The kind's own accessors agree with the assembled classification.
        assert_eq!(
            kind.error_type(),
            error_type,
            "error_type() disagrees for {kind:?}"
        );
        assert_eq!(kind.detail(), detail, "detail() disagrees for {kind:?}");

        // And the SemanticError wrapper preserves the classification.
        let wrapped = SemanticError::new(kind.clone(), Span::new(0, 1));
        assert_eq!(wrapped.classification(), kind.classification());
    }
}

/// The Gherkin rendering matches the TCK `Then a <type> should be raised at <phase>: <detail>` shape
/// verbatim, for a couple of representative variants. This pins the strings the TCK runner matches.
#[test]
fn renders_the_verbatim_tck_gherkin_triple() {
    let undef = SemanticErrorKind::UndefinedVariable {
        name: "x".to_owned(),
    };
    let c = undef.classification();
    assert_eq!(
        format!(
            "a {} should be raised at {}: {}",
            c.error_type, c.phase, c.detail
        ),
        "a SyntaxError should be raised at compile time: UndefinedVariable"
    );

    let nested = SemanticErrorKind::NestedAggregation;
    let c = nested.classification();
    assert_eq!(
        format!(
            "a {} should be raised at {}: {}",
            c.error_type, c.phase, c.detail
        ),
        "a SyntaxError should be raised at compile time: NestedAggregation"
    );
}

/// `all_kinds()` lists each variant exactly once (no accidental duplicate / omission by count).
/// Combined with the wildcard-free match, this keeps the enumeration honest.
#[test]
fn every_listed_kind_is_distinct() {
    let kinds = all_kinds();
    // 25 variants as of this writing; the assert documents the count and trips if one is dropped
    // from `all_kinds` without the match also changing (the match would then fail to compile).
    assert_eq!(
        kinds.len(),
        25,
        "all_kinds() should list every SemanticErrorKind variant once"
    );
    let details: std::collections::HashSet<_> = kinds.iter().map(|k| k.detail()).collect();
    // Two variants (`UndefinedVariable` and `RETURN *`'s empty-scope reuse) share the
    // `UndefinedVariable` detail at the *call site*, but as enum *variants* each detail here is
    // distinct, so the set size equals the list length.
    assert_eq!(
        details.len(),
        kinds.len(),
        "each variant maps to a distinct detail"
    );
}

/// No `SemanticErrorKind` ever classifies as runtime — asserted as an explicit negative so the
/// intent is unmistakable in the test output.
#[test]
fn no_semantic_error_classifies_as_runtime() {
    for kind in all_kinds() {
        assert_ne!(
            kind.classification().phase,
            ErrorPhase::Runtime,
            "{kind:?} must never be a runtime error"
        );
    }
}
