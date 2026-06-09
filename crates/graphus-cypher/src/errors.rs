//! The Cypher **semantic-error** taxonomy and the TCK **error-classification table** (`04
//! §7.3`).
//!
//! Semantic analysis ([`crate::semantics`]) is the *only* phase allowed to emit compile-time
//! errors, and it runs to completion **before any side effect** (`04 §7.3`). Every fault it can
//! raise is one variant of [`SemanticErrorKind`]; each variant is statically classified — by
//! [`SemanticErrorKind::classification`] — into its openCypher TCK
//! [`(type, phase)`](Classification) pair, where the phase is **always**
//! [`ErrorPhase::CompileTime`]. The CI-style test in this module (and in
//! `tests/error_classification.rs`) asserts that invariant for *every* variant so the
//! compile-vs-runtime split cannot silently regress.
//!
//! # Grounding in the openCypher TCK
//!
//! The TCK expresses an expected error as a triple — a **phase** (`compile time` / `runtime`), a
//! **type** (`SyntaxError`, `SemanticError`, …) and a fine-grained **detail** — in the Gherkin
//! shape
//!
//! ```text
//! Then a SyntaxError should be raised at compile time: UndefinedVariable
//! ```
//!
//! (see the openCypher TCK `tck/features/**` feature files; `tck/README.adoc` documents the
//! `PHASE` / `TYPE` / `DETAIL` decomposition). The `type` strings are taken verbatim from
//! `tck/README.adoc` (`SyntaxError`, `SemanticError`); the `detail` strings
//! ([`SemanticDetail`]) are taken verbatim from the feature files that assert them — each variant
//! cites where. The two-letter Neo4j status codes are **not** modelled here: they are a Neo4j
//! surface, not part of the openCypher TCK triple, and the pinned-tag reconciliation is the
//! escalated open item in `02-decision-register.md` Q2.
//!
//! # Why `UndefinedVariable` is a `SyntaxError`, not a `SemanticError`
//!
//! Intuitively an undefined variable is "semantic", but the openCypher TCK raises it as a
//! **`SyntaxError`** at compile time (e.g. `tck/features/clauses/return/Return1.feature`:
//! `Then a SyntaxError should be raised at compile time: UndefinedVariable`). We follow the TCK
//! verbatim rather than our intuition (`CLAUDE.md`: never guess; the TCK is inviolable). Both
//! `SyntaxError` and `SemanticError` are compile-time types, so the phase split — the load-bearing
//! invariant — is unaffected by the type choice.

use crate::lexer::Span;
use graphus_core::GraphusError;
use std::fmt;

/// The TCK error **phase**: when the error is required to be raised relative to execution
/// (`04 §7.3`; openCypher TCK `tck/README.adoc`).
///
/// Semantic analysis raises **only** [`Self::CompileTime`] errors. [`Self::Runtime`] exists so the
/// classification table can name the boundary explicitly (and so a future executor error taxonomy
/// can reuse this type), but no [`SemanticErrorKind`] ever maps to it — asserted by
/// [`SemanticErrorKind::classification`]'s test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum ErrorPhase {
    /// Raised during compilation, **before any side effect** (`04 §7.3`). This is the phase of
    /// every semantic-analysis error.
    CompileTime,
    /// Raised during row production by the executor (e.g. division by zero on actual data, type
    /// coercion on actual values, constraint violations). **Never** produced by semantic analysis;
    /// present only to document the boundary.
    Runtime,
}

impl ErrorPhase {
    /// The TCK Gherkin spelling of the phase (`"compile time"` / `"runtime"`).
    #[must_use]
    pub const fn as_tck_str(self) -> &'static str {
        match self {
            Self::CompileTime => "compile time",
            Self::Runtime => "runtime",
        }
    }
}

impl fmt::Display for ErrorPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_tck_str())
    }
}

/// The TCK error **type** (the second component of the TCK triple), taken verbatim from the
/// openCypher TCK `tck/README.adoc`.
///
/// Only the two compile-time types are modelled here, since semantic analysis emits only those.
/// The runtime types (`TypeError`, `ArithmeticError`, `EntityNotFound`,
/// `ConstraintVerificationFailed`, …) belong to the executor and are intentionally **not** in this
/// enum (see [`crate::semantics`] for the boundary documentation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum ErrorType {
    /// `SyntaxError` — *"The statement contains invalid or unsupported syntax."* (TCK
    /// `tck/README.adoc`.) The TCK raises some statically-detectable name-resolution faults under
    /// this type (notably `UndefinedVariable`).
    SyntaxError,
    /// `SemanticError` — *"The statement is syntactically valid, but expresses something that the
    /// database cannot do."* (TCK `tck/README.adoc`.)
    SemanticError,
}

impl ErrorType {
    /// The verbatim TCK type name (`"SyntaxError"` / `"SemanticError"`).
    #[must_use]
    pub const fn as_tck_str(self) -> &'static str {
        match self {
            Self::SyntaxError => "SyntaxError",
            Self::SemanticError => "SemanticError",
        }
    }
}

impl fmt::Display for ErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_tck_str())
    }
}

/// The fine-grained TCK **detail** (the third component of the TCK triple).
///
/// Each spelling is taken **verbatim** from the openCypher TCK feature files that assert it; the
/// originating [`SemanticErrorKind`] variant cites the concrete `tck/features/**` path. These are
/// the strings a TCK `Then a … should be raised at … : <Detail>` step matches against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SemanticDetail {
    /// `UndefinedVariable` — a variable is referenced where it is not in scope.
    UndefinedVariable,
    /// `VariableAlreadyBound` — a pattern re-introduces a name already bound to an entity where
    /// Cypher forbids rebinding.
    VariableAlreadyBound,
    /// `VariableTypeConflict` — a name is bound to two incompatible entity types (e.g. used as both
    /// a node and a relationship variable).
    VariableTypeConflict,
    /// `AmbiguousAggregationExpression` — a projection mixes aggregating and non-aggregating terms
    /// such that the grouping is ambiguous.
    AmbiguousAggregationExpression,
    /// `NestedAggregation` — an aggregating function is nested inside another aggregating function.
    NestedAggregation,
    /// `InvalidAggregation` — an aggregation appears where aggregation is not allowed (e.g. in
    /// `WHERE`, in `ORDER BY` of a non-aggregating projection, in a pattern predicate).
    InvalidAggregation,
    /// `NoExpressionAlias` — a non-trivial `RETURN`/`WITH` expression lacks the required `AS` alias
    /// (mandatory for `WITH`; for the final `RETURN` where a name cannot be inferred).
    NoExpressionAlias,
    /// `ColumnNameConflict` — two projected result columns share the same name.
    ColumnNameConflict,
    /// `NegativeIntegerArgument` — a syntactic position requiring a non-negative integer literal got
    /// a negative one (e.g. a variable-length lower bound).
    NegativeIntegerArgument,
    /// `NoSingleRelationshipType` — a `CREATE`/`MERGE` relationship pattern does not specify exactly
    /// one relationship type.
    NoSingleRelationshipType,
    /// `RequiresDirectedRelationship` — a `CREATE`/`MERGE` relationship pattern is undirected, but
    /// creation requires a direction.
    RequiresDirectedRelationship,
    /// `CreatingVarLength` — a `CREATE`/`MERGE` pattern uses a variable-length relationship, which is
    /// not creatable.
    CreatingVarLength,
    /// `UnknownFunction` — a function invocation names a function the database does not provide.
    UnknownFunction,
    /// `InvalidNumberOfArguments` — a known function is called with the wrong arity.
    InvalidNumberOfArguments,
    /// `InvalidDelete` — `DELETE` targets something that is not a deletable graph entity reference.
    InvalidDelete,
    /// `InvalidClauseComposition` — clauses are composed in an order Cypher forbids (e.g. a
    /// `RETURN` that is not the final clause, or an empty single query).
    InvalidClauseComposition,
}

impl SemanticDetail {
    /// The verbatim TCK detail spelling (matches a `Then a … should be raised at … : <here>` step).
    #[must_use]
    pub const fn as_tck_str(self) -> &'static str {
        match self {
            Self::UndefinedVariable => "UndefinedVariable",
            Self::VariableAlreadyBound => "VariableAlreadyBound",
            Self::VariableTypeConflict => "VariableTypeConflict",
            Self::AmbiguousAggregationExpression => "AmbiguousAggregationExpression",
            Self::NestedAggregation => "NestedAggregation",
            Self::InvalidAggregation => "InvalidAggregation",
            Self::NoExpressionAlias => "NoExpressionAlias",
            Self::ColumnNameConflict => "ColumnNameConflict",
            Self::NegativeIntegerArgument => "NegativeIntegerArgument",
            Self::NoSingleRelationshipType => "NoSingleRelationshipType",
            Self::RequiresDirectedRelationship => "RequiresDirectedRelationship",
            Self::CreatingVarLength => "CreatingVarLength",
            Self::UnknownFunction => "UnknownFunction",
            Self::InvalidNumberOfArguments => "InvalidNumberOfArguments",
            Self::InvalidDelete => "InvalidDelete",
            Self::InvalidClauseComposition => "InvalidClauseComposition",
        }
    }
}

impl fmt::Display for SemanticDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_tck_str())
    }
}

/// A fully-resolved TCK error **classification**: the `(phase, type, detail)` triple a TCK error
/// scenario asserts (`04 §7.3`; openCypher TCK `tck/README.adoc`).
///
/// This is the value the **error-classification table** ([`SemanticErrorKind::classification`])
/// maps each internal error variant to. The CI test asserts `phase == CompileTime` for every
/// semantic-error variant, so the compile-vs-runtime split is machine-checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub struct Classification {
    /// When the error must be raised relative to execution. For every [`SemanticErrorKind`] this is
    /// [`ErrorPhase::CompileTime`].
    pub phase: ErrorPhase,
    /// The TCK error type (`SyntaxError` / `SemanticError`).
    pub error_type: ErrorType,
    /// The fine-grained TCK detail.
    pub detail: SemanticDetail,
}

/// A compile-time **semantic** error (`04 §7.3`), carrying the byte [`Span`] of the offending AST
/// node.
///
/// This is the semantic-analysis analogue of the parser's
/// [`SyntaxError`](crate::parser::SyntaxError). Like it, [`SemanticError`] converts into the
/// crate-wide [`GraphusError::Compile`] at the engine boundary, preserving the span in the message
/// so the connectivity layer can surface a positional error. Its [`classification`] gives the TCK
/// `(phase, type, detail)` triple, with the phase guaranteed to be compile-time.
///
/// [`classification`]: SemanticError::classification
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct SemanticError {
    /// The classified cause.
    pub kind: SemanticErrorKind,
    /// The byte range of the offending AST node.
    pub span: Span,
}

impl SemanticError {
    /// Builds a [`SemanticError`].
    pub fn new(kind: SemanticErrorKind, span: Span) -> Self {
        Self { kind, span }
    }

    /// The TCK `(phase, type, detail)` classification of this error (always compile-time).
    pub fn classification(&self) -> Classification {
        self.kind.classification()
    }
}

impl fmt::Display for SemanticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "semantic error at bytes {}: {}", self.span, self.kind)
    }
}

impl std::error::Error for SemanticError {}

impl From<SemanticError> for GraphusError {
    /// Semantic-analysis errors are compile-time errors (`04 §7.3`); they map onto the crate-wide
    /// [`GraphusError::Compile`] variant, carrying the positional message.
    fn from(e: SemanticError) -> Self {
        GraphusError::Compile(e.to_string())
    }
}

/// What semantic analysis found wrong, paired with a byte [`Span`] by [`SemanticError`].
///
/// Every variant is a **compile-time** error (`04 §7.3`); [`Self::classification`] maps each to its
/// verbatim TCK `(phase, type, detail)` triple. Variants carry just enough payload to render a
/// precise human message; the offending position lives on the enclosing [`SemanticError`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SemanticErrorKind {
    /// A variable is referenced where it is not in scope. The most common scope-reset case: a name
    /// not carried through a `WITH` is undefined afterwards. TCK detail `UndefinedVariable`, raised
    /// as a `SyntaxError` (e.g. `tck/features/clauses/return/Return1.feature`).
    UndefinedVariable {
        /// The referenced name.
        name: String,
    },
    /// A pattern re-introduces a name already bound to an entity, which Cypher forbids in that
    /// position. TCK detail `VariableAlreadyBound` (e.g. `tck/features/clauses/merge/Merge*`).
    VariableAlreadyBound {
        /// The conflicting name.
        name: String,
    },
    /// A name is used as two incompatible entity kinds (e.g. node vs relationship) within one
    /// scope. TCK detail `VariableTypeConflict`.
    VariableTypeConflict {
        /// The conflicting name.
        name: String,
        /// How the name was first bound (e.g. `"node"`).
        first: VarKind,
        /// How the name was then re-used (e.g. `"relationship"`).
        second: VarKind,
    },
    /// A projection mixes aggregating and non-aggregating terms ambiguously (a non-grouping,
    /// non-aggregating sub-expression alongside an aggregation). TCK detail
    /// `AmbiguousAggregationExpression`.
    AmbiguousAggregationExpression,
    /// An aggregating function is nested inside another aggregating function. TCK detail
    /// `NestedAggregation`.
    NestedAggregation,
    /// An aggregation appears where aggregation is forbidden (`WHERE`, a pattern predicate, a
    /// variable-length bound, …). TCK detail `InvalidAggregation`.
    InvalidAggregation {
        /// Where the illegal aggregation appeared (e.g. `"WHERE"`).
        position: &'static str,
    },
    /// A `WITH` (or inferable-name-less final `RETURN`) projection expression lacks its mandatory
    /// `AS` alias. TCK detail `NoExpressionAlias`.
    NoExpressionAlias,
    /// Two projected result columns share a name. TCK detail `ColumnNameConflict`.
    ColumnNameConflict {
        /// The duplicated column name.
        name: String,
    },
    /// A non-negative-integer position got a negative literal. TCK detail `NegativeIntegerArgument`.
    NegativeIntegerArgument,
    /// A `CREATE`/`MERGE` relationship does not specify exactly one type. TCK detail
    /// `NoSingleRelationshipType`.
    NoSingleRelationshipType {
        /// How many types were written (0 or ≥2).
        count: usize,
    },
    /// A `CREATE`/`MERGE` relationship is undirected. TCK detail `RequiresDirectedRelationship`.
    RequiresDirectedRelationship,
    /// A `CREATE`/`MERGE` pattern uses a variable-length relationship. TCK detail
    /// `CreatingVarLength`.
    CreatingVarLength,
    /// A function invocation names an unknown function. TCK detail `UnknownFunction`.
    UnknownFunction {
        /// The (dotted) function name as written.
        name: String,
    },
    /// A known function is called with the wrong number of arguments. TCK detail
    /// `InvalidNumberOfArguments`.
    InvalidNumberOfArguments {
        /// The function name.
        name: String,
        /// How many arguments the function accepts (rendered as a human range).
        expected: String,
        /// How many were supplied.
        got: usize,
    },
    /// `DELETE` targets a non-entity expression. TCK detail `InvalidDelete`.
    InvalidDelete,
    /// Clauses are composed illegally (e.g. `RETURN` not last, an empty single query). TCK detail
    /// `InvalidClauseComposition`.
    InvalidClauseComposition {
        /// A short human reason.
        reason: &'static str,
    },
}

/// How a pattern variable is bound — used to report [`SemanticErrorKind::VariableTypeConflict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum VarKind {
    /// Bound to a node by a node pattern.
    Node,
    /// Bound to a relationship by a relationship pattern.
    Relationship,
    /// Bound to a path by a named path / `UNWIND` / `WITH`/`RETURN` projection / `YIELD`.
    Value,
}

impl fmt::Display for VarKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Node => "node",
            Self::Relationship => "relationship",
            Self::Value => "value",
        })
    }
}

impl SemanticErrorKind {
    /// The TCK detail this error maps to.
    pub const fn detail(&self) -> SemanticDetail {
        match self {
            Self::UndefinedVariable { .. } => SemanticDetail::UndefinedVariable,
            Self::VariableAlreadyBound { .. } => SemanticDetail::VariableAlreadyBound,
            Self::VariableTypeConflict { .. } => SemanticDetail::VariableTypeConflict,
            Self::AmbiguousAggregationExpression => SemanticDetail::AmbiguousAggregationExpression,
            Self::NestedAggregation => SemanticDetail::NestedAggregation,
            Self::InvalidAggregation { .. } => SemanticDetail::InvalidAggregation,
            Self::NoExpressionAlias => SemanticDetail::NoExpressionAlias,
            Self::ColumnNameConflict { .. } => SemanticDetail::ColumnNameConflict,
            Self::NegativeIntegerArgument => SemanticDetail::NegativeIntegerArgument,
            Self::NoSingleRelationshipType { .. } => SemanticDetail::NoSingleRelationshipType,
            Self::RequiresDirectedRelationship => SemanticDetail::RequiresDirectedRelationship,
            Self::CreatingVarLength => SemanticDetail::CreatingVarLength,
            Self::UnknownFunction { .. } => SemanticDetail::UnknownFunction,
            Self::InvalidNumberOfArguments { .. } => SemanticDetail::InvalidNumberOfArguments,
            Self::InvalidDelete => SemanticDetail::InvalidDelete,
            Self::InvalidClauseComposition { .. } => SemanticDetail::InvalidClauseComposition,
        }
    }

    /// The TCK error **type** for this error.
    ///
    /// Almost every semantic-analysis fault is a TCK `SemanticError`; the lone exception is
    /// [`Self::UndefinedVariable`], which the openCypher TCK raises as a **`SyntaxError`** (verbatim
    /// in e.g. `tck/features/clauses/return/Return1.feature`). We follow the TCK, not intuition.
    pub const fn error_type(&self) -> ErrorType {
        match self {
            Self::UndefinedVariable { .. } => ErrorType::SyntaxError,
            _ => ErrorType::SemanticError,
        }
    }

    /// The full TCK `(phase, type, detail)` classification — the **error-classification table**
    /// (`04 §7.3`).
    ///
    /// The phase is **always** [`ErrorPhase::CompileTime`]: semantic analysis is the only phase
    /// permitted to emit compile-time errors and never emits runtime ones (`04 §7.3`). This is the
    /// machine-checked invariant the CI test relies on.
    pub const fn classification(&self) -> Classification {
        Classification {
            phase: ErrorPhase::CompileTime,
            error_type: self.error_type(),
            detail: self.detail(),
        }
    }
}

impl fmt::Display for SemanticErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UndefinedVariable { name } => write!(f, "variable `{name}` is not defined"),
            Self::VariableAlreadyBound { name } => {
                write!(
                    f,
                    "variable `{name}` is already bound and cannot be rebound here"
                )
            }
            Self::VariableTypeConflict {
                name,
                first,
                second,
            } => write!(
                f,
                "variable `{name}` is used as a {first} and as a {second} in the same scope"
            ),
            Self::AmbiguousAggregationExpression => f.write_str(
                "projection mixes aggregating and non-aggregating expressions; \
                 every non-aggregated term must be a grouping key",
            ),
            Self::NestedAggregation => {
                f.write_str("aggregate functions may not be nested inside one another")
            }
            Self::InvalidAggregation { position } => {
                write!(f, "aggregation is not allowed in {position}")
            }
            Self::NoExpressionAlias => {
                f.write_str("expression in WITH/RETURN must be aliased with `AS`")
            }
            Self::ColumnNameConflict { name } => {
                write!(f, "result column `{name}` is defined more than once")
            }
            Self::NegativeIntegerArgument => {
                f.write_str("a non-negative integer is required here, but a negative one was given")
            }
            Self::NoSingleRelationshipType { count } => write!(
                f,
                "a created relationship must declare exactly one type, but {count} were given"
            ),
            Self::RequiresDirectedRelationship => {
                f.write_str("only directed relationships can be created")
            }
            Self::CreatingVarLength => {
                f.write_str("variable-length relationships cannot be created")
            }
            Self::UnknownFunction { name } => write!(f, "unknown function `{name}`"),
            Self::InvalidNumberOfArguments {
                name,
                expected,
                got,
            } => write!(
                f,
                "function `{name}` takes {expected} argument(s), but {got} were given"
            ),
            Self::InvalidDelete => {
                f.write_str("DELETE expects a node, relationship or path expression")
            }
            Self::InvalidClauseComposition { reason } => {
                write!(f, "invalid clause composition: {reason}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every detail variant exists, and the round-trip `detail -> &str` is stable and non-empty.
    /// This pins the verbatim TCK spellings (renaming one is a deliberate, test-breaking act).
    #[test]
    fn detail_strings_are_the_verbatim_tck_spellings() {
        let pairs = [
            (SemanticDetail::UndefinedVariable, "UndefinedVariable"),
            (SemanticDetail::VariableAlreadyBound, "VariableAlreadyBound"),
            (SemanticDetail::VariableTypeConflict, "VariableTypeConflict"),
            (
                SemanticDetail::AmbiguousAggregationExpression,
                "AmbiguousAggregationExpression",
            ),
            (SemanticDetail::NestedAggregation, "NestedAggregation"),
            (SemanticDetail::InvalidAggregation, "InvalidAggregation"),
            (SemanticDetail::NoExpressionAlias, "NoExpressionAlias"),
            (SemanticDetail::ColumnNameConflict, "ColumnNameConflict"),
            (
                SemanticDetail::NegativeIntegerArgument,
                "NegativeIntegerArgument",
            ),
            (
                SemanticDetail::NoSingleRelationshipType,
                "NoSingleRelationshipType",
            ),
            (
                SemanticDetail::RequiresDirectedRelationship,
                "RequiresDirectedRelationship",
            ),
            (SemanticDetail::CreatingVarLength, "CreatingVarLength"),
            (SemanticDetail::UnknownFunction, "UnknownFunction"),
            (
                SemanticDetail::InvalidNumberOfArguments,
                "InvalidNumberOfArguments",
            ),
            (SemanticDetail::InvalidDelete, "InvalidDelete"),
            (
                SemanticDetail::InvalidClauseComposition,
                "InvalidClauseComposition",
            ),
        ];
        for (detail, s) in pairs {
            assert_eq!(detail.as_tck_str(), s);
            assert_eq!(detail.to_string(), s);
        }
    }

    /// `UndefinedVariable` is a `SyntaxError` (TCK-faithful); everything else is a `SemanticError`.
    #[test]
    fn undefined_variable_is_a_syntax_error() {
        let undef = SemanticErrorKind::UndefinedVariable {
            name: "n".to_owned(),
        };
        assert_eq!(undef.error_type(), ErrorType::SyntaxError);

        let other = SemanticErrorKind::NestedAggregation;
        assert_eq!(other.error_type(), ErrorType::SemanticError);
    }

    /// The phase-split invariant in isolation (also asserted across *all* variants in
    /// `tests/error_classification.rs`).
    #[test]
    fn every_classification_is_compile_time() {
        let kinds = [
            SemanticErrorKind::UndefinedVariable {
                name: "x".to_owned(),
            },
            SemanticErrorKind::NestedAggregation,
            SemanticErrorKind::InvalidDelete,
        ];
        for k in kinds {
            assert_eq!(k.classification().phase, ErrorPhase::CompileTime);
        }
    }

    /// **Compile-time exhaustiveness guard** (`04 §7.3`): this wildcard-free match over
    /// `SemanticErrorKind` (legal here because we are *in-crate*, where `#[non_exhaustive]` does not
    /// force a wildcard) fails to compile the moment a new variant is added without classifying it —
    /// so the error-classification table can never silently miss a variant. Each arm also asserts
    /// the phase is compile-time, so the split is checked structurally, not just by sampling.
    #[test]
    fn classification_table_is_exhaustive() {
        // A helper whose match has no `_` arm: adding a variant breaks the build here.
        fn classify(kind: &SemanticErrorKind) -> Classification {
            match kind {
                SemanticErrorKind::UndefinedVariable { .. }
                | SemanticErrorKind::VariableAlreadyBound { .. }
                | SemanticErrorKind::VariableTypeConflict { .. }
                | SemanticErrorKind::AmbiguousAggregationExpression
                | SemanticErrorKind::NestedAggregation
                | SemanticErrorKind::InvalidAggregation { .. }
                | SemanticErrorKind::NoExpressionAlias
                | SemanticErrorKind::ColumnNameConflict { .. }
                | SemanticErrorKind::NegativeIntegerArgument
                | SemanticErrorKind::NoSingleRelationshipType { .. }
                | SemanticErrorKind::RequiresDirectedRelationship
                | SemanticErrorKind::CreatingVarLength
                | SemanticErrorKind::UnknownFunction { .. }
                | SemanticErrorKind::InvalidNumberOfArguments { .. }
                | SemanticErrorKind::InvalidDelete
                | SemanticErrorKind::InvalidClauseComposition { .. } => kind.classification(),
            }
        }

        for kind in [
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
            SemanticErrorKind::InvalidDelete,
            SemanticErrorKind::InvalidClauseComposition { reason: "x" },
        ] {
            assert_eq!(classify(&kind).phase, ErrorPhase::CompileTime, "{kind:?}");
        }
    }

    #[test]
    fn maps_to_graphus_compile_error() {
        let e = SemanticError::new(
            SemanticErrorKind::UndefinedVariable {
                name: "n".to_owned(),
            },
            Span::new(7, 8),
        );
        let g: GraphusError = e.into();
        assert!(matches!(g, GraphusError::Compile(_)));
        assert!(g.to_string().starts_with("compile error: "));
    }
}
