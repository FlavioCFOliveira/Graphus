//! `graphus-cypher` — Cypher parse, plan and execute pipeline for Graphus (targets the openCypher
//! TCK).
//!
//! This crate hosts the compile/execute pipeline (`04-technical-design.md` §7.1). Two parts exist
//! today:
//!
//! - The **lexer** ([`lexer`]) — the pipeline's front door — turns query text into a token stream
//!   with byte-accurate source spans (`04 §7.1`). Lexer errors are the compile-time `SyntaxError`
//!   class with precise positions (`04 §7.3`), as the openCypher TCK asserts error offsets.
//! - The **Cypher value-model semantics** ([`ordering`], [`equality`], [`equivalence`],
//!   [`ternary`]) — the meaning of comparing, ordering, and de-duplicating [`graphus_core::Value`]s
//!   (`04 §7.2`, §7.6). Every rule there is taken **verbatim from the openCypher
//!   comparability/orderability/equality CIP** (CIP2016-06-14), the source the TCK enforces.
//!
//! - The **parser** ([`parser`]) — the pipeline's second stage — consumes the lexer's token stream
//!   and produces a typed [`ast`] (`04 §7.1`: *"parser (hand-written recursive descent / Pratt) →
//!   AST"*). It raises **only** compile-time `SyntaxError`s with precise byte positions (`04 §7.3`);
//!   the semantic-analysis phase raises `SemanticError`s.
//!
//! - The **semantic analysis** ([`semantics`]) — the pipeline's third stage — walks the parser's
//!   [`ast`] and raises **all** statically-detectable Cypher errors as **compile-time** errors
//!   ([`semantics::analyze`] → [`semantics::ValidatedQuery`]), then hands a validated AST to the
//!   planner (`04 §7.1`/§7.3). It is the *only* phase allowed to emit compile-time errors and runs
//!   to completion **before any side effect**; the error taxonomy and the TCK
//!   **error-classification table** (the machine-checked compile-vs-runtime phase split) live in
//!   [`errors`], and the built-in [`function_registry`] backs the unknown-function / wrong-arity
//!   checks. Errors the TCK expects at *runtime* (division by zero, value type errors, constraint
//!   violations, missing parameters) are deliberately **not** raised here — they belong to the
//!   executor (`04 §7.3`; see [`semantics`] for the boundary).
//!
//! - The **logical planner** ([`lower`]) — the pipeline's fourth stage — lowers a
//!   [`semantics::ValidatedQuery`] into a [logical plan](logical) ([`lower::lower`] →
//!   [`logical::LogicalOp`]): a tree of relational-graph algebra operators (`04 §7.1`:
//!   *"logical planner → logical plan (relational-graph algebra: Expand, NodeScan, Filter, Project,
//!   Apply, Optional, Merge, Create, SetProperty, …)"*). The plan is deliberately **index-agnostic**
//!   and strategy-agnostic — index seeks, expand-into vs expand-all, and join/limit/sort strategy
//!   are the **physical** planner's job. The lowering is total and infallible over a validated query
//!   and applies only conservative, semantics-preserving normalisation (inline-property-map
//!   predicate hoisting); cost-based optimisation is Phase 2 (`00-overview`).
//!
//! - The **physical planner** ([`physical`]) — the pipeline's fifth stage — lowers a
//!   [logical plan](logical) into a [`physical::PhysicalPlan`] ([`physical::plan_physical`] →
//!   [`physical::PhysicalOp`]), consulting the **index catalog** ([`catalog`]) to make the strategy
//!   choices the logical plan left open (`04 §7.1`: *"physical planner → physical plan (index seeks,
//!   expand-into vs expand-all, hash vs nested-loop join, sort, limit pushdown)"*). v1 is
//!   heuristic/rule-based with index awareness (`04 §6.6`); each rule is chosen to be obviously
//!   semantics-preserving. The plan records the catalog [`catalog::IndexId`]s it depends on so the
//!   plan cache invalidates on schema/index change (`04 §6.6`).
//!
//! - The **plan cache** ([`plan_cache`]) — keyed by `(normalized_query_text, schema_version,
//!   feature_flags)` (`04 §7.5`), capacity-bounded LRU, invalidated on a `schema_version` bump.
//!   Normalisation applies **literal auto-parameterisation** ([`plan_cache::normalize_query`]):
//!   inline scalar literals are lifted to auto-parameters so structurally identical queries share a
//!   plan — a TCK-safe transformation that preserves observable semantics (`04 §7.5`).
//!
//! - **Parameter binding** ([`binding`]) — the **runtime** phase ([`binding::bind_parameters`])
//!   that binds parameters to a compiled plan at *execution*, never compile (`04 §7.5`). The plan is
//!   parameter-independent (so the cache is parameter-independent); a missing or ill-typed parameter
//!   is a **runtime** error ([`binding::BindError`]), validated here against the plan's expectations
//!   (`04 §7.3`/§7.5).
//!
//! # The four value-model operations (they are genuinely different)
//!
//! A recurring source of TCK failures is conflating these; Graphus keeps them as four separate,
//! independently-tested operations:
//!
//! | Operation | Module | Result | `null` | `NaN` | `-0.0` vs `+0.0` |
//! |-----------|--------|--------|--------|-------|------------------|
//! | Ordering (`ORDER BY`) | [`ordering`] | total order | largest | largest number | distinct (`-0.0 < +0.0`) |
//! | Equality (`=`) | [`equality`] | `Ternary` | propagates (`→ NULL`) | `NaN = NaN → FALSE` | equal |
//! | Membership (`IN`) | [`equality::is_in`] | `Ternary` | propagates | never matches | equal |
//! | Equivalence (`DISTINCT`/grouping) | [`equivalence`] | `bool` | `null ≡ null → true` | `NaN ≡ NaN → true` | equal |
//!
//! Boolean predicates combine via three-valued (Kleene) logic in [`ternary`].
//!
//! # Ascending global order (CIP2016-06-14 §Orderability), verbatim
//!
//! ```text
//! MAP < NODE < RELATIONSHIP < LIST < PATH < {temporals} < STRING < BOOLEAN < NUMBER < NaN < null
//! ```
//!
//! with `{temporals}` ascending `ZonedDateTime < LocalDateTime < Date < ZonedTime < LocalTime <
//! Duration`. (Note the openCypher quirk `STRING < BOOLEAN < NUMBER`.)
//!
//! # Cross-validation against the index
//!
//! For the index-encodable value classes, [`ordering::cmp_values`] is proven byte-for-byte
//! identical to `graphus_index::keycodec`'s encoded order by `tests/ordering_vs_keycodec.rs`. The
//! two are written independently, so the agreement guarantees a memcmp B+-tree returns rows in
//! exactly Cypher order.
//!
//! # Temporal values
//!
//! The temporal value classes are present as additive variants of [`graphus_core::Value`]
//! ([`Date`](graphus_core::Date), [`LocalTime`](graphus_core::LocalTime),
//! [`ZonedTime`](graphus_core::ZonedTime), [`LocalDateTime`](graphus_core::LocalDateTime),
//! [`ZonedDateTime`](graphus_core::ZonedDateTime), [`Duration`](graphus_core::Duration)), at
//! nanosecond resolution, and are fully ordered, compared, grouped, and index-encoded here and in
//! `graphus-index`.
//!
//! # Deferred
//!
//! The **structural** value classes — `Node`, `Relationship`, and `Path` — are **deferred to the
//! executor sub-task**: they are not yet variants of [`graphus_core::Value`] (they require entity
//! identity and the graph store). Their orderability rank slots are reserved in [`ordering`] (ranks
//! 1, 2 and 4) so they slot in without renumbering. The `Point` (spatial) class is likewise future
//! work. Until then, this crate's operations are total over the value classes that *do* exist.
#![forbid(unsafe_code)]

pub mod ast;
pub mod authorized_graph;
pub mod binding;
pub mod cardinality;
pub mod catalog;
pub mod column_cache;
pub mod constraint;
pub mod coordinator;
pub mod cost;
pub mod csr_adjacency;
pub mod equality;
pub mod equivalence;
pub mod errors;
pub mod eval;
pub mod executor;
pub mod extension;
pub mod function_registry;
pub mod gds_procedures;
pub mod graph_access;
pub mod index_set;
pub mod lexer;
pub mod loadcsv;
pub mod logical;
pub mod lower;
pub mod morsel;
pub mod ordering;
pub mod parser;
pub mod physical;
pub mod plan_cache;
pub mod procedure_registry;
pub mod read_only_graph;
pub mod read_source;
pub mod record_graph;
pub mod result;
pub mod runtime;
pub mod semantics;
pub mod snapshot;
pub(crate) mod spatial_fns;
pub mod statement_clock;
pub mod static_type;
pub mod statistics;
pub(crate) mod store_statistics;
pub(crate) mod temporal_fns;
pub mod ternary;
pub(crate) mod timezone;
pub mod value_depth;
pub mod zone_map;

pub use ast::{Clause, Expr, ExprKind, Query, QueryBody, SingleQuery};
pub use authorized_graph::{AuthorizedGraph, PrivilegeOracle};
pub use binding::{
    BindError, BoundParameters, ParamType, Parameters, bind_parameters, referenced_parameters,
};
pub use cardinality::estimate_rows;
pub use catalog::{
    IndexCatalog, IndexCatalogBuilder, IndexDescriptor, IndexId, IndexKind, IndexTarget,
};
pub use constraint::{CONSTRAINT_VIOLATION_PREFIX, ConstraintViolation};
pub use coordinator::{ConstraintInfo, CoordinatorStatistics, ReadTaskInputs, TxnCoordinator};
pub use cost::{CostEstimate, estimate_cost};
pub use equality::{equals, is_in, not_equals};
pub use equivalence::equivalent;
pub use errors::{
    Classification, ErrorPhase, ErrorType, SemanticDetail, SemanticError, SemanticErrorKind,
    VarKind,
};
pub use eval::{EvalError, EvalResult, eval, eval_value};
pub use executor::{
    CancellationToken, Cursor, ExecError, Executor, SuspendedCursor, execute,
    execute_with_extensions, execute_with_procedures,
};
pub use extension::{ExtensionRegistry, function_handler};
pub use function_registry::{
    Arity, FunctionFailure, FunctionHandler, FunctionRegistry, FunctionSet, FunctionSignature,
    no_functions,
};
pub use gds_procedures::{
    GdsCatalogHandle, new_catalog as new_gds_catalog, register_gds_procedures,
};
pub use graph_access::{ExpandDirection, GraphAccess, Incident, MemGraph, NodeId, RelData, RelId};
/// The full-text [`Analyzer`](graphus_index::fulltext::Analyzer) (`rmp` task #72), re-exported so the
/// server's index-DDL surface can validate / name analyzers without a direct `graphus-index` dep.
pub use graphus_index::fulltext::Analyzer;
pub use graphus_storage::ConstraintKind;
pub use index_set::{ConstraintRule, IndexSet};
pub use lexer::{IntBase, IntLiteral, LexError, LexErrorKind, Span, Token, TokenKind, tokenize};
pub use logical::{
    CreatePart, LogicalOp, ProjectionColumn, RemoveOp, SetOp, SortKey, Var, YieldColumn,
};
pub use lower::lower;
pub use ordering::{cmp_values, compare_values};
pub use parser::{MAX_EXPR_DEPTH, SyntaxError, SyntaxErrorKind, parse, parse_tokens};
pub use physical::{PhysicalOp, PhysicalPlan, RangeBound, plan_physical, plan_physical_with_stats};
pub use plan_cache::{
    CacheStats, FeatureFlags, NormalizedQuery, PlanCache, PlanCacheKey, SchemaVersion,
    normalize_query,
};
pub use procedure_registry::{
    FieldSpec, FieldType, ProcedureFailure, ProcedureRegistry, ProcedureSet, ProcedureSignature,
    ValueClass,
};
pub use read_only_graph::ReadOnlyGraph;
pub use read_source::{LiveSource, ReadSink, ReadViewSource, StoreReadSource, VisCtx};
pub use record_graph::RecordStoreGraph;
pub use result::{
    MaterializedNode, MaterializedPath, MaterializedRel, MaterializedStep, MaterializedValue,
};
pub use runtime::{
    NodeRef, RelRef, Row, RowSchema, RowValue, cmp_row_values, row_values_equivalent,
};
pub use semantics::{
    ValidatedQuery, analyze, analyze_to_graphus, analyze_with_extensions, analyze_with_procedures,
    check_implicit_call_parameters,
};
pub use snapshot::{GraphSnapshot, LabelId, RelTypeId, SnapId, SnapIncident, SnapshotSpec};
pub use statement_clock::StatementClock;
pub use statistics::Statistics;
pub use ternary::Ternary;
