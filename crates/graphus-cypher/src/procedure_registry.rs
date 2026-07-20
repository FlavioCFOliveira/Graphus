//! The Cypher **procedure registry** — the catalogue the engine consults to resolve a
//! `CALL ns.proc(args) [YIELD …]` (openCypher `StandaloneCall` / `InQueryCall`; `04 §7.3`).
//!
//! Semantic analysis ([`crate::semantics`]) resolves every procedure invocation against a
//! [`ProcedureRegistry`] at **compile time** — an unknown name is the TCK
//! `ProcedureError`/`ProcedureNotFound`, a wrong argument count is
//! `SyntaxError`/`InvalidNumberOfArguments`, and a statically-typed literal argument that cannot
//! satisfy the declared input type is `SyntaxError`/`InvalidArgumentType` (all spellings verbatim
//! from `tck/features/clauses/call/**`). The executor ([`crate::executor`]) consults the **same**
//! registry at execution time to stream the procedure's result rows.
//!
//! # The two registry roles
//!
//! - **Built-ins** ([`builtins`]): the engine's own procedures (`db.labels`,
//!   `db.relationshipTypes`, `db.propertyKeys`), implemented over the [`GraphAccess`] seam so they
//!   work against any backend. This is the registry the default [`crate::semantics::analyze`] /
//!   [`crate::executor::execute`] entry points use.
//! - **Caller-supplied sets** ([`ProcedureSet`]): the openCypher TCK registers scenario-local
//!   procedures dynamically (`Given … there exists a procedure …`), and a server deployment may
//!   register its own. [`crate::semantics::analyze_with_procedures`] and
//!   [`crate::executor::execute_with_procedures`] accept any [`ProcedureRegistry`].
//!
//! # Name matching
//!
//! Procedure names are dotted (`Namespace SymbolicName`, e.g. `db.labels`) and are matched
//! **case-insensitively**, consistent with the [`crate::function_registry`] (openCypher symbolic
//! names used as callables are resolved case-insensitively); the registry lowercases on both
//! insert and lookup.
//!
//! # Argument and result values
//!
//! v1 procedures consume and produce **property [`Value`]s**. Entity-valued (node/relationship/
//! path) procedure arguments and results are a named deferral alongside the structural variants of
//! [`graphus_core::Value`] itself (see [`crate::runtime`]); nothing in the TCK `clauses/call`
//! corpus requires them.

use std::collections::HashMap;
use std::fmt;
use std::sync::LazyLock;

use graphus_core::Value;

use crate::equivalence::equivalent;
use crate::graph_access::{GraphAccess, NodeId, RelId, VectorQueryResult};

// =================================================================================================
// Signature model
// =================================================================================================

/// The Cypher value class a procedure field is declared with (the TCK signature spellings
/// `INTEGER`, `FLOAT`, `NUMBER`, `STRING`, `BOOLEAN`, plus the unconstrained `ANY`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum ValueClass {
    /// Any value is acceptable.
    Any,
    /// `BOOLEAN`.
    Boolean,
    /// `STRING`.
    String,
    /// `INTEGER`.
    Integer,
    /// `FLOAT` — an `INTEGER` argument is coercible to it (Cypher's numeric widening; TCK
    /// `Call3.feature` "argument of type FLOAT accepts value of type INTEGER").
    Float,
    /// `NUMBER` — accepts both `INTEGER` and `FLOAT` (TCK `Call3.feature`).
    Number,
    /// `NODE` — a **structural node** result column (`rmp` task #72). This class is **output-only**:
    /// a procedure that declares a `NODE` output yields the node's id as a [`Value::Integer`] (the
    /// only id-carrying property value), and the executor's `ProcedureCall` operator converts that
    /// id into a [`RowValue::Node`](crate::runtime::RowValue::Node) so the result-egress boundary
    /// materializes it into a full structural node (rmp #96) — composing MVCC visibility + RBAC for
    /// free. No procedure declares a `NODE` **input** (entity-valued arguments remain deferred).
    Node,
    /// `RELATIONSHIP` — a **structural relationship** result column (`rmp` task #663), the relationship
    /// analogue of [`Node`](Self::Node). **Output-only**: a procedure that declares a `RELATIONSHIP`
    /// output yields the relationship's id as a [`Value::Integer`], and the executor's `ProcedureCall`
    /// operator converts it into a [`RowValue::Rel`](crate::runtime::RowValue::Rel) so result egress
    /// materializes it into a full structural relationship (type/properties/endpoints through the same
    /// seam, composing MVCC + RBAC). Used by `db.index.fulltext.queryRelationships`.
    Relationship,
}

impl ValueClass {
    /// The TCK signature spelling of the class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Any => "ANY",
            Self::Boolean => "BOOLEAN",
            Self::String => "STRING",
            Self::Integer => "INTEGER",
            Self::Float => "FLOAT",
            Self::Number => "NUMBER",
            Self::Node => "NODE",
            Self::Relationship => "RELATIONSHIP",
        }
    }
}

impl fmt::Display for ValueClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A procedure field's declared type: a [`ValueClass`] plus nullability (the TCK `?` suffix, e.g.
/// `INTEGER?`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub struct FieldType {
    /// The value class.
    pub class: ValueClass,
    /// Whether `null` is acceptable (the `?` suffix).
    pub nullable: bool,
}

impl FieldType {
    /// A nullable field of `class` (the only form the TCK corpus writes).
    pub const fn nullable(class: ValueClass) -> Self {
        Self {
            class,
            nullable: true,
        }
    }

    /// A **required** (non-null) field of `class` — the form the engine's own built-in signatures
    /// declare for their inputs and outputs (`db.*` catalogue procedures, `dbms.components`, …), where
    /// the value is always present.
    pub const fn required(class: ValueClass) -> Self {
        Self {
            class,
            nullable: false,
        }
    }

    /// Whether a **statically-known** argument value satisfies this type, applying Cypher's
    /// argument coercions: `INTEGER` is acceptable where `FLOAT` or `NUMBER` is declared, `FLOAT`
    /// where `NUMBER` is declared, and `null` wherever the type is nullable.
    ///
    /// Used by semantic analysis for literal arguments (the compile-time
    /// `InvalidArgumentType` check) and by [`ProcedureSet::invoke`]'s defensive runtime check.
    #[must_use]
    pub fn accepts(&self, value: &Value) -> bool {
        match value {
            Value::Null => self.nullable,
            Value::Boolean(_) => matches!(self.class, ValueClass::Any | ValueClass::Boolean),
            Value::String(_) => matches!(self.class, ValueClass::Any | ValueClass::String),
            Value::Integer(_) => matches!(
                self.class,
                ValueClass::Any | ValueClass::Integer | ValueClass::Float | ValueClass::Number
            ),
            Value::Float(_) => matches!(
                self.class,
                ValueClass::Any | ValueClass::Float | ValueClass::Number
            ),
            // A node id rides as an `Integer` (the only id-carrying property value); a `NODE`-typed
            // field accepts it. This only matters for the defensive runtime check on a procedure that
            // re-feeds an output — no procedure declares a `NODE` *input*.
            _ => matches!(self.class, ValueClass::Any),
        }
    }
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.class, if self.nullable { "?" } else { "" })
    }
}

/// One named, typed field of a procedure signature (an input parameter or an output column).
// Not `Eq`: a `FieldSpec` may carry a default [`Value`] (`rmp` task #667), which is only `PartialEq`
// (it can hold an `f64`). `PartialEq` is enough for the tests and admin introspection.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct FieldSpec {
    /// The field name (an input parameter name, or a `YIELD`-able result column name).
    pub name: String,
    /// The declared type.
    pub ty: FieldType,
    /// For an **input** field, the default value substituted when the caller omits this (trailing)
    /// argument — the Neo4j `arg = default :: TYPE` optional-argument form (e.g.
    /// `db.awaitIndexes(timeOutSeconds = 300 :: INTEGER)`, `rmp` task #667). `None` means the argument
    /// is **required**. Always `None` for an output column (a result field is never defaulted).
    ///
    /// Optional inputs must be **trailing** — every input after the first optional one is also
    /// optional — matching Neo4j; [`ProcedureSignature::required_arity`] relies on that invariant.
    pub default: Option<Value>,
}

impl FieldSpec {
    /// Builds a **required** field spec (no default): the form for every output column and every
    /// mandatory input.
    pub fn new(name: impl Into<String>, ty: FieldType) -> Self {
        Self {
            name: name.into(),
            ty,
            default: None,
        }
    }

    /// Builds an **optional input** field spec whose `default` value is substituted when the caller
    /// omits the trailing argument (Neo4j's `arg = default :: TYPE`, `rmp` task #667). Optional inputs
    /// must be trailing.
    pub fn optional(name: impl Into<String>, ty: FieldType, default: Value) -> Self {
        Self {
            name: name.into(),
            ty,
            default: Some(default),
        }
    }
}

/// A procedure's full signature: its canonical (lower-cased) dotted name, typed inputs, and typed
/// outputs (openCypher `ProcedureName ( inputs ) :: ( outputs )` as the TCK writes it).
///
/// A procedure with **no outputs** is a *void* procedure: in-query it passes each driving row
/// through unchanged (it adds no columns), and standalone it produces no client-facing result rows
/// — the openCypher TCK's `test.doNothing() :: ()` semantics.
// Not `Eq`: contains `FieldSpec`s that may carry a default [`Value`] (only `PartialEq`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct ProcedureSignature {
    /// The canonical lower-cased dotted name (e.g. `"db.labels"`).
    pub name: String,
    /// The input parameters, in declaration order.
    pub inputs: Vec<FieldSpec>,
    /// The output columns, in declaration order. Empty for a void procedure.
    pub outputs: Vec<FieldSpec>,
}

impl ProcedureSignature {
    /// Builds a signature, canonicalising `name` to lower case.
    pub fn new(name: impl Into<String>, inputs: Vec<FieldSpec>, outputs: Vec<FieldSpec>) -> Self {
        Self {
            name: name.into().to_ascii_lowercase(),
            inputs,
            outputs,
        }
    }

    /// The **minimum** number of arguments a caller must supply: the count of leading **required**
    /// inputs (those with no [`FieldSpec::default`]). Optional inputs are trailing (`rmp` task #667),
    /// so any argument count in `required_arity()..=inputs.len()` is a valid arity — a shorter call
    /// has its omitted trailing optionals filled from their declared defaults by
    /// [`ProcedureSet::invoke`]. When every input is required this equals `inputs.len()` (strict
    /// arity, unchanged).
    #[must_use]
    pub fn required_arity(&self) -> usize {
        self.inputs
            .iter()
            .take_while(|f| f.default.is_none())
            .count()
    }
}

// =================================================================================================
// Invocation failure (runtime)
// =================================================================================================

/// A **runtime** procedure-invocation failure (`04 §7.3`): the procedure exists (compile-time
/// resolution succeeded) but its execution failed.
///
/// Distinct from the compile-time TCK `ProcedureError`/`ProcedureNotFound` classification, which
/// is a [`crate::errors::SemanticErrorKind::ProcedureNotFound`] raised by semantic analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct ProcedureFailure {
    /// The dotted procedure name as invoked.
    pub name: String,
    /// A human description of the failure.
    pub message: String,
}

impl ProcedureFailure {
    /// Builds a failure for `name`.
    pub fn new(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ProcedureFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "procedure `{}` failed: {}", self.name, self.message)
    }
}

impl std::error::Error for ProcedureFailure {}

// =================================================================================================
// The registry trait
// =================================================================================================

/// The procedure catalogue the compile pipeline and the executor consult (`04 §7.3`).
///
/// The **same** registry must back both phases of one statement: semantic analysis resolves names,
/// arities and static argument types against it, and the executor invokes through it — a registry
/// swap between the phases would void the compile-time guarantees.
pub trait ProcedureRegistry {
    /// Resolves a (possibly mixed-case) dotted procedure name to its signature, or `None` if no
    /// such procedure is registered. Matching is case-insensitive.
    fn signature(&self, dotted_name: &str) -> Option<&ProcedureSignature>;

    /// Invokes the named procedure with the already-evaluated `args` (one per declared input, in
    /// order), returning its result rows — each row one [`Value`] per declared output, in order. A
    /// void procedure returns no rows (its unit semantics are the executor's job).
    ///
    /// `graph` is the live statement seam, so built-ins can read the graph.
    ///
    /// # Errors
    ///
    /// Returns a [`ProcedureFailure`] if the name is unknown (defensively — compile-time
    /// resolution normally prevents it), the argument count or a runtime argument type does not
    /// match the signature, or the procedure body itself fails.
    fn invoke(
        &self,
        dotted_name: &str,
        args: &[Value],
        graph: &mut dyn GraphAccess,
    ) -> Result<Vec<Vec<Value>>, ProcedureFailure>;

    /// Whether the named procedure is **reader-safe** (`rmp` task #546): its body performs no
    /// graph-store write and no non-thread-safe side effect, so a read-only auto-commit statement
    /// that calls only reader-safe procedures may be dispatched to the off-thread reader pool
    /// (`ReadOnlyGraph` over the captured read view serves it identically to inline).
    ///
    /// Defaults to `false` — conservative: an unknown or unclassified procedure keeps a plan on the
    /// engine thread. A registry that does not track reader-safety therefore never moves a
    /// procedure-calling read off-thread, exactly as before this task.
    fn is_reader_safe(&self, _dotted_name: &str) -> bool {
        false
    }
}

// =================================================================================================
// ProcedureSet: the concrete registry
// =================================================================================================

/// A procedure's executable body: evaluated argument values + the live graph seam in, result rows
/// out.
type ProcedureHandler = Box<
    dyn Fn(&[Value], &mut dyn GraphAccess) -> Result<Vec<Vec<Value>>, ProcedureFailure>
        + Send
        + Sync,
>;

/// One registered procedure: its signature, its body, and whether it is **reader-safe**.
struct Procedure {
    signature: ProcedureSignature,
    handler: ProcedureHandler,
    /// Whether this procedure is **reader-safe** (`rmp` task #546): its body performs **no**
    /// graph-store write and no non-thread-safe side effect, so a read-only auto-commit statement
    /// that calls only reader-safe procedures may be dispatched to the off-thread reader pool
    /// (running concurrently with the single writer) instead of being pinned to the engine thread.
    ///
    /// The default for a plainly-[`register`](ProcedureSet::register)ed procedure is **`false`**
    /// (conservative: a deployment UDP receives a `&mut dyn GraphAccess` and *could* write, so it
    /// stays inline unless it opts in via [`register_reader_safe`](ProcedureSet::register_reader_safe)).
    /// The engine built-ins (`db.*` introspection + `db.index.fulltext.queryNodes`) and the whole
    /// GDS (`gds.*`) surface are registered reader-safe: they only *read* the graph through the
    /// `GraphAccess` seam (GDS additionally mutates only its own `Arc<Mutex<GraphCatalog>>`, never the
    /// transactional store), so the off-thread read view serves them identically to inline.
    reader_safe: bool,
}

/// A read-only snapshot of one registered procedure, for administrative introspection
/// (`SHOW PROCEDURES`). Carries only the public signature and the reader-safe classification — never
/// the executable handler.
// Not `Eq`: `inputs` may carry default [`Value`]s (only `PartialEq`).
#[derive(Debug, Clone, PartialEq)]
pub struct ProcedureListing {
    /// The canonical (lower-cased) dotted name (e.g. `"db.labels"`, `"gds.pageRank.stream"`).
    pub name: String,
    /// The declared input fields (name + type), in signature order.
    pub inputs: Vec<FieldSpec>,
    /// The declared output (YIELD) fields (name + type), in signature order.
    pub outputs: Vec<FieldSpec>,
    /// Whether the procedure is **reader-safe** (reads only; dispatchable to the off-thread reader
    /// pool). The engine built-ins (`db.*`) and the GDS surface (`gds.*`) are reader-safe.
    pub reader_safe: bool,
}

/// The concrete, mutable [`ProcedureRegistry`]: a name-indexed set of procedures.
///
/// Build one with [`ProcedureSet::new`] (empty) or [`ProcedureSet::with_builtins`] (pre-loaded
/// with the engine built-ins), then [`register`](Self::register) handler-backed procedures or
/// [`register_table`](Self::register_table) fixture-table procedures (the openCypher TCK form).
#[derive(Default)]
pub struct ProcedureSet {
    procedures: HashMap<String, Procedure>,
}

impl fmt::Debug for ProcedureSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Handlers are opaque closures; list the registered signatures.
        let mut names: Vec<&str> = self.procedures.keys().map(String::as_str).collect();
        names.sort_unstable();
        f.debug_struct("ProcedureSet")
            .field("procedures", &names)
            .finish()
    }
}

impl ProcedureSet {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry pre-loaded with the engine built-ins: `db.labels()`, `db.relationshipTypes()`
    /// and `db.propertyKeys()` (the Neo4j-compatible catalogue procedures, each yielding one
    /// `STRING` column over the live graph).
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut set = Self::new();
        set.register_reader_safe(
            ProcedureSignature::new(
                "db.labels",
                Vec::new(),
                vec![FieldSpec::new(
                    "label",
                    FieldType {
                        class: ValueClass::String,
                        nullable: false,
                    },
                )],
            ),
            Box::new(|_args, graph| Ok(string_rows(distinct_node_labels(graph)))),
        );
        set.register_reader_safe(
            ProcedureSignature::new(
                "db.relationshipTypes",
                Vec::new(),
                vec![FieldSpec::new(
                    "relationshipType",
                    FieldType {
                        class: ValueClass::String,
                        nullable: false,
                    },
                )],
            ),
            Box::new(|_args, graph| Ok(string_rows(distinct_rel_types(graph)))),
        );
        set.register_reader_safe(
            ProcedureSignature::new(
                "db.propertyKeys",
                Vec::new(),
                vec![FieldSpec::new(
                    "propertyKey",
                    FieldType {
                        class: ValueClass::String,
                        nullable: false,
                    },
                )],
            ),
            Box::new(|_args, graph| Ok(string_rows(distinct_property_keys(graph)))),
        );
        // `db.index.fulltext.queryNodes(indexName, queryString) YIELD node, score` — the full-text
        // search procedure (`rmp` task #72), Neo4j-compatible. `node` is a **structural NODE** result
        // (rmp #96 materialization composes MVCC + RBAC at egress); `score` is the best-effort
        // term-overlap relevance count (a FLOAT, as Neo4j returns).
        set.register_reader_safe(
            ProcedureSignature::new(
                "db.index.fulltext.queryNodes",
                vec![
                    FieldSpec::new(
                        "indexName",
                        FieldType {
                            class: ValueClass::String,
                            nullable: false,
                        },
                    ),
                    FieldSpec::new(
                        "queryString",
                        FieldType {
                            class: ValueClass::String,
                            nullable: false,
                        },
                    ),
                    // Optional Neo4j `options` MAP (`rmp` task #667): `{skip, limit, analyzer, …}`.
                    // `skip`/`limit` trim the result; `analyzer` is validated but the index's own
                    // analyzer governs matching; unknown keys are accepted-and-ignored. There is no
                    // `MAP` value class in the v1 registry, so it rides as `ANY` (like `dbms.components`
                    // `versions`), nullable with a `{}` default so the 2-arg form still resolves.
                    FieldSpec::optional(
                        "options",
                        FieldType::nullable(ValueClass::Any),
                        Value::Map(Vec::new()),
                    ),
                ],
                vec![
                    FieldSpec::new(
                        "node",
                        FieldType {
                            class: ValueClass::Node,
                            nullable: false,
                        },
                    ),
                    FieldSpec::new(
                        "score",
                        FieldType {
                            class: ValueClass::Float,
                            nullable: false,
                        },
                    ),
                ],
            ),
            Box::new(|args, graph| fulltext_query_nodes(args, graph)),
        );
        // `db.index.fulltext.queryRelationships(indexName, queryString) YIELD relationship, score` —
        // the relationship analogue of `queryNodes` (`rmp` tasks #639, #663), now backed by a real
        // relationship full-text index. `relationship` is a **structural RELATIONSHIP** result (the
        // yielded id is materialized into a full relationship at result egress, composing MVCC + RBAC);
        // `score` is the best-effort term-overlap relevance count (a FLOAT, as Neo4j returns).
        //
        // Registered **reader-safe** (`rmp` #663), exactly like `queryNodes`: it only reads the graph
        // through the `GraphAccess` seam, and the off-thread reader pool serves it from the captured
        // full-text catalogue via the snapshot-correct relationship scan fallback
        // (`read_source::fulltext_rel_scan_fallback`), byte-identical to the inline store-backed path.
        set.register_reader_safe(
            ProcedureSignature::new(
                "db.index.fulltext.queryRelationships",
                vec![
                    FieldSpec::new("indexName", FieldType::required(ValueClass::String)),
                    FieldSpec::new("queryString", FieldType::required(ValueClass::String)),
                    // Optional Neo4j `options` MAP (`rmp` task #667), identical to `queryNodes`.
                    FieldSpec::optional(
                        "options",
                        FieldType::nullable(ValueClass::Any),
                        Value::Map(Vec::new()),
                    ),
                ],
                vec![
                    FieldSpec::new(
                        "relationship",
                        FieldType::required(ValueClass::Relationship),
                    ),
                    FieldSpec::new("score", FieldType::required(ValueClass::Float)),
                ],
            ),
            Box::new(fulltext_query_relationships),
        );
        // `db.index.vector.queryNodes(indexName, numberOfNearestNeighbours, query) YIELD node, score`
        // — the vector (HNSW) k-NN search procedure (`rmp` task #671), Neo4j-compatible. `node` is a
        // **structural NODE** result (rmp #96 materialization composes MVCC + RBAC at egress); `score`
        // is the index's normalized similarity in `(0, 1]` (cosine `(1 + cos) / 2`, euclidean
        // `1 / (1 + d²)`), returned by descending score. `query` is a `LIST<FLOAT | INTEGER>` of the
        // index's dimension, carried as `ANY` (the v1 registry has no LIST value class).
        //
        // Registered **not** reader-safe (inline on the engine thread): an HNSW is a large, mutable,
        // *approximate* structure the off-thread reader pool cannot serve byte-identically — a
        // captured clone would blow up RSS under load, and a store-recompute would return exact
        // neighbours diverging from the HNSW. Inline execution runs against the live index through the
        // `AuthorizedGraph` seam, so MVCC visibility + RBAC are preserved and the statement stays a
        // read (no write path); only its thread placement differs from the full-text procedures. This
        // mirrors `db.awaitIndex`, likewise inline for an authoritative live-seam reason.
        set.register(
            ProcedureSignature::new(
                "db.index.vector.queryNodes",
                vec![
                    FieldSpec::new("indexName", FieldType::required(ValueClass::String)),
                    FieldSpec::new(
                        "numberOfNearestNeighbours",
                        FieldType::required(ValueClass::Integer),
                    ),
                    FieldSpec::new("query", FieldType::required(ValueClass::Any)),
                ],
                vec![
                    FieldSpec::new("node", FieldType::required(ValueClass::Node)),
                    FieldSpec::new("score", FieldType::required(ValueClass::Float)),
                ],
            ),
            Box::new(vector_query_nodes_proc),
        );
        // `db.index.vector.queryRelationships(indexName, numberOfNearestNeighbours, query) YIELD
        // relationship, score` — the relationship analogue of `queryNodes` (`rmp` task #671).
        // `relationship` is a **structural RELATIONSHIP** result (materialized at egress, composing
        // MVCC + RBAC). Registered **not** reader-safe for the same reason as `queryNodes`.
        set.register(
            ProcedureSignature::new(
                "db.index.vector.queryRelationships",
                vec![
                    FieldSpec::new("indexName", FieldType::required(ValueClass::String)),
                    FieldSpec::new(
                        "numberOfNearestNeighbours",
                        FieldType::required(ValueClass::Integer),
                    ),
                    FieldSpec::new("query", FieldType::required(ValueClass::Any)),
                ],
                vec![
                    FieldSpec::new(
                        "relationship",
                        FieldType::required(ValueClass::Relationship),
                    ),
                    FieldSpec::new("score", FieldType::required(ValueClass::Float)),
                ],
            ),
            Box::new(vector_query_relationships_proc),
        );
        // `dbms.components() YIELD name, versions, edition` — the product/version/edition triple every
        // Neo4j driver and admin tool reads at connect time to render the server banner and gate
        // feature negotiation (`rmp` task #639). Neo4j returns `name`, a `LIST<STRING>` `versions`, and
        // `edition`; Graphus reports `name = "Graphus"`, `versions = [<workspace version>]` and
        // `edition = "community"`. The product name is fixed to `"Graphus"` (the task's default): a
        // Neo4j-compat override keyed on the server's `bolt_server_agent` config is out of reach here —
        // a procedure handler receives only its arguments and the `GraphAccess` seam, never the server
        // configuration — and modern drivers do not parse this string. `versions` is declared `ANY`
        // (the v1 registry `ValueClass` has no list class; the value is a `Value::List` of one string).
        set.register_reader_safe(
            ProcedureSignature::new(
                "dbms.components",
                Vec::new(),
                vec![
                    FieldSpec::new("name", FieldType::required(ValueClass::String)),
                    FieldSpec::new("versions", FieldType::required(ValueClass::Any)),
                    FieldSpec::new("edition", FieldType::required(ValueClass::String)),
                ],
            ),
            Box::new(|_args, _graph| Ok(dbms_components_rows())),
        );
        // `db.awaitIndexes(timeOutSeconds = 300)` — block until every index is ONLINE, or the timeout
        // elapses (`rmp` tasks #639, #667). A **VOID** procedure (no yielded columns). Graphus builds
        // every index **synchronously** at `CREATE INDEX` time — an index is ONLINE the moment its DDL
        // commits, so there is never a pending population to await. The body is therefore a genuine
        // no-op that returns immediately regardless of the timeout, which is the correct behaviour
        // (nothing to wait for), not a stub. The Neo4j argument (`timeOutSeconds`, INTEGER, **default
        // 300**) is now **optional** (`rmp` task #667), so both `CALL db.awaitIndexes()` and
        // `CALL db.awaitIndexes(60)` are valid, exactly as Neo4j allows.
        set.register_reader_safe(
            ProcedureSignature::new(
                "db.awaitIndexes",
                vec![FieldSpec::optional(
                    "timeOutSeconds",
                    FieldType::required(ValueClass::Integer),
                    Value::Integer(300),
                )],
                Vec::new(),
            ),
            Box::new(|_args, _graph| Ok(Vec::new())),
        );
        // `db.awaitIndex(indexName, timeOutSeconds = 300)` — the **singular** form: await one named
        // index (`rmp` task #667). A **VOID** no-op for the same reason as `db.awaitIndexes` (indexes
        // are ONLINE synchronously), **but** it rejects a genuinely-unknown index name — Neo4j raises on
        // an index that does not exist. Existence is checked across **every** index kind (node/rel
        // property, composite, full-text, spatial/point, text) through the [`GraphAccess`] seam's
        // `index_exists_by_name`, the same name namespace the `DROP INDEX <name>` resolver searches; a
        // seam without name-catalog visibility answers `None` and the await stays a lenient no-op.
        // Registered **not** reader-safe (unlike its plural sibling) so it always runs inline over the
        // store-backed seam, where the durable name catalog is authoritative.
        set.register(
            ProcedureSignature::new(
                "db.awaitIndex",
                vec![
                    FieldSpec::new("indexName", FieldType::required(ValueClass::String)),
                    FieldSpec::optional(
                        "timeOutSeconds",
                        FieldType::required(ValueClass::Integer),
                        Value::Integer(300),
                    ),
                ],
                Vec::new(),
            ),
            Box::new(db_await_index),
        );
        // `db.index.fulltext.awaitEventuallyConsistentIndexRefresh()` — a **VOID** no-op (`rmp` task
        // #667). Graphus full-text indexes are **not** eventually-consistent: every index is maintained
        // synchronously on the committing write, so there is no asynchronous refresh queue to drain.
        // Registered for driver/tooling compatibility (so `SHOW PROCEDURES` lists it and a `CALL`
        // type-checks) and completes immediately with no effect.
        set.register_reader_safe(
            ProcedureSignature::new(
                "db.index.fulltext.awaitEventuallyConsistentIndexRefresh",
                Vec::new(),
                Vec::new(),
            ),
            Box::new(|_args, _graph| Ok(Vec::new())),
        );
        // `db.index.fulltext.listAvailableAnalyzers() YIELD analyzer, description, stopwords` — the
        // full-text analyzers Graphus supports (`rmp` task #667). Graphus ships the `standard` and
        // `keyword` analyzers ([`graphus_index::fulltext::Analyzer`]); this yields one row each with a
        // short description and the analyzer's stop-word list (`standard`'s documented English set;
        // `keyword` has none). `stopwords` is a `LIST<STRING>`, carried as `ANY` (the v1 registry has no
        // list value class, exactly like `dbms.components` `versions`). A real listing, not a stub.
        set.register_reader_safe(
            ProcedureSignature::new(
                "db.index.fulltext.listAvailableAnalyzers",
                Vec::new(),
                vec![
                    FieldSpec::new("analyzer", FieldType::required(ValueClass::String)),
                    FieldSpec::new("description", FieldType::required(ValueClass::String)),
                    FieldSpec::new("stopwords", FieldType::required(ValueClass::Any)),
                ],
            ),
            Box::new(|_args, _graph| Ok(list_available_analyzers_rows())),
        );
        // `db.resampleIndex(indexName)` and `db.resampleOutdatedIndexes()` — re-sample index
        // statistics (`rmp` tasks #639, #572). Both are **VOID**, and both really do the work: they are
        // Graphus's `ANALYZE` (Neo4j has no `ANALYZE` keyword — these procedures *are* it).
        //
        // Graphus keeps two kinds of planner statistic, and they are maintained differently:
        //
        // - the per-label / per-type **counts** (`rmp` tasks #79 / #82) are live — every write keeps
        //   them current incrementally, so they never go stale and never need a resample;
        // - the per-`(label, property)` equi-depth **histograms** (`rmp` task #81) are *sampled*: an
        //   equi-depth histogram cannot be maintained incrementally without resampling (see
        //   `RecordStoreGraph::recompute_property_histogram`), so it is a point-in-time image that
        //   drifts as the data changes. It is recomputed by a full scan on demand — requested here and
        //   executed by the engine's drain, and directly when an index is created (so a declared index
        //   is born with real statistics).
        //
        // So there IS a separately-sampled statistic that goes stale, and this is what refreshes it.
        // A histogram that is stale or absent is never *wrong*, only imprecise: the estimator falls
        // back to `cardinality::DEFAULT_PREDICATE_SELECTIVITY` and the plan is merely less well
        // informed.
        //
        // The resample is NOT part of the caller's transaction, and a ROLLBACK does not undo it — that
        // is the Neo4j model (it schedules a background job), and it is what makes the outcome
        // deterministic. See `db_resample_index` for the full rationale; do not "fix" it back to
        // transactional.
        //
        // NOT reader-safe (`rmp` task #546): both record their request into the shared `IndexSet` for
        // the engine's drain. That is a mutation of engine-thread state, and the off-thread reader pool
        // works from an owned, snapshot-captured view whose `IndexSet` the engine never reads back — so
        // a dispatched resample request would be dropped on the floor and the procedure would report
        // success having queued nothing.
        set.register(
            ProcedureSignature::new(
                "db.resampleIndex",
                vec![FieldSpec::new(
                    "indexName",
                    FieldType::required(ValueClass::String),
                )],
                Vec::new(),
            ),
            Box::new(db_resample_index),
        );
        set.register(
            ProcedureSignature::new("db.resampleOutdatedIndexes", Vec::new(), Vec::new()),
            Box::new(db_resample_outdated_indexes),
        );
        set
    }

    /// Registers (or replaces) a handler-backed procedure under its signature's canonical name.
    ///
    /// The procedure is registered **not** reader-safe (the conservative default): a read plan that
    /// calls it stays on the engine thread. Use [`register_reader_safe`](Self::register_reader_safe)
    /// for a side-effect-free procedure that may be dispatched off-thread (`rmp` task #546).
    pub fn register(&mut self, signature: ProcedureSignature, handler: ProcedureHandler) {
        self.register_with_safety(signature, handler, false);
    }

    /// Registers (or replaces) a **reader-safe** handler-backed procedure (`rmp` task #546): its body
    /// performs no graph-store write and no non-thread-safe side effect, so a read-only auto-commit
    /// statement calling only reader-safe procedures may run on the off-thread reader pool. The engine
    /// registers its built-ins and the GDS surface through this; a deployment may register a read-only
    /// UDP here to let it parallelize too.
    pub fn register_reader_safe(
        &mut self,
        signature: ProcedureSignature,
        handler: ProcedureHandler,
    ) {
        self.register_with_safety(signature, handler, true);
    }

    /// The shared registration body: inserts the procedure keyed by its canonical name, tagged with
    /// its `reader_safe` capability (`rmp` task #546).
    fn register_with_safety(
        &mut self,
        signature: ProcedureSignature,
        handler: ProcedureHandler,
        reader_safe: bool,
    ) {
        let key = signature.name.clone();
        self.procedures.insert(
            key,
            Procedure {
                signature,
                handler,
                reader_safe,
            },
        );
    }

    /// Registers a **fixture-table** procedure (the openCypher TCK's
    /// `there exists a procedure …` form): each table row maps one input tuple to one output
    /// tuple. Invoked with arguments, the procedure yields — in table order — the output tuple of
    /// every row whose input tuple is [`equivalent`] to the arguments (so a `null` argument
    /// matches a `null` table cell, and `42` matches `42.0`, per the openCypher equivalence CIP).
    ///
    /// # Errors
    ///
    /// Returns a description if any row's input/output widths do not match the signature.
    pub fn register_table(
        &mut self,
        signature: ProcedureSignature,
        rows: Vec<(Vec<Value>, Vec<Value>)>,
    ) -> Result<(), String> {
        for (i, (ins, outs)) in rows.iter().enumerate() {
            if ins.len() != signature.inputs.len() || outs.len() != signature.outputs.len() {
                return Err(format!(
                    "procedure `{}` fixture row {i} has {}+{} cells, but the signature declares \
                     {} input(s) and {} output(s)",
                    signature.name,
                    ins.len(),
                    outs.len(),
                    signature.inputs.len(),
                    signature.outputs.len()
                ));
            }
        }
        self.register(
            signature,
            Box::new(move |args, _graph| {
                Ok(rows
                    .iter()
                    .filter(|(ins, _)| {
                        ins.len() == args.len()
                            && ins
                                .iter()
                                .zip(args)
                                .all(|(cell, arg)| equivalent(cell, arg))
                    })
                    .map(|(_, outs)| outs.clone())
                    .collect())
            }),
        );
        Ok(())
    }

    /// The number of registered procedures.
    #[must_use]
    pub fn len(&self) -> usize {
        self.procedures.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.procedures.is_empty()
    }

    /// Lists every registered procedure as a read-only [`ProcedureListing`], for administrative
    /// introspection (`SHOW PROCEDURES`). Sorted by canonical name for a deterministic, stable
    /// result (the internal map is unordered). Read-only: it clones public signature data and the
    /// reader-safe flag, never the handler.
    #[must_use]
    pub fn list(&self) -> Vec<ProcedureListing> {
        let mut out: Vec<ProcedureListing> = self
            .procedures
            .values()
            .map(|p| ProcedureListing {
                name: p.signature.name.clone(),
                inputs: p.signature.inputs.clone(),
                outputs: p.signature.outputs.clone(),
                reader_safe: p.reader_safe,
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

impl ProcedureRegistry for ProcedureSet {
    fn signature(&self, dotted_name: &str) -> Option<&ProcedureSignature> {
        self.procedures
            .get(dotted_name.to_ascii_lowercase().as_str())
            .map(|p| &p.signature)
    }

    fn invoke(
        &self,
        dotted_name: &str,
        args: &[Value],
        graph: &mut dyn GraphAccess,
    ) -> Result<Vec<Vec<Value>>, ProcedureFailure> {
        let Some(proc) = self
            .procedures
            .get(dotted_name.to_ascii_lowercase().as_str())
        else {
            // Defensive: semantic analysis raises ProcedureNotFound at compile time, so reaching
            // here means the compile-time and execution-time registries diverged.
            return Err(ProcedureFailure::new(
                dotted_name,
                "procedure is not registered (compile/execute registry mismatch)",
            ));
        };
        // Arity is a *range* `[required_arity, inputs.len()]` (`rmp` task #667): trailing optional
        // inputs may be omitted. When every input is required the range collapses to the exact count,
        // so this is byte-identical to the old strict check for every existing procedure.
        let min = proc.signature.required_arity();
        let max = proc.signature.inputs.len();
        if args.len() < min || args.len() > max {
            return Err(ProcedureFailure::new(
                dotted_name,
                if min == max {
                    format!("expected {max} argument(s), got {}", args.len())
                } else {
                    format!("expected {min}..={max} argument(s), got {}", args.len())
                },
            ));
        }
        if args.len() == max {
            // Full argument list — no substitution needed (the overwhelmingly common path).
            (proc.handler)(args, graph)
        } else {
            // Substitute the declared defaults for the omitted trailing optionals, so the handler
            // always sees a full argument list (Neo4j's optional-argument semantics).
            let mut full: Vec<Value> = args.to_vec();
            for input in &proc.signature.inputs[args.len()..] {
                full.push(input.default.clone().expect(
                    "INVARIANT: an input beyond required_arity() is optional and carries a default",
                ));
            }
            (proc.handler)(&full, graph)
        }
    }

    fn is_reader_safe(&self, dotted_name: &str) -> bool {
        self.procedures
            .get(dotted_name.to_ascii_lowercase().as_str())
            .is_some_and(|p| p.reader_safe)
    }
}

/// The engine's built-in procedure registry, built once on first use. This is the registry the
/// registry-less [`crate::semantics::analyze`] / [`crate::executor::execute`] entry points consult.
pub fn builtins() -> &'static ProcedureSet {
    static BUILTINS: LazyLock<ProcedureSet> = LazyLock::new(ProcedureSet::with_builtins);
    &BUILTINS
}

// =================================================================================================
// Built-in bodies (over the GraphAccess seam)
// =================================================================================================

/// Wraps sorted strings into single-column result rows.
fn string_rows(items: Vec<String>) -> Vec<Vec<Value>> {
    items.into_iter().map(|s| vec![Value::String(s)]).collect()
}

/// Every distinct node label in the graph, ascending (a deterministic order; openCypher leaves the
/// order unspecified).
fn distinct_node_labels(graph: &dyn GraphAccess) -> Vec<String> {
    let mut labels = std::collections::BTreeSet::new();
    for node in graph.scan_nodes() {
        for label in graph.node_labels(node).unwrap_or_default() {
            labels.insert(label);
        }
    }
    labels.into_iter().collect()
}

/// Every distinct relationship type in the graph, ascending.
fn distinct_rel_types(graph: &dyn GraphAccess) -> Vec<String> {
    let mut types = std::collections::BTreeSet::new();
    let mut seen = std::collections::BTreeSet::new();
    for node in graph.scan_nodes() {
        for rel in graph.incident_rels(node) {
            if seen.insert(rel) {
                if let Some(data) = graph.rel_data(rel) {
                    types.insert(data.rel_type);
                }
            }
        }
    }
    types.into_iter().collect()
}

/// The product name `dbms.components()` reports. Fixed to the Graphus product name; see the
/// registration site for why the Neo4j-compat override is not wired at this layer.
const SERVER_PRODUCT_NAME: &str = "Graphus";

/// The server version `dbms.components()` reports. Taken from this crate's `CARGO_PKG_VERSION`, which
/// is the single workspace version (`version.workspace = true`), so it tracks every release bump with
/// no hand-maintained constant to drift.
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The edition `dbms.components()` reports. Graphus ships a single edition, reported as `community`
/// (the Neo4j-compatible spelling drivers expect).
const SERVER_EDITION: &str = "community";

/// The single-row result of `dbms.components()` (`rmp` task #639): `[name, versions, edition]`, where
/// `versions` is a one-element `LIST<STRING>` carrying the server version. Neo4j-shaped so a driver's
/// connect-time banner/version probe reads it exactly as it reads a Neo4j server.
fn dbms_components_rows() -> Vec<Vec<Value>> {
    vec![vec![
        Value::String(SERVER_PRODUCT_NAME.to_owned()),
        Value::List(vec![Value::String(SERVER_VERSION.to_owned())]),
        Value::String(SERVER_EDITION.to_owned()),
    ]]
}

/// The `db.awaitIndex(indexName, timeOutSeconds)` body (`rmp` task #667).
///
/// A **VOID** no-op — Graphus builds every index synchronously, so a named index is ONLINE the moment
/// its DDL commits and there is nothing to await — **except** that it rejects a genuinely-unknown index
/// name, matching Neo4j (which raises on an index that does not exist). Existence is checked across
/// **every** index kind through [`GraphAccess::index_exists_by_name`], the same name namespace the
/// `DROP INDEX <name>` resolver searches. The `timeOutSeconds` argument (defaulted to 300 when omitted)
/// is accepted for signature fidelity and ignored — there is never a pending build to time out on.
///
/// # Errors
/// Returns a [`ProcedureFailure`] if the first argument is not a string, or if the seam reports
/// authoritatively (`Some(false)`) that no index of that name exists. A seam without name-catalog
/// visibility (`None`) leaves the await a lenient no-op.
fn db_await_index(
    args: &[Value],
    graph: &mut dyn GraphAccess,
) -> Result<Vec<Vec<Value>>, ProcedureFailure> {
    const NAME: &str = "db.awaitIndex";
    let index_name = match args.first() {
        Some(Value::String(s)) => s.as_str(),
        _ => {
            return Err(ProcedureFailure::new(
                NAME,
                "the first argument (indexName) must be a string",
            ));
        }
    };
    // `Some(false)` = the seam is authoritative and no index of that name exists → error (Neo4j
    // behaviour). `Some(true)` (exists) and `None` (seam cannot tell) both keep the no-op contract.
    if graph.index_exists_by_name(index_name) == Some(false) {
        return Err(ProcedureFailure::new(
            NAME,
            format!("there is no index named {index_name:?}"),
        ));
    }
    Ok(Vec::new())
}

/// The `db.resampleIndex(indexName)` body (`rmp` task #572) — Graphus's `ANALYZE`.
///
/// Resolves `indexName` to the `(label, property)` it covers and **requests** that its equi-depth
/// selectivity histogram be recomputed from the current data, so the planner estimates ranges and joins
/// from the real distribution instead of its constant fallback. The engine performs the recompute
/// shortly afterwards, in its **own** transaction.
///
/// # This is deliberately NOT part of the caller's transaction — do not "fix" it
///
/// A `ROLLBACK` does not undo a resample, and that is **correct**, not a compromise:
///
/// * **It is what Neo4j does.** `db.resampleIndex` there *schedules* a background re-sampling job that
///   ignores the caller's transaction entirely. Resampling is not a transactional graph mutation in the
///   Neo4j model, and Graphus is bound to that model. Making it transactional would be the deviation.
/// * **It is what keeps the outcome deterministic.** A resample staged in the caller's transaction is
///   undone by a rollback only when no *other* transaction happens to be open: `RecordStore::rollback`
///   restores the catalog's schema half wholesale when the active set is non-empty, resurrecting the
///   very change it was undoing. So the transactional reading gave "discarded, or not, depending on
///   unrelated concurrency" — which is indefensible in either direction. Out of the caller's
///   transaction, the answer is the same every time.
/// * **It sidesteps `rmp` #734 rather than closing it.** That per-transaction catalog-undo gap is
///   pre-existing and still open for any future DDL that mutates the catalog inside a yielding
///   transaction; this procedure simply no longer triggers it. Nothing here fixes #734.
///
/// The consequence to keep in mind: a `true` return means "accepted and will run", not "already done"
/// — exactly as Neo4j's scheduled job does.
///
/// # Name resolution
///
/// Searches the declared **node-property** indexes — the only kind an equi-depth histogram is keyed by
/// — using the same names `SHOW INDEXES` displays. Three cases, in order:
///
/// - the name is a node-property index → request its recompute;
/// - the name is an index of **another kind** (full-text, vector, composite, …) → a genuine **no-op
///   success**: that index exists, it simply keeps no sampled statistic to refresh;
/// - the name is in **no** catalog → an error, matching Neo4j (and `db.awaitIndex`, which shares this
///   name namespace and this spelling).
///
/// # Errors
/// Returns a [`ProcedureFailure`] if the first argument is not a string, or if the seam reports
/// authoritatively that no index of that name exists. A scan fault during the later recompute cannot be
/// reported here (the work has not run yet); it fails closed, leaving the histogram absent rather than
/// partial (`rmp` task #733), and the planner falls back to its constant.
fn db_resample_index(
    args: &[Value],
    graph: &mut dyn GraphAccess,
) -> Result<Vec<Vec<Value>>, ProcedureFailure> {
    const NAME: &str = "db.resampleIndex";
    let index_name = match args.first() {
        Some(Value::String(s)) => s.as_str(),
        _ => {
            return Err(ProcedureFailure::new(
                NAME,
                "the first argument (indexName) must be a string",
            ));
        }
    };
    // `None` = the seam has no index-catalog visibility → keep the lenient no-op contract, exactly as
    // `db.awaitIndex` does for a seam that cannot resolve names.
    let Some(declared) = graph.resamplable_node_property_indexes() else {
        return Ok(Vec::new());
    };
    let Some((_, label, property)) = declared.into_iter().find(|(n, _, _)| n == index_name) else {
        // Not a node-property index. Distinguish "exists, but keeps no histogram" (no-op success) from
        // "no such index at all" (error) — only the seam's cross-kind catalog can tell them apart.
        if graph.index_exists_by_name(index_name) == Some(false) {
            return Err(ProcedureFailure::new(
                NAME,
                format!("there is no index named {index_name:?}"),
            ));
        }
        return Ok(Vec::new());
    };
    graph.request_index_resample(&label, &property);
    Ok(Vec::new())
}

/// The `db.resampleOutdatedIndexes()` body (`rmp` task #572) — `ANALYZE` over every declared index.
///
/// Requests a recompute of the equi-depth selectivity histogram of **every** declared node-property
/// index. As with [`db_resample_index`], the recomputes run in the engine's own transactions and are
/// **not** part of the caller's — see that function for why that is the conformant behaviour and must
/// not be "corrected" to transactional.
///
/// # "Outdated"
///
/// Graphus tracks no per-index update counter, so it cannot single out the indexes whose statistics have
/// actually drifted (Neo4j gates on `updates > round(0.05 * indexSize)`); it recomputes **all** of them.
/// That is a deliberate **superset** of the Neo4j selection and is therefore never wrong — resampling an
/// already-current histogram recomputes the same values — but it does cost a full scan per declared
/// `(label, property)`. Gating on real drift needs an update counter, which is a separate, measured task.
fn db_resample_outdated_indexes(
    _args: &[Value],
    graph: &mut dyn GraphAccess,
) -> Result<Vec<Vec<Value>>, ProcedureFailure> {
    // `None` = no index-catalog visibility → lenient no-op (the `db.awaitIndex` convention).
    let Some(declared) = graph.resamplable_node_property_indexes() else {
        return Ok(Vec::new());
    };
    for (_, label, property) in declared {
        graph.request_index_resample(&label, &property);
    }
    Ok(Vec::new())
}

/// The single-column-per-analyzer result of `db.index.fulltext.listAvailableAnalyzers()` (`rmp` task
/// #667): one row `[analyzer (STRING), description (STRING), stopwords (LIST<STRING> as ANY)]` for each
/// analyzer Graphus supports ([`graphus_index::fulltext::Analyzer`] — `keyword` and `standard`), sorted
/// by analyzer name ascending (a deterministic order; Neo4j leaves it unspecified).
fn list_available_analyzers_rows() -> Vec<Vec<Value>> {
    let stopwords = |words: &[&str]| {
        Value::List(
            words
                .iter()
                .map(|w| Value::String((*w).to_owned()))
                .collect(),
        )
    };
    vec![
        vec![
            Value::String("keyword".to_owned()),
            Value::String(
                "Keeps the entire input as a single lowercased, NFC-normalized term \
                 (no tokenization, no stop-word removal)."
                    .to_owned(),
            ),
            stopwords(&[]),
        ],
        vec![
            Value::String("standard".to_owned()),
            Value::String(
                "Unicode tokenization with lowercasing and English stop-word removal (NFC-normalized)."
                    .to_owned(),
            ),
            stopwords(graphus_index::fulltext::STANDARD_STOP_WORDS),
        ],
    ]
}

/// The parsed, **honoured** subset of the `db.index.fulltext.query*` options MAP (`rmp` task #667).
/// Only `skip`/`limit` change results; other Neo4j keys (`analyzer`, `sort`, …) are validated or
/// accepted-and-ignored (see [`parse_fulltext_options`]).
struct FulltextQueryOptions {
    /// Rows to drop from the front of the relevance-ordered result (`skip`, default 0).
    skip: usize,
    /// Maximum rows to return (`limit`); `None` = unbounded.
    limit: Option<usize>,
}

/// Parses the optional `options` MAP third argument of `db.index.fulltext.queryNodes` /
/// `queryRelationships` (`rmp` task #667).
///
/// **Honoured:** `skip` and `limit` (non-negative integers), applied to the relevance-ordered result.
/// **Validated but not re-applied:** `analyzer` — the value must name a supported analyzer
/// ([`graphus_index::fulltext::Analyzer::from_name`]), but the index's own analyzer governs matching
/// (Graphus does not re-analyze the query with a different analyzer), a documented limitation.
/// **Accepted-and-ignored:** any other key (e.g. Neo4j's `sort`), so a Neo4j-shaped 3-arg call runs.
///
/// A `null` / absent options argument, or an empty map, yields the defaults (no skip, no limit).
///
/// # Errors
/// Returns a [`ProcedureFailure`] if `options` is neither a map nor null, if `skip`/`limit` is not a
/// non-negative integer, or if `analyzer` is not a string naming a supported analyzer.
fn parse_fulltext_options(
    name: &str,
    arg: Option<&Value>,
) -> Result<FulltextQueryOptions, ProcedureFailure> {
    let mut opts = FulltextQueryOptions {
        skip: 0,
        limit: None,
    };
    let entries = match arg {
        None | Some(Value::Null) => return Ok(opts),
        Some(Value::Map(entries)) => entries,
        Some(_) => {
            return Err(ProcedureFailure::new(
                name,
                "the third argument (options) must be a map",
            ));
        }
    };
    for (key, value) in entries {
        match key.as_str() {
            "skip" => opts.skip = non_negative_usize(name, "skip", value)?,
            "limit" => opts.limit = Some(non_negative_usize(name, "limit", value)?),
            "analyzer" => match value {
                Value::String(s) if graphus_index::fulltext::Analyzer::from_name(s).is_some() => {}
                Value::String(s) => {
                    return Err(ProcedureFailure::new(
                        name,
                        format!(
                            "unknown analyzer {s:?}; supported analyzers are 'standard' and 'keyword'"
                        ),
                    ));
                }
                _ => {
                    return Err(ProcedureFailure::new(
                        name,
                        "the 'analyzer' option must be a string",
                    ));
                }
            },
            // Neo4j accepts further keys (e.g. `sort`); accept-and-ignore so a Neo4j-shaped call runs.
            _ => {}
        }
    }
    Ok(opts)
}

/// Coerces an `options`-map integer (`skip` / `limit`) to a `usize`, rejecting a non-integer or a
/// negative value with a clear [`ProcedureFailure`] (`rmp` task #667).
fn non_negative_usize(name: &str, key: &str, value: &Value) -> Result<usize, ProcedureFailure> {
    match value {
        Value::Integer(i) if *i >= 0 => Ok(*i as usize),
        Value::Integer(_) => Err(ProcedureFailure::new(
            name,
            format!("the '{key}' option must be a non-negative integer"),
        )),
        _ => Err(ProcedureFailure::new(
            name,
            format!("the '{key}' option must be an integer"),
        )),
    }
}

// =================================================================================================
// Vector (HNSW) index query procedures (`rmp` task #671)
// =================================================================================================

/// Extracts a required **string** procedure argument, or a clear [`ProcedureFailure`].
fn string_arg<'a>(
    proc: &str,
    value: Option<&'a Value>,
    field: &str,
) -> Result<&'a str, ProcedureFailure> {
    match value {
        Some(Value::String(s)) => Ok(s.as_str()),
        _ => Err(ProcedureFailure::new(
            proc,
            format!("the `{field}` argument must be a string"),
        )),
    }
}

/// Extracts a required **positive integer** procedure argument (a non-positive or non-integer value is
/// a clear error — `k` nearest neighbours must be `>= 1`).
fn positive_int_arg(
    proc: &str,
    value: Option<&Value>,
    field: &str,
) -> Result<usize, ProcedureFailure> {
    match value {
        Some(Value::Integer(i)) if *i > 0 => Ok(*i as usize),
        Some(Value::Integer(_)) => Err(ProcedureFailure::new(
            proc,
            format!("the `{field}` argument must be a positive integer"),
        )),
        _ => Err(ProcedureFailure::new(
            proc,
            format!("the `{field}` argument must be an integer"),
        )),
    }
}

/// Parses the `query` argument of a `db.index.vector.query*` procedure into an `f32` vector: it must
/// be a `LIST<FLOAT | INTEGER>` (an INTEGER element widens to FLOAT, matching the stored-embedding
/// coercion) with only **finite** elements (a `NaN` / ±∞ element is a clear error — an ill-defined
/// query vector, Neo4j parity). Dimension conformance is checked by the seam against the index.
fn query_vector_arg(proc: &str, value: Option<&Value>) -> Result<Vec<f32>, ProcedureFailure> {
    let Some(Value::List(items)) = value else {
        return Err(ProcedureFailure::new(
            proc,
            "the `query` argument must be a list of numbers",
        ));
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let x = match item {
            Value::Integer(i) => *i as f32,
            Value::Float(f) => *f as f32,
            _ => {
                return Err(ProcedureFailure::new(
                    proc,
                    "the `query` vector must contain only numbers",
                ));
            }
        };
        if !x.is_finite() {
            return Err(ProcedureFailure::new(
                proc,
                "the `query` vector must not contain NaN or infinite values",
            ));
        }
        out.push(x);
    }
    Ok(out)
}

/// A clear "no such vector index" error (`kind` is `"node"` or `"relationship"`).
fn no_such_vector_index(proc: &str, name: &str, kind: &str) -> ProcedureFailure {
    ProcedureFailure::new(
        proc,
        format!("there is no {kind} vector index named {name:?}"),
    )
}

/// A clear "the index cannot answer yet" error (`rmp` task #733): the named vector index is declared
/// but not `Online` — its build has not finished, or a failed index rebuild demoted it.
///
/// A vector (HNSW) index is the one kind with **no equivalent scan fallback** (it is approximate, so a
/// brute-force re-rank would return a different neighbour set), so an unusable index cannot be served
/// correctly. Erroring is the only safe outcome: an empty neighbour list would be indistinguishable
/// from "no near neighbours exist", which is a silent wrong answer.
fn vector_index_not_online(proc: &str, name: &str) -> ProcedureFailure {
    ProcedureFailure::new(
        proc,
        format!(
            "the vector index {name:?} is still populating and cannot be queried yet; \
             retry once it is online"
        ),
    )
}

/// A clear query-dimension-mismatch error.
fn vector_dim_mismatch(proc: &str, expected: usize, got: usize) -> ProcedureFailure {
    ProcedureFailure::new(
        proc,
        format!("the query vector has dimension {got}, but the vector index expects {expected}"),
    )
}

/// Whether `value` is a snapshot-visible embedding of the covered index: a `LIST` of exactly `dim`
/// **finite** numbers (INTEGER or FLOAT), the shape [`extract_embedding`](crate::index_set) accepts on
/// the write path. A candidate whose current value fails this (absent, wrong dimension, non-numeric,
/// non-finite) is dropped from the result — it is no longer a member of the index at this snapshot.
fn embedding_present(value: Option<&Value>, dim: usize) -> bool {
    let Some(Value::List(items)) = value else {
        return false;
    };
    items.len() == dim
        && items.iter().all(|it| match it {
            Value::Integer(i) => (*i as f32).is_finite(),
            Value::Float(f) => (*f as f32).is_finite(),
            _ => false,
        })
}

/// The `db.index.vector.queryNodes(indexName, numberOfNearestNeighbours, query)` body (`rmp` task
/// #671).
///
/// Resolves the named **node** vector (HNSW) index, runs the k-NN over the current committed graph,
/// then **MVCC-/RBAC-filters** the candidates by re-checking each through the same [`GraphAccess`]
/// seam the cursor holds — a candidate survives only if it is snapshot-visible (`node_exists`), still
/// carries the covered label (`node_labels`), and still holds a valid embedding of the declared
/// dimension (`node_property`). When `graph` is an `AuthorizedGraph` the RBAC filtering composes for
/// free. Emits one row `[node_id (Value::Integer, bound to a structural NODE), score (Value::Float)]`
/// per survivor, ordered by descending score then ascending id.
///
/// # Errors
/// A [`ProcedureFailure`] on a non-string index name, a non-positive / non-integer `k`, a
/// non-list / non-finite query vector, an unknown index, a **relationship** vector index of that name
/// (wrong kind), or a query-dimension mismatch.
fn vector_query_nodes_proc(
    args: &[Value],
    graph: &mut dyn GraphAccess,
) -> Result<Vec<Vec<Value>>, ProcedureFailure> {
    const NAME: &str = "db.index.vector.queryNodes";
    let index_name = string_arg(NAME, args.first(), "indexName")?;
    let k = positive_int_arg(NAME, args.get(1), "numberOfNearestNeighbours")?;
    let query = query_vector_arg(NAME, args.get(2))?;

    match graph.vector_query_nodes(index_name, &query, k) {
        VectorQueryResult::NoSuchIndex => Err(no_such_vector_index(NAME, index_name, "node")),
        VectorQueryResult::WrongEntity => Err(ProcedureFailure::new(
            NAME,
            format!(
                "index {index_name:?} is a relationship vector index; \
                 use db.index.vector.queryRelationships"
            ),
        )),
        VectorQueryResult::NotOnline => Err(vector_index_not_online(NAME, index_name)),
        VectorQueryResult::DimensionMismatch { expected, got } => {
            Err(vector_dim_mismatch(NAME, expected, got))
        }
        VectorQueryResult::Hits {
            label_or_type,
            property,
            dimensions,
            similarity,
            hits,
        } => {
            // Re-check each candidate against the caller's snapshot (MVCC + RBAC compose through the
            // seam), and RE-SCORE every survivor from its own snapshot-visible embedding.
            let mut kept =
                rescore_candidates(hits, similarity, dimensions, query_ref(&query), |id| {
                    let nid = NodeId(id);
                    if !graph.node_exists(nid) {
                        return None;
                    }
                    if !graph
                        .node_labels(nid)
                        .is_some_and(|labels| labels.iter().any(|l| l == &label_or_type))
                    {
                        return None;
                    }
                    graph.node_property(nid, &property)
                });
            kept.truncate(k);
            Ok(kept
                .into_iter()
                .map(|(score, id)| vec![Value::Integer(id as i64), Value::Float(f64::from(score))])
                .collect())
        }
    }
}

/// Borrows a query vector as a slice (a tiny helper so the two procedure bodies read identically).
fn query_ref(q: &[f32]) -> &[f32] {
    q
}

/// The shared candidate post-processing for both vector procedures (`rmp` task #780):
/// **re-score → dedup → order**, over the candidate `(id, score)` pairs the seam returned.
///
/// `visible_value` returns the candidate's snapshot-visible covered property value, or [`None`] if the
/// candidate is not a member at this snapshot (invisible, wrong label/type, or RBAC-filtered).
///
/// # Why re-scoring is mandatory, not cosmetic
///
/// The seam's `score` is computed from whatever vector the ANN graph holds, which is **not necessarily
/// the vector this reader's snapshot sees** — a reader on an older snapshot already gets scores derived
/// from a newer *committed* vector, with no `rmp` #766 build conflict involved at all. Passing that
/// through returns a value computed from data the transaction may not observe (a dirty read on the
/// score channel), and makes the score **non-deterministic** with respect to an unrelated writer's
/// transaction state — which the project's DST determinism mandate forbids outright. Measured on a
/// 20 000-entity corpus, a realistic re-embed produced score errors up to 0.2333 on a (0,1] scale.
///
/// Re-scoring is close to free: the membership re-check above already fetched the property, so the page
/// read is paid; this adds one distance computation per surviving candidate.
///
/// # Dedup
///
/// One entity may appear only once. The ANN graph is keyed one-slot-per-entity today, so this is a
/// no-op — it is here because it is the invariant the ROW CONTRACT owes the caller regardless of how
/// the graph is keyed, and a future multi-version graph (`rmp` #798) must not be able to violate it by
/// construction. Best score per entity wins.
fn rescore_candidates(
    hits: Vec<(u64, f32)>,
    similarity: graphus_index::Similarity,
    dimensions: usize,
    query: &[f32],
    mut visible_value: impl FnMut(u64) -> Option<Value>,
) -> Vec<(f32, u64)> {
    let mut kept: Vec<(f32, u64)> = Vec::with_capacity(hits.len());
    for (id, _provisional) in hits {
        let value = visible_value(id);
        if !embedding_present(value.as_ref(), dimensions) {
            continue;
        }
        // `embedding_present` just proved the shape, so this cannot fail.
        let Some(embedding) = value.as_ref().and_then(|v| to_embedding(v, dimensions)) else {
            continue;
        };
        let score = graphus_index::similarity_score(similarity, &embedding, query);
        kept.push((score, id));
    }
    // Descending score, ascending id tie-break — deterministic after filtering.
    kept.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
    // Dedup AFTER the sort: O(n) on an ordered list, where deduping during the push loop needed a linear
    // scan per candidate (O(n^2)) for the same result.
    //
    // `dedup_by_key` only collapses ADJACENT equals, so this is correct only because two occurrences of
    // one entity are necessarily adjacent here — and they are, load-bearingly, BECAUSE of the re-score
    // above: every occurrence of an entity is scored from that entity's ONE snapshot-visible embedding,
    // so duplicates carry an identical score, and the `(score desc, id asc)` order therefore places them
    // side by side. If a future change ever lets two rows of the same entity carry DIFFERENT scores
    // (`rmp` #798's multi-version graph would, if it re-scored per version rather than per entity), this
    // silently stops deduping and must become a sort by `(id, score)` + dedup + re-sort.
    kept.dedup_by_key(|(_, id)| *id);
    kept
}

/// The `f32` embedding behind a snapshot-visible property value, or [`None`] if it is not a valid
/// embedding of `dim` finite numbers. Mirrors `embedding_present`'s acceptance exactly.
fn to_embedding(value: &Value, dim: usize) -> Option<Vec<f32>> {
    let Value::List(items) = value else {
        return None;
    };
    if items.len() != dim {
        return None;
    }
    let mut out = Vec::with_capacity(dim);
    for item in items {
        let x = match item {
            Value::Integer(i) => *i as f32,
            Value::Float(f) => *f as f32,
            _ => return None,
        };
        if !x.is_finite() {
            return None;
        }
        out.push(x);
    }
    Some(out)
}

/// The `db.index.vector.queryRelationships(indexName, numberOfNearestNeighbours, query)` body (`rmp`
/// task #671) — the relationship analogue of [`vector_query_nodes_proc`].
///
/// # Errors
/// As [`vector_query_nodes_proc`], with a **node** vector index of that name reported as the wrong
/// kind.
fn vector_query_relationships_proc(
    args: &[Value],
    graph: &mut dyn GraphAccess,
) -> Result<Vec<Vec<Value>>, ProcedureFailure> {
    const NAME: &str = "db.index.vector.queryRelationships";
    let index_name = string_arg(NAME, args.first(), "indexName")?;
    let k = positive_int_arg(NAME, args.get(1), "numberOfNearestNeighbours")?;
    let query = query_vector_arg(NAME, args.get(2))?;

    match graph.vector_query_rels(index_name, &query, k) {
        VectorQueryResult::NoSuchIndex => {
            Err(no_such_vector_index(NAME, index_name, "relationship"))
        }
        VectorQueryResult::WrongEntity => Err(ProcedureFailure::new(
            NAME,
            format!("index {index_name:?} is a node vector index; use db.index.vector.queryNodes"),
        )),
        VectorQueryResult::NotOnline => Err(vector_index_not_online(NAME, index_name)),
        VectorQueryResult::DimensionMismatch { expected, got } => {
            Err(vector_dim_mismatch(NAME, expected, got))
        }
        VectorQueryResult::Hits {
            label_or_type,
            property,
            dimensions,
            similarity,
            hits,
        } => {
            // Re-score + dedup + order, exactly as the node twin (`rmp` task #780).
            let mut kept =
                rescore_candidates(hits, similarity, dimensions, query_ref(&query), |id| {
                    let rid = RelId(id);
                    if !graph.rel_exists(rid) {
                        return None;
                    }
                    if graph
                        .rel_data(rid)
                        .is_none_or(|data| data.rel_type != label_or_type)
                    {
                        return None;
                    }
                    graph.rel_property(rid, &property)
                });
            kept.truncate(k);
            Ok(kept
                .into_iter()
                .map(|(score, id)| vec![Value::Integer(id as i64), Value::Float(f64::from(score))])
                .collect())
        }
    }
}

/// The `db.index.fulltext.queryRelationships(indexName, queryString)` body (`rmp` task #663).
///
/// The relationship analogue of [`fulltext_query_nodes`]: resolves candidate relationship ids from the
/// named relationship full-text index (analyzed with the index's own analyzer), **MVCC-/RBAC-filters**
/// them by re-checking each through the same [`GraphAccess`] seam (a deleted / invisible / unauthorized
/// relationship is dropped — when `graph` is an `AuthorizedGraph` the filtering composes for free),
/// computes a best-effort relevance `score`, and emits one row `[rel_id (Value::Integer, bound to a
/// structural RELATIONSHIP), score (Value::Float)]` per match, ordered by descending score then
/// ascending id.
///
/// # Errors
/// Returns a [`ProcedureFailure`] if an argument is not a string, or if **no relationship full-text
/// index of that name is declared** (so a typo — or a *node* index name given here — is a clear error,
/// not silently-empty results).
fn fulltext_query_relationships(
    args: &[Value],
    graph: &mut dyn GraphAccess,
) -> Result<Vec<Vec<Value>>, ProcedureFailure> {
    const NAME: &str = "db.index.fulltext.queryRelationships";
    let index_name = match args.first() {
        Some(Value::String(s)) => s.as_str(),
        _ => {
            return Err(ProcedureFailure::new(
                NAME,
                "the first argument (indexName) must be a string",
            ));
        }
    };
    let query_string = match args.get(1) {
        Some(Value::String(s)) => s.as_str(),
        _ => {
            return Err(ProcedureFailure::new(
                NAME,
                "the second argument (queryString) must be a string",
            ));
        }
    };
    // Optional Neo4j `options` MAP (`rmp` task #667): `skip`/`limit` trim the result.
    let options = parse_fulltext_options(NAME, args.get(2))?;

    // Candidate ids from the relationship full-text index; `None` means no such index is declared —
    // a node index name given here yields `None` too (it is not a *relationship* full-text index), so a
    // wrong-kind name is a clear error rather than silently-empty results.
    let Some(candidates) = graph.fulltext_query_rel(index_name, query_string) else {
        return Err(ProcedureFailure::new(
            NAME,
            format!("there is no relationship full-text index named {index_name:?}"),
        ));
    };

    // Re-check each candidate's visibility through the same seam (composes MVCC + RBAC), compute its
    // score, and collect `(score, id)` so we can order relevance-first.
    let mut scored: Vec<(u64, u64)> = candidates
        .into_iter()
        .filter(|&id| graph.rel_exists(id))
        .map(|id| {
            let score = graph
                .fulltext_score_rel(index_name, id, query_string)
                .unwrap_or(0);
            (score, id.0)
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));

    Ok(scored
        .into_iter()
        // Apply the options MAP's `skip`/`limit` AFTER relevance ordering (Neo4j semantics).
        .skip(options.skip)
        .take(options.limit.unwrap_or(usize::MAX))
        .map(|(score, id)| {
            // The rel id rides as an Integer; the `relationship` output is `RELATIONSHIP`-classed, so
            // the executor binds it as a structural relationship. The score is a Float (Neo4j-compatible).
            vec![Value::Integer(id as i64), Value::Float(score as f64)]
        })
        .collect())
}

/// The `db.index.fulltext.queryNodes(indexName, queryString)` body (`rmp` task #72).
///
/// Resolves candidate node ids from the named full-text index (analyzed with the index's own
/// analyzer), **MVCC-/RBAC-filters** them by re-checking each through the same [`GraphAccess`] seam
/// the cursor holds (a deleted / invisible / unauthorized node is dropped — when `graph` is an
/// `AuthorizedGraph` the filtering composes for free), computes a best-effort relevance `score`, and
/// emits one row `[node_id (Value::Integer, bound to a structural NODE), score (Value::Float)]` per
/// match. Rows are ordered by descending score then ascending id (a deterministic, relevance-first
/// order).
///
/// # Errors
/// Returns a [`ProcedureFailure`] if an argument is not a string, or — crucially — if **no full-text
/// index of that name is declared** (so a typo is a clear error, not silently-empty results).
fn fulltext_query_nodes(
    args: &[Value],
    graph: &mut dyn GraphAccess,
) -> Result<Vec<Vec<Value>>, ProcedureFailure> {
    const NAME: &str = "db.index.fulltext.queryNodes";
    let index_name = match args.first() {
        Some(Value::String(s)) => s.as_str(),
        _ => {
            return Err(ProcedureFailure::new(
                NAME,
                "the first argument (indexName) must be a string",
            ));
        }
    };
    let query_string = match args.get(1) {
        Some(Value::String(s)) => s.as_str(),
        _ => {
            return Err(ProcedureFailure::new(
                NAME,
                "the second argument (queryString) must be a string",
            ));
        }
    };
    // Optional Neo4j `options` MAP (`rmp` task #667): `skip`/`limit` trim the result.
    let options = parse_fulltext_options(NAME, args.get(2))?;

    // Candidate ids from the index; `None` means no such index is declared (a clear error).
    let Some(candidates) = graph.fulltext_query(index_name, query_string) else {
        return Err(ProcedureFailure::new(
            NAME,
            format!("there is no full-text index named {index_name:?}"),
        ));
    };

    // Re-check each candidate's visibility through the same seam (composes MVCC + RBAC), compute its
    // score, and collect `(score, id)` so we can order relevance-first.
    let mut scored: Vec<(u64, u64)> = candidates
        .into_iter()
        .filter(|&id| graph.node_exists(id))
        .map(|id| {
            let score = graph
                .fulltext_score(index_name, id, query_string)
                .unwrap_or(0);
            (score, id.0)
        })
        .collect();
    // Order: descending score (more relevant first), then ascending id (deterministic tie-break).
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));

    Ok(scored
        .into_iter()
        // Apply the options MAP's `skip`/`limit` AFTER relevance ordering (Neo4j semantics).
        .skip(options.skip)
        .take(options.limit.unwrap_or(usize::MAX))
        .map(|(score, id)| {
            // The node id rides as an Integer; the `node` output is `NODE`-classed, so the executor
            // binds it as a structural node. The score is a Float (Neo4j-compatible).
            vec![Value::Integer(id as i64), Value::Float(score as f64)]
        })
        .collect())
}

/// Every distinct property key on any node or relationship, ascending.
fn distinct_property_keys(graph: &dyn GraphAccess) -> Vec<String> {
    let mut keys = std::collections::BTreeSet::new();
    let mut seen_rels = std::collections::BTreeSet::new();
    for node in graph.scan_nodes() {
        for (key, _) in graph.node_properties(node).unwrap_or_default() {
            keys.insert(key);
        }
        for rel in graph.incident_rels(node) {
            if seen_rels.insert(rel) {
                for (key, _) in graph.rel_properties(rel).unwrap_or_default() {
                    keys.insert(key);
                }
            }
        }
    }
    keys.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_access::MemGraph;

    const NO_PROPS: [(&str, Value); 0] = [];

    fn nullable(class: ValueClass) -> FieldType {
        FieldType::nullable(class)
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let set = ProcedureSet::with_builtins();
        assert!(set.signature("db.labels").is_some());
        assert!(set.signature("DB.Labels").is_some());
        assert!(set.signature("db.nope").is_none());
    }

    #[test]
    fn builtin_db_labels_yields_distinct_sorted_labels() {
        let mut g = MemGraph::new();
        let _ = g.add_node(["B", "A"], NO_PROPS);
        let _ = g.add_node(["A"], NO_PROPS);
        let rows = builtins().invoke("db.labels", &[], &mut g).expect("invoke");
        assert_eq!(
            rows,
            vec![
                vec![Value::String("A".into())],
                vec![Value::String("B".into())]
            ]
        );
    }

    #[test]
    fn builtin_db_relationship_types_and_property_keys() {
        let mut g = MemGraph::new();
        let a = g.add_node(["N"], [("p", Value::Integer(1))]);
        let b = g.add_node(["N"], NO_PROPS);
        let _ = g.add_rel("KNOWS", a, b, [("since", Value::Integer(2020))]);
        let types = builtins()
            .invoke("db.relationshipTypes", &[], &mut g)
            .expect("invoke");
        assert_eq!(types, vec![vec![Value::String("KNOWS".into())]]);
        let keys = builtins()
            .invoke("db.propertyKeys", &[], &mut g)
            .expect("invoke");
        assert_eq!(
            keys,
            vec![
                vec![Value::String("p".into())],
                vec![Value::String("since".into())]
            ]
        );
    }

    #[test]
    fn table_procedure_matches_inputs_in_table_order() {
        let mut set = ProcedureSet::new();
        set.register_table(
            ProcedureSignature::new(
                "test.my.proc",
                vec![
                    FieldSpec::new("name", nullable(ValueClass::String)),
                    FieldSpec::new("id", nullable(ValueClass::Integer)),
                ],
                vec![FieldSpec::new("city", nullable(ValueClass::String))],
            ),
            vec![
                (
                    vec![Value::String("Stefan".into()), Value::Integer(1)],
                    vec![Value::String("Berlin".into())],
                ),
                (
                    vec![Value::String("Stefan".into()), Value::Integer(2)],
                    vec![Value::String("München".into())],
                ),
            ],
        )
        .expect("register");

        let mut g = MemGraph::new();
        let rows = set
            .invoke(
                "test.my.proc",
                &[Value::String("Stefan".into()), Value::Integer(1)],
                &mut g,
            )
            .expect("invoke");
        assert_eq!(rows, vec![vec![Value::String("Berlin".into())]]);
    }

    #[test]
    fn table_procedure_null_argument_matches_null_cell() {
        // TCK Call4: `CALL test.my.proc(null)` must match the `| null | 'nix' |` row (equivalence,
        // not equality: null ≡ null is true).
        let mut set = ProcedureSet::new();
        set.register_table(
            ProcedureSignature::new(
                "test.my.proc",
                vec![FieldSpec::new("in", nullable(ValueClass::Integer))],
                vec![FieldSpec::new("out", nullable(ValueClass::String))],
            ),
            vec![(vec![Value::Null], vec![Value::String("nix".into())])],
        )
        .expect("register");
        let mut g = MemGraph::new();
        let rows = set
            .invoke("test.my.proc", &[Value::Null], &mut g)
            .expect("invoke");
        assert_eq!(rows, vec![vec![Value::String("nix".into())]]);
    }

    #[test]
    fn table_procedure_integer_argument_matches_float_cell() {
        // TCK Call3: a FLOAT? input called with 42 matches the 42.0 row (numeric equivalence).
        let mut set = ProcedureSet::new();
        set.register_table(
            ProcedureSignature::new(
                "test.my.proc",
                vec![FieldSpec::new("in", nullable(ValueClass::Float))],
                vec![FieldSpec::new("out", nullable(ValueClass::String))],
            ),
            vec![(
                vec![Value::Float(42.0)],
                vec![Value::String("close enough".into())],
            )],
        )
        .expect("register");
        let mut g = MemGraph::new();
        let rows = set
            .invoke("test.my.proc", &[Value::Integer(42)], &mut g)
            .expect("invoke");
        assert_eq!(rows, vec![vec![Value::String("close enough".into())]]);
    }

    #[test]
    fn register_table_rejects_misshapen_rows() {
        let mut set = ProcedureSet::new();
        let err = set
            .register_table(
                ProcedureSignature::new(
                    "test.bad",
                    vec![FieldSpec::new("in", nullable(ValueClass::Integer))],
                    vec![FieldSpec::new("out", nullable(ValueClass::String))],
                ),
                vec![(vec![], vec![Value::Null])],
            )
            .expect_err("misshapen row must be rejected");
        assert!(err.contains("test.bad"));
    }

    #[test]
    fn invoke_unknown_or_wrong_arity_fails() {
        let set = ProcedureSet::with_builtins();
        let mut g = MemGraph::new();
        assert!(set.invoke("no.such.proc", &[], &mut g).is_err());
        assert!(set.invoke("db.labels", &[Value::Null], &mut g).is_err());
    }

    #[test]
    fn fulltext_query_nodes_is_registered_with_node_and_score_outputs() {
        let set = ProcedureSet::with_builtins();
        let sig = set
            .signature("db.index.fulltext.queryNodes")
            .expect("registered");
        // `indexName`, `queryString`, and the optional `options` MAP (`rmp` task #667).
        assert_eq!(sig.inputs.len(), 3);
        assert_eq!(sig.required_arity(), 2);
        assert_eq!(sig.outputs.len(), 2);
        assert_eq!(sig.outputs[0].name, "node");
        assert_eq!(sig.outputs[0].ty.class, ValueClass::Node);
        assert_eq!(sig.outputs[1].name, "score");
        assert_eq!(sig.outputs[1].ty.class, ValueClass::Float);
        // Case-insensitive resolution like the other built-ins.
        assert!(set.signature("DB.Index.Fulltext.QueryNodes").is_some());
    }

    #[test]
    fn fulltext_query_nodes_returns_ids_and_scores_ordered_by_relevance() {
        use crate::graph_access::MemGraph;
        use graphus_index::fulltext::Analyzer;

        let mut g = MemGraph::new();
        let a = g.add_node(
            ["Doc"],
            [("t", Value::String("graph database fast".into()))],
        );
        let b = g.add_node(["Doc"], [("t", Value::String("graph theory".into()))]);
        g.create_fulltext_index("ix", "Doc", ["t"], Analyzer::Standard);

        // "graph database": a matches both terms (score 2), b matches one (score 1) -> a first.
        let rows = builtins()
            .invoke(
                "db.index.fulltext.queryNodes",
                &[
                    Value::String("ix".into()),
                    Value::String("graph database".into()),
                ],
                &mut g,
            )
            .expect("invoke");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], vec![Value::Integer(a.0 as i64), Value::Float(2.0)]);
        assert_eq!(rows[1], vec![Value::Integer(b.0 as i64), Value::Float(1.0)]);
    }

    #[test]
    fn fulltext_query_nodes_errors_on_unknown_index() {
        use crate::graph_access::MemGraph;
        let mut g = MemGraph::new();
        let err = builtins()
            .invoke(
                "db.index.fulltext.queryNodes",
                &[Value::String("nope".into()), Value::String("x".into())],
                &mut g,
            )
            .expect_err("unknown index must error");
        assert!(format!("{err}").contains("nope"));
    }

    #[test]
    fn fulltext_query_nodes_rejects_non_string_args() {
        use crate::graph_access::MemGraph;
        let mut g = MemGraph::new();
        assert!(
            builtins()
                .invoke(
                    "db.index.fulltext.queryNodes",
                    &[Value::Integer(1), Value::String("x".into())],
                    &mut g,
                )
                .is_err()
        );
    }

    #[test]
    fn dbms_components_reports_graphus_community_and_workspace_version() {
        // `rmp` task #639: `CALL dbms.components()` returns exactly one row of
        // `[name, versions, edition]`, where `versions` is a one-element LIST<STRING> of the server
        // version. Drivers read this at connect time.
        let mut g = MemGraph::new();
        let rows = builtins()
            .invoke("dbms.components", &[], &mut g)
            .expect("invoke");
        assert_eq!(
            rows,
            vec![vec![
                Value::String("Graphus".into()),
                Value::List(vec![Value::String(env!("CARGO_PKG_VERSION").into())]),
                Value::String("community".into()),
            ]]
        );
    }

    #[test]
    fn dbms_components_signature_has_name_versions_edition_outputs() {
        let set = ProcedureSet::with_builtins();
        let sig = set.signature("dbms.components").expect("registered");
        assert!(sig.inputs.is_empty());
        let out_names: Vec<&str> = sig.outputs.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(out_names, ["name", "versions", "edition"]);
        // Case-insensitive, like every other built-in.
        assert!(set.signature("DBMS.Components").is_some());
        assert!(set.is_reader_safe("dbms.components"));
    }

    #[test]
    fn db_await_indexes_is_a_void_noop() {
        // `rmp` tasks #639/#667: a VOID no-op (indexes are ONLINE synchronously, nothing to await). The
        // INTEGER timeout is **optional** (default 300), so both `()` and `(n)` are valid.
        let set = ProcedureSet::with_builtins();
        let sig = set.signature("db.awaitIndexes").expect("registered");
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(sig.inputs[0].name, "timeOutSeconds");
        assert_eq!(sig.inputs[0].ty.class, ValueClass::Integer);
        assert_eq!(
            sig.inputs[0].default,
            Some(Value::Integer(300)),
            "the timeout defaults to 300"
        );
        assert_eq!(sig.required_arity(), 0, "the timeout is optional");
        assert!(sig.outputs.is_empty(), "db.awaitIndexes is VOID");

        let mut g = MemGraph::new();
        // With an explicit timeout: no-op.
        assert!(
            set.invoke("db.awaitIndexes", &[Value::Integer(30)], &mut g)
                .expect("invoke")
                .is_empty()
        );
        // With no argument (default 300): now valid (`rmp` #667), still a no-op.
        assert!(
            set.invoke("db.awaitIndexes", &[], &mut g)
                .expect("invoke with default timeout")
                .is_empty()
        );
        // Too many arguments still fails (arity ceiling).
        assert!(
            set.invoke(
                "db.awaitIndexes",
                &[Value::Integer(1), Value::Integer(2)],
                &mut g,
            )
            .is_err()
        );
    }

    #[test]
    fn db_resample_index_and_outdated_are_void_and_lenient_without_a_catalog() {
        // `rmp` tasks #639, #572: both are VOID. Against a seam with no index-catalog visibility
        // (`MemGraph` returns `None` from `resamplable_node_property_indexes`), both keep the lenient
        // no-op contract rather than erroring — the same convention `db.awaitIndex` follows. The real
        // resampling behaviour, over the store-backed seam, is proven in
        // `tests/index_statistics.rs`. `db.resampleIndex` takes a STRING index name; the outdated
        // form is nullary.
        let set = ProcedureSet::with_builtins();

        let sig = set.signature("db.resampleIndex").expect("registered");
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(sig.inputs[0].name, "indexName");
        assert_eq!(sig.inputs[0].ty.class, ValueClass::String);
        assert!(sig.outputs.is_empty());

        let sig2 = set
            .signature("db.resampleOutdatedIndexes")
            .expect("registered");
        assert!(sig2.inputs.is_empty());
        assert!(sig2.outputs.is_empty());

        let mut g = MemGraph::new();
        assert!(
            set.invoke(
                "db.resampleIndex",
                &[Value::String("some_index".into())],
                &mut g,
            )
            .expect("invoke")
            .is_empty()
        );
        assert!(
            set.invoke("db.resampleOutdatedIndexes", &[], &mut g)
                .expect("invoke")
                .is_empty()
        );
    }

    #[test]
    fn fulltext_query_relationships_is_registered_with_relationship_and_score_outputs() {
        // `rmp` task #663: registered with the Neo4j `relationship, score` outputs, where `relationship`
        // is a structural RELATIONSHIP class. Registered NOT reader-safe (stays inline; no off-thread
        // relationship full-text scan-fallback path).
        let set = ProcedureSet::with_builtins();
        let sig = set
            .signature("db.index.fulltext.queryRelationships")
            .expect("registered");
        // `indexName`, `queryString`, and the optional `options` MAP (`rmp` task #667).
        assert_eq!(sig.inputs.len(), 3);
        assert_eq!(sig.required_arity(), 2);
        let out_names: Vec<&str> = sig.outputs.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(out_names, ["relationship", "score"]);
        assert_eq!(sig.outputs[0].ty.class, ValueClass::Relationship);
        assert_eq!(sig.outputs[1].ty.class, ValueClass::Float);
        assert!(set.is_reader_safe("db.index.fulltext.queryRelationships"));
        // Case-insensitive resolution like the other built-ins.
        assert!(
            set.signature("DB.Index.Fulltext.QueryRelationships")
                .is_some()
        );
    }

    #[test]
    fn fulltext_query_relationships_returns_matching_rels_with_scores() {
        use crate::graph_access::MemGraph;
        use graphus_index::fulltext::Analyzer;

        let mut g = MemGraph::new();
        let a = g.add_node(["N"], NO_PROPS);
        let b = g.add_node(["N"], NO_PROPS);
        let c = g.add_node(["N"], NO_PROPS);
        let r1 = g.add_rel(
            "KNOWS",
            a,
            b,
            [("note", Value::String("graph database fast".into()))],
        );
        let r2 = g.add_rel(
            "KNOWS",
            b,
            c,
            [("note", Value::String("graph theory".into()))],
        );
        g.create_fulltext_rel_index("rel_ix", ["KNOWS"], ["note"], Analyzer::Standard);

        // "graph database": r1 matches both terms (score 2), r2 matches one (score 1) -> r1 first.
        let rows = builtins()
            .invoke(
                "db.index.fulltext.queryRelationships",
                &[
                    Value::String("rel_ix".into()),
                    Value::String("graph database".into()),
                ],
                &mut g,
            )
            .expect("invoke");
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            vec![Value::Integer(r1.0 as i64), Value::Float(2.0)]
        );
        assert_eq!(
            rows[1],
            vec![Value::Integer(r2.0 as i64), Value::Float(1.0)]
        );
    }

    #[test]
    fn fulltext_query_relationships_errors_on_unknown_or_node_index() {
        use crate::graph_access::MemGraph;
        let mut g = MemGraph::new();
        // A wholly-unknown name errors.
        let err = builtins()
            .invoke(
                "db.index.fulltext.queryRelationships",
                &[Value::String("nope".into()), Value::String("x".into())],
                &mut g,
            )
            .expect_err("unknown relationship index must error");
        assert!(format!("{err}").contains("nope"));

        // A *node* full-text index name given to queryRelationships also errors (wrong kind).
        g.create_fulltext_index(
            "node_ix",
            "Doc",
            ["t"],
            graphus_index::fulltext::Analyzer::Standard,
        );
        assert!(
            builtins()
                .invoke(
                    "db.index.fulltext.queryRelationships",
                    &[Value::String("node_ix".into()), Value::String("x".into())],
                    &mut g,
                )
                .is_err(),
            "a node index name given to queryRelationships must error"
        );
    }

    #[test]
    fn new_admin_procedures_are_reader_safe() {
        // The `rmp` #639/#667 admin procedures are read-only / no-op, and `queryRelationships`
        // (`rmp` #663) is a real read served off-thread via the captured catalogue — so all are
        // reader-safe (`SHOW PROCEDURES` mode = READ; off-thread-pool eligible).
        let set = ProcedureSet::with_builtins();
        for name in [
            "dbms.components",
            "db.awaitIndexes",
            "db.index.fulltext.queryRelationships",
            "db.index.fulltext.awaitEventuallyConsistentIndexRefresh",
            "db.index.fulltext.listAvailableAnalyzers",
        ] {
            assert!(set.is_reader_safe(name), "`{name}` must be reader-safe");
        }
        // `db.awaitIndex` (singular) is deliberately **not** reader-safe (`rmp` #667): it needs the
        // authoritative store-backed name catalog, so it always runs inline.
        assert!(
            !set.is_reader_safe("db.awaitIndex"),
            "db.awaitIndex must run inline (authoritative catalog)"
        );
    }

    #[test]
    fn resample_procedures_are_not_reader_safe() {
        // `rmp` task #572. These two were reader-safe while they were no-ops — trivially true of a body
        // that does nothing. Now that they really resample, they record their request into the shared
        // engine-thread `IndexSet` for the drain to execute, so they must run inline. Were they still
        // dispatched to the off-thread reader pool (`rmp` #546), they would record into an owned
        // snapshot view the engine never reads back, and the resample the caller explicitly asked for
        // would be silently dropped — the procedure would report success having queued nothing.
        let set = ProcedureSet::with_builtins();
        for name in ["db.resampleIndex", "db.resampleOutdatedIndexes"] {
            assert!(
                !set.is_reader_safe(name),
                "`{name}` writes a histogram: it must run inline, never on the reader pool"
            );
        }
    }

    #[test]
    fn optional_argument_arity_and_default_substitution() {
        // `rmp` task #667: the registry supports trailing optional arguments (a `FieldSpec` default).
        let mut set = ProcedureSet::new();
        set.register(
            ProcedureSignature::new(
                "test.opt",
                vec![
                    FieldSpec::new("a", FieldType::required(ValueClass::Integer)),
                    FieldSpec::optional(
                        "b",
                        FieldType::required(ValueClass::Integer),
                        Value::Integer(99),
                    ),
                ],
                vec![
                    FieldSpec::new("a", FieldType::required(ValueClass::Integer)),
                    FieldSpec::new("b", FieldType::required(ValueClass::Integer)),
                ],
            ),
            // Echo the (post-substitution) arguments back so we can observe the default.
            Box::new(|args, _g| Ok(vec![args.to_vec()])),
        );
        let sig = set.signature("test.opt").expect("registered");
        assert_eq!(sig.required_arity(), 1);
        assert_eq!(sig.inputs.len(), 2);

        let mut g = MemGraph::new();
        // Omitting the trailing optional substitutes its default (99).
        let rows = set
            .invoke("test.opt", &[Value::Integer(1)], &mut g)
            .expect("invoke with default");
        assert_eq!(rows, vec![vec![Value::Integer(1), Value::Integer(99)]]);
        // Supplying it uses the caller's value.
        let rows = set
            .invoke("test.opt", &[Value::Integer(1), Value::Integer(2)], &mut g)
            .expect("invoke full");
        assert_eq!(rows, vec![vec![Value::Integer(1), Value::Integer(2)]]);
        // Below the required floor, and above the ceiling, both fail.
        assert!(set.invoke("test.opt", &[], &mut g).is_err());
        assert!(
            set.invoke(
                "test.opt",
                &[Value::Integer(1), Value::Integer(2), Value::Integer(3)],
                &mut g,
            )
            .is_err()
        );
    }

    #[test]
    fn db_await_index_singular_registered_with_optional_timeout() {
        // `rmp` task #667: `db.awaitIndex(indexName, timeOutSeconds = 300) :: VOID`.
        let set = ProcedureSet::with_builtins();
        let sig = set.signature("db.awaitIndex").expect("registered");
        assert_eq!(sig.inputs.len(), 2);
        assert_eq!(sig.inputs[0].name, "indexName");
        assert_eq!(sig.inputs[0].ty.class, ValueClass::String);
        assert_eq!(sig.inputs[1].name, "timeOutSeconds");
        assert_eq!(sig.inputs[1].default, Some(Value::Integer(300)));
        assert_eq!(sig.required_arity(), 1, "only indexName is required");
        assert!(sig.outputs.is_empty(), "db.awaitIndex is VOID");
        // Case-insensitive, like every built-in.
        assert!(set.signature("DB.AwaitIndex").is_some());
    }

    #[test]
    fn db_await_index_noops_on_known_index_and_errors_on_unknown() {
        // `rmp` task #667: a no-op for a real index, an error for a nonexistent one (Neo4j behaviour),
        // exercised over the reference `MemGraph` (authoritative for its full-text index names).
        let mut g = MemGraph::new();
        let _ = g.add_node(["Doc"], [("t", Value::String("graph".into()))]);
        g.create_fulltext_index(
            "doc_ft",
            "Doc",
            ["t"],
            graphus_index::fulltext::Analyzer::Standard,
        );
        let set = ProcedureSet::with_builtins();

        // Known index → no-op success (both with and without the optional timeout).
        assert!(
            set.invoke("db.awaitIndex", &[Value::String("doc_ft".into())], &mut g)
                .expect("known index, default timeout")
                .is_empty()
        );
        assert!(
            set.invoke(
                "db.awaitIndex",
                &[Value::String("doc_ft".into()), Value::Integer(60)],
                &mut g,
            )
            .expect("known index, explicit timeout")
            .is_empty()
        );
        // Unknown index → error.
        let err = set
            .invoke("db.awaitIndex", &[Value::String("nope".into())], &mut g)
            .expect_err("unknown index must error");
        assert!(format!("{err}").contains("nope"));
        // Non-string first argument → error.
        assert!(
            set.invoke("db.awaitIndex", &[Value::Integer(1)], &mut g)
                .is_err()
        );
    }

    #[test]
    fn await_eventually_consistent_refresh_is_a_void_noop() {
        // `rmp` task #667: a nullary VOID no-op (Graphus full-text is synchronous, not eventually
        // consistent).
        let set = ProcedureSet::with_builtins();
        let sig = set
            .signature("db.index.fulltext.awaitEventuallyConsistentIndexRefresh")
            .expect("registered");
        assert!(sig.inputs.is_empty());
        assert!(sig.outputs.is_empty(), "VOID");
        let mut g = MemGraph::new();
        assert!(
            set.invoke(
                "db.index.fulltext.awaitEventuallyConsistentIndexRefresh",
                &[],
                &mut g,
            )
            .expect("invoke")
            .is_empty()
        );
    }

    #[test]
    fn list_available_analyzers_yields_standard_and_keyword() {
        // `rmp` task #667: one row per supported analyzer with (analyzer, description, stopwords).
        let set = ProcedureSet::with_builtins();
        let sig = set
            .signature("db.index.fulltext.listAvailableAnalyzers")
            .expect("registered");
        assert!(sig.inputs.is_empty());
        let out_names: Vec<&str> = sig.outputs.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(out_names, ["analyzer", "description", "stopwords"]);

        let mut g = MemGraph::new();
        let rows = set
            .invoke("db.index.fulltext.listAvailableAnalyzers", &[], &mut g)
            .expect("invoke");
        // Two analyzers, name-sorted ascending: keyword then standard.
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0][0], Value::String("keyword".into()));
        assert_eq!(rows[1][0], Value::String("standard".into()));
        // keyword has no stop-words; standard carries the documented English set.
        assert_eq!(rows[0][2], Value::List(Vec::new()));
        let Value::List(standard_stops) = &rows[1][2] else {
            panic!("standard stopwords must be a LIST");
        };
        assert!(!standard_stops.is_empty());
        assert!(standard_stops.contains(&Value::String("the".into())));
    }

    #[test]
    fn query_nodes_options_map_trims_with_skip_and_limit() {
        // `rmp` task #667: the optional 3-arg options MAP `{skip, limit}` trims the relevance-ordered
        // result. Three docs match "graph" with distinct scores → deterministic order a, b, c.
        use graphus_index::fulltext::Analyzer;
        let mut g = MemGraph::new();
        let a = g.add_node(["Doc"], [("t", Value::String("graph graph graph".into()))]);
        let b = g.add_node(["Doc"], [("t", Value::String("graph graph".into()))]);
        let c = g.add_node(["Doc"], [("t", Value::String("graph".into()))]);
        g.create_fulltext_index("ix", "Doc", ["t"], Analyzer::Standard);
        let set = ProcedureSet::with_builtins();

        // Baseline (2-arg, no options): all three, ordered by score then id.
        let all = set
            .invoke(
                "db.index.fulltext.queryNodes",
                &[Value::String("ix".into()), Value::String("graph".into())],
                &mut g,
            )
            .expect("2-arg");
        let ids: Vec<i64> = all
            .iter()
            .map(|r| match r[0] {
                Value::Integer(i) => i,
                _ => panic!("node id must be an Integer"),
            })
            .collect();
        assert_eq!(ids, vec![a.0 as i64, b.0 as i64, c.0 as i64]);

        // 3-arg with skip:1, limit:1 → just the second (b).
        let opts = Value::Map(vec![
            ("skip".to_owned(), Value::Integer(1)),
            ("limit".to_owned(), Value::Integer(1)),
        ]);
        let trimmed = set
            .invoke(
                "db.index.fulltext.queryNodes",
                &[
                    Value::String("ix".into()),
                    Value::String("graph".into()),
                    opts,
                ],
                &mut g,
            )
            .expect("3-arg options");
        assert_eq!(trimmed.len(), 1);
        assert_eq!(trimmed[0][0], Value::Integer(b.0 as i64));

        // A recognized analyzer override and an unknown key are accepted (shape works).
        let opts2 = Value::Map(vec![
            ("analyzer".to_owned(), Value::String("standard".into())),
            ("sort".to_owned(), Value::String("ignored".into())),
        ]);
        assert!(
            set.invoke(
                "db.index.fulltext.queryNodes",
                &[
                    Value::String("ix".into()),
                    Value::String("graph".into()),
                    opts2,
                ],
                &mut g,
            )
            .is_ok()
        );
        // A bogus analyzer name is rejected.
        let bad = Value::Map(vec![(
            "analyzer".to_owned(),
            Value::String("nonsense".into()),
        )]);
        assert!(
            set.invoke(
                "db.index.fulltext.queryNodes",
                &[
                    Value::String("ix".into()),
                    Value::String("graph".into()),
                    bad,
                ],
                &mut g,
            )
            .is_err()
        );
    }

    #[test]
    fn query_nodes_and_relationships_declare_optional_options_map() {
        // `rmp` task #667: the options MAP is a trailing optional 3rd input on both query procedures.
        let set = ProcedureSet::with_builtins();
        for name in [
            "db.index.fulltext.queryNodes",
            "db.index.fulltext.queryRelationships",
        ] {
            let sig = set.signature(name).expect("registered");
            assert_eq!(sig.inputs.len(), 3, "{name} gains an options input");
            assert_eq!(sig.inputs[2].name, "options");
            assert_eq!(
                sig.required_arity(),
                2,
                "{name}: options is optional (2-arg form stays valid)"
            );
            assert_eq!(sig.inputs[2].default, Some(Value::Map(Vec::new())));
        }
    }

    #[test]
    fn field_type_accepts_models_cypher_coercions() {
        let int = nullable(ValueClass::Integer);
        let float = nullable(ValueClass::Float);
        let number = nullable(ValueClass::Number);
        let string = FieldType {
            class: ValueClass::String,
            nullable: false,
        };
        assert!(int.accepts(&Value::Integer(1)));
        assert!(!int.accepts(&Value::Boolean(true)));
        assert!(int.accepts(&Value::Null));
        assert!(!string.accepts(&Value::Null));
        assert!(float.accepts(&Value::Integer(1)));
        assert!(float.accepts(&Value::Float(1.5)));
        assert!(number.accepts(&Value::Integer(1)));
        assert!(number.accepts(&Value::Float(1.5)));
        assert!(!number.accepts(&Value::String("x".into())));
    }

    #[test]
    fn builtins_are_reader_safe_and_register_default_is_not() {
        // `rmp` task #546: every built-in procedure is registered reader-safe (they only read the
        // graph), so a read plan calling them may dispatch off-thread.
        let set = ProcedureSet::with_builtins();
        for name in [
            "db.labels",
            "db.relationshipTypes",
            "db.propertyKeys",
            "db.index.fulltext.queryNodes",
        ] {
            assert!(
                set.is_reader_safe(name),
                "built-in `{name}` must be reader-safe"
            );
            // Case-insensitive, like every other name lookup.
            assert!(set.is_reader_safe(&name.to_ascii_uppercase()));
        }
        // An unknown name is conservatively NOT reader-safe (keeps a caller inline).
        assert!(!set.is_reader_safe("no.such.procedure"));

        // The plain `register` default is NOT reader-safe; `register_reader_safe` opts in.
        let mut set = ProcedureSet::new();
        let sig = |name: &str| ProcedureSignature::new(name, Vec::new(), Vec::new());
        set.register(sig("ext.maybeWrites"), Box::new(|_a, _g| Ok(Vec::new())));
        set.register_reader_safe(sig("ext.pureRead"), Box::new(|_a, _g| Ok(Vec::new())));
        assert!(!set.is_reader_safe("ext.maybeWrites"));
        assert!(set.is_reader_safe("ext.pureRead"));
    }
}
