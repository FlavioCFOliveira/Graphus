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
use crate::graph_access::GraphAccess;

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
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct FieldSpec {
    /// The field name (an input parameter name, or a `YIELD`-able result column name).
    pub name: String,
    /// The declared type.
    pub ty: FieldType,
}

impl FieldSpec {
    /// Builds a field spec.
    pub fn new(name: impl Into<String>, ty: FieldType) -> Self {
        Self {
            name: name.into(),
            ty,
        }
    }
}

/// A procedure's full signature: its canonical (lower-cased) dotted name, typed inputs, and typed
/// outputs (openCypher `ProcedureName ( inputs ) :: ( outputs )` as the TCK writes it).
///
/// A procedure with **no outputs** is a *void* procedure: in-query it passes each driving row
/// through unchanged (it adds no columns), and standalone it produces no client-facing result rows
/// — the openCypher TCK's `test.doNothing() :: ()` semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
        // the relationship analogue of `queryNodes` (`rmp` task #639). Graphus full-text indexes cover
        // **nodes only** (a [`FulltextIndexEntry`](graphus_storage::FulltextIndexEntry) records a node
        // *label* token, and the [`GraphAccess`] seam exposes only node full-text via
        // [`fulltext_query`](GraphAccess::fulltext_query)), so this procedure is registered — so it is
        // listed by `SHOW PROCEDURES` and type-checks under `YIELD` for driver/tooling compatibility —
        // but its body returns a **clear runtime error** rather than silently-empty results (which would
        // mislead a caller into thinking their relationship index simply matched nothing). Output
        // `relationship` is declared `ANY`: Neo4j types it `RELATIONSHIP`, but the v1 registry
        // [`ValueClass`] models `NODE` structurally and not `RELATIONSHIP`; since no row is ever yielded,
        // no structural relationship is materialized. Kept in step with the two-input `queryNodes`
        // signature (the registry has no optional-argument support for Neo4j's third `options` MAP).
        set.register_reader_safe(
            ProcedureSignature::new(
                "db.index.fulltext.queryRelationships",
                vec![
                    FieldSpec::new("indexName", FieldType::required(ValueClass::String)),
                    FieldSpec::new("queryString", FieldType::required(ValueClass::String)),
                ],
                vec![
                    FieldSpec::new("relationship", FieldType::required(ValueClass::Any)),
                    FieldSpec::new("score", FieldType::required(ValueClass::Float)),
                ],
            ),
            Box::new(|_args, _graph| fulltext_query_relationships()),
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
        // `db.awaitIndexes(timeOutSeconds)` — block until every index is ONLINE, or the timeout elapses
        // (`rmp` task #639). A **VOID** procedure (no yielded columns). Graphus builds every index
        // **synchronously** at `CREATE INDEX` time — an index is ONLINE the moment its DDL commits, so
        // there is never a pending population to await. The body is therefore a genuine no-op that
        // returns immediately regardless of the timeout, which is the correct behaviour (nothing to wait
        // for), not a stub. The Neo4j argument name (`timeOutSeconds`, INTEGER, default 300) is kept
        // verbatim for signature fidelity; the registry's strict arity means the timeout is required
        // here (v1 has no optional/default-argument support).
        set.register_reader_safe(
            ProcedureSignature::new(
                "db.awaitIndexes",
                vec![FieldSpec::new(
                    "timeOutSeconds",
                    FieldType::required(ValueClass::Integer),
                )],
                Vec::new(),
            ),
            Box::new(|_args, _graph| Ok(Vec::new())),
        );
        // `db.resampleIndex(indexName)` and `db.resampleOutdatedIndexes()` — schedule a re-sampling of
        // index statistics (`rmp` task #639). Both are **VOID** no-ops in Graphus: the planner's
        // statistics are maintained **automatically** — live per-label/per-type counts and equi-depth
        // property histograms rebuilt from the store on open (see [`crate::statistics`] /
        // `graphus-index::histogram`) — so there is no separately-sampled index statistic that could go
        // stale and need an explicit resample. They are registered for driver/tooling compatibility and
        // complete successfully with no effect. `indexName` is not validated against the catalog (the
        // `GraphAccess` seam exposes no index-catalog listing), matching the lenient no-op contract.
        set.register_reader_safe(
            ProcedureSignature::new(
                "db.resampleIndex",
                vec![FieldSpec::new(
                    "indexName",
                    FieldType::required(ValueClass::String),
                )],
                Vec::new(),
            ),
            Box::new(|_args, _graph| Ok(Vec::new())),
        );
        set.register_reader_safe(
            ProcedureSignature::new("db.resampleOutdatedIndexes", Vec::new(), Vec::new()),
            Box::new(|_args, _graph| Ok(Vec::new())),
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
        if args.len() != proc.signature.inputs.len() {
            return Err(ProcedureFailure::new(
                dotted_name,
                format!(
                    "expected {} argument(s), got {}",
                    proc.signature.inputs.len(),
                    args.len()
                ),
            ));
        }
        (proc.handler)(args, graph)
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

/// The `db.index.fulltext.queryRelationships(indexName, queryString)` body (`rmp` task #639).
///
/// Graphus full-text indexes cover **nodes only** (there is no relationship full-text backing on the
/// [`GraphAccess`] seam), so this always fails with a clear, actionable message rather than returning
/// silently-empty results that would masquerade as "no matches". The procedure is still *registered*
/// (so `SHOW PROCEDURES` lists it and `YIELD relationship, score` type-checks) for driver/tooling
/// compatibility.
///
/// # Errors
///
/// Always returns a [`ProcedureFailure`] explaining that relationship full-text indexes are not
/// supported and pointing to the node-index procedure.
fn fulltext_query_relationships() -> Result<Vec<Vec<Value>>, ProcedureFailure> {
    Err(ProcedureFailure::new(
        "db.index.fulltext.queryRelationships",
        "relationship full-text indexes are not supported: Graphus full-text indexes cover nodes \
         only — use db.index.fulltext.queryNodes for node full-text search",
    ))
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
        assert_eq!(sig.inputs.len(), 2);
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
        // `rmp` task #639: a VOID no-op (indexes are ONLINE synchronously, nothing to await). Takes the
        // required INTEGER timeout and yields no rows.
        let set = ProcedureSet::with_builtins();
        let sig = set.signature("db.awaitIndexes").expect("registered");
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(sig.inputs[0].name, "timeOutSeconds");
        assert_eq!(sig.inputs[0].ty.class, ValueClass::Integer);
        assert!(sig.outputs.is_empty(), "db.awaitIndexes is VOID");

        let mut g = MemGraph::new();
        let rows = set
            .invoke("db.awaitIndexes", &[Value::Integer(30)], &mut g)
            .expect("invoke");
        assert!(rows.is_empty());
        // Wrong arity still fails (strict, like every built-in).
        assert!(set.invoke("db.awaitIndexes", &[], &mut g).is_err());
    }

    #[test]
    fn db_resample_index_and_outdated_are_void_noops() {
        // `rmp` task #639: both VOID no-ops (planner statistics are maintained automatically, so there
        // is nothing to resample). `db.resampleIndex` takes a STRING index name; the outdated form is
        // nullary.
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
    fn fulltext_query_relationships_is_registered_but_errors_clearly() {
        // `rmp` task #639: registered (so SHOW PROCEDURES lists it and YIELD type-checks) with the
        // Neo4j `relationship, score` outputs, but errors clearly — Graphus full-text indexes cover
        // nodes only.
        let set = ProcedureSet::with_builtins();
        let sig = set
            .signature("db.index.fulltext.queryRelationships")
            .expect("registered");
        assert_eq!(sig.inputs.len(), 2);
        let out_names: Vec<&str> = sig.outputs.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(out_names, ["relationship", "score"]);
        assert_eq!(sig.outputs[1].ty.class, ValueClass::Float);
        assert!(set.is_reader_safe("db.index.fulltext.queryRelationships"));

        let mut g = MemGraph::new();
        let err = set
            .invoke(
                "db.index.fulltext.queryRelationships",
                &[
                    Value::String("rel_ix".into()),
                    Value::String("query".into()),
                ],
                &mut g,
            )
            .expect_err("relationship full-text must error");
        let msg = format!("{err}");
        assert!(msg.contains("nodes only"), "message was: {msg}");
        assert!(msg.contains("queryNodes"), "message was: {msg}");
    }

    #[test]
    fn new_admin_procedures_are_reader_safe() {
        // Every procedure added in `rmp` #639 is read-only / no-op, so all are reader-safe (dispatchable
        // to the off-thread reader pool; keeps `SHOW PROCEDURES` mode = READ).
        let set = ProcedureSet::with_builtins();
        for name in [
            "dbms.components",
            "db.awaitIndexes",
            "db.resampleIndex",
            "db.resampleOutdatedIndexes",
            "db.index.fulltext.queryRelationships",
        ] {
            assert!(set.is_reader_safe(name), "`{name}` must be reader-safe");
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
