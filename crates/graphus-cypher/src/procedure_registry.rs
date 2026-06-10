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

/// One registered procedure: its signature and its body.
struct Procedure {
    signature: ProcedureSignature,
    handler: ProcedureHandler,
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
        set.register(
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
        set.register(
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
        set.register(
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
        set
    }

    /// Registers (or replaces) a handler-backed procedure under its signature's canonical name.
    pub fn register(&mut self, signature: ProcedureSignature, handler: ProcedureHandler) {
        let key = signature.name.clone();
        self.procedures
            .insert(key, Procedure { signature, handler });
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
}
