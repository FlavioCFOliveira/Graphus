//! The **extension registry** — the combined user-defined-function (UDF) and user-defined-procedure
//! (UDP) catalogue (`rmp` task #75: *user-defined functions/procedures + extension mechanism*).
//!
//! An [`ExtensionRegistry`] bundles a [`FunctionSet`] (extension *functions*, `rmp` #75) and a
//! [`ProcedureSet`] (extension *procedures*, building on the procedure framework of `rmp` #57). It is
//! the single object a server deployment builds once at startup and threads through both phases of
//! every statement: semantic analysis ([`analyze_with_extensions`](crate::semantics::analyze_with_extensions))
//! resolves names/arities/types against it, and the executor
//! ([`execute_with_extensions`](crate::executor::execute_with_extensions)) invokes through it. The
//! **same** registry must back both phases, or the compile-time guarantees are void.
//!
//! # The loading model (v1: compiled-in registration)
//!
//! v1 is **compiled-in** registration: extension functions and procedures are ordinary Rust
//! closures, registered through a safe Rust API the server calls at startup. This is safe by
//! construction — everything is statically linked, type-checked at registration, and there is **no
//! dynamic code loading**: an extension cannot escape the type system, corrupt the engine, or load
//! arbitrary code. A deployment adds its own UDFs/UDPs by calling
//! [`ExtensionRegistry::register_function`] / [`ExtensionRegistry::register_procedure`] in its
//! startup wiring (the server's `register_builtin_extensions` hook).
//!
//! # The future dynamic-extension path (out of scope for v1, documented — `CLAUDE.md`: never guess; scope and document)
//!
//! A *dynamic* extension mechanism — loading extensions from disk at runtime, without recompiling —
//! is **deliberately out of scope for v1** because it is a security boundary that must be designed,
//! not guessed:
//!
//! - **Dynamic native (`dylib`) loading is rejected for v1.** A C-ABI `dylib` loaded via a stable
//!   registration entrypoint would let a deployment ship extensions as shared objects — but native
//!   code runs with the **full privileges of the host process**: arbitrary memory access, arbitrary
//!   syscalls, no resource limits, and any `unsafe`/UB in the extension is the engine's
//!   crash/exploit. Loading arbitrary native code is therefore equivalent to arbitrary host access,
//!   which violates Graphus's safety posture; it is not offered.
//! - **WASM is the recommended future direction.** A WebAssembly module boundary (via a WASM runtime
//!   such as Wasmtime) gives **memory isolation** (the extension cannot touch host memory outside its
//!   sandbox), a **capability-restricted host interface** (the extension sees only the value-passing
//!   API the engine exposes — no ambient filesystem/network), and **deterministic resource limits**
//!   (fuel/epoch interruption, memory caps), so a malicious or buggy extension can be contained and
//!   cancelled. This is the path a later task should take if dynamic loading is required; it is
//!   scoped here, not implemented.
//!
//! Until then, the compiled-in path above is the supported, safe extension mechanism.

use graphus_core::Value;

use crate::function_registry::{
    Arity, FunctionFailure, FunctionHandler, FunctionRegistry, FunctionSet,
};
use crate::procedure_registry::{
    ProcedureFailure, ProcedureRegistry, ProcedureSet, ProcedureSignature,
};

/// A procedure body handler, matching [`ProcedureSet::register`]'s parameter (re-aliased here so
/// callers of [`ExtensionRegistry::register_procedure`] need not import the procedure module).
pub type ProcedureHandler = Box<
    dyn Fn(
            &[Value],
            &mut dyn crate::graph_access::GraphAccess,
        ) -> Result<Vec<Vec<Value>>, ProcedureFailure>
        + Send
        + Sync,
>;

/// The combined extension catalogue: user-defined **functions** and **procedures** (`rmp` task #75).
///
/// Build one with [`ExtensionRegistry::new`] (extension functions empty, procedures pre-loaded with
/// the engine built-ins), register your own, and pass [`functions_dyn`](Self::functions_dyn) /
/// [`procedures_dyn`](Self::procedures_dyn) to
/// [`analyze_with_extensions`](crate::semantics::analyze_with_extensions) and
/// [`execute_with_extensions`](crate::executor::execute_with_extensions).
#[derive(Debug, Default)]
pub struct ExtensionRegistry {
    functions: FunctionSet,
    procedures: ProcedureSet,
}

impl ExtensionRegistry {
    /// A registry with **no** extension functions and the engine's **built-in procedures**
    /// pre-loaded (`db.labels`, `db.relationshipTypes`, `db.propertyKeys`,
    /// `db.index.fulltext.queryNodes`).
    ///
    /// The built-in procedures are always present so a deployment that registers only its own UDFs
    /// does not lose the catalogue procedures the engine relies on. For a no-builtins registry (test
    /// fixtures), use [`empty`](Self::empty).
    #[must_use]
    pub fn new() -> Self {
        Self {
            functions: FunctionSet::new(),
            procedures: ProcedureSet::with_builtins(),
        }
    }

    /// A registry with **no** extension functions and **no** procedures at all (not even the
    /// built-ins) — a clean slate for tests that want to assert exactly what is registered.
    ///
    /// Production code should use [`new`](Self::new), which keeps the built-in procedures.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Registers a user-defined **scalar** function (`rmp` task #75).
    ///
    /// Delegates to [`FunctionSet::register`]: `name` is canonicalised to lower case, `aggregate`
    /// marks an aggregating function (registration allowed; folding is a v1 deferral — see the
    /// [`crate::function_registry`] module docs), and the handler takes property [`Value`]s in and
    /// returns one [`Value`] out.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `name` collides with a built-in function (which may not be shadowed) or with
    /// an already-registered UDF.
    pub fn register_function(
        &mut self,
        name: impl Into<String>,
        arity: Arity,
        aggregate: bool,
        handler: FunctionHandler,
    ) -> Result<(), String> {
        self.functions.register(name, arity, aggregate, handler)
    }

    /// Registers a user-defined **procedure** (building on the `rmp` #57 procedure framework).
    ///
    /// Delegates to [`ProcedureSet::register`]: the procedure is keyed by its signature's canonical
    /// name and yields result rows over the live [`GraphAccess`](crate::graph_access::GraphAccess)
    /// seam (so a UDP may read the graph — the procedure side carries graph access, unlike the
    /// scalar function side).
    pub fn register_procedure(&mut self, signature: ProcedureSignature, handler: ProcedureHandler) {
        self.procedures.register(signature, handler);
    }

    /// Registers the **Graph Data Science (`gds.*`) procedure surface** (`rmp` task #133) into this
    /// registry's procedure set, all sharing the one `catalog` handle.
    ///
    /// This is the one wiring point a deployment calls to make `CALL gds.graph.project(...)`,
    /// `CALL gds.pageRank.stream(...)` and the rest of the GDS algorithms available. The shared
    /// [`GdsCatalogHandle`](crate::gds_procedures::GdsCatalogHandle) makes named projections outlive a
    /// single statement (project once, stream many times). Delegates to
    /// [`register_gds_procedures`](crate::gds_procedures::register_gds_procedures).
    pub fn register_gds_procedures(&mut self, catalog: crate::gds_procedures::GdsCatalogHandle) {
        crate::gds_procedures::register_gds_procedures(&mut self.procedures, catalog);
    }

    /// Registers a **fixture-table** procedure (the openCypher TCK's `there exists a procedure …`
    /// form), delegating to [`ProcedureSet::register_table`].
    ///
    /// # Errors
    ///
    /// Returns a description if any row's input/output widths do not match the signature.
    pub fn register_procedure_table(
        &mut self,
        signature: ProcedureSignature,
        rows: Vec<(Vec<Value>, Vec<Value>)>,
    ) -> Result<(), String> {
        self.procedures.register_table(signature, rows)
    }

    /// The extension function set (concrete type).
    #[must_use]
    pub fn functions(&self) -> &FunctionSet {
        &self.functions
    }

    /// The procedure set (concrete type), including the built-ins.
    #[must_use]
    pub fn procedures(&self) -> &ProcedureSet {
        &self.procedures
    }

    /// The extension function set as a `&dyn FunctionRegistry`, ready to pass to
    /// [`analyze_with_extensions`](crate::semantics::analyze_with_extensions) /
    /// [`execute_with_extensions`](crate::executor::execute_with_extensions).
    #[must_use]
    pub fn functions_dyn(&self) -> &dyn FunctionRegistry {
        &self.functions
    }

    /// The procedure set as a `&dyn ProcedureRegistry`, ready to pass to
    /// [`analyze_with_extensions`](crate::semantics::analyze_with_extensions) /
    /// [`execute_with_extensions`](crate::executor::execute_with_extensions).
    #[must_use]
    pub fn procedures_dyn(&self) -> &dyn ProcedureRegistry {
        &self.procedures
    }
}

/// A convenience wrapper turning a plain `Fn(&[Value]) -> Result<Value, FunctionFailure>` into a
/// boxed [`FunctionHandler`]. Saves callers a `Box::new(...)` and an explicit type at every
/// registration site.
#[must_use]
pub fn function_handler<F>(f: F) -> FunctionHandler
where
    F: Fn(&[Value]) -> Result<Value, FunctionFailure> + Send + Sync + 'static,
{
    Box::new(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_includes_builtin_procedures_but_no_functions() {
        let reg = ExtensionRegistry::new();
        // Built-in procedures are present.
        assert!(reg.procedures().signature("db.labels").is_some());
        assert!(reg.procedures().signature("db.propertyKeys").is_some());
        // No extension functions.
        assert!(reg.functions().is_empty());
        assert!(reg.functions_dyn().signature("ext.double").is_none());
    }

    #[test]
    fn empty_has_no_builtins() {
        let reg = ExtensionRegistry::empty();
        assert!(reg.procedures().signature("db.labels").is_none());
        assert!(reg.functions().is_empty());
    }

    #[test]
    fn register_function_then_resolve_through_dyn() {
        let mut reg = ExtensionRegistry::new();
        reg.register_function(
            "ext.double",
            Arity::Exact(1),
            false,
            function_handler(|args| match args.first() {
                Some(Value::Integer(i)) => Ok(Value::Integer(i * 2)),
                _ => Err(FunctionFailure::new("ext.double", "expected an integer")),
            }),
        )
        .expect("register");
        let sig = reg.functions_dyn().signature("ext.double").expect("found");
        assert_eq!(sig.name, "ext.double");
        assert_eq!(
            reg.functions_dyn()
                .invoke("ext.double", &[Value::Integer(5)]),
            Ok(Value::Integer(10))
        );
    }

    #[test]
    fn register_function_collision_with_builtin_is_rejected() {
        let mut reg = ExtensionRegistry::new();
        assert!(
            reg.register_function(
                "size",
                Arity::Exact(1),
                false,
                function_handler(|_| { Ok(Value::Null) })
            )
            .is_err()
        );
    }

    #[test]
    fn register_procedure_yields_rows() {
        use crate::graph_access::MemGraph;
        use crate::procedure_registry::{FieldSpec, FieldType, ValueClass};

        let mut reg = ExtensionRegistry::new();
        reg.register_procedure(
            ProcedureSignature::new(
                "ext.range",
                vec![
                    FieldSpec::new(
                        "a",
                        FieldType {
                            class: ValueClass::Integer,
                            nullable: false,
                        },
                    ),
                    FieldSpec::new(
                        "b",
                        FieldType {
                            class: ValueClass::Integer,
                            nullable: false,
                        },
                    ),
                ],
                vec![FieldSpec::new(
                    "value",
                    FieldType {
                        class: ValueClass::Integer,
                        nullable: false,
                    },
                )],
            ),
            Box::new(|args, _graph| {
                let (Some(Value::Integer(a)), Some(Value::Integer(b))) =
                    (args.first(), args.get(1))
                else {
                    return Err(ProcedureFailure::new("ext.range", "expected two integers"));
                };
                Ok((*a..=*b).map(|n| vec![Value::Integer(n)]).collect())
            }),
        );
        let mut g = MemGraph::new();
        let rows = reg
            .procedures_dyn()
            .invoke("ext.range", &[Value::Integer(1), Value::Integer(3)], &mut g)
            .expect("invoke");
        assert_eq!(
            rows,
            vec![
                vec![Value::Integer(1)],
                vec![Value::Integer(2)],
                vec![Value::Integer(3)]
            ]
        );
    }
}
