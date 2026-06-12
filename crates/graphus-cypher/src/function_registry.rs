//! A minimal Cypher **function registry** — the framework plus a representative set of built-ins —
//! used by semantic analysis to raise the compile-time [`UnknownFunction`] and
//! [`InvalidNumberOfArguments`] errors (`04 §7.3`; openCypher TCK details, verbatim).
//!
//! [`UnknownFunction`]: crate::errors::SemanticErrorKind::UnknownFunction
//! [`InvalidNumberOfArguments`]: crate::errors::SemanticErrorKind::InvalidNumberOfArguments
//!
//! # What this is, and is not
//!
//! The openCypher TCK raises an **unknown function name** and a **wrong arity** as compile-time
//! `SemanticError`s (TCK details `UnknownFunction` / `InvalidNumberOfArguments`, found verbatim in
//! the `tck/features/**` feature files). To detect those, the semantic phase needs to know which
//! function names exist and how many arguments each accepts — hence this registry.
//!
//! It is deliberately a **framework + a curated, representative subset** of the openCypher
//! scalar/list/aggregating functions, not the full library. The set is the one the early planner /
//! TCK acceptance scenarios lean on most. Adding the remaining built-ins is mechanical (extend the
//! internal `TABLE`); the *mechanism* — name lookup + arity classification + aggregate flag — is
//! complete.
//! The full function-library completeness is tracked as a follow-up of the Cypher engine epic
//! rather than guessed at here (`CLAUDE.md`: never guess; scope and document).
//!
//! Function **name matching is case-insensitive** (openCypher function names are
//! case-insensitive); the registry lowercases on both insert and lookup.
//!
//! Argument **types** are intentionally *not* modelled here: argument type mismatches on actual
//! values are runtime `TypeError`s by TCK design (`04 §7.3`), so they are the executor's job, not
//! the compile-time phase's.

use std::collections::HashMap;
use std::fmt;
use std::sync::LazyLock;

use graphus_core::Value;

/// How many arguments a function accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Arity {
    /// Exactly `n` arguments.
    Exact(usize),
    /// An inclusive range `[min, max]` of arguments (for optional trailing args).
    Range(usize, usize),
    /// Any number of arguments (e.g. `coalesce`).
    Variadic,
}

/// The result of checking a supplied argument count against an [`Arity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum ArityCheck {
    /// The argument count is acceptable.
    Ok,
    /// The argument count is wrong for this function.
    Wrong,
}

impl Arity {
    /// Classifies a supplied argument count.
    pub const fn check(self, got: usize) -> ArityCheck {
        let ok = match self {
            Self::Exact(n) => got == n,
            Self::Range(lo, hi) => got >= lo && got <= hi,
            Self::Variadic => true,
        };
        if ok {
            ArityCheck::Ok
        } else {
            ArityCheck::Wrong
        }
    }

    /// A short human description of the accepted arity (for the error message).
    #[must_use]
    pub fn describe(self) -> String {
        match self {
            Self::Exact(n) => n.to_string(),
            Self::Range(lo, hi) => format!("{lo}..{hi}"),
            Self::Variadic => "any number of".to_owned(),
        }
    }
}

/// A function's registry entry: its canonical (lower-cased, dotted) name, accepted [`Arity`], and
/// whether it is an **aggregating** function (which drives the aggregation-placement rules in
/// [`crate::semantics`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct Signature {
    /// The canonical lower-cased dotted name (e.g. `"size"`, `"point.distance"`).
    pub name: &'static str,
    /// The accepted argument count.
    pub arity: Arity,
    /// `true` for aggregating functions (`count`, `sum`, `collect`, …).
    pub aggregate: bool,
}

/// The curated built-in table. Names are written canonical (lower-case); lookup lowercases its
/// query so callers may pass any casing. Kept sorted by name for readability.
static TABLE: &[Signature] = &[
    // ---- aggregating functions (drive aggregation rules) ------------------------------------
    Signature {
        name: "avg",
        arity: Arity::Exact(1),
        aggregate: true,
    },
    Signature {
        name: "collect",
        arity: Arity::Exact(1),
        aggregate: true,
    },
    Signature {
        name: "count",
        arity: Arity::Exact(1),
        aggregate: true,
    },
    Signature {
        name: "max",
        arity: Arity::Exact(1),
        aggregate: true,
    },
    Signature {
        name: "min",
        arity: Arity::Exact(1),
        aggregate: true,
    },
    Signature {
        name: "percentilecont",
        arity: Arity::Exact(2),
        aggregate: true,
    },
    Signature {
        name: "percentiledisc",
        arity: Arity::Exact(2),
        aggregate: true,
    },
    Signature {
        name: "stdev",
        arity: Arity::Exact(1),
        aggregate: true,
    },
    Signature {
        name: "stdevp",
        arity: Arity::Exact(1),
        aggregate: true,
    },
    Signature {
        name: "sum",
        arity: Arity::Exact(1),
        aggregate: true,
    },
    // ---- temporal constructors (openCypher temporal CIP; rmp #53) ----------------------------
    // Arity 0 is the "current instant" form, which needs the transaction clock (a named
    // deferral); arity 1 covers the string / component-map / projection forms.
    Signature {
        name: "date",
        arity: Arity::Range(0, 1),
        aggregate: false,
    },
    Signature {
        name: "datetime",
        arity: Arity::Range(0, 1),
        aggregate: false,
    },
    Signature {
        name: "date.truncate",
        arity: Arity::Range(2, 3),
        aggregate: false,
    },
    Signature {
        name: "datetime.truncate",
        arity: Arity::Range(2, 3),
        aggregate: false,
    },
    Signature {
        name: "duration",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "duration.between",
        arity: Arity::Exact(2),
        aggregate: false,
    },
    Signature {
        name: "duration.indays",
        arity: Arity::Exact(2),
        aggregate: false,
    },
    Signature {
        name: "duration.inmonths",
        arity: Arity::Exact(2),
        aggregate: false,
    },
    Signature {
        name: "duration.inseconds",
        arity: Arity::Exact(2),
        aggregate: false,
    },
    Signature {
        name: "localdatetime.truncate",
        arity: Arity::Range(2, 3),
        aggregate: false,
    },
    Signature {
        name: "localtime.truncate",
        arity: Arity::Range(2, 3),
        aggregate: false,
    },
    Signature {
        name: "time.truncate",
        arity: Arity::Range(2, 3),
        aggregate: false,
    },
    Signature {
        name: "localdatetime",
        arity: Arity::Range(0, 1),
        aggregate: false,
    },
    Signature {
        name: "localtime",
        arity: Arity::Range(0, 1),
        aggregate: false,
    },
    Signature {
        name: "time",
        arity: Arity::Range(0, 1),
        aggregate: false,
    },
    // ---- spatial functions (openCypher spatial; rmp #73) ------------------------------------
    Signature {
        name: "point",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "distance",
        arity: Arity::Exact(2),
        aggregate: false,
    },
    Signature {
        name: "point.distance",
        arity: Arity::Exact(2),
        aggregate: false,
    },
    // ---- scalar functions -------------------------------------------------------------------
    Signature {
        name: "abs",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "ceil",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "coalesce",
        arity: Arity::Variadic,
        aggregate: false,
    },
    Signature {
        name: "endnode",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "exists",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "floor",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "head",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "id",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "last",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "length",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "properties",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "rand",
        arity: Arity::Exact(0),
        aggregate: false,
    },
    Signature {
        name: "round",
        arity: Arity::Range(1, 2),
        aggregate: false,
    },
    Signature {
        name: "sign",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "size",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "sqrt",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "startnode",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "toboolean",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "tobooleanornull",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "tofloat",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "tointeger",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "tostring",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "type",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    // ---- list functions ---------------------------------------------------------------------
    Signature {
        name: "keys",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "labels",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "nodes",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "range",
        arity: Arity::Range(2, 3),
        aggregate: false,
    },
    Signature {
        name: "relationships",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "reverse",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "tail",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    // ---- string functions -------------------------------------------------------------------
    Signature {
        name: "left",
        arity: Arity::Exact(2),
        aggregate: false,
    },
    Signature {
        name: "ltrim",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "replace",
        arity: Arity::Exact(3),
        aggregate: false,
    },
    Signature {
        name: "right",
        arity: Arity::Exact(2),
        aggregate: false,
    },
    Signature {
        name: "rtrim",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "split",
        arity: Arity::Exact(2),
        aggregate: false,
    },
    Signature {
        name: "substring",
        arity: Arity::Range(2, 3),
        aggregate: false,
    },
    Signature {
        name: "tolower",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "toupper",
        arity: Arity::Exact(1),
        aggregate: false,
    },
    Signature {
        name: "trim",
        arity: Arity::Exact(1),
        aggregate: false,
    },
];

/// A lower-cased-name → [`Signature`] index, built once on first use.
static INDEX: LazyLock<std::collections::HashMap<&'static str, Signature>> = LazyLock::new(|| {
    let mut m = std::collections::HashMap::with_capacity(TABLE.len());
    for sig in TABLE {
        // The static table is the single source of truth; a duplicate name is a programming error.
        debug_assert!(
            !m.contains_key(sig.name),
            "duplicate function `{}` in TABLE",
            sig.name
        );
        m.insert(sig.name, *sig);
    }
    m
});

/// Looks up a (possibly mixed-case, dotted) function name, returning its [`Signature`] if known.
///
/// Matching is case-insensitive (openCypher function names are case-insensitive); the dotted form
/// (`"point.distance"`) is matched as a whole.
#[must_use]
pub fn lookup(dotted_name: &str) -> Option<Signature> {
    let lower = dotted_name.to_ascii_lowercase();
    INDEX.get(lower.as_str()).copied()
}

/// Whether the named function is an **aggregating** function. An unknown name is not an aggregate
/// (the unknown-function error is raised separately, where the call is resolved).
#[must_use]
pub fn is_aggregate(dotted_name: &str) -> bool {
    lookup(dotted_name).is_some_and(|s| s.aggregate)
}

// =================================================================================================
// Registrable functions: the user-defined-function (UDF) framework (`rmp` task #75)
// =================================================================================================
//
// The static [`TABLE`]/[`lookup`]/[`is_aggregate`] above are the **built-in** library — frozen, the
// engine's own functions, evaluated by name in [`crate::eval`]. Everything below is the *additive*
// **extension** mechanism: a deployment (or a test) registers its own scalar functions into a
// [`FunctionSet`], which semantic analysis and the executor consult **after** the built-ins, so a
// UDF can never shadow a built-in (registration rejects a built-in-colliding name, and the runtime
// matches built-ins first regardless). This mirrors the procedure side
// ([`crate::procedure_registry::ProcedureSet`]) exactly.
//
// # v1 scope (deliberate, documented — `CLAUDE.md`: never guess; scope and document)
//
// - **Scalar only.** A UDF takes property [`Value`]s in and returns one [`Value`] out; it has **no**
//   graph access. Built-ins that need the graph (`id()`, `labels()`, `type()`, `properties()`, …)
//   stay built-in — a UDF is for pure value computation (`ext.double(n)`, a domain hash, a unit
//   conversion). Entity-/graph-aware extension *functions* are a named follow-up; the *procedure*
//   side already covers graph-reading extensions (it threads the `GraphAccess` seam).
// - **Argument types are runtime-checked.** Like the built-ins (see this module's header), a UDF's
//   argument *types* are not modelled in the signature; a handler that rejects a wrong-typed value
//   returns a [`FunctionFailure`], which the executor surfaces as a **runtime**
//   [`ExtensionFunction`](crate::eval::EvalError::ExtensionFunction) error — the
//   `ArgumentError`-class case, consistent with the TCK's compile-vs-runtime split.
// - **Aggregate UDF folding is deferred.** An *aggregate* UDF may be **registered** (so it
//   type-checks and drives the aggregation-placement rules in [`crate::semantics`]), but the actual
//   per-group folding of a custom aggregate by the
//   [`Aggregation`](crate::physical::PhysicalOp::Aggregation) operator (which folds built-in
//   aggregates by name) is a named v1 deferral. Scalar UDFs are wired **end-to-end**; the primary
//   acceptance case is a scalar `ext.double`.

/// A **runtime** user-defined-function failure (`rmp` task #75): the function exists (compile-time
/// resolution succeeded) but its body — or its own argument-type check — failed.
///
/// The registrable-function analogue of [`crate::procedure_registry::ProcedureFailure`]. It surfaces
/// at the executor as [`EvalError::ExtensionFunction`](crate::eval::EvalError::ExtensionFunction),
/// which maps (via `From<EvalError>`) to [`GraphusError::Runtime`](graphus_core::GraphusError::Runtime)
/// and thus to the Bolt `ArgumentError` class — the same class a built-in's runtime type error takes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct FunctionFailure {
    /// The dotted function name as invoked.
    pub name: String,
    /// A human description of the failure.
    pub message: String,
}

impl FunctionFailure {
    /// Builds a failure for `name`.
    pub fn new(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for FunctionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "function `{}` failed: {}", self.name, self.message)
    }
}

impl std::error::Error for FunctionFailure {}

/// A registrable function's signature: its canonical (lower-cased) name, accepted [`Arity`], and
/// whether it is an **aggregating** function (which drives the aggregation-placement rules in
/// [`crate::semantics`]).
///
/// The owned, registrable analogue of the static [`Signature`] (whose `name` is `&'static str`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct FunctionSignature {
    /// The canonical lower-cased dotted name (e.g. `"ext.double"`).
    pub name: String,
    /// The accepted argument count.
    pub arity: Arity,
    /// `true` for an aggregating function (registration is allowed; folding is a v1 deferral).
    pub aggregate: bool,
}

impl FunctionSignature {
    /// Builds a signature, canonicalising `name` to lower case (function names are
    /// case-insensitive, like the built-ins).
    pub fn new(name: impl Into<String>, arity: Arity, aggregate: bool) -> Self {
        Self {
            name: name.into().to_ascii_lowercase(),
            arity,
            aggregate,
        }
    }
}

/// A user-defined function's executable body: already-evaluated property argument values in, one
/// property [`Value`] out (or a [`FunctionFailure`]). No graph access in v1 (see the module section
/// header above).
pub type FunctionHandler = Box<dyn Fn(&[Value]) -> Result<Value, FunctionFailure> + Send + Sync>;

/// The function catalogue the compile pipeline and the executor consult for **extension** functions
/// (`rmp` task #75).
///
/// As with [`ProcedureRegistry`](crate::procedure_registry::ProcedureRegistry), the **same**
/// registry must back both phases of one statement: semantic analysis resolves names and arities
/// against it, and the executor invokes through it.
pub trait FunctionRegistry {
    /// Resolves a (possibly mixed-case) dotted function name to its [`FunctionSignature`], or `None`
    /// if no such UDF is registered. Matching is case-insensitive. Built-ins are **not** reported
    /// here — they are resolved separately via the static [`lookup`], which always takes precedence.
    fn signature(&self, dotted_name: &str) -> Option<FunctionSignature>;

    /// Invokes the named UDF with the already-evaluated `args`, returning its single result value.
    ///
    /// # Errors
    ///
    /// Returns a [`FunctionFailure`] if the name is unknown (defensively — compile-time resolution
    /// normally prevents it), the argument count does not match the signature, or the handler
    /// itself fails (including its own argument-type rejection).
    fn invoke(&self, dotted_name: &str, args: &[Value]) -> Result<Value, FunctionFailure>;
}

/// One registered UDF: its signature and its body.
struct Function {
    signature: FunctionSignature,
    handler: FunctionHandler,
}

/// The concrete, mutable [`FunctionRegistry`]: a name-indexed set of user-defined functions.
///
/// Build one with [`FunctionSet::new`] (empty), then [`register`](Self::register) handler-backed
/// functions. Registration **rejects** a name that collides with a built-in (built-ins may not be
/// shadowed) or a duplicate UDF name.
#[derive(Default)]
pub struct FunctionSet {
    functions: HashMap<String, Function>,
}

impl fmt::Debug for FunctionSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Handlers are opaque closures; list the registered names (sorted, like `ProcedureSet`).
        let mut names: Vec<&str> = self.functions.keys().map(String::as_str).collect();
        names.sort_unstable();
        f.debug_struct("FunctionSet")
            .field("functions", &names)
            .finish()
    }
}

impl FunctionSet {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a handler-backed user-defined function.
    ///
    /// `name` is canonicalised to lower case. `aggregate` marks the function as an aggregating one
    /// (registration is allowed; the per-group fold is a v1 deferral — see the module section
    /// header).
    ///
    /// # Errors
    ///
    /// Returns `Err` (and registers nothing) if `name` collides with a **built-in** function (those
    /// take precedence and may not be shadowed) or with an already-registered UDF. The message
    /// names the offending function.
    pub fn register(
        &mut self,
        name: impl Into<String>,
        arity: Arity,
        aggregate: bool,
        handler: FunctionHandler,
    ) -> Result<(), String> {
        let signature = FunctionSignature::new(name, arity, aggregate);
        let key = signature.name.clone();
        if lookup(&key).is_some() {
            return Err(format!(
                "function `{key}` collides with a built-in function and cannot be redefined"
            ));
        }
        if self.functions.contains_key(&key) {
            return Err(format!("function `{key}` is already registered"));
        }
        self.functions.insert(key, Function { signature, handler });
        Ok(())
    }

    /// The number of registered user-defined functions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    /// Whether the registry holds no user-defined functions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }
}

impl FunctionRegistry for FunctionSet {
    fn signature(&self, dotted_name: &str) -> Option<FunctionSignature> {
        self.functions
            .get(dotted_name.to_ascii_lowercase().as_str())
            .map(|fun| fun.signature.clone())
    }

    fn invoke(&self, dotted_name: &str, args: &[Value]) -> Result<Value, FunctionFailure> {
        let key = dotted_name.to_ascii_lowercase();
        let Some(fun) = self.functions.get(&key) else {
            // Defensive: semantic analysis resolves names at compile time, so reaching here means
            // the compile-time and execution-time registries diverged.
            return Err(FunctionFailure::new(
                dotted_name,
                "function is not registered (compile/execute registry mismatch)",
            ));
        };
        if fun.signature.arity.check(args.len()) == ArityCheck::Wrong {
            return Err(FunctionFailure::new(
                dotted_name,
                format!(
                    "expected {} argument(s), got {}",
                    fun.signature.arity.describe(),
                    args.len()
                ),
            ));
        }
        (fun.handler)(args)
    }
}

/// The empty user-defined-function registry, built once on first use. This is the registry the
/// function-less entry points ([`crate::semantics::analyze`] /
/// [`crate::semantics::analyze_with_procedures`] / [`crate::executor::execute`] /
/// [`crate::executor::execute_with_procedures`]) consult, so those paths see **no** UDFs — only the
/// built-ins — and behave exactly as before this task. It is the function-side analogue of
/// [`crate::procedure_registry::builtins`].
pub fn no_functions() -> &'static FunctionSet {
    static NO_FUNCTIONS: LazyLock<FunctionSet> = LazyLock::new(FunctionSet::new);
    &NO_FUNCTIONS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_case_insensitive() {
        assert!(lookup("COUNT").is_some());
        assert!(lookup("Count").is_some());
        assert!(lookup("count").is_some());
    }

    #[test]
    fn unknown_function_is_none() {
        assert!(lookup("definitely_not_a_function").is_none());
        assert!(!is_aggregate("definitely_not_a_function"));
    }

    #[test]
    fn aggregate_flag_matches_table() {
        assert!(is_aggregate("count"));
        assert!(is_aggregate("collect"));
        assert!(!is_aggregate("size"));
        assert!(!is_aggregate("abs"));
    }

    #[test]
    fn arity_classification() {
        assert_eq!(Arity::Exact(1).check(1), ArityCheck::Ok);
        assert_eq!(Arity::Exact(1).check(2), ArityCheck::Wrong);
        assert_eq!(Arity::Range(1, 2).check(0), ArityCheck::Wrong);
        assert_eq!(Arity::Range(1, 2).check(2), ArityCheck::Ok);
        assert_eq!(Arity::Variadic.check(0), ArityCheck::Ok);
        assert_eq!(Arity::Variadic.check(9), ArityCheck::Ok);
    }

    #[test]
    fn scalar_gap_fill_entries_are_registered() {
        // rmp #62: the TCK-exercised scalar gaps (`rand`, `sqrt`, `toBoolean`) plus the
        // `toBooleanOrNull` companion.
        assert_eq!(lookup("rand").map(|s| s.arity), Some(Arity::Exact(0)));
        assert_eq!(lookup("sqrt").map(|s| s.arity), Some(Arity::Exact(1)));
        assert_eq!(lookup("toBoolean").map(|s| s.arity), Some(Arity::Exact(1)));
        assert_eq!(
            lookup("toBooleanOrNull").map(|s| s.arity),
            Some(Arity::Exact(1))
        );
        assert!(!is_aggregate("rand"));
    }

    #[test]
    fn no_duplicate_names_in_table() {
        // Force the lazy index, which `debug_assert!`s uniqueness; also assert by count.
        let unique: std::collections::HashSet<_> = TABLE.iter().map(|s| s.name).collect();
        assert_eq!(
            unique.len(),
            TABLE.len(),
            "TABLE has a duplicate function name"
        );
        assert_eq!(INDEX.len(), TABLE.len());
    }

    // ---- registrable UDF framework (`rmp` task #75) -----------------------------------------

    /// Builds a scalar `ext.double` UDF that doubles an integer/float, passes `null` through, and
    /// rejects any other type with a [`FunctionFailure`].
    fn double_handler() -> FunctionHandler {
        Box::new(|args| match args.first() {
            Some(Value::Integer(i)) => Ok(Value::Integer(i * 2)),
            Some(Value::Float(f)) => Ok(Value::Float(f * 2.0)),
            Some(Value::Null) | None => Ok(Value::Null),
            Some(other) => Err(FunctionFailure::new(
                "ext.double",
                format!("expected a number, got {other:?}"),
            )),
        })
    }

    #[test]
    fn udf_register_and_invoke_case_insensitively() {
        let mut set = FunctionSet::new();
        set.register("ext.double", Arity::Exact(1), false, double_handler())
            .expect("register");
        assert_eq!(set.len(), 1);
        assert!(!set.is_empty());
        // Case-insensitive resolution, like the built-ins.
        assert!(set.signature("ext.double").is_some());
        assert!(set.signature("EXT.Double").is_some());
        assert_eq!(
            set.invoke("ext.double", &[Value::Integer(21)]),
            Ok(Value::Integer(42))
        );
        assert_eq!(
            set.invoke("Ext.Double", &[Value::Float(1.5)]),
            Ok(Value::Float(3.0))
        );
        assert_eq!(set.invoke("ext.double", &[Value::Null]), Ok(Value::Null));
    }

    #[test]
    fn udf_invoke_wrong_arity_is_a_failure() {
        let mut set = FunctionSet::new();
        set.register("ext.double", Arity::Exact(1), false, double_handler())
            .expect("register");
        // Two args where the signature declares one — a defensive runtime failure (compile-time
        // normally catches it).
        let err = set
            .invoke("ext.double", &[Value::Integer(1), Value::Integer(2)])
            .expect_err("wrong arity");
        assert_eq!(err.name, "ext.double");
        assert!(err.message.contains("argument"));
    }

    #[test]
    fn udf_handler_type_rejection_surfaces_as_failure() {
        let mut set = FunctionSet::new();
        set.register("ext.double", Arity::Exact(1), false, double_handler())
            .expect("register");
        let err = set
            .invoke("ext.double", &[Value::String("x".into())])
            .expect_err("wrong type");
        assert_eq!(err.name, "ext.double");
    }

    #[test]
    fn registering_a_builtin_name_is_rejected() {
        let mut set = FunctionSet::new();
        // `size` and `abs` are built-ins; they may not be shadowed (any casing).
        assert!(
            set.register("size", Arity::Exact(1), false, double_handler())
                .is_err()
        );
        assert!(
            set.register("ABS", Arity::Exact(1), false, double_handler())
                .is_err()
        );
        // Aggregating built-ins are likewise protected.
        assert!(
            set.register("count", Arity::Exact(1), true, double_handler())
                .is_err()
        );
        assert!(set.is_empty(), "a rejected registration must add nothing");
    }

    #[test]
    fn registering_a_duplicate_udf_is_rejected() {
        let mut set = FunctionSet::new();
        set.register("ext.double", Arity::Exact(1), false, double_handler())
            .expect("first register");
        let err = set
            .register("EXT.DOUBLE", Arity::Exact(1), false, double_handler())
            .expect_err("duplicate");
        assert!(err.contains("ext.double"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn aggregate_udf_registers_and_reports_aggregate() {
        let mut set = FunctionSet::new();
        set.register(
            "ext.mysum",
            Arity::Exact(1),
            true,
            Box::new(|_args| Ok(Value::Null)),
        )
        .expect("register aggregate");
        let sig = set.signature("ext.mysum").expect("registered");
        assert!(sig.aggregate);
        assert_eq!(sig.name, "ext.mysum");
    }

    #[test]
    fn no_functions_registry_is_empty() {
        assert!(no_functions().is_empty());
        assert!(no_functions().signature("anything").is_none());
    }

    #[test]
    fn invoke_unknown_udf_is_defensive_failure() {
        let set = FunctionSet::new();
        assert!(set.invoke("ext.nope", &[]).is_err());
    }
}
