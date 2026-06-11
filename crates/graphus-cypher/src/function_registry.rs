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

use std::sync::LazyLock;

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
}
