//! Constraint **violation** errors and their TCK-faithful error class (`rmp` task #99;
//! `04-technical-design.md` §6.5, §7.3).
//!
//! This module is the Cypher-layer home of a constraint *violation* — the runtime error raised when
//! a `CREATE` / `SET` / `MERGE` (or a `CREATE CONSTRAINT` over non-conforming existing data) would
//! break a declared **uniqueness** or **existence** (`NOT NULL`) constraint. The constraint *catalog*
//! and *enforcement machinery* live elsewhere (the durable
//! [`graphus_storage::ConstraintEntry`], the in-memory [`crate::index_set::ConstraintRule`], and the
//! write-path checks in [`crate::record_graph`]); this module only defines the **error value** and
//! how it maps onto the wire error class.
//!
//! # Error class — `ConstraintValidationFailed` (runtime, the openCypher/Neo4j class)
//!
//! A constraint violation is a Cypher **runtime** error (`04 §7.3`: raised during execution, before
//! commit, never at compile time). On the Bolt wire the faithful class is
//! `Neo.ClientError.Schema.ConstraintValidationFailed` (the code the Neo4j driver ecosystem and the
//! openCypher schema corpus assert for a unique/existence-constraint breach). To carry that class
//! across the existing [`GraphusError`] boundary **without** widening the cross-crate
//! `#[non_exhaustive]` `GraphusError` enum (whose `Runtime` variant already documents "constraint" as
//! one of its runtime causes), a constraint-violation message is prefixed with the stable sentinel
//! [`CONSTRAINT_VIOLATION_PREFIX`]. The Bolt error renderer detects that prefix and emits the precise
//! schema class instead of the generic runtime class; every other surface (REST, logs) renders the
//! human message unchanged. The sentinel is an internal marker, stripped from the message the wire
//! actually carries — see `graphus_bolt::failure_from_error`.

use graphus_storage::ConstraintKind;

/// The stable sentinel that prefixes every constraint-violation message so the Bolt error renderer
/// can classify it as `Neo.ClientError.Schema.ConstraintValidationFailed` (`rmp` task #99).
///
/// Re-exported from [`graphus_core`] — the shared base crate both the producer (this crate) and the
/// consumer (`graphus-bolt`) depend on — so the marker has a single source of truth with no
/// crate-to-crate dependency between the query engine and the Bolt codec. `graphus_bolt::failure_from_error`
/// detects + strips it from the `FAILURE` message it sends.
pub use graphus_core::CONSTRAINT_VIOLATION_PREFIX;

/// A declared constraint a write would violate (`rmp` task #99). Carries enough context to render a
/// precise, human message naming the constraint, the label, the property and the offending value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintViolation {
    /// A **uniqueness** constraint was violated: a node carrying `label` already holds `value` for
    /// `property`, so a second one cannot.
    Uniqueness {
        /// The declared constraint's name.
        name: String,
        /// The covered node label.
        label: String,
        /// The covered property key.
        property: String,
        /// A short rendering of the duplicate value (for the human message).
        value: String,
    },
    /// An **existence** (`NOT NULL`) constraint was violated: a node carrying `label` lacks the
    /// required `property` (or set it to null).
    Existence {
        /// The declared constraint's name.
        name: String,
        /// The covered node label.
        label: String,
        /// The required property key.
        property: String,
    },
}

impl ConstraintViolation {
    /// The constraint kind this violation concerns.
    pub fn kind(&self) -> ConstraintKind {
        match self {
            Self::Uniqueness { .. } => ConstraintKind::Unique,
            Self::Existence { .. } => ConstraintKind::Existence,
        }
    }

    /// The human-readable description (without the wire sentinel), e.g.
    /// `"Node(:Person) already exists with property `email` = 'a@x.com' (constraint `c1`)"`.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Uniqueness {
                name,
                label,
                property,
                value,
            } => format!(
                "Node(:{label}) already exists with property `{property}` = {value} \
                 (uniqueness constraint `{name}`)"
            ),
            Self::Existence {
                name,
                label,
                property,
            } => format!(
                "Node(:{label}) must have the property `{property}` \
                 (existence constraint `{name}`)"
            ),
        }
    }

    /// The full message **with** the [`CONSTRAINT_VIOLATION_PREFIX`] sentinel, so the Bolt renderer
    /// classifies it as `ConstraintValidationFailed`. This is the string a constraint check captures
    /// into a [`GraphusError::Runtime`](graphus_core::GraphusError::Runtime).
    #[must_use]
    pub fn wire_message(&self) -> String {
        format!("{CONSTRAINT_VIOLATION_PREFIX}{}", self.message())
    }

    /// The violation as a crate-wide runtime error, ready to capture on the write path. The message
    /// carries the wire sentinel so the Bolt layer renders the precise schema error class.
    #[must_use]
    pub fn into_error(self) -> graphus_core::GraphusError {
        graphus_core::GraphusError::Runtime(self.wire_message())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniqueness_message_names_constraint_label_property_value() {
        let v = ConstraintViolation::Uniqueness {
            name: "c1".to_owned(),
            label: "Person".to_owned(),
            property: "email".to_owned(),
            value: "'a@x.com'".to_owned(),
        };
        let m = v.message();
        assert!(m.contains("Person"), "{m}");
        assert!(m.contains("email"), "{m}");
        assert!(m.contains("'a@x.com'"), "{m}");
        assert!(m.contains("c1"), "{m}");
        assert_eq!(v.kind(), ConstraintKind::Unique);
    }

    #[test]
    fn existence_message_names_constraint_label_property() {
        let v = ConstraintViolation::Existence {
            name: "c2".to_owned(),
            label: "Person".to_owned(),
            property: "name".to_owned(),
        };
        let m = v.message();
        assert!(m.contains("Person"), "{m}");
        assert!(m.contains("name"), "{m}");
        assert!(m.contains("c2"), "{m}");
        assert_eq!(v.kind(), ConstraintKind::Existence);
    }

    #[test]
    fn wire_message_carries_the_sentinel_prefix_exactly_once() {
        let v = ConstraintViolation::Existence {
            name: "c".to_owned(),
            label: "L".to_owned(),
            property: "p".to_owned(),
        };
        let w = v.wire_message();
        assert!(w.starts_with(CONSTRAINT_VIOLATION_PREFIX));
        // The human part follows the sentinel verbatim.
        assert_eq!(&w[CONSTRAINT_VIOLATION_PREFIX.len()..], v.message());
    }

    #[test]
    fn into_error_is_a_runtime_error_with_the_wire_message() {
        let v = ConstraintViolation::Existence {
            name: "c".to_owned(),
            label: "L".to_owned(),
            property: "p".to_owned(),
        };
        let wire = v.wire_message();
        match v.into_error() {
            graphus_core::GraphusError::Runtime(m) => assert_eq!(m, wire),
            other => panic!("expected Runtime, got {other:?}"),
        }
    }
}
