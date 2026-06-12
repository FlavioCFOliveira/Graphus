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

use graphus_core::Value;
use graphus_storage::{ConstraintKind, ConstraintTypeDescriptor};

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
    /// A **node-key** constraint was violated because the covered composite tuple is **incomplete**: a
    /// node carrying `label` lacks (or nulled) at least one of the key's `properties` (`rmp` task #100).
    NodeKeyMissing {
        /// The declared constraint's name.
        name: String,
        /// The covered node label.
        label: String,
        /// The key's covered properties, in declared order.
        properties: Vec<String>,
    },
    /// A **node-key** constraint was violated because the covered composite tuple is **not unique**:
    /// another node carrying `label` already holds the same tuple of `properties` values (`rmp` task
    /// #100).
    NodeKeyDuplicate {
        /// The declared constraint's name.
        name: String,
        /// The covered node label.
        label: String,
        /// The key's covered properties, in declared order.
        properties: Vec<String>,
        /// A short rendering of the duplicate composite tuple (for the human message).
        values: String,
    },
    /// A **property-type** constraint was violated: a node carrying `label` holds a value for
    /// `property` whose type is `actual`, but the constraint requires `expected` (`rmp` task #100).
    PropertyType {
        /// The declared constraint's name.
        name: String,
        /// The covered node label.
        label: String,
        /// The covered property key.
        property: String,
        /// The required type's openCypher rendering (e.g. `INTEGER`, `LIST<STRING>`).
        expected: String,
        /// The offending value's actual type rendering.
        actual: String,
    },
}

impl ConstraintViolation {
    /// The constraint kind this violation concerns.
    pub fn kind(&self) -> ConstraintKind {
        match self {
            Self::Uniqueness { .. } => ConstraintKind::Unique,
            Self::Existence { .. } => ConstraintKind::Existence,
            Self::NodeKeyMissing { .. } | Self::NodeKeyDuplicate { .. } => ConstraintKind::NodeKey,
            Self::PropertyType { .. } => ConstraintKind::PropertyType,
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
            Self::NodeKeyMissing {
                name,
                label,
                properties,
            } => format!(
                "Node(:{label}) must have all properties {} \
                 (node-key constraint `{name}`)",
                render_property_list(properties)
            ),
            Self::NodeKeyDuplicate {
                name,
                label,
                properties,
                values,
            } => format!(
                "Node(:{label}) already exists with properties {} = {values} \
                 (node-key constraint `{name}`)",
                render_property_list(properties)
            ),
            Self::PropertyType {
                name,
                label,
                property,
                expected,
                actual,
            } => format!(
                "Node(:{label}) property `{property}` must be of type {expected} but was {actual} \
                 (property-type constraint `{name}`)"
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

/// Renders a backtick-quoted, comma-separated property list (e.g. ``` `a`, `b` ```) for a node-key
/// violation message (`rmp` task #100).
fn render_property_list(properties: &[String]) -> String {
    properties
        .iter()
        .map(|p| format!("`{p}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The openCypher type-name rendering of a declared [`ConstraintTypeDescriptor`] (`rmp` task #100),
/// e.g. `INTEGER`, `LIST<STRING>`, `LIST<ANY>` — used in a property-type violation message and by
/// `SHOW CONSTRAINTS`.
#[must_use]
pub fn type_descriptor_name(descriptor: &ConstraintTypeDescriptor) -> String {
    match descriptor {
        ConstraintTypeDescriptor::Integer => "INTEGER".to_owned(),
        ConstraintTypeDescriptor::Float => "FLOAT".to_owned(),
        ConstraintTypeDescriptor::String => "STRING".to_owned(),
        ConstraintTypeDescriptor::Boolean => "BOOLEAN".to_owned(),
        ConstraintTypeDescriptor::List(inner) => {
            format!("LIST<{}>", type_descriptor_name(inner))
        }
        ConstraintTypeDescriptor::Any => "ANY".to_owned(),
    }
}

/// The openCypher type-name rendering of a [`Value`] (`rmp` task #100), used in a property-type
/// violation message. Mirrors the spelling of [`type_descriptor_name`] for the comparable types.
#[must_use]
pub fn value_type_name(value: &Value) -> String {
    match value {
        Value::Null => "NULL".to_owned(),
        Value::Boolean(_) => "BOOLEAN".to_owned(),
        Value::Integer(_) => "INTEGER".to_owned(),
        Value::Float(_) => "FLOAT".to_owned(),
        Value::String(_) => "STRING".to_owned(),
        Value::Bytes(_) => "BYTES".to_owned(),
        Value::List(_) => "LIST".to_owned(),
        Value::Map(_) => "MAP".to_owned(),
        Value::Date(_) => "DATE".to_owned(),
        Value::LocalTime(_) => "LOCAL TIME".to_owned(),
        Value::ZonedTime(_) => "ZONED TIME".to_owned(),
        Value::LocalDateTime(_) => "LOCAL DATETIME".to_owned(),
        Value::ZonedDateTime(_) => "ZONED DATETIME".to_owned(),
        Value::Duration(_) => "DURATION".to_owned(),
        Value::Point(_) => "POINT".to_owned(),
    }
}

/// Whether `value` satisfies the declared property type `descriptor` (`rmp` task #100).
///
/// The type check the property-type constraint enforces, applied **only** when the property is present
/// and non-null (a missing / null value never triggers a property-type violation — that is the
/// existence constraint's job, not the type constraint's). The mapping onto the [`Value`] model:
///
/// - [`Integer`](ConstraintTypeDescriptor::Integer) ⇔ [`Value::Integer`]; [`Float`] ⇔ [`Value::Float`]
///   (no integer↔float widening — openCypher `IS :: FLOAT` is exact); [`String`] ⇔ [`Value::String`];
///   [`Boolean`] ⇔ [`Value::Boolean`].
/// - [`List(inner)`](ConstraintTypeDescriptor::List) ⇔ a [`Value::List`] **every** element of which
///   matches `inner`; an empty list trivially matches (every element matches), and a bare `LIST` (its
///   `inner` is [`Any`](ConstraintTypeDescriptor::Any)) matches any list.
/// - [`Any`](ConstraintTypeDescriptor::Any) matches every non-null value (the list-element wildcard).
#[must_use]
pub fn value_matches_descriptor(value: &Value, descriptor: &ConstraintTypeDescriptor) -> bool {
    match descriptor {
        ConstraintTypeDescriptor::Integer => matches!(value, Value::Integer(_)),
        ConstraintTypeDescriptor::Float => matches!(value, Value::Float(_)),
        ConstraintTypeDescriptor::String => matches!(value, Value::String(_)),
        ConstraintTypeDescriptor::Boolean => matches!(value, Value::Boolean(_)),
        ConstraintTypeDescriptor::List(inner) => match value {
            Value::List(items) => items
                .iter()
                .all(|item| value_matches_descriptor(item, inner)),
            _ => false,
        },
        // The list-element wildcard: matches any non-null value. (A null never reaches this function —
        // the caller short-circuits a null/absent value before type-checking.)
        ConstraintTypeDescriptor::Any => !value.is_null(),
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

    #[test]
    fn node_key_and_property_type_messages_and_kinds() {
        let missing = ConstraintViolation::NodeKeyMissing {
            name: "k".to_owned(),
            label: "Person".to_owned(),
            properties: vec!["first".to_owned(), "last".to_owned()],
        };
        let m = missing.message();
        assert!(
            m.contains("Person") && m.contains("`first`") && m.contains("`last`"),
            "{m}"
        );
        assert_eq!(missing.kind(), ConstraintKind::NodeKey);

        let dup = ConstraintViolation::NodeKeyDuplicate {
            name: "k".to_owned(),
            label: "Person".to_owned(),
            properties: vec!["first".to_owned(), "last".to_owned()],
            values: "('Ada', 'Byron')".to_owned(),
        };
        assert!(
            dup.message().contains("('Ada', 'Byron')"),
            "{}",
            dup.message()
        );
        assert_eq!(dup.kind(), ConstraintKind::NodeKey);

        let ty = ConstraintViolation::PropertyType {
            name: "t".to_owned(),
            label: "Person".to_owned(),
            property: "age".to_owned(),
            expected: "INTEGER".to_owned(),
            actual: "STRING".to_owned(),
        };
        let m = ty.message();
        assert!(
            m.contains("INTEGER") && m.contains("STRING") && m.contains("`age`"),
            "{m}"
        );
        assert_eq!(ty.kind(), ConstraintKind::PropertyType);
    }

    #[test]
    fn type_descriptor_names_render_opencypher_spelling() {
        use ConstraintTypeDescriptor as T;
        assert_eq!(type_descriptor_name(&T::Integer), "INTEGER");
        assert_eq!(type_descriptor_name(&T::Float), "FLOAT");
        assert_eq!(type_descriptor_name(&T::String), "STRING");
        assert_eq!(type_descriptor_name(&T::Boolean), "BOOLEAN");
        assert_eq!(
            type_descriptor_name(&T::List(Box::new(T::String))),
            "LIST<STRING>"
        );
        assert_eq!(
            type_descriptor_name(&T::List(Box::new(T::Any))),
            "LIST<ANY>"
        );
    }

    #[test]
    fn value_matches_descriptor_is_exact_with_recursive_lists() {
        use ConstraintTypeDescriptor as T;
        assert!(value_matches_descriptor(&Value::Integer(1), &T::Integer));
        assert!(value_matches_descriptor(&Value::Float(1.5), &T::Float));
        assert!(value_matches_descriptor(
            &Value::String("x".to_owned()),
            &T::String
        ));
        assert!(value_matches_descriptor(&Value::Boolean(true), &T::Boolean));

        // No integer↔float widening — `IS :: FLOAT` is exact (openCypher).
        assert!(!value_matches_descriptor(&Value::Integer(1), &T::Float));
        assert!(!value_matches_descriptor(&Value::Float(1.0), &T::Integer));
        // A string is not an integer.
        assert!(!value_matches_descriptor(
            &Value::String("1".to_owned()),
            &T::Integer
        ));

        // LIST<INTEGER>: every element must be an integer; an empty list trivially matches.
        let li = T::List(Box::new(T::Integer));
        assert!(value_matches_descriptor(&Value::List(vec![]), &li));
        assert!(value_matches_descriptor(
            &Value::List(vec![Value::Integer(1), Value::Integer(2)]),
            &li
        ));
        assert!(!value_matches_descriptor(
            &Value::List(vec![Value::Integer(1), Value::String("x".to_owned())]),
            &li
        ));
        // A non-list never matches a LIST type.
        assert!(!value_matches_descriptor(&Value::Integer(1), &li));

        // LIST<ANY> (a bare list) matches any list, including a heterogeneous one.
        let la = T::List(Box::new(T::Any));
        assert!(value_matches_descriptor(
            &Value::List(vec![Value::Integer(1), Value::String("x".to_owned())]),
            &la
        ));

        // Nested LIST<LIST<INTEGER>>.
        let lli = T::List(Box::new(T::List(Box::new(T::Integer))));
        assert!(value_matches_descriptor(
            &Value::List(vec![
                Value::List(vec![Value::Integer(1)]),
                Value::List(vec![]),
            ]),
            &lli
        ));
        assert!(!value_matches_descriptor(
            &Value::List(vec![Value::List(vec![Value::String("x".to_owned())])]),
            &lli
        ));
    }
}
