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

/// Whether a violated constraint covers **nodes** or **relationships** (`rmp` #638), for
/// entity-aware message rendering. The `token` in [`render`](Self::render) is the covered node label
/// or relationship type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationEntity {
    /// A node constraint (`FOR (n:Label)`) — the token is a node label.
    Node,
    /// A relationship constraint (`FOR ()-[r:TYPE]-()`) — the token is a relationship type.
    Relationship,
}

impl ViolationEntity {
    /// Renders the entity reference for a message: `Node(:Label)` or `Relationship[:TYPE]`.
    #[must_use]
    fn render(self, token: &str) -> String {
        match self {
            Self::Node => format!("Node(:{token})"),
            Self::Relationship => format!("Relationship[:{token}]"),
        }
    }

    /// The constraint-kind label word for a message: `"node-key"` / `"relationship-key"`, etc.
    #[must_use]
    fn word(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Relationship => "relationship",
        }
    }
}

/// A declared constraint a write would violate (`rmp` task #99, #638). Carries enough context to
/// render a precise, human message naming the constraint, the covered entity (node label or
/// relationship type), the property and the offending value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintViolation {
    /// A **uniqueness** constraint was violated: an entity of `label` already holds `value` for
    /// `property`, so a second one cannot.
    Uniqueness {
        /// The declared constraint's name.
        name: String,
        /// Whether the covered entity is a node or a relationship.
        entity: ViolationEntity,
        /// The covered node label / relationship type.
        label: String,
        /// The covered property key.
        property: String,
        /// A short rendering of the duplicate value (for the human message).
        value: String,
    },
    /// An **existence** (`NOT NULL`) constraint was violated: an entity of `label` lacks the required
    /// `property` (or set it to null).
    Existence {
        /// The declared constraint's name.
        name: String,
        /// Whether the covered entity is a node or a relationship.
        entity: ViolationEntity,
        /// The covered node label / relationship type.
        label: String,
        /// The required property key.
        property: String,
    },
    /// A **key** constraint was violated because the covered composite tuple is **incomplete**: an
    /// entity of `label` lacks (or nulled) at least one of the key's `properties` (`rmp` task #100).
    NodeKeyMissing {
        /// The declared constraint's name.
        name: String,
        /// Whether the covered entity is a node or a relationship.
        entity: ViolationEntity,
        /// The covered node label / relationship type.
        label: String,
        /// The key's covered properties, in declared order.
        properties: Vec<String>,
    },
    /// A **key** constraint was violated because the covered composite tuple is **not unique**:
    /// another entity of `label` already holds the same tuple of `properties` values (`rmp` task
    /// #100).
    NodeKeyDuplicate {
        /// The declared constraint's name.
        name: String,
        /// Whether the covered entity is a node or a relationship.
        entity: ViolationEntity,
        /// The covered node label / relationship type.
        label: String,
        /// The key's covered properties, in declared order.
        properties: Vec<String>,
        /// A short rendering of the duplicate composite tuple (for the human message).
        values: String,
    },
    /// A **property-type** constraint was violated: an entity of `label` holds a value for `property`
    /// whose type is `actual`, but the constraint requires `expected` (`rmp` task #100).
    PropertyType {
        /// The declared constraint's name.
        name: String,
        /// Whether the covered entity is a node or a relationship.
        entity: ViolationEntity,
        /// The covered node label / relationship type.
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
    /// The covered entity of this violation (`rmp` #638).
    fn entity(&self) -> ViolationEntity {
        match self {
            Self::Uniqueness { entity, .. }
            | Self::Existence { entity, .. }
            | Self::NodeKeyMissing { entity, .. }
            | Self::NodeKeyDuplicate { entity, .. }
            | Self::PropertyType { entity, .. } => *entity,
        }
    }

    /// The constraint kind this violation concerns — the node or relationship discriminant per the
    /// covered [`entity`](Self::entity) (`rmp` #638).
    pub fn kind(&self) -> ConstraintKind {
        let rel = self.entity() == ViolationEntity::Relationship;
        match self {
            Self::Uniqueness { .. } => {
                if rel {
                    ConstraintKind::RelUnique
                } else {
                    ConstraintKind::Unique
                }
            }
            Self::Existence { .. } => {
                if rel {
                    ConstraintKind::RelExistence
                } else {
                    ConstraintKind::Existence
                }
            }
            Self::NodeKeyMissing { .. } | Self::NodeKeyDuplicate { .. } => {
                if rel {
                    ConstraintKind::RelKey
                } else {
                    ConstraintKind::NodeKey
                }
            }
            Self::PropertyType { .. } => {
                if rel {
                    ConstraintKind::RelPropertyType
                } else {
                    ConstraintKind::PropertyType
                }
            }
        }
    }

    /// The human-readable description (without the wire sentinel), e.g.
    /// `"Node(:Person) already exists with property `email` = 'a@x.com' (constraint `c1`)"`.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Uniqueness {
                name,
                entity,
                label,
                property,
                value,
            } => format!(
                "{} already exists with property `{property}` = {value} \
                 (uniqueness constraint `{name}`)",
                entity.render(label)
            ),
            Self::Existence {
                name,
                entity,
                label,
                property,
            } => format!(
                "{} must have the property `{property}` \
                 (existence constraint `{name}`)",
                entity.render(label)
            ),
            Self::NodeKeyMissing {
                name,
                entity,
                label,
                properties,
            } => format!(
                "{} must have all properties {} \
                 ({}-key constraint `{name}`)",
                entity.render(label),
                render_property_list(properties),
                entity.word(),
            ),
            Self::NodeKeyDuplicate {
                name,
                entity,
                label,
                properties,
                values,
            } => format!(
                "{} already exists with properties {} = {values} \
                 ({}-key constraint `{name}`)",
                entity.render(label),
                render_property_list(properties),
                entity.word(),
            ),
            Self::PropertyType {
                name,
                entity,
                label,
                property,
                expected,
                actual,
            } => format!(
                "{} property `{property}` must be of type {expected} but was {actual} \
                 (property-type constraint `{name}`)",
                entity.render(label)
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
    use ConstraintTypeDescriptor as T;
    match descriptor {
        T::Integer => "INTEGER".to_owned(),
        T::Float => "FLOAT".to_owned(),
        T::String => "STRING".to_owned(),
        T::Boolean => "BOOLEAN".to_owned(),
        T::Date => "DATE".to_owned(),
        T::LocalTime => "LOCAL TIME".to_owned(),
        T::ZonedTime => "ZONED TIME".to_owned(),
        T::LocalDateTime => "LOCAL DATETIME".to_owned(),
        T::ZonedDateTime => "ZONED DATETIME".to_owned(),
        T::Duration => "DURATION".to_owned(),
        T::Point => "POINT".to_owned(),
        // Neo4j renders a property-type list element as `NOT NULL` (the only allowed list form); the
        // legacy `ANY` wildcard (never producible by the current parser) keeps the bare `LIST<ANY>`.
        T::List(inner) => match inner.as_ref() {
            T::Any => "LIST<ANY>".to_owned(),
            other => format!("LIST<{} NOT NULL>", type_descriptor_name(other)),
        },
        T::Any => "ANY".to_owned(),
        // A closed union renders its members `|`-separated, in declared order (`INTEGER | STRING`).
        T::Union(members) => members
            .iter()
            .map(type_descriptor_name)
            .collect::<Vec<_>>()
            .join(" | "),
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
    use ConstraintTypeDescriptor as T;
    match descriptor {
        T::Integer => matches!(value, Value::Integer(_)),
        T::Float => matches!(value, Value::Float(_)),
        T::String => matches!(value, Value::String(_)),
        T::Boolean => matches!(value, Value::Boolean(_)),
        T::Date => matches!(value, Value::Date(_)),
        T::LocalTime => matches!(value, Value::LocalTime(_)),
        T::ZonedTime => matches!(value, Value::ZonedTime(_)),
        T::LocalDateTime => matches!(value, Value::LocalDateTime(_)),
        T::ZonedDateTime => matches!(value, Value::ZonedDateTime(_)),
        T::Duration => matches!(value, Value::Duration(_)),
        T::Point => matches!(value, Value::Point(_)),
        T::List(inner) => match value {
            Value::List(items) => items
                .iter()
                .all(|item| value_matches_descriptor(item, inner)),
            // Graphus models a byte string as a `LIST<INTEGER NOT NULL>` of its byte values, mirroring
            // the `IS ::` predicate matcher in `eval.rs`, so a byte string conforms to `LIST<INTEGER>`.
            Value::Bytes(bytes) => bytes
                .iter()
                .all(|&b| value_matches_descriptor(&Value::Integer(i64::from(b)), inner)),
            _ => false,
        },
        // The list-element wildcard: matches any non-null value. (A null never reaches this function —
        // the caller short-circuits a null/absent value before type-checking.)
        T::Any => !value.is_null(),
        // A closed union matches iff the value conforms to any member.
        T::Union(members) => members
            .iter()
            .any(|member| value_matches_descriptor(value, member)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniqueness_message_names_constraint_label_property_value() {
        let v = ConstraintViolation::Uniqueness {
            name: "c1".to_owned(),
            entity: ViolationEntity::Node,
            label: "Person".to_owned(),
            property: "email".to_owned(),
            value: "'a@x.com'".to_owned(),
        };
        let m = v.message();
        assert!(m.contains("Node(:Person)"), "{m}");
        assert!(m.contains("email"), "{m}");
        assert!(m.contains("'a@x.com'"), "{m}");
        assert!(m.contains("c1"), "{m}");
        assert_eq!(v.kind(), ConstraintKind::Unique);
    }

    #[test]
    fn existence_message_names_constraint_label_property() {
        let v = ConstraintViolation::Existence {
            name: "c2".to_owned(),
            entity: ViolationEntity::Node,
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
    fn relationship_violation_message_and_kind_are_entity_aware() {
        // `rmp` #638: a relationship existence violation renders `Relationship[:TYPE]` and reports the
        // relationship kind.
        let v = ConstraintViolation::Existence {
            name: "rc".to_owned(),
            entity: ViolationEntity::Relationship,
            label: "KNOWS".to_owned(),
            property: "since".to_owned(),
        };
        let m = v.message();
        assert!(m.contains("Relationship[:KNOWS]"), "{m}");
        assert!(!m.contains("Node("), "{m}");
        assert_eq!(v.kind(), ConstraintKind::RelExistence);

        // A relationship key violation reports the relationship-key kind + `relationship-key` wording.
        let dup = ConstraintViolation::NodeKeyDuplicate {
            name: "rk".to_owned(),
            entity: ViolationEntity::Relationship,
            label: "RATED".to_owned(),
            properties: vec!["user".to_owned(), "movie".to_owned()],
            values: "(1, 2)".to_owned(),
        };
        let dm = dup.message();
        assert!(dm.contains("Relationship[:RATED]"), "{dm}");
        assert!(dm.contains("relationship-key constraint"), "{dm}");
        assert_eq!(dup.kind(), ConstraintKind::RelKey);

        let uniq = ConstraintViolation::Uniqueness {
            name: "ru".to_owned(),
            entity: ViolationEntity::Relationship,
            label: "PAID".to_owned(),
            property: "ref".to_owned(),
            value: "'x'".to_owned(),
        };
        assert_eq!(uniq.kind(), ConstraintKind::RelUnique);

        let ty = ConstraintViolation::PropertyType {
            name: "rt".to_owned(),
            entity: ViolationEntity::Relationship,
            label: "WEIGHS".to_owned(),
            property: "kg".to_owned(),
            expected: "INTEGER".to_owned(),
            actual: "STRING".to_owned(),
        };
        assert_eq!(ty.kind(), ConstraintKind::RelPropertyType);
    }

    #[test]
    fn wire_message_carries_the_sentinel_prefix_exactly_once() {
        let v = ConstraintViolation::Existence {
            name: "c".to_owned(),
            entity: ViolationEntity::Node,
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
            entity: ViolationEntity::Node,
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
            entity: ViolationEntity::Node,
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
            entity: ViolationEntity::Node,
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
            entity: ViolationEntity::Node,
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
        // Temporal + spatial scalars (`rmp` #652).
        assert_eq!(type_descriptor_name(&T::Date), "DATE");
        assert_eq!(type_descriptor_name(&T::LocalTime), "LOCAL TIME");
        assert_eq!(type_descriptor_name(&T::ZonedTime), "ZONED TIME");
        assert_eq!(type_descriptor_name(&T::LocalDateTime), "LOCAL DATETIME");
        assert_eq!(type_descriptor_name(&T::ZonedDateTime), "ZONED DATETIME");
        assert_eq!(type_descriptor_name(&T::Duration), "DURATION");
        assert_eq!(type_descriptor_name(&T::Point), "POINT");
        // A constraint list element is always `NOT NULL` in the canonical Neo4j spelling.
        assert_eq!(
            type_descriptor_name(&T::List(Box::new(T::String))),
            "LIST<STRING NOT NULL>"
        );
        assert_eq!(
            type_descriptor_name(&T::List(Box::new(T::Point))),
            "LIST<POINT NOT NULL>"
        );
        // The legacy `ANY` element wildcard keeps the bare `LIST<ANY>`.
        assert_eq!(
            type_descriptor_name(&T::List(Box::new(T::Any))),
            "LIST<ANY>"
        );
        // A closed union renders its members `|`-separated in declared order.
        assert_eq!(
            type_descriptor_name(&T::Union(vec![T::Integer, T::String])),
            "INTEGER | STRING"
        );
        assert_eq!(
            type_descriptor_name(&T::Union(vec![T::String, T::List(Box::new(T::String)),])),
            "STRING | LIST<STRING NOT NULL>"
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

        // A closed union (`rmp` #652) matches iff the value conforms to any member.
        let u = T::Union(vec![T::Integer, T::String]);
        assert!(value_matches_descriptor(&Value::Integer(7), &u));
        assert!(value_matches_descriptor(&Value::String("x".to_owned()), &u));
        assert!(!value_matches_descriptor(&Value::Boolean(true), &u));
        assert!(!value_matches_descriptor(&Value::Float(1.0), &u));
        // A union nesting a list member: `STRING | LIST<INTEGER NOT NULL>`.
        let ul = T::Union(vec![T::String, T::List(Box::new(T::Integer))]);
        assert!(value_matches_descriptor(
            &Value::String("x".to_owned()),
            &ul
        ));
        assert!(value_matches_descriptor(
            &Value::List(vec![Value::Integer(1), Value::Integer(2)]),
            &ul
        ));
        assert!(!value_matches_descriptor(&Value::Integer(1), &ul));
    }
}
