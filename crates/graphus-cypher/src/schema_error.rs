//! Schema-rule **declaration** errors and their TCK-faithful `Neo.ClientError.Schema.*` classes
//! (`rmp` task #624).
//!
//! This module is the Cypher-layer home of the errors raised when a `CREATE INDEX` / `CREATE
//! CONSTRAINT` / `DROP INDEX` cannot proceed for a *schema-management* reason (as opposed to a data
//! *violation*, which is [`crate::constraint`]'s job):
//!
//! - an **equivalent** index/constraint already covers the same schema — Neo4j
//!   `Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists`;
//! - the requested **name** is already used by another index/constraint — Neo4j
//!   `Neo.ClientError.Schema.IndexWithNameAlreadyExists`;
//! - a `DROP INDEX <name>` names an index that does not exist (and no `IF EXISTS` was given) — Neo4j
//!   `Neo.ClientError.Schema.IndexDropFailed`.
//!
//! # Error class — carried across the `GraphusError` boundary by a sentinel
//!
//! Each of these is a schema error the Neo4j driver ecosystem expects under the `Neo.ClientError.Schema.*`
//! classification. To carry the precise leaf class across the cross-crate `#[non_exhaustive]`
//! [`GraphusError`] boundary **without** widening the enum, the message is prefixed with the stable
//! sentinel [`SCHEMA_RULE_ERROR_PREFIX`] followed by `<leaf code>\u{1f}<human message>`. The Bolt /
//! REST error renderers detect that prefix, split off the leaf code and emit it, stripping the
//! sentinel + code from the wire message — exactly the mechanism [`crate::constraint`] uses for a
//! constraint *violation*. This mirrors the existing pattern with a single new sentinel.

pub use graphus_core::SCHEMA_RULE_ERROR_PREFIX;
use graphus_core::{GraphusError, SCHEMA_RULE_ERROR_SEP};

/// Neo4j status code: an index/constraint equivalent to the requested one already exists.
const CODE_EQUIVALENT_EXISTS: &str = "Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists";
/// Neo4j status code: an index with the requested name already exists.
const CODE_INDEX_NAME_EXISTS: &str = "Neo.ClientError.Schema.IndexWithNameAlreadyExists";
/// Neo4j status code: a `DROP INDEX <name>` failed because no such index exists.
const CODE_INDEX_DROP_FAILED: &str = "Neo.ClientError.Schema.IndexDropFailed";
/// Neo4j status code: a constraint with the requested name already exists (`rmp` #638).
const CODE_CONSTRAINT_NAME_EXISTS: &str = "Neo.ClientError.Schema.ConstraintWithNameAlreadyExists";

/// A schema-rule declaration error (`rmp` task #624), carrying the precise Neo4j leaf `code` and a
/// human `message`. Rendered onto the wire as a [`GraphusError::Runtime`] via [`into_error`](Self::into_error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaRuleError {
    /// The verbatim `Neo.ClientError.Schema.*` leaf code the driver ecosystem asserts.
    pub code: &'static str,
    /// The human-readable description (without the wire sentinel or code).
    pub message: String,
}

impl SchemaRuleError {
    /// The full message **with** the [`SCHEMA_RULE_ERROR_PREFIX`] sentinel and the leaf code, so the
    /// Bolt / REST renderers classify it as the precise `Neo.ClientError.Schema.*` leaf.
    #[must_use]
    pub fn wire_message(&self) -> String {
        format!(
            "{SCHEMA_RULE_ERROR_PREFIX}{}{SCHEMA_RULE_ERROR_SEP}{}",
            self.code, self.message
        )
    }

    /// The error as a crate-wide runtime error, ready to return from a coordinator DDL path. The
    /// message carries the wire sentinel + leaf code so the wire layer renders the precise schema class.
    #[must_use]
    pub fn into_error(self) -> GraphusError {
        GraphusError::Runtime(self.wire_message())
    }
}

/// A `CREATE INDEX` whose covered `(label, property)` is already indexed
/// (`Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists`). This is the error a plain
/// (no `IF NOT EXISTS`) create raises when an equivalent index exists (`rmp` task #624).
#[must_use]
pub fn equivalent_index_exists(label: &str, property: &str) -> GraphusError {
    SchemaRuleError {
        code: CODE_EQUIVALENT_EXISTS,
        message: format!(
            "An equivalent index already exists for (:{label} {{{property}}}). \
             Use `IF NOT EXISTS` to make the create idempotent."
        ),
    }
    .into_error()
}

/// A `CREATE INDEX FOR ()-[r:TYPE]-() ON (r.property)` whose covered `(type, property)` is already
/// indexed (`Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists`) (`rmp` task #646). The
/// relationship analogue of [`equivalent_index_exists`], rendering the relationship pattern syntax.
#[must_use]
pub fn equivalent_rel_index_exists(rel_type: &str, property: &str) -> GraphusError {
    SchemaRuleError {
        code: CODE_EQUIVALENT_EXISTS,
        message: format!(
            "An equivalent index already exists for ()-[:{rel_type} {{{property}}}]-(). \
             Use `IF NOT EXISTS` to make the create idempotent."
        ),
    }
    .into_error()
}

/// A `CREATE INDEX FOR (n:Label) ON (n.a, n.b, …)` whose covered `(label, ordered property tuple)` is
/// already indexed by an equivalent composite index
/// (`Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists`) (`rmp` task #657). The composite
/// analogue of [`equivalent_index_exists`]; the property order is significant.
#[must_use]
pub fn equivalent_composite_index_exists(label: &str, properties: &[String]) -> GraphusError {
    SchemaRuleError {
        code: CODE_EQUIVALENT_EXISTS,
        message: format!(
            "An equivalent index already exists for (:{label} {{{}}}). \
             Use `IF NOT EXISTS` to make the create idempotent.",
            properties.join(", ")
        ),
    }
    .into_error()
}

/// A `CREATE INDEX <name>` whose `name` is already used by another index or constraint
/// (`Neo.ClientError.Schema.IndexWithNameAlreadyExists`). Index/constraint names are unique across
/// every schema catalog (`rmp` task #624).
#[must_use]
pub fn index_name_in_use(name: &str) -> GraphusError {
    SchemaRuleError {
        code: CODE_INDEX_NAME_EXISTS,
        message: format!(
            "There already exists an index or constraint named `{name}`. \
             Use `IF NOT EXISTS` to make the create idempotent."
        ),
    }
    .into_error()
}

/// A `CREATE CONSTRAINT <name>` whose `name` is already used by another constraint, with no
/// `IF NOT EXISTS` (`Neo.ClientError.Schema.ConstraintWithNameAlreadyExists`) (`rmp` #638). Names are
/// unique across every schema catalog; a name colliding with an **index** raises
/// [`index_name_in_use`] instead (that check runs first in the create path).
#[must_use]
pub fn constraint_name_in_use(name: &str) -> GraphusError {
    SchemaRuleError {
        code: CODE_CONSTRAINT_NAME_EXISTS,
        message: format!(
            "There already exists a constraint named `{name}`. \
             Use `IF NOT EXISTS` to make the create idempotent, or `OR REPLACE` to replace it."
        ),
    }
    .into_error()
}

/// A `CREATE CONSTRAINT` whose covered schema (label/type + property tuple + kind) is already
/// constrained by an equivalent rule, with no `IF NOT EXISTS`
/// (`Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists`) (`rmp` #638).
#[must_use]
pub fn equivalent_constraint_exists(covering: &str, properties: &[&str]) -> GraphusError {
    SchemaRuleError {
        code: CODE_EQUIVALENT_EXISTS,
        message: format!(
            "An equivalent constraint already exists for `{covering}` on ({}). \
             Use `IF NOT EXISTS` to make the create idempotent.",
            properties.join(", ")
        ),
    }
    .into_error()
}

/// A `DROP INDEX <name>` that names an index that does not exist, with no `IF EXISTS`
/// (`Neo.ClientError.Schema.IndexDropFailed`) (`rmp` task #624).
#[must_use]
pub fn index_drop_not_found(name: &str) -> GraphusError {
    SchemaRuleError {
        code: CODE_INDEX_DROP_FAILED,
        message: format!(
            "Unable to drop index named `{name}`: no such index exists. \
             Use `IF EXISTS` to make the drop idempotent."
        ),
    }
    .into_error()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_message_carries_prefix_code_and_human_parts() {
        let e = SchemaRuleError {
            code: CODE_INDEX_NAME_EXISTS,
            message: "already exists".to_owned(),
        };
        let w = e.wire_message();
        assert!(w.starts_with(SCHEMA_RULE_ERROR_PREFIX));
        // After the sentinel: `<code>\u{1f}<message>`.
        let rest = &w[SCHEMA_RULE_ERROR_PREFIX.len()..];
        let (code, human) = rest.split_once(SCHEMA_RULE_ERROR_SEP).unwrap();
        assert_eq!(code, CODE_INDEX_NAME_EXISTS);
        assert_eq!(human, "already exists");
    }

    #[test]
    fn constructors_are_runtime_errors_with_the_expected_leaf_codes() {
        for (err, code) in [
            (
                equivalent_index_exists("Person", "name"),
                CODE_EQUIVALENT_EXISTS,
            ),
            (index_name_in_use("ix"), CODE_INDEX_NAME_EXISTS),
            (index_drop_not_found("ix"), CODE_INDEX_DROP_FAILED),
        ] {
            match err {
                GraphusError::Runtime(m) => {
                    let rest = m.strip_prefix(SCHEMA_RULE_ERROR_PREFIX).expect("sentinel");
                    let (leaf, _) = rest.split_once(SCHEMA_RULE_ERROR_SEP).expect("separator");
                    assert_eq!(leaf, code);
                }
                other => panic!("expected Runtime, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_user_name_cannot_inject_a_status_code() {
        // A malicious index name containing the separator lands entirely in the HUMAN segment: the
        // renderer splits on the FIRST separator (ours), so the code segment stays our fixed leaf.
        let err = index_name_in_use("evil\u{1f}Neo.Injected.Code");
        let GraphusError::Runtime(m) = err else {
            panic!("expected Runtime")
        };
        let rest = m.strip_prefix(SCHEMA_RULE_ERROR_PREFIX).unwrap();
        let (leaf, _human) = rest.split_once(SCHEMA_RULE_ERROR_SEP).unwrap();
        assert_eq!(
            leaf, CODE_INDEX_NAME_EXISTS,
            "the injected code never becomes the leaf"
        );
    }
}
