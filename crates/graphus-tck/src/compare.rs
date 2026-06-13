//! Matching a parsed [`ExpectedValue`] against the value the engine
//! actually produced, and deciding result-set assertions (`tck/README.adoc`).
//!
//! # The two value spaces
//!
//! The engine produces [`RowValue`](graphus_cypher::RowValue)s: a property
//! [`Value`], or an entity *reference* whose labels/type/properties are read
//! lazily through the [`GraphAccess`](graphus_cypher::graph_access::GraphAccess) seam. The runner
//! resolves each reference into a [`Concrete`] **while the statement seam is still live** (before
//! commit), because the reference is meaningless afterwards. [`Concrete`] is therefore a fully
//! self-contained snapshot of a result cell: a scalar/list/map `Value`, or a node `(labels, props)`,
//! or a relationship `(type, props)`, or a path.
//!
//! # The comparison
//!
//! - Scalars / lists / maps are matched by converting the [`ExpectedValue`] into a [`Value`] and
//!   asking the **engine's own** [`equivalent`] — so `1 ≡ 1.0`, `NaN ≡ NaN`, `null ≡ null` all behave
//!   exactly as the engine defines them (`CLAUDE.md`: never reinvent the value semantics).
//! - Nodes match when labels are equal **as sets** and properties match **as a map** (same keys,
//!   each value matched recursively). Relationships match on type + properties-as-map. Paths match
//!   when the node/relationship sequence and per-step direction line up.
//!
//! A [`Concrete::List`]/[`Concrete::Map`] can itself contain entity snapshots (e.g.
//! `RETURN collect(n)` yields a list of nodes), so the recursion crosses the `Value`/structural
//! boundary: a list/map expected value is matched element-wise against a concrete list/map, falling
//! back to scalar equivalence only when both sides are pure property values.

use std::collections::BTreeSet;

use graphus_core::Value;
use graphus_cypher::equivalent;

use crate::value::{ExpectedNode, ExpectedPath, ExpectedRel, ExpectedValue};

/// A fully-resolved result cell: structural references have been read through the graph seam into
/// owned snapshots, so the value no longer depends on a live transaction.
#[derive(Debug, Clone, PartialEq)]
pub enum Concrete {
    /// A property value (scalar, temporal, null) — or a list/map of *pure* property values.
    Value(Value),
    /// A node snapshot: its labels and its properties (key → value).
    Node {
        /// The node's labels (compared as a set).
        labels: Vec<String>,
        /// The node's properties (compared as a map).
        properties: Vec<(String, Value)>,
    },
    /// A relationship snapshot: its single type and its properties.
    Rel {
        /// The relationship type (compared for equality).
        rel_type: String,
        /// The relationship's properties (compared as a map).
        properties: Vec<(String, Value)>,
    },
    /// A list whose elements may themselves be structural (e.g. `collect(n)`).
    List(Vec<Concrete>),
    /// A map whose values may themselves be structural.
    Map(Vec<(String, Concrete)>),
    /// A path: an alternating node/relationship sequence with per-step direction.
    Path(ConcretePath),
}

/// A resolved path: a start node followed by `(forward, rel, node)` hops.
#[derive(Debug, Clone, PartialEq)]
pub struct ConcretePath {
    /// The first node of the path.
    pub start: ConcreteNode,
    /// The subsequent hops.
    pub steps: Vec<ConcretePathStep>,
}

/// A node as it appears inside a [`ConcretePath`].
#[derive(Debug, Clone, PartialEq)]
pub struct ConcreteNode {
    /// The node's labels (set comparison).
    pub labels: Vec<String>,
    /// The node's properties (map comparison).
    pub properties: Vec<(String, Value)>,
}

/// One hop of a [`ConcretePath`].
#[derive(Debug, Clone, PartialEq)]
pub struct ConcretePathStep {
    /// `true` if traversed start→end relative to the path's left-to-right reading.
    pub forward: bool,
    /// The traversed relationship's type.
    pub rel_type: String,
    /// The traversed relationship's properties.
    pub rel_properties: Vec<(String, Value)>,
    /// The node reached by this hop.
    pub node: ConcreteNode,
}

/// Returns `true` if the engine's resolved cell `actual` matches the TCK `expected` value, with
/// **order-significant** list comparison (the default for `… in any order` / `… in order`).
#[must_use]
pub fn matches(expected: &ExpectedValue, actual: &Concrete) -> bool {
    matches_with(expected, actual, false)
}

/// As [`matches`], but when `ignore_list_order` is set the elements *within* a list cell are matched
/// as a bag (order-insensitive) — the `… (ignoring element order for lists)` assertion variant. The
/// flag is propagated into nested lists/maps so it holds at every depth.
#[must_use]
pub fn matches_with(expected: &ExpectedValue, actual: &Concrete, ignore_list_order: bool) -> bool {
    match (expected, actual) {
        // ---- structural: node / rel / path ----------------------------------------------------
        (ExpectedValue::Node(en), Concrete::Node { labels, properties }) => {
            node_matches(en, labels, properties)
        }
        (
            ExpectedValue::Relationship(er),
            Concrete::Rel {
                rel_type,
                properties,
            },
        ) => rel_matches(er, rel_type, properties),
        (ExpectedValue::Path(ep), Concrete::Path(ap)) => path_matches(ep, ap),

        // ---- containers that may straddle the value/structural boundary ------------------------
        (ExpectedValue::List(exs), Concrete::List(acs)) => {
            list_matches(exs, acs, ignore_list_order, |e, a| {
                matches_with(e, a, ignore_list_order)
            })
        }
        (ExpectedValue::List(exs), Concrete::Value(Value::List(avs))) => {
            // A pure-property list on the actual side: lift each element to a `Concrete::Value`.
            let acs: Vec<Concrete> = avs.iter().cloned().map(Concrete::Value).collect();
            list_matches(exs, &acs, ignore_list_order, |e, a| {
                matches_with(e, a, ignore_list_order)
            })
        }
        (ExpectedValue::Map(exs), Concrete::Map(acs)) => map_matches(exs, acs, ignore_list_order),
        (ExpectedValue::Map(exs), Concrete::Value(Value::Map(avs))) => {
            map_matches_values(exs, avs, ignore_list_order)
        }

        // ---- pure property values: defer to the engine's equivalence ---------------------------
        (_, Concrete::Value(av)) => match expected_to_value(expected) {
            // TCK feature files write temporal cells as their canonical ISO-8601 strings
            // (`| d | '1984-10-11' |`), so a temporal actual matches the expected string of its
            // ISO rendering (the engine's `Display` impls are pinned to the TCK formats).
            Some(Value::String(s)) if temporal_iso(av).is_some() => {
                temporal_iso(av).is_some_and(|iso| iso == s)
            }
            Some(ev) => equivalent(av, &ev),
            // A structural expected value can never equal a pure property value.
            None => false,
        },

        // Any other cross-kind pairing is a non-match.
        _ => false,
    }
}

/// Matches an expected list against an actual list, either positionally or — when `ignore_order` is
/// set — as a bag (each expected element matched to a distinct actual element via the same
/// backtracking bipartite matching used for unordered rows). `cell` compares a single element pair.
fn list_matches(
    exs: &[ExpectedValue],
    acs: &[Concrete],
    ignore_order: bool,
    cell: impl Fn(&ExpectedValue, &Concrete) -> bool,
) -> bool {
    if exs.len() != acs.len() {
        return false;
    }
    if !ignore_order {
        return exs.iter().zip(acs).all(|(e, a)| cell(e, a));
    }
    let candidates: Vec<Vec<usize>> = exs
        .iter()
        .map(|e| {
            acs.iter()
                .enumerate()
                .filter(|(_, a)| cell(e, a))
                .map(|(j, _)| j)
                .collect()
        })
        .collect();
    bipartite_perfect_match(&candidates, acs.len())
}

/// The canonical ISO-8601 rendering of a temporal [`Value`], or `None` for non-temporals.
fn temporal_iso(v: &Value) -> Option<String> {
    match v {
        Value::Date(d) => Some(d.to_string()),
        Value::LocalTime(t) => Some(t.to_string()),
        Value::ZonedTime(t) => Some(t.to_string()),
        Value::LocalDateTime(dt) => Some(dt.to_string()),
        Value::ZonedDateTime(z) => Some(z.to_string()),
        Value::Duration(d) => Some(d.to_string()),
        _ => None,
    }
}

/// Converts an [`ExpectedValue`] to a [`Value`] **iff** it is a pure property value (scalar,
/// temporal-free list/map of property values); structural elements return `None`.
///
/// Lists/maps convert only when **every** element is itself convertible — a list containing a node
/// literal is structural and is matched by [`matches`], not here.
fn expected_to_value(expected: &ExpectedValue) -> Option<Value> {
    match expected {
        ExpectedValue::Null => Some(Value::Null),
        ExpectedValue::Boolean(b) => Some(Value::Boolean(*b)),
        ExpectedValue::Integer(i) => Some(Value::Integer(*i)),
        ExpectedValue::Float(f) => Some(Value::Float(*f)),
        ExpectedValue::String(s) => Some(Value::String(s.clone())),
        ExpectedValue::List(items) => items
            .iter()
            .map(expected_to_value)
            .collect::<Option<Vec<_>>>()
            .map(Value::List),
        ExpectedValue::Map(entries) => entries
            .iter()
            .map(|(k, v)| expected_to_value(v).map(|vv| (k.clone(), vv)))
            .collect::<Option<Vec<_>>>()
            .map(Value::Map),
        ExpectedValue::Node(_) | ExpectedValue::Relationship(_) | ExpectedValue::Path(_) => None,
    }
}

/// A node matches when labels are equal **as sets** and properties match **as a map**.
fn node_matches(en: &ExpectedNode, labels: &[String], properties: &[(String, Value)]) -> bool {
    let expected_labels: BTreeSet<&str> = en.labels.iter().map(String::as_str).collect();
    let actual_labels: BTreeSet<&str> = labels.iter().map(String::as_str).collect();
    expected_labels == actual_labels && props_match(&en.properties, properties)
}

/// A relationship matches when its type is equal and its properties match as a map.
fn rel_matches(er: &ExpectedRel, rel_type: &str, properties: &[(String, Value)]) -> bool {
    er.rel_type == rel_type && props_match(&er.properties, properties)
}

/// A path matches when start node, each step's direction + relationship, and each reached node line
/// up in order.
fn path_matches(ep: &ExpectedPath, ap: &ConcretePath) -> bool {
    if ep.steps.len() != ap.steps.len() {
        return false;
    }
    if !concrete_node_matches(&ep.start, &ap.start) {
        return false;
    }
    ep.steps.iter().zip(&ap.steps).all(|(es, as_)| {
        es.forward == as_.forward
            && rel_matches(&es.rel, &as_.rel_type, &as_.rel_properties)
            && concrete_node_matches(&es.node, &as_.node)
    })
}

/// A path-internal node matches an expected node literal (labels as set, properties as map).
fn concrete_node_matches(en: &ExpectedNode, an: &ConcreteNode) -> bool {
    let expected_labels: BTreeSet<&str> = en.labels.iter().map(String::as_str).collect();
    let actual_labels: BTreeSet<&str> = an.labels.iter().map(String::as_str).collect();
    expected_labels == actual_labels && props_match(&en.properties, &an.properties)
}

/// Property-map match where the actual side is pure `Value`s (node / rel property sets).
///
/// Same key set; each value compared via [`matches`] against a `Concrete::Value` so a property whose
/// value is itself a list/map of scalars still routes through engine equivalence.
fn props_match(expected: &[(String, ExpectedValue)], actual: &[(String, Value)]) -> bool {
    props_match_ordered(expected, actual, false)
}

/// As [`props_match`], threading `ignore_list_order` into each value comparison.
fn props_match_ordered(
    expected: &[(String, ExpectedValue)],
    actual: &[(String, Value)],
    ignore_list_order: bool,
) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    expected.iter().all(|(k, ev)| {
        actual
            .iter()
            .find(|(ak, _)| ak == k)
            .is_some_and(|(_, av)| {
                matches_with(ev, &Concrete::Value(av.clone()), ignore_list_order)
            })
    })
}

/// Map match where the actual side is a [`Concrete::Map`] (values may be structural).
fn map_matches(
    expected: &[(String, ExpectedValue)],
    actual: &[(String, Concrete)],
    ignore_list_order: bool,
) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    expected.iter().all(|(k, ev)| {
        actual
            .iter()
            .find(|(ak, _)| ak == k)
            .is_some_and(|(_, av)| matches_with(ev, av, ignore_list_order))
    })
}

/// Map match where the actual side is a pure-`Value` map.
fn map_matches_values(
    expected: &[(String, ExpectedValue)],
    actual: &[(String, Value)],
    ignore_list_order: bool,
) -> bool {
    props_match_ordered(expected, actual, ignore_list_order)
}

/// The outcome of a result-set comparison: success, or a human description of the first mismatch.
pub type RowSetResult = Result<(), String>;

/// Asserts an **ordered** result set: row `i` of `expected` must match row `i` of `actual`,
/// positionally (`Then the result should be, in order:`).
///
/// # Errors
///
/// Returns a description if the row counts differ or any positional row fails to match.
pub fn assert_ordered(
    expected: &[Vec<ExpectedValue>],
    actual: &[Vec<Concrete>],
    ignore_list_order: bool,
) -> RowSetResult {
    if expected.len() != actual.len() {
        return Err(format!(
            "row count mismatch: expected {}, got {}",
            expected.len(),
            actual.len()
        ));
    }
    for (i, (erow, arow)) in expected.iter().zip(actual).enumerate() {
        if !row_matches(erow, arow, ignore_list_order) {
            return Err(format!(
                "ordered row {i} mismatch:\n  expected {erow:?}\n  got      {arow:?}"
            ));
        }
    }
    Ok(())
}

/// Asserts an **unordered** (bag / multiset) result set: every expected row matches a *distinct*
/// actual row and vice versa (`Then the result should be, in any order:`).
///
/// Uses greedy matching with backtracking over a small candidate set (TCK result tables are tiny, so
/// the worst-case cost is irrelevant); a row may match several candidates, so a naive greedy pass
/// can fail spuriously — the backtracking `bipartite_perfect_match` avoids that.
///
/// # Errors
///
/// Returns a description if counts differ or no perfect one-to-one matching exists.
pub fn assert_unordered(
    expected: &[Vec<ExpectedValue>],
    actual: &[Vec<Concrete>],
    ignore_list_order: bool,
) -> RowSetResult {
    if expected.len() != actual.len() {
        return Err(format!(
            "row count mismatch: expected {}, got {}",
            expected.len(),
            actual.len()
        ));
    }
    // Adjacency: expected row i can match actual rows in `candidates[i]`.
    let candidates: Vec<Vec<usize>> = expected
        .iter()
        .map(|erow| {
            actual
                .iter()
                .enumerate()
                .filter(|(_, arow)| row_matches(erow, arow, ignore_list_order))
                .map(|(j, _)| j)
                .collect()
        })
        .collect();

    if bipartite_perfect_match(&candidates, actual.len()) {
        Ok(())
    } else {
        Err(format!(
            "no one-to-one match between expected and actual rows:\n  expected {expected:?}\n  got      {actual:?}"
        ))
    }
}

/// Whether the two rows match cell-by-cell, positionally (columns are already aligned by header).
fn row_matches(expected: &[ExpectedValue], actual: &[Concrete], ignore_list_order: bool) -> bool {
    expected.len() == actual.len()
        && expected
            .iter()
            .zip(actual)
            .all(|(e, a)| matches_with(e, a, ignore_list_order))
}

/// Hopcroft–Karp-style augmenting-path matching: returns `true` iff every left vertex (expected row)
/// can be matched to a distinct right vertex (actual row) given the `candidates` adjacency. With
/// equal counts on both sides a perfect left-matching is a perfect matching.
fn bipartite_perfect_match(candidates: &[Vec<usize>], right_count: usize) -> bool {
    // `match_right[j] = Some(i)` means actual row j is currently assigned to expected row i.
    let mut match_right: Vec<Option<usize>> = vec![None; right_count];
    for left in 0..candidates.len() {
        let mut seen = vec![false; right_count];
        if !augment(left, candidates, &mut match_right, &mut seen) {
            return false;
        }
    }
    true
}

/// Tries to assign expected row `left` to some actual row, freeing previous assignments along an
/// augmenting path (standard Kuhn's algorithm step).
fn augment(
    left: usize,
    candidates: &[Vec<usize>],
    match_right: &mut [Option<usize>],
    seen: &mut [bool],
) -> bool {
    for &right in &candidates[left] {
        if seen[right] {
            continue;
        }
        seen[right] = true;
        let free_or_reassignable = match match_right[right] {
            None => true,
            Some(other_left) => augment(other_left, candidates, match_right, seen),
        };
        if free_or_reassignable {
            match_right[right] = Some(left);
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(value: Value) -> Concrete {
        Concrete::Value(value)
    }
    fn ev_int(n: i64) -> ExpectedValue {
        ExpectedValue::Integer(n)
    }

    #[test]
    fn scalar_equivalence_uses_the_engine() {
        // 1 ≡ 1.0 via the engine's equivalence.
        assert!(matches(&ev_int(1), &v(Value::Float(1.0))));
        assert!(matches(&ExpectedValue::Float(1.0), &v(Value::Integer(1))));
        assert!(!matches(&ev_int(1), &v(Value::Integer(2))));
        // null ≡ null, NaN ≡ NaN.
        assert!(matches(&ExpectedValue::Null, &v(Value::Null)));
        assert!(matches(
            &ExpectedValue::Float(f64::NAN),
            &v(Value::Float(f64::NAN))
        ));
    }

    #[test]
    fn node_labels_are_a_set_and_props_a_map() {
        let expected = ExpectedValue::Node(ExpectedNode {
            labels: vec!["B".to_owned(), "A".to_owned()],
            properties: vec![("n".to_owned(), ev_int(1))],
        });
        let actual = Concrete::Node {
            labels: vec!["A".to_owned(), "B".to_owned()],
            properties: vec![("n".to_owned(), Value::Integer(1))],
        };
        assert!(matches(&expected, &actual), "label order is irrelevant");

        // A missing label fails.
        let actual_missing = Concrete::Node {
            labels: vec!["A".to_owned()],
            properties: vec![("n".to_owned(), Value::Integer(1))],
        };
        assert!(!matches(&expected, &actual_missing));
    }

    #[test]
    fn rel_matches_type_and_props() {
        let expected = ExpectedValue::Relationship(ExpectedRel {
            rel_type: "KNOWS".to_owned(),
            properties: vec![("since".to_owned(), ev_int(1999))],
        });
        let ok = Concrete::Rel {
            rel_type: "KNOWS".to_owned(),
            properties: vec![("since".to_owned(), Value::Integer(1999))],
        };
        assert!(matches(&expected, &ok));
        let wrong_type = Concrete::Rel {
            rel_type: "LIKES".to_owned(),
            properties: vec![("since".to_owned(), Value::Integer(1999))],
        };
        assert!(!matches(&expected, &wrong_type));
    }

    #[test]
    fn list_of_nodes_matches_structurally() {
        let expected = ExpectedValue::List(vec![
            ExpectedValue::Node(ExpectedNode {
                labels: vec!["A".to_owned()],
                properties: vec![],
            }),
            ExpectedValue::Node(ExpectedNode::default()),
        ]);
        let actual = Concrete::List(vec![
            Concrete::Node {
                labels: vec!["A".to_owned()],
                properties: vec![],
            },
            Concrete::Node {
                labels: vec![],
                properties: vec![],
            },
        ]);
        assert!(matches(&expected, &actual));
    }

    #[test]
    fn pure_value_list_matches_via_equivalence() {
        let expected = ExpectedValue::List(vec![ev_int(1), ev_int(2), ev_int(3)]);
        let actual = v(Value::List(vec![
            Value::Integer(1),
            Value::Integer(2),
            Value::Integer(3),
        ]));
        assert!(matches(&expected, &actual));
    }

    #[test]
    fn ordered_rows_are_positional() {
        let expected = vec![vec![ev_int(1)], vec![ev_int(2)]];
        let actual = vec![vec![v(Value::Integer(1))], vec![v(Value::Integer(2))]];
        assert!(assert_ordered(&expected, &actual, false).is_ok());
        // Swapped order fails for an ordered assertion.
        let swapped = vec![vec![v(Value::Integer(2))], vec![v(Value::Integer(1))]];
        assert!(assert_ordered(&expected, &swapped, false).is_err());
    }

    #[test]
    fn unordered_rows_are_a_bag() {
        let expected = vec![vec![ev_int(1)], vec![ev_int(2)]];
        // Reversed order is fine for a bag.
        let actual = vec![vec![v(Value::Integer(2))], vec![v(Value::Integer(1))]];
        assert!(assert_unordered(&expected, &actual, false).is_ok());
        // A duplicate where the expected had distinct values fails.
        let dup = vec![vec![v(Value::Integer(1))], vec![v(Value::Integer(1))]];
        assert!(assert_unordered(&expected, &dup, false).is_err());
    }

    #[test]
    fn unordered_bag_needs_backtracking() {
        // Expected rows both match actual row 0, but only one matches actual row 1; a naive greedy
        // pass that assigns expected[0]→actual[0] would then fail expected[1]. Backtracking succeeds.
        let expected = vec![vec![ev_int(1)], vec![ev_int(1), ev_int(2)]];
        let actual = vec![
            vec![v(Value::Integer(1)), v(Value::Integer(2))],
            vec![v(Value::Integer(1))],
        ];
        // Note: row arities differ, so expected[0] (arity 1) only matches actual[1] (arity 1), and
        // expected[1] (arity 2) only matches actual[0]. This is the unambiguous case; assert it.
        assert!(assert_unordered(&expected, &actual, false).is_ok());
    }

    #[test]
    fn duplicate_rows_match_as_multiset() {
        // Two identical expected rows require two distinct identical actual rows.
        let expected = vec![vec![ev_int(7)], vec![ev_int(7)]];
        let actual = vec![vec![v(Value::Integer(7))], vec![v(Value::Integer(7))]];
        assert!(assert_unordered(&expected, &actual, false).is_ok());
        let only_one = vec![vec![v(Value::Integer(7))], vec![v(Value::Integer(8))]];
        assert!(assert_unordered(&expected, &only_one, false).is_err());
    }
}
