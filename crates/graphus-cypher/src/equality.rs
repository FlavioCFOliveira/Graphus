//! The Cypher `=` / `<>` equality operator and the `IN` list-membership predicate
//! (`04-technical-design.md` §7.2; openCypher CIP2016-06-14 §Equality, the TCK-enforced source).
//!
//! Cypher equality is **three-valued** ([`crate::ternary::Ternary`]) and is *not* the structural
//! `PartialEq` derived on [`Value`], nor the grouping equivalence in [`crate::equivalence`]. The
//! distinguishing rules this module enforces, verbatim from the CIP where quoted:
//!
//! - **`NULL` propagates.** If either operand is `null`, `a = b` is `NULL` (so `1 = null` → `NULL`
//!   and `null = null` → `NULL`). `NULL` takes precedence over every other rule below.
//! - **`NaN` makes `=` false.** Quoting the CIP §Equality: *"`a = b` is always `false` and `a <> b`
//!   is always `true` when `b` is `NaN`."* So `NaN = NaN` → `FALSE` (and `1 = NaN` → `FALSE`). We
//!   apply it symmetrically — `NaN` on *either* side yields `FALSE` — since `=` is symmetric and a
//!   non-`null`, non-`NaN` value compared to `NaN` is likewise unequal.
//! - **Signed zero is equal.** `-0.0 = +0.0` → `TRUE` (IEEE/openCypher equality; contrast the
//!   *ordering* rule where `-0.0 < +0.0`, see [`crate::ordering`]).
//! - **Numbers compare numerically** across `INTEGER`/`FLOAT` (`1 = 1.0` → `TRUE`).
//! - **Lists and maps compare deeply and three-valuedly.** A definite length / key-set mismatch is
//!   `FALSE`; otherwise `NULL` from any element comparison propagates, and only an all-`TRUE`
//!   comparison is `TRUE`.
//!
//! `IN` is built on `=` and is likewise three-valued ([`is_in`]).

use graphus_core::Value;

use crate::ternary::Ternary;

/// Cypher equality `a = b`, three-valued (CIP §Equality).
///
/// Returns [`Ternary::Null`] if either operand is `null`; [`Ternary::False`] if either operand is a
/// `NaN` float (the CIP's "`=` is always false when `b` is NaN", applied symmetrically); otherwise
/// the deep value equality as [`Ternary::True`] / [`Ternary::False`] (with `null` *inside* nested
/// lists/maps still able to make the result `NULL`).
pub fn equals(a: &Value, b: &Value) -> Ternary {
    // NULL propagation dominates everything (1 = null → NULL, null = null → NULL).
    if a.is_null() || b.is_null() {
        return Ternary::Null;
    }
    // NaN: `=` is always FALSE (CIP §Equality), applied symmetrically.
    if is_nan(a) || is_nan(b) {
        return Ternary::False;
    }
    deep_equals(a, b)
}

/// Cypher inequality `a <> b`, the logical negation of [`equals`] in three-valued logic.
///
/// In particular `NaN <> NaN` → `TRUE` and `null <> x` → `NULL` (CIP §Equality).
pub fn not_equals(a: &Value, b: &Value) -> Ternary {
    !equals(a, b)
}

/// Returns `true` if `v` is a `NaN` float.
fn is_nan(v: &Value) -> bool {
    matches!(v, Value::Float(f) if f.is_nan())
}

/// Deep three-valued equality for two **non-null, non-NaN-at-the-top** values.
///
/// Numbers compare numerically; strings/bytes/booleans/temporals by value; lists and maps element-
/// by-element with three-valued propagation. Nested `null`/`NaN` are handled by recursing through
/// [`equals`] for list/map elements (so an inner `null` can still surface as `NULL`).
fn deep_equals(a: &Value, b: &Value) -> Ternary {
    match (a, b) {
        (Value::Boolean(x), Value::Boolean(y)) => Ternary::from_bool(x == y),
        (Value::String(x), Value::String(y)) => Ternary::from_bool(x == y),
        (Value::Bytes(x), Value::Bytes(y)) => Ternary::from_bool(x == y),
        // Numbers compare numerically across INTEGER/FLOAT; -0.0 == +0.0 (Rust `==` already does
        // this for f64), and neither is NaN here (filtered in `equals`).
        (Value::Integer(_) | Value::Float(_), Value::Integer(_) | Value::Float(_)) => {
            Ternary::from_bool(num_f64(a) == num_f64(b))
        }
        (Value::List(x), Value::List(y)) => list_equals(x, y),
        (Value::Map(x), Value::Map(y)) => map_equals(x, y),
        // Same-class temporals use their structural (component) equality, which is exactly Cypher
        // temporal equality at nanosecond resolution.
        (Value::Date(x), Value::Date(y)) => Ternary::from_bool(x == y),
        (Value::LocalTime(x), Value::LocalTime(y)) => Ternary::from_bool(x == y),
        (Value::ZonedTime(x), Value::ZonedTime(y)) => Ternary::from_bool(x == y),
        (Value::LocalDateTime(x), Value::LocalDateTime(y)) => Ternary::from_bool(x == y),
        (Value::ZonedDateTime(x), Value::ZonedDateTime(y)) => Ternary::from_bool(x == y),
        (Value::Duration(x), Value::Duration(y)) => Ternary::from_bool(x == y),
        // Two points are equal iff same CRS and equal coordinates (openCypher; `rmp` task #73).
        // `Point::value_eq` is the CRS-aware coordinate comparison; a cross-CRS pair is `false`. (A
        // `NaN` coordinate is already excluded — `is_nan` in `equals` makes a `NaN`-bearing operand
        // `FALSE` before reaching here.)
        (Value::Point(x), Value::Point(y)) => Ternary::from_bool(x.value_eq(y)),
        // Different value classes are never equal (e.g. a string is not a number).
        _ => Ternary::False,
    }
}

/// The numeric value of an `INTEGER`/`FLOAT` as `f64`.
fn num_f64(v: &Value) -> f64 {
    match v {
        Value::Integer(i) => *i as f64,
        Value::Float(f) => *f,
        _ => unreachable!("num_f64 on a non-number"),
    }
}

/// Three-valued list equality.
///
/// A definite length mismatch is `FALSE`. Otherwise compare element-wise with [`equals`]: any
/// `FALSE` makes the whole list `FALSE`; otherwise any `NULL` makes it `NULL`; only all-`TRUE` is
/// `TRUE` (CIP §Equality, list comparison).
fn list_equals(x: &[Value], y: &[Value]) -> Ternary {
    if x.len() != y.len() {
        return Ternary::False;
    }
    let mut acc = Ternary::True;
    for (xe, ye) in x.iter().zip(y.iter()) {
        match equals(xe, ye) {
            Ternary::False => return Ternary::False,
            Ternary::Null => acc = Ternary::Null,
            Ternary::True => {}
        }
    }
    acc
}

/// Three-valued map equality.
///
/// A differing key *set* is a definite `FALSE`. Otherwise compare the values at each shared key
/// with [`equals`] and combine like [`list_equals`] (any `FALSE` → `FALSE`, else any `NULL` →
/// `NULL`, else `TRUE`). Key order is irrelevant.
fn map_equals(x: &[(String, Value)], y: &[(String, Value)]) -> Ternary {
    if x.len() != y.len() {
        return Ternary::False;
    }
    let mut acc = Ternary::True;
    for (k, xv) in x {
        match y.iter().find(|(yk, _)| yk == k) {
            None => return Ternary::False, // key absent on the other side
            Some((_, yv)) => match equals(xv, yv) {
                Ternary::False => return Ternary::False,
                Ternary::Null => acc = Ternary::Null,
                Ternary::True => {}
            },
        }
    }
    acc
}

/// The Cypher `IN` predicate: `value IN list`, three-valued (CIP §Equality, list membership).
///
/// `IN` is defined by the CIP as the **`OR`-fold of `=`** over the elements, and the openCypher TCK
/// (`expressions/list/List5.feature`) pins the resulting cases:
/// - `3 IN [1, null, 3]` → `TRUE` — a definite match wins even past a `null` (TCK scenario 24).
/// - `1 IN [null]` → `NULL` — no definite match, but a `null` element leaves it unknown.
/// - `null IN [1, 2]` → `NULL` — a `null` search value is unknown against each element.
/// - `4 IN [1, null, 3]` → `NULL` — no match, a `null` present (TCK scenario 25).
/// - `x IN []` → `FALSE` — the `OR` of no terms is its identity `FALSE`, *regardless of `x`* (so
///   `null IN []` is `FALSE` too); TCK scenario 36 `[] IN []` → `false`.
///
/// Operationally: fold `=` over the elements with three-valued OR ([`Ternary::or`]), short-circuiting
/// on a definite match. If `list` is `null` or not a list at all, the result is unknown (`NULL`).
pub fn is_in(value: &Value, list: &Value) -> Ternary {
    let elems = match list {
        Value::List(elems) => elems,
        Value::Null => return Ternary::Null,
        _ => return Ternary::Null, // non-list operand: result is unknown
    };
    // `OR`-fold: TRUE dominates (so a real match wins over later nulls), else NULL if any element
    // comparison was unknown, else FALSE. An empty list folds to FALSE (the identity of OR).
    let mut acc = Ternary::False;
    for e in elems {
        acc = acc.or(equals(value, e));
        if acc.is_true() {
            return Ternary::True; // short-circuit on a definite match
        }
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_core::{Date, Duration};

    fn i(n: i64) -> Value {
        Value::Integer(n)
    }
    fn f(x: f64) -> Value {
        Value::Float(x)
    }
    fn s(t: &str) -> Value {
        Value::String(t.to_owned())
    }
    fn nan() -> Value {
        Value::Float(f64::NAN)
    }

    #[test]
    fn null_propagates_through_equals() {
        assert_eq!(equals(&i(1), &Value::Null), Ternary::Null); // 1 = null → NULL
        assert_eq!(equals(&Value::Null, &i(1)), Ternary::Null);
        assert_eq!(equals(&Value::Null, &Value::Null), Ternary::Null); // null = null → NULL
    }

    #[test]
    fn nan_makes_equals_false() {
        // The resolved tricky case: NaN = NaN → FALSE under `=` (CIP §Equality).
        assert_eq!(equals(&nan(), &nan()), Ternary::False);
        assert_eq!(equals(&i(1), &nan()), Ternary::False);
        assert_eq!(equals(&nan(), &i(1)), Ternary::False);
        // <> is the negation: NaN <> NaN → TRUE.
        assert_eq!(not_equals(&nan(), &nan()), Ternary::True);
        // But NULL still beats NaN: null = NaN → NULL (NULL propagation dominates).
        assert_eq!(equals(&Value::Null, &nan()), Ternary::Null);
        assert_eq!(equals(&nan(), &Value::Null), Ternary::Null);
    }

    #[test]
    fn signed_zero_is_equal_under_equals() {
        assert_eq!(equals(&f(-0.0), &f(0.0)), Ternary::True);
        assert_eq!(equals(&f(0.0), &f(-0.0)), Ternary::True);
    }

    #[test]
    fn numbers_compare_numerically() {
        assert_eq!(equals(&i(1), &f(1.0)), Ternary::True); // 1 = 1.0 → TRUE
        assert_eq!(equals(&i(1), &f(1.5)), Ternary::False);
        assert_eq!(equals(&i(2), &i(2)), Ternary::True);
    }

    #[test]
    fn cross_class_is_false() {
        assert_eq!(equals(&i(1), &s("1")), Ternary::False);
        assert_eq!(equals(&Value::Boolean(true), &i(1)), Ternary::False);
    }

    #[test]
    fn list_equality_is_three_valued() {
        assert_eq!(
            equals(
                &Value::List(vec![i(1), i(2)]),
                &Value::List(vec![i(1), i(2)])
            ),
            Ternary::True
        );
        // Length mismatch is a definite FALSE even with a null present.
        assert_eq!(
            equals(
                &Value::List(vec![i(1)]),
                &Value::List(vec![i(1), Value::Null])
            ),
            Ternary::False
        );
        // Equal length, an inner null comparison → NULL.
        assert_eq!(
            equals(
                &Value::List(vec![i(1), Value::Null]),
                &Value::List(vec![i(1), i(2)])
            ),
            Ternary::Null
        );
        // A definite element mismatch → FALSE regardless of a null elsewhere.
        assert_eq!(
            equals(
                &Value::List(vec![i(9), Value::Null]),
                &Value::List(vec![i(1), i(2)])
            ),
            Ternary::False
        );
    }

    #[test]
    fn map_equality_is_three_valued_and_order_independent() {
        let m1 = Value::Map(vec![("a".to_owned(), i(1)), ("b".to_owned(), i(2))]);
        let m2 = Value::Map(vec![("b".to_owned(), i(2)), ("a".to_owned(), i(1))]);
        assert_eq!(equals(&m1, &m2), Ternary::True); // order-independent
        let m3 = Value::Map(vec![("a".to_owned(), i(1)), ("c".to_owned(), i(2))]);
        assert_eq!(equals(&m1, &m3), Ternary::False); // differing key set
        let m4 = Value::Map(vec![("a".to_owned(), i(1)), ("b".to_owned(), Value::Null)]);
        assert_eq!(equals(&m1, &m4), Ternary::Null); // shared keys, an inner null
    }

    #[test]
    fn temporal_equality_is_component_wise() {
        assert_eq!(
            equals(
                &Value::Date(Date {
                    days_since_epoch: 5
                }),
                &Value::Date(Date {
                    days_since_epoch: 5
                })
            ),
            Ternary::True
        );
        assert_eq!(
            equals(
                &Value::Duration(Duration::default()),
                &Value::Duration(Duration {
                    months: 1,
                    ..Duration::default()
                })
            ),
            Ternary::False
        );
    }

    #[test]
    fn in_resolved_cases() {
        // 1 IN [1, null] → TRUE
        assert_eq!(
            is_in(&i(1), &Value::List(vec![i(1), Value::Null])),
            Ternary::True
        );
        // 1 IN [null] → NULL
        assert_eq!(is_in(&i(1), &Value::List(vec![Value::Null])), Ternary::Null);
        // null IN [non-empty] → NULL (every element comparison is `null = e` → NULL).
        assert_eq!(
            is_in(&Value::Null, &Value::List(vec![i(1), i(2)])),
            Ternary::Null
        );
        // null IN [] → FALSE: `IN` is an OR-fold of `=` over the elements and the OR of *no* terms
        // is its identity FALSE; the LHS is never compared. This matches openCypher TCK List5
        // scenario [36] `[] IN []` → false (empty RHS folds to false regardless of the LHS).
        assert_eq!(is_in(&Value::Null, &Value::List(vec![])), Ternary::False);
        // x IN [] → FALSE (TCK List5 [36]).
        assert_eq!(is_in(&i(1), &Value::List(vec![])), Ternary::False);
        // A definite non-membership with no nulls → FALSE.
        assert_eq!(is_in(&i(3), &Value::List(vec![i(1), i(2)])), Ternary::False);
        // Match dominates a later null even when the null comes first.
        assert_eq!(
            is_in(&i(1), &Value::List(vec![Value::Null, i(1)])),
            Ternary::True
        );
        // No match but a null present → NULL.
        assert_eq!(
            is_in(&i(3), &Value::List(vec![i(1), Value::Null])),
            Ternary::Null
        );
        // NaN never matches under `=`, so NaN IN [NaN] → FALSE.
        assert_eq!(is_in(&nan(), &Value::List(vec![nan()])), Ternary::False);
    }

    #[test]
    fn in_against_null_or_non_list_is_null() {
        assert_eq!(is_in(&i(1), &Value::Null), Ternary::Null);
        assert_eq!(is_in(&i(1), &i(1)), Ternary::Null); // RHS not a list
    }
}
