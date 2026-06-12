//! Cypher **equivalence** for `DISTINCT` and grouping (`04-technical-design.md` §7.2; openCypher
//! CIP2016-06-14 §Equality, the TCK-enforced source).
//!
//! `DISTINCT`, `count(DISTINCT …)`, grouping keys in `WITH`/`RETURN`, and aggregation grouping use a
//! **two-valued equivalence** relation — *not* the three-valued `=` ([`crate::equality`]) and *not*
//! ordering ([`crate::ordering`]). It always returns a definite `true`/`false`, and groups together
//! exactly the values a user expects to "be the same" when deduplicating. The resolved rules:
//!
//! - **`null ≡ null` → `true`.** Two `null`s land in the same group (so `DISTINCT` keeps one
//!   `null`), unlike `null = null` which is `NULL`.
//! - **`NaN ≡ NaN` → `true`.** All `NaN`s group together (so `DISTINCT` keeps one `NaN`), unlike
//!   `NaN = NaN` which is `FALSE`.
//! - **`-0.0 ≡ +0.0` → `true`.** Signed zeros group together (matching `=`, contrasting *ordering*
//!   where `-0.0 < +0.0`).
//! - Otherwise it agrees with `=`: `1 ≡ 1.0` → `true`, `1 ≡ 2` → `false`, cross-class → `false`,
//!   with lists and maps compared element-wise / key-wise under equivalence.
//!
//! Because it is total and reflexive (every value is equivalent to itself, including `null` and
//! `NaN`), it is the correct relation for a `HashSet`/group key — see [`equivalent`].

use graphus_core::Value;

/// Returns `true` if `a` and `b` are **equivalent** for `DISTINCT`/grouping (CIP §Equality).
///
/// This is a total, reflexive, symmetric, transitive two-valued relation: `null ≡ null`,
/// `NaN ≡ NaN`, `-0.0 ≡ +0.0` are all `true`; otherwise it matches Cypher `=` coerced to a definite
/// boolean. Lists and maps are compared deeply under the same relation (so `[null] ≡ [null]` and
/// `[NaN] ≡ [NaN]` are `true`).
#[must_use]
pub fn equivalent(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true, // null ≡ null (unlike `=`, which is NULL)
        (Value::Null, _) | (_, Value::Null) => false,
        (Value::Boolean(x), Value::Boolean(y)) => x == y,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Bytes(x), Value::Bytes(y)) => x == y,
        (Value::Integer(_) | Value::Float(_), Value::Integer(_) | Value::Float(_)) => {
            num_equivalent(a, b)
        }
        (Value::List(x), Value::List(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(xe, ye)| equivalent(xe, ye))
        }
        (Value::Map(x), Value::Map(y)) => map_equivalent(x, y),
        (Value::Date(x), Value::Date(y)) => x == y,
        (Value::LocalTime(x), Value::LocalTime(y)) => x == y,
        (Value::ZonedTime(x), Value::ZonedTime(y)) => x == y,
        (Value::LocalDateTime(x), Value::LocalDateTime(y)) => x == y,
        (Value::ZonedDateTime(x), Value::ZonedDateTime(y)) => x == y,
        (Value::Duration(x), Value::Duration(y)) => x == y,
        // Two points are equivalent iff same CRS and each coordinate is *number-equivalent* — so,
        // consistent with `NaN ≡ NaN` and `-0.0 ≡ +0.0` for plain numbers, a `NaN` coordinate is
        // equivalent to itself and signed zeros group together (`rmp` task #73).
        (Value::Point(x), Value::Point(y)) => point_equivalent(x, y),
        _ => false, // distinct classes are never equivalent
    }
}

/// Numeric equivalence: `NaN ≡ NaN` (`true`), `-0.0 ≡ +0.0` (`true`), else numeric `==` across
/// `INTEGER`/`FLOAT` (`1 ≡ 1.0`).
fn num_equivalent(a: &Value, b: &Value) -> bool {
    let (x, y) = (num_f64(a), num_f64(b));
    if x.is_nan() || y.is_nan() {
        // Both NaN group together; a NaN and a non-NaN do not.
        return x.is_nan() && y.is_nan();
    }
    // Rust `f64::==` already treats -0.0 == +0.0 as true, which is exactly the equivalence rule.
    x == y
}

/// The numeric value of an `INTEGER`/`FLOAT` as `f64`.
fn num_f64(v: &Value) -> f64 {
    match v {
        Value::Integer(i) => *i as f64,
        Value::Float(f) => *f,
        _ => unreachable!("num_f64 on a non-number"),
    }
}

/// Grouping equivalence of two points (`rmp` task #73): same CRS and each coordinate
/// number-equivalent (`NaN ≡ NaN`, `-0.0 ≡ +0.0`), mirroring [`num_equivalent`] per coordinate.
fn point_equivalent(x: &graphus_core::Point, y: &graphus_core::Point) -> bool {
    if x.crs != y.crs {
        return false;
    }
    x.coords().iter().zip(y.coords().iter()).all(|(a, b)| {
        if a.is_nan() || b.is_nan() {
            a.is_nan() && b.is_nan()
        } else {
            a == b
        }
    })
}

/// Order-independent map equivalence under [`equivalent`].
fn map_equivalent(x: &[(String, Value)], y: &[(String, Value)]) -> bool {
    if x.len() != y.len() {
        return false;
    }
    x.iter()
        .all(|(k, xv)| match y.iter().find(|(yk, _)| yk == k) {
            Some((_, yv)) => equivalent(xv, yv),
            None => false,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn i(n: i64) -> Value {
        Value::Integer(n)
    }
    fn f(x: f64) -> Value {
        Value::Float(x)
    }
    fn nan() -> Value {
        Value::Float(f64::NAN)
    }

    #[test]
    fn null_is_equivalent_to_null() {
        // The resolved tricky case: null ≡ null → TRUE (unlike `=`, which is NULL).
        assert!(equivalent(&Value::Null, &Value::Null));
        assert!(!equivalent(&Value::Null, &i(1)));
        assert!(!equivalent(&i(1), &Value::Null));
    }

    #[test]
    fn nan_is_equivalent_to_nan() {
        // The resolved tricky case: NaN ≡ NaN → TRUE (unlike `=`, which is FALSE).
        assert!(equivalent(&nan(), &nan()));
        assert!(!equivalent(&nan(), &i(1)));
        assert!(!equivalent(&i(1), &nan()));
    }

    #[test]
    fn signed_zero_is_equivalent() {
        // The resolved tricky case: -0.0 ≡ +0.0 → TRUE (matches `=`; contrast ordering).
        assert!(equivalent(&f(-0.0), &f(0.0)));
    }

    #[test]
    fn agrees_with_equality_for_ordinary_values() {
        assert!(equivalent(&i(1), &f(1.0))); // 1 ≡ 1.0
        assert!(!equivalent(&i(1), &i(2)));
        assert!(equivalent(
            &Value::String("a".to_owned()),
            &Value::String("a".to_owned())
        ));
        assert!(!equivalent(&i(1), &Value::String("1".to_owned()))); // cross-class
    }

    #[test]
    fn nested_null_and_nan_group_together() {
        assert!(equivalent(
            &Value::List(vec![Value::Null, nan()]),
            &Value::List(vec![Value::Null, nan()])
        ));
        assert!(!equivalent(
            &Value::List(vec![Value::Null]),
            &Value::List(vec![Value::Null, Value::Null])
        ));
    }

    #[test]
    fn map_equivalence_is_order_independent() {
        let m1 = Value::Map(vec![("a".to_owned(), nan()), ("b".to_owned(), Value::Null)]);
        let m2 = Value::Map(vec![("b".to_owned(), Value::Null), ("a".to_owned(), nan())]);
        assert!(equivalent(&m1, &m2)); // inner NaN and null both group; order ignored
    }

    #[test]
    fn equivalence_is_reflexive_symmetric_transitive() {
        let pool = [
            Value::Null,
            nan(),
            f(-0.0),
            f(0.0),
            i(1),
            f(1.0),
            i(2),
            Value::String("x".to_owned()),
            Value::List(vec![Value::Null, nan()]),
        ];
        for a in &pool {
            assert!(equivalent(a, a), "reflexivity: {a:?}");
            for b in &pool {
                assert_eq!(equivalent(a, b), equivalent(b, a), "symmetry: {a:?},{b:?}");
                for c in &pool {
                    if equivalent(a, b) && equivalent(b, c) {
                        assert!(equivalent(a, c), "transitivity: {a:?},{b:?},{c:?}");
                    }
                }
            }
        }
    }
}
