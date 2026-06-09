//! The Cypher total **ordering** over [`Value`] (`ORDER BY`, `min`, `max`, sortedness;
//! `04-technical-design.md` §7.6).
//!
//! This is the openCypher *orderability* relation (CIP2016-06-14 §Orderability, the TCK-enforced
//! source). It is a **total order** over *all* values — distinct from Cypher equality
//! (`crate::equality`, three-valued) and from grouping equivalence (`crate::equivalence`,
//! two-valued). The ascending global order is, verbatim from the CIP:
//!
//! ```text
//! MAP < NODE < RELATIONSHIP < LIST < PATH < {temporals} < STRING < BOOLEAN < NUMBER < NaN < null
//! ```
//!
//! with the temporal block ascending
//! `ZonedDateTime < LocalDateTime < Date < ZonedTime < LocalTime < Duration`, `NaN` treated as the
//! **largest number** (just below `null`), and **`null` larger than any other value**. Note the
//! openCypher quirk that `STRING < BOOLEAN < NUMBER` (numbers are the largest non-NaN scalars).
//!
//! Structural classes (`NODE`, `RELATIONSHIP`, `PATH`) are **deferred** to the executor sub-task
//! (they are not yet variants of [`Value`]); their rank slots are reserved in the internal
//! `class_rank` so they
//! drop in unchanged. `Bytes` is a Graphus/PackStream extension, not an openCypher class; it is
//! ordered just above `STRING` as an internally-consistent, implementation-defined placement that
//! never participates in TCK ordering.
//!
//! # Signed zero in *ordering* (a separate concern from equality)
//!
//! In **ordering**, `-0.0 < +0.0` (they are distinct points on the float line); in **equality** and
//! **equivalence** they are equal. This split is the standard openCypher/IEEE behaviour and matches
//! the index keycodec doc. See [`total_f64`].
//!
//! # Cross-check with the index keycodec
//!
//! For the index-encodable classes, this ordering is proven byte-for-byte identical to
//! `graphus_index::keycodec` encoded order by a dev-dependency test
//! (`tests/ordering_vs_keycodec.rs`): the two implementations are written independently, so the
//! agreement is a genuine cross-validation that a memcmp B+-tree is Cypher-ordered.

use std::cmp::Ordering;

use graphus_core::Value;
use graphus_core::value::temporal::NANOS_PER_DAY;

/// The average nanoseconds per month used **only** to order durations (`365.2425 / 12 ≈ 30.436875`
/// days, expressed in nanoseconds). Cypher durations have no exact length, so the order compares
/// them by this normalised approximation (openCypher temporal CIP); equality stays component-wise.
const AVG_NANOS_PER_MONTH: i128 = 30_436_875 * 1_000_000;

/// The global value-class rank (ascending), per CIP2016-06-14 §Orderability.
///
/// Cross-class comparisons are decided by this rank alone. The deferred structural classes
/// (`NODE` = 1, `RELATIONSHIP` = 2, `PATH` = 4) keep reserved slots so adding them later does not
/// renumber the rest. `null` is the largest, above even `NaN` (which is handled inside the number
/// class by [`total_f64`], so `null` simply sits above all numbers).
fn class_rank(v: &Value) -> u8 {
    match v {
        Value::Map(_) => 0,
        // 1 = NODE, 2 = RELATIONSHIP (deferred to the executor sub-task).
        Value::List(_) => 3,
        // 4 = PATH (deferred).
        Value::ZonedDateTime(_) => 5,
        Value::LocalDateTime(_) => 6,
        Value::Date(_) => 7,
        Value::ZonedTime(_) => 8,
        Value::LocalTime(_) => 9,
        Value::Duration(_) => 10,
        Value::String(_) => 11,
        Value::Bytes(_) => 12, // non-CIP extension, just above STRING
        Value::Boolean(_) => 13,
        Value::Integer(_) | Value::Float(_) => 14, // NaN handled within, as the largest number
        Value::Null => 15,                         // null is larger than any other value
    }
}

/// The Cypher orderability `Ordering` of two `f64`s: `-inf < … < -0.0 < +0.0 < … < +inf < NaN`.
///
/// `-0.0` sorts strictly below `+0.0` (the *ordering* rule). All `NaN`s are the single largest
/// value and compare equal to each other. This is bit-identical to the index keycodec's
/// `encode_f64_bits` monotonic key, which is what makes the cross-check pass.
pub fn total_f64(a: f64, b: f64) -> Ordering {
    fn mono(x: f64) -> u64 {
        if x.is_nan() {
            // Canonical largest key, matching the keycodec's NaN canonicalisation.
            !0u64
        } else {
            let bits = x.to_bits();
            if bits & 0x8000_0000_0000_0000 != 0 {
                !bits
            } else {
                bits ^ 0x8000_0000_0000_0000
            }
        }
    }
    mono(a).cmp(&mono(b))
}

/// The numeric value of an `INTEGER`/`FLOAT` as `f64` (the domain Cypher mixes them in for ordering;
/// `1` and `1.0` compare equal numerically, then a stable type tie-break keeps the order total).
fn as_f64(v: &Value) -> f64 {
    match v {
        Value::Integer(i) => *i as f64,
        Value::Float(f) => *f,
        _ => unreachable!("as_f64 on a non-number"),
    }
}

/// The approximate normalised length (in nanoseconds) used to order a [`Value::Duration`].
fn duration_order_nanos(months: i64, days: i64, seconds: i64, nanos: i32) -> i128 {
    i128::from(months) * AVG_NANOS_PER_MONTH
        + i128::from(days) * i128::from(NANOS_PER_DAY)
        + i128::from(seconds) * 1_000_000_000
        + i128::from(nanos)
}

/// Compares two values of the *same* temporal class chronologically (by the instant they denote),
/// with deterministic tie-breaks (offset, then zone id) so the order is total.
fn cmp_same_temporal(a: &Value, b: &Value) -> Ordering {
    match (a, b) {
        (Value::Date(x), Value::Date(y)) => x.days_since_epoch.cmp(&y.days_since_epoch),
        (Value::LocalTime(x), Value::LocalTime(y)) => x.nanos_of_day.cmp(&y.nanos_of_day),
        (Value::ZonedTime(x), Value::ZonedTime(y)) => {
            let xi = (x.time.nanos_of_day as i64)
                .wrapping_sub(i64::from(x.offset_seconds) * 1_000_000_000);
            let yi = (y.time.nanos_of_day as i64)
                .wrapping_sub(i64::from(y.offset_seconds) * 1_000_000_000);
            xi.cmp(&yi).then(x.offset_seconds.cmp(&y.offset_seconds))
        }
        (Value::LocalDateTime(x), Value::LocalDateTime(y)) => x
            .epoch_seconds
            .cmp(&y.epoch_seconds)
            .then(x.nanos.cmp(&y.nanos)),
        (Value::ZonedDateTime(x), Value::ZonedDateTime(y)) => {
            let xi = x
                .local
                .epoch_seconds
                .saturating_sub(i64::from(x.offset_seconds));
            let yi = y
                .local
                .epoch_seconds
                .saturating_sub(i64::from(y.offset_seconds));
            xi.cmp(&yi)
                .then(x.local.nanos.cmp(&y.local.nanos))
                .then(x.offset_seconds.cmp(&y.offset_seconds))
                .then(x.zone_id.as_bytes().cmp(y.zone_id.as_bytes()))
        }
        (Value::Duration(x), Value::Duration(y)) => {
            duration_order_nanos(x.months, x.days, x.seconds, x.nanos)
                .cmp(&duration_order_nanos(y.months, y.days, y.seconds, y.nanos))
        }
        _ => unreachable!("cmp_same_temporal on a non-temporal or mismatched pair"),
    }
}

/// Returns the Cypher orderability of two values (`04 §7.6`, CIP2016-06-14 §Orderability).
///
/// This is a **total order**: reflexive, antisymmetric, transitive and total over every pair of
/// values, including across classes, with `NaN` treated as the largest number and `null` larger
/// than any value. It is *not* Cypher `=` (see [`crate::equality`]) — in particular `cmp_values`
/// reports `NaN` equal to `NaN` and `null` equal to `null`, which a total order requires, whereas
/// `=` returns `FALSE` and `NULL` respectively.
///
/// Lists compare lexicographically element-by-element (shorter is the prefix). Maps compare by
/// their sorted key set, then by the corresponding values, so the order is independent of insertion
/// order (`04 §7.6`).
pub fn cmp_values(a: &Value, b: &Value) -> Ordering {
    let (ra, rb) = (class_rank(a), class_rank(b));
    if ra != rb {
        return ra.cmp(&rb);
    }
    match (a, b) {
        (Value::Null, Value::Null) => Ordering::Equal,
        (Value::Boolean(x), Value::Boolean(y)) => x.cmp(y),
        (Value::String(x), Value::String(y)) => x.as_bytes().cmp(y.as_bytes()),
        (Value::Bytes(x), Value::Bytes(y)) => x.cmp(y),
        (Value::List(x), Value::List(y)) => cmp_lists(x, y),
        (Value::Map(x), Value::Map(y)) => cmp_maps(x, y),
        // Any same-class temporal pair.
        (Value::Date(_), _)
        | (Value::LocalTime(_), _)
        | (Value::ZonedTime(_), _)
        | (Value::LocalDateTime(_), _)
        | (Value::ZonedDateTime(_), _)
        | (Value::Duration(_), _) => cmp_same_temporal(a, b),
        // Otherwise both are numbers (same class rank 14): compare numerically, then INTEGER before
        // FLOAT on a magnitude tie, so `1` and `1.0` (equal numerically) still order deterministically.
        _ => {
            let by_value = total_f64(as_f64(a), as_f64(b));
            if by_value != Ordering::Equal {
                by_value
            } else {
                let is_float = |v: &Value| matches!(v, Value::Float(_));
                is_float(a).cmp(&is_float(b))
            }
        }
    }
}

/// Lexicographic order over lists: compare element-by-element with [`cmp_values`]; on a common
/// prefix, the shorter list sorts first (`04 §7.6`).
fn cmp_lists(x: &[Value], y: &[Value]) -> Ordering {
    for (xe, ye) in x.iter().zip(y.iter()) {
        match cmp_values(xe, ye) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    x.len().cmp(&y.len())
}

/// Order over maps, independent of insertion order: compare by the sorted key sequence first, then
/// (on equal key sets) by the values in that sorted-key order (`04 §7.6`).
fn cmp_maps(x: &[(String, Value)], y: &[(String, Value)]) -> Ordering {
    let mut xs: Vec<&(String, Value)> = x.iter().collect();
    let mut ys: Vec<&(String, Value)> = y.iter().collect();
    xs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    ys.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    for (xe, ye) in xs.iter().zip(ys.iter()) {
        match xe.0.as_bytes().cmp(ye.0.as_bytes()) {
            Ordering::Equal => {}
            other => return other,
        }
        match cmp_values(&xe.1, &ye.1) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    xs.len().cmp(&ys.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_core::{Date, Duration, LocalDateTime, LocalTime, ZonedDateTime, ZonedTime};

    fn lt(a: Value, b: Value) {
        assert_eq!(
            cmp_values(&a, &b),
            Ordering::Less,
            "{a:?} should be < {b:?}"
        );
        assert_eq!(
            cmp_values(&b, &a),
            Ordering::Greater,
            "antisymmetry for {a:?},{b:?}"
        );
    }

    #[test]
    fn global_class_order_matches_cip() {
        // MAP < LIST < temporal < STRING < BOOLEAN < NUMBER < NaN < null
        // (NODE/RELATIONSHIP/PATH deferred; Bytes is between String and Boolean as an extension).
        let chain = [
            Value::Map(vec![]),
            Value::List(vec![]),
            Value::ZonedDateTime(ZonedDateTime::default()),
            Value::LocalDateTime(LocalDateTime::default()),
            Value::Date(Date::default()),
            Value::ZonedTime(ZonedTime::default()),
            Value::LocalTime(LocalTime::default()),
            Value::Duration(Duration::default()),
            Value::String(String::new()),
            Value::Bytes(vec![]),
            Value::Boolean(false),
            Value::Integer(i64::MIN),
            Value::Float(f64::NAN),
            Value::Null,
        ];
        for w in chain.windows(2) {
            lt(w[0].clone(), w[1].clone());
        }
    }

    #[test]
    fn null_is_the_largest_value() {
        for v in [
            Value::Boolean(true),
            Value::Integer(i64::MAX),
            Value::Float(f64::NAN),
            Value::String("zzz".to_owned()),
            Value::List(vec![Value::Null]),
        ] {
            lt(v, Value::Null);
        }
        assert_eq!(cmp_values(&Value::Null, &Value::Null), Ordering::Equal);
    }

    #[test]
    fn nan_is_the_largest_number_below_null() {
        lt(Value::Float(f64::INFINITY), Value::Float(f64::NAN));
        lt(Value::Integer(i64::MAX), Value::Float(f64::NAN));
        lt(Value::Float(f64::NAN), Value::Null);
        // For *ordering*, NaN == NaN (a total order demands it); `=` differs (see equality module).
        assert_eq!(
            cmp_values(&Value::Float(f64::NAN), &Value::Float(f64::NAN)),
            Ordering::Equal
        );
    }

    #[test]
    fn signed_zero_is_distinct_in_ordering() {
        lt(Value::Float(-0.0), Value::Float(0.0));
        assert_eq!(
            cmp_values(&Value::Float(0.0), &Value::Float(0.0)),
            Ordering::Equal
        );
    }

    #[test]
    fn integers_and_floats_compare_numerically() {
        lt(Value::Integer(1), Value::Float(1.5));
        lt(Value::Float(0.5), Value::Integer(1));
        // 1 and 1.0 are numerically equal; INTEGER tie-breaks before FLOAT for a total order.
        lt(Value::Integer(1), Value::Float(1.0));
    }

    #[test]
    fn strings_order_by_codepoint() {
        lt(
            Value::String("a".to_owned()),
            Value::String("ab".to_owned()),
        );
        lt(
            Value::String("ab".to_owned()),
            Value::String("b".to_owned()),
        );
    }

    #[test]
    fn lists_order_lexicographically_then_by_length() {
        lt(
            Value::List(vec![Value::Integer(1)]),
            Value::List(vec![Value::Integer(2)]),
        );
        // Prefix sorts before the longer list.
        lt(
            Value::List(vec![Value::Integer(1)]),
            Value::List(vec![Value::Integer(1), Value::Integer(0)]),
        );
        // Nested lists.
        lt(
            Value::List(vec![Value::List(vec![Value::Integer(1)])]),
            Value::List(vec![Value::List(vec![Value::Integer(2)])]),
        );
    }

    #[test]
    fn maps_order_independently_of_insertion_order() {
        let m1 = Value::Map(vec![
            ("b".to_owned(), Value::Integer(2)),
            ("a".to_owned(), Value::Integer(1)),
        ]);
        let m2 = Value::Map(vec![
            ("a".to_owned(), Value::Integer(1)),
            ("b".to_owned(), Value::Integer(2)),
        ]);
        // Same content, different insertion order => equal in ordering.
        assert_eq!(cmp_values(&m1, &m2), Ordering::Equal);
        // Differing value at a key orders.
        let m3 = Value::Map(vec![
            ("a".to_owned(), Value::Integer(1)),
            ("b".to_owned(), Value::Integer(3)),
        ]);
        lt(m2, m3);
    }

    #[test]
    fn temporal_within_class_is_chronological() {
        lt(
            Value::Date(Date {
                days_since_epoch: -1,
            }),
            Value::Date(Date {
                days_since_epoch: 0,
            }),
        );
        lt(
            Value::LocalTime(LocalTime { nanos_of_day: 0 }),
            Value::LocalTime(LocalTime { nanos_of_day: 1 }),
        );
        // ZonedDateTime by UTC instant: 12:00+01:00 (== 11:00 UTC) < 12:00+00:00 (== 12:00 UTC).
        lt(
            Value::ZonedDateTime(ZonedDateTime {
                local: LocalDateTime {
                    epoch_seconds: 43_200,
                    nanos: 0,
                },
                offset_seconds: 3600,
                zone_id: String::new(),
            }),
            Value::ZonedDateTime(ZonedDateTime {
                local: LocalDateTime {
                    epoch_seconds: 43_200,
                    nanos: 0,
                },
                offset_seconds: 0,
                zone_id: String::new(),
            }),
        );
        lt(
            Value::Duration(Duration {
                months: 0,
                days: 0,
                seconds: 1,
                nanos: 0,
            }),
            Value::Duration(Duration {
                months: 1,
                days: 0,
                seconds: 0,
                nanos: 0,
            }),
        );
    }

    #[test]
    fn total_order_properties_hold_over_random_values() {
        // Antisymmetry, transitivity and totality over a deterministic spread of values, including
        // every class, cross-class pairs, signed zeros, NaN, null and nested lists.
        let pool = sample_pool();
        for a in &pool {
            // Reflexivity.
            assert_eq!(cmp_values(a, a), Ordering::Equal, "reflexivity: {a:?}");
            for b in &pool {
                let ab = cmp_values(a, b);
                let ba = cmp_values(b, a);
                // Antisymmetry / totality.
                assert_eq!(ab, ba.reverse(), "antisymmetry: {a:?} vs {b:?}");
                for c in &pool {
                    let bc = cmp_values(b, c);
                    let ac = cmp_values(a, c);
                    // Transitivity: a<=b and b<=c => a<=c.
                    if ab != Ordering::Greater && bc != Ordering::Greater {
                        assert_ne!(ac, Ordering::Greater, "transitivity: {a:?},{b:?},{c:?}");
                    }
                }
            }
        }
    }

    /// A deterministic spread of values covering every class and the tricky cases.
    fn sample_pool() -> Vec<Value> {
        vec![
            Value::Null,
            Value::Boolean(false),
            Value::Boolean(true),
            Value::Integer(i64::MIN),
            Value::Integer(-1),
            Value::Integer(0),
            Value::Integer(1),
            Value::Integer(i64::MAX),
            Value::Float(f64::NEG_INFINITY),
            Value::Float(-0.0),
            Value::Float(0.0),
            Value::Float(1.0),
            Value::Float(f64::INFINITY),
            Value::Float(f64::NAN),
            Value::String(String::new()),
            Value::String("a".to_owned()),
            Value::String("ab".to_owned()),
            Value::Bytes(vec![]),
            Value::Bytes(vec![0xFF]),
            Value::List(vec![]),
            Value::List(vec![Value::Integer(1)]),
            Value::List(vec![Value::Integer(1), Value::Null]),
            Value::List(vec![Value::List(vec![Value::Integer(2)])]),
            Value::Map(vec![]),
            Value::Map(vec![("a".to_owned(), Value::Integer(1))]),
            Value::Date(Date {
                days_since_epoch: -1,
            }),
            Value::Date(Date {
                days_since_epoch: 0,
            }),
            Value::LocalTime(LocalTime { nanos_of_day: 0 }),
            Value::ZonedTime(ZonedTime::default()),
            Value::LocalDateTime(LocalDateTime::default()),
            Value::ZonedDateTime(ZonedDateTime::default()),
            Value::Duration(Duration::default()),
            Value::Duration(Duration {
                months: 1,
                days: 0,
                seconds: 0,
                nanos: 0,
            }),
        ]
    }
}
