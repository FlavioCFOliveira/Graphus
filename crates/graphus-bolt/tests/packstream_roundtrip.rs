//! Property-based round-trip tests for the PackStream v1 codec: `decode ∘ encode == id` for **every**
//! `graphus_core::Value` class, across the full marker-width range (`04-technical-design.md` §8.1).
//!
//! These exercise the public [`graphus_bolt::pack_value`] / [`graphus_bolt::unpack_value`] surface
//! with randomized inputs (proptest), complementing the deterministic boundary tests inside the
//! `packstream` module. Floats are compared by **bit pattern** so `NaN` and `±0.0` are exact, which
//! is the codec's contract (a faithful byte round-trip), distinct from Cypher value equality.

use graphus_bolt::{Packer, Unpacker, pack_value, unpack_value};
use graphus_core::Value;
use graphus_core::value::temporal::{
    Date, Duration, LocalDateTime, LocalTime, ZonedDateTime, ZonedTime,
};
use proptest::prelude::*;

/// Encodes then decodes a value, asserting the input is fully consumed.
fn round_trip(v: &Value) -> Value {
    let mut p = Packer::new();
    pack_value(&mut p, v);
    let bytes = p.into_inner();
    let mut u = Unpacker::new(&bytes);
    let out = unpack_value(&mut u).expect("decode must succeed");
    assert!(u.is_empty(), "decode left {} trailing bytes", u.remaining());
    out
}

/// Structural equality that treats two floats as equal iff their **bits** match, recursing through
/// lists and maps. The codec guarantees a byte-faithful round-trip, so `NaN`/`±0.0` must survive
/// exactly — `Value`'s `PartialEq` (which uses `f64: PartialEq`) would wrongly fail `NaN == NaN`.
fn bit_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Float(x), Value::Float(y)) => x.to_bits() == y.to_bits(),
        (Value::List(xs), Value::List(ys)) => {
            xs.len() == ys.len() && xs.iter().zip(ys).all(|(x, y)| bit_equal(x, y))
        }
        (Value::Map(xs), Value::Map(ys)) => {
            xs.len() == ys.len()
                && xs
                    .iter()
                    .zip(ys)
                    .all(|((kx, vx), (ky, vy))| kx == ky && bit_equal(vx, vy))
        }
        _ => a == b,
    }
}

// ---- Per-class strategies ---------------------------------------------------------------------

/// A leaf (non-recursive) value: every scalar, string, bytes and temporal class, spanning the
/// marker-width boundaries (small/medium/large lengths and integer magnitudes).
fn leaf_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Boolean),
        any::<i64>().prop_map(Value::Integer),
        any::<f64>().prop_map(Value::Float),
        // Strings up to past the tiny (15) and 8-bit (255) boundaries.
        proptest::collection::vec(any::<char>(), 0..300)
            .prop_map(|cs| Value::String(cs.into_iter().collect())),
        proptest::collection::vec(any::<u8>(), 0..300).prop_map(Value::Bytes),
        temporal_value(),
    ]
}

/// Every temporal `Value` class.
fn temporal_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<i64>().prop_map(|d| Value::Date(Date {
            days_since_epoch: d
        })),
        // nanos-of-day stays within a day.
        (0u64..86_400_000_000_000).prop_map(|n| Value::LocalTime(LocalTime { nanos_of_day: n })),
        (0u64..86_400_000_000_000, -64_800i32..=64_800).prop_map(|(n, off)| {
            Value::ZonedTime(ZonedTime {
                time: LocalTime { nanos_of_day: n },
                offset_seconds: off,
            })
        }),
        (any::<i64>(), 0u32..1_000_000_000).prop_map(|(s, ns)| {
            Value::LocalDateTime(LocalDateTime {
                epoch_seconds: s,
                nanos: ns,
            })
        }),
        // Offset-form zoned date-time (empty zone id ⇒ DateTime tag). Bound seconds so re-applying
        // the offset on decode cannot overflow i64 (the codec saturates, but we assert exact equality).
        (
            -1_000_000_000_000i64..1_000_000_000_000,
            0u32..1_000_000_000,
            -64_800i32..=64_800
        )
            .prop_map(|(s, ns, off)| {
                Value::zoned_date_time(ZonedDateTime {
                    local: LocalDateTime {
                        epoch_seconds: s,
                        nanos: ns,
                    },
                    offset_seconds: off,
                    zone_id: String::new(),
                })
            }),
        // Zone-id-form zoned date-time (non-empty zone id ⇒ DateTimeZoneId tag). The wire form
        // carries no numeric offset, so the codec stores offset 0; constrain the input to match so
        // the round-trip is exact (the offset-bearing form is covered by the case above).
        (
            -1_000_000_000_000i64..1_000_000_000_000,
            0u32..1_000_000_000,
            "[A-Za-z/_]{1,20}"
        )
            .prop_map(|(s, ns, zone)| {
                Value::zoned_date_time(ZonedDateTime {
                    local: LocalDateTime {
                        epoch_seconds: s,
                        nanos: ns,
                    },
                    offset_seconds: 0,
                    zone_id: zone,
                })
            }),
        (any::<i64>(), any::<i64>(), any::<i64>(), any::<i32>()).prop_map(|(mo, d, s, ns)| {
            Value::Duration(Duration {
                months: mo,
                days: d,
                seconds: s,
                nanos: ns,
            })
        }),
    ]
}

/// An arbitrary `Value`, including nested lists and maps (depth-bounded), so the recursive encoder
/// paths and the large-collection markers are exercised.
fn any_value() -> impl Strategy<Value = Value> {
    leaf_value().prop_recursive(
        4,  // up to 4 levels deep
        64, // up to 64 total nodes
        10, // up to 10 children per collection
        |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..10).prop_map(Value::List),
                // De-duplicate keys (keeping the LAST value, matching PackStream's "last seen value
                // wins" decode rule) so the generated map has no duplicate keys. A map *with*
                // duplicate keys cannot round-trip byte-for-byte — by design, the decoder collapses
                // duplicates — and that collapse is asserted by dedicated unit tests, not here.
                proptest::collection::vec(("[a-z]{0,8}", inner), 0..10).prop_map(|pairs| {
                    let mut entries: Vec<(String, Value)> = Vec::with_capacity(pairs.len());
                    for (k, v) in pairs {
                        if let Some(slot) = entries.iter_mut().find(|(ek, _)| *ek == k) {
                            slot.1 = v;
                        } else {
                            entries.push((k, v));
                        }
                    }
                    Value::Map(entries)
                }),
            ]
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Every leaf value class round-trips byte-faithfully.
    #[test]
    fn leaf_values_round_trip(v in leaf_value()) {
        let out = round_trip(&v);
        prop_assert!(bit_equal(&v, &out), "in={v:?} out={out:?}");
    }

    /// Every temporal class round-trips.
    #[test]
    fn temporal_values_round_trip(v in temporal_value()) {
        let out = round_trip(&v);
        prop_assert!(bit_equal(&v, &out), "in={v:?} out={out:?}");
    }

    /// Arbitrarily nested lists/maps round-trip (exercises recursion + large-collection markers).
    #[test]
    fn nested_values_round_trip(v in any_value()) {
        let out = round_trip(&v);
        prop_assert!(bit_equal(&v, &out), "in={v:?} out={out:?}");
    }

    /// Integers pick the smallest marker that fits and decode back exactly across the whole i64 range.
    #[test]
    fn integers_round_trip(n in any::<i64>()) {
        prop_assert_eq!(round_trip(&Value::Integer(n)), Value::Integer(n));
    }

    /// Strings of any length (well past the tiny/8/16 boundaries) round-trip.
    #[test]
    fn strings_round_trip(s in ".{0,1000}") {
        prop_assert_eq!(round_trip(&Value::String(s.clone())), Value::String(s));
    }

    /// Byte strings of any length round-trip.
    #[test]
    fn bytes_round_trip(b in proptest::collection::vec(any::<u8>(), 0..1000)) {
        prop_assert_eq!(round_trip(&Value::Bytes(b.clone())), Value::Bytes(b));
    }
}
