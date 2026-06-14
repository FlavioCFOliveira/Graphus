//! Property-based round-trip invariants for the Graphus storage value codecs (`rmp` task #27, the
//! verification arsenal's proptest TR).
//!
//! These complement the crate's example-based unit tests with `proptest`'s randomized generation +
//! **shrinking**: a counterexample is automatically minimized, so a regression surfaces the smallest
//! failing value rather than an opaque random one. The invariants are the codecs' defining contract:
//!
//! 1. **Inline scalar round-trip** ([`propenc`]): `decode_inline(encode_inline(v)) == v` for every
//!    inline scalar class (`Boolean`/`Integer`/`Float`), bit-exact (so `NaN`/`-0.0` are included).
//! 2. **Overflow value round-trip** ([`valenc`]): `decode(encode(v)) == v` for `String`, the six
//!    temporal classes, and homogeneous scalar/temporal `List`s — the classes the overflow heap
//!    stores.
//!
//! Floats are compared by their bit pattern (`f64::to_bits`), not `==`, because the codec's contract
//! is bit-exact preservation and `NaN != NaN` under `==` would make a correct round-trip look broken.

use graphus_core::Value;
use graphus_core::value::temporal::{
    Date, Duration, LocalDateTime, LocalTime, ZonedDateTime, ZonedTime,
};
use graphus_storage::{propenc, valenc};
use proptest::prelude::*;

/// Whether two [`Value`]s are bit-exactly equal, treating floats (including `NaN`/`-0.0`) by their
/// bit pattern and recursing into lists. This is the right equality for a *codec* round-trip.
fn bit_exact_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Float(x), Value::Float(y)) => x.to_bits() == y.to_bits(),
        (Value::List(xs), Value::List(ys)) => {
            xs.len() == ys.len() && xs.iter().zip(ys).all(|(x, y)| bit_exact_eq(x, y))
        }
        _ => a == b,
    }
}

/// A strategy for an inline scalar value: `Boolean`, `Integer` (full i64 range), or `Float`
/// (arbitrary bit patterns via `to_bits`, so NaN / subnormal / ±inf are all generated).
fn inline_scalar() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<bool>().prop_map(Value::Boolean),
        any::<i64>().prop_map(Value::Integer),
        any::<u64>().prop_map(|bits| Value::Float(f64::from_bits(bits))),
    ]
}

/// A strategy for a scalar usable as a homogeneous list element of the `String` family: a String of
/// arbitrary unicode (bounded length to keep the heap encoding fast).
fn small_string() -> impl Strategy<Value = String> {
    proptest::string::string_regex(".{0,32}").expect("valid regex")
}

/// A strategy for any temporal value, generating the **full bit range** of every component (the
/// codec's contract is bit-exact preservation, like the float codec; component-range invariants are
/// owned by graphus-core's constructors, not the codec).
fn temporal_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<i64>().prop_map(|days_since_epoch| Value::Date(Date { days_since_epoch })),
        any::<u64>().prop_map(|nanos_of_day| Value::LocalTime(LocalTime { nanos_of_day })),
        (any::<u64>(), any::<i32>()).prop_map(|(nanos_of_day, offset_seconds)| {
            Value::ZonedTime(ZonedTime {
                time: LocalTime { nanos_of_day },
                offset_seconds,
            })
        }),
        (any::<i64>(), any::<u32>()).prop_map(|(epoch_seconds, nanos)| {
            Value::LocalDateTime(LocalDateTime {
                epoch_seconds,
                nanos,
            })
        }),
        (any::<i64>(), any::<u32>(), any::<i32>(), small_string()).prop_map(
            |(epoch_seconds, nanos, offset_seconds, zone_id)| {
                Value::zoned_date_time(ZonedDateTime {
                    local: LocalDateTime {
                        epoch_seconds,
                        nanos,
                    },
                    offset_seconds,
                    zone_id,
                })
            }
        ),
        (any::<i64>(), any::<i64>(), any::<i64>(), any::<i32>()).prop_map(
            |(months, days, seconds, nanos)| {
                Value::Duration(Duration {
                    months,
                    days,
                    seconds,
                    nanos,
                })
            }
        ),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Inline scalar codec round-trip: `decode_inline(encode_inline(v)) == v`, bit-exact.
    #[test]
    fn inline_scalar_round_trips(v in inline_scalar()) {
        let (tag, inline) = propenc::encode_inline(&v).expect("inline scalar must encode");
        let decoded = propenc::decode_inline(tag, inline).expect("inline scalar must decode");
        prop_assert!(
            bit_exact_eq(&v, &decoded),
            "inline round-trip mismatch: {v:?} -> (tag={tag}, inline={inline}) -> {decoded:?}"
        );
    }

    /// A non-inline class (here a String) is rejected by the inline codec with a precise error,
    /// never silently mis-encoded — the inline codec's documented boundary.
    #[test]
    fn non_inline_value_is_rejected_not_mis_encoded(s in small_string()) {
        let v = Value::String(s);
        prop_assert!(
            propenc::encode_inline(&v).is_err(),
            "a String must not encode as an inline scalar"
        );
    }

    /// Overflow String codec round-trip via `valenc`: `decode(tag, encode(v).1) == v`.
    #[test]
    fn overflow_string_round_trips(s in small_string()) {
        let v = Value::String(s);
        let (tag, bytes) = valenc::encode(&v).expect("string must encode");
        // The caller masks the overflow bit off before `decode` (see `valenc::decode` docs).
        let class_tag = tag & !valenc::OVERFLOW_BIT;
        let decoded = valenc::decode(class_tag, &bytes).expect("string must decode");
        prop_assert!(
            bit_exact_eq(&v, &decoded),
            "string round-trip mismatch: {v:?} -> {decoded:?}"
        );
    }

    /// Overflow homogeneous-`List` codec round-trip. Lists are constrained to be homogeneous (all
    /// `Integer`, here) because the stored-property subtype requires homogeneity (`05 §7.2`); a
    /// heterogeneous list is a runtime error elsewhere and is not a codec round-trip case.
    #[test]
    fn overflow_int_list_round_trips(xs in prop::collection::vec(any::<i64>(), 0..16)) {
        let v = Value::List(xs.into_iter().map(Value::Integer).collect());
        let (tag, bytes) = valenc::encode(&v).expect("list must encode");
        let class_tag = tag & !valenc::OVERFLOW_BIT;
        let decoded = valenc::decode(class_tag, &bytes).expect("list must decode");
        prop_assert!(
            bit_exact_eq(&v, &decoded),
            "int-list round-trip mismatch: {v:?} -> {decoded:?}"
        );
    }

    /// Overflow homogeneous String-`List` round-trip (the other common list element type, exercising
    /// the variable-width element framing).
    #[test]
    fn overflow_string_list_round_trips(
        ss in prop::collection::vec(small_string(), 0..8)
    ) {
        let v = Value::List(ss.into_iter().map(Value::String).collect());
        let (tag, bytes) = valenc::encode(&v).expect("string list must encode");
        let class_tag = tag & !valenc::OVERFLOW_BIT;
        let decoded = valenc::decode(class_tag, &bytes).expect("string list must decode");
        prop_assert!(
            bit_exact_eq(&v, &decoded),
            "string-list round-trip mismatch: {v:?} -> {decoded:?}"
        );
    }

    /// Overflow temporal codec round-trip via `valenc`: `decode(tag, encode(v).1) == v` bit-exactly
    /// for every temporal class over its full component bit range.
    #[test]
    fn overflow_temporal_round_trips(v in temporal_value()) {
        let (tag, bytes) = valenc::encode(&v).expect("temporal must encode");
        let class_tag = tag & !valenc::OVERFLOW_BIT;
        let decoded = valenc::decode(class_tag, &bytes).expect("temporal must decode");
        prop_assert!(
            bit_exact_eq(&v, &decoded),
            "temporal round-trip mismatch: {v:?} -> {decoded:?}"
        );
    }

    /// A temporal value is rejected by the inline codec (it never fits the 64-bit inline payload),
    /// never silently mis-encoded — the same boundary contract as for Strings.
    #[test]
    fn temporal_value_is_rejected_by_the_inline_codec(v in temporal_value()) {
        prop_assert!(
            propenc::encode_inline(&v).is_err(),
            "a temporal value must not encode as an inline scalar"
        );
    }

    /// Overflow homogeneous `Duration`-`List` round-trip (a temporal element class inside the list
    /// framing; `Duration` has the widest fixed-width element body).
    #[test]
    fn overflow_duration_list_round_trips(
        ds in prop::collection::vec(
            (any::<i64>(), any::<i64>(), any::<i64>(), any::<i32>()),
            0..8
        )
    ) {
        let v = Value::List(
            ds.into_iter()
                .map(|(months, days, seconds, nanos)| {
                    Value::Duration(Duration {
                        months,
                        days,
                        seconds,
                        nanos,
                    })
                })
                .collect(),
        );
        let (tag, bytes) = valenc::encode(&v).expect("duration list must encode");
        let class_tag = tag & !valenc::OVERFLOW_BIT;
        let decoded = valenc::decode(class_tag, &bytes).expect("duration list must decode");
        prop_assert!(
            bit_exact_eq(&v, &decoded),
            "duration-list round-trip mismatch: {v:?} -> {decoded:?}"
        );
    }

    /// Overflow homogeneous `ZonedDateTime`-`List` round-trip (the variable-width temporal element,
    /// exercising the per-element zone-id length framing).
    #[test]
    fn overflow_zoned_date_time_list_round_trips(
        zs in prop::collection::vec(
            (any::<i64>(), any::<u32>(), any::<i32>(), small_string()),
            0..8
        )
    ) {
        let v = Value::List(
            zs.into_iter()
                .map(|(epoch_seconds, nanos, offset_seconds, zone_id)| {
                    Value::zoned_date_time(ZonedDateTime {
                        local: LocalDateTime {
                            epoch_seconds,
                            nanos,
                        },
                        offset_seconds,
                        zone_id,
                    })
                })
                .collect(),
        );
        let (tag, bytes) = valenc::encode(&v).expect("zoned-date-time list must encode");
        let class_tag = tag & !valenc::OVERFLOW_BIT;
        let decoded = valenc::decode(class_tag, &bytes).expect("zoned-date-time list must decode");
        prop_assert!(
            bit_exact_eq(&v, &decoded),
            "zoned-date-time-list round-trip mismatch: {v:?} -> {decoded:?}"
        );
    }
}
