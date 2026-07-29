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

/// Real IANA zone ids for the `DateTimeZoneId` (tag `0x69`) strategy.
///
/// Deliberately a spread of offset *shapes*: seasonal DST and fixed-offset zones, both
/// hemispheres, whole-hour as well as 30- and 45-minute offsets, the positive and negative
/// extremes of the range, and zones whose historical rules are unusual. The wire form carries no
/// numeric offset, so the decoder must resolve one from the zone rules at that instant — a
/// generator of random names could never check that.
const NAMED_ZONES: &[&str] = &[
    "Europe/Paris",        // CET/CEST, +01:00 / +02:00
    "Europe/Lisbon",       // WET/WEST, +00:00 / +01:00 — a named zone that is sometimes UTC
    "America/New_York",    // EST/EDT, -05:00 / -04:00
    "America/St_Johns",    // -03:30 / -02:30, a half-hour offset with DST
    "Asia/Kolkata",        // +05:30 fixed, half-hour
    "Asia/Kathmandu",      // +05:45 fixed, quarter-hour
    "Australia/Lord_Howe", // +10:30 / +11:00, a 30-minute DST shift
    "Pacific/Chatham",     // +12:45 / +13:45, quarter-hour with DST
    "Pacific/Kiritimati",  // +14:00, the maximum standard offset in the database
    "Pacific/Honolulu",    // -10:00 fixed, no DST since 1947
    "Pacific/Apia",        // skipped 2011-12-30 entirely when it jumped the date line
    "Africa/Nairobi",      // +03:00 fixed
    "America/Sao_Paulo",   // southern hemisphere; DST abolished in 2019
    "UTC",                 // a named zone whose offset really is zero, in every era
];

/// Zone-id-form zoned date-times (non-empty `zone_id` ⇒ `DateTimeZoneId`, tag `0x69`).
///
/// The offset is **derived** from the zone at the generated instant rather than generated
/// independently, because for this form the offset is not free: it is a function of
/// `(zone, instant)`, and building the value any other way would either invent a wall clock that
/// does not exist in that zone (a DST gap) or pick the wrong side of an overlap. This mirrors
/// exactly how the engine constructs such a value, so the generated values are the ones that can
/// really occur.
///
/// This replaces a generator that produced random `[A-Za-z/_]{1,20}` names with `offset_seconds`
/// pinned to `0`. The pin was not incidental — it encoded the decoder's bug as an expectation, so
/// no amount of random search could reach it. That is how `rmp` #908 survived: the property test
/// was structurally incapable of failing on it.
fn zoned_by_zone_id() -> impl Strategy<Value = Value> {
    (
        -1_000_000_000_000i64..1_000_000_000_000,
        0u32..1_000_000_000,
        0usize..NAMED_ZONES.len(),
    )
        .prop_map(|(utc_seconds, nanos, zone_index)| {
            let zone = NAMED_ZONES[zone_index];
            let offset_seconds = graphus_core::timezone::offset_at_instant(zone, utc_seconds)
                .expect(
                    "every zone above is in the embedded database, at any representable instant",
                );
            Value::zoned_date_time(ZonedDateTime {
                local: LocalDateTime {
                    epoch_seconds: utc_seconds + i64::from(offset_seconds),
                    nanos,
                },
                offset_seconds,
                zone_id: zone.to_owned(),
            })
        })
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
        // Zone-id-form zoned date-time (non-empty zone id ⇒ DateTimeZoneId tag). See
        // `zoned_by_zone_id` for why the offset is derived rather than generated.
        zoned_by_zone_id(),
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

    /// A `DateTimeZoneId` value is **localized** on decode: the wire carries a UTC instant and a
    /// zone id, and the decoded wall clock must be that instant *expressed in that zone*.
    ///
    /// Asserted directly, not only as `decode ∘ encode == id`, so that the contract itself is
    /// pinned: a future change that made the encoder and the decoder wrong in mirror-image ways
    /// would still round-trip, but would fail here.
    #[test]
    fn zone_id_date_times_are_localized_on_decode(v in zoned_by_zone_id()) {
        let Value::ZonedDateTime(input) = &v else {
            unreachable!("the strategy builds a ZonedDateTime")
        };
        let mut p = Packer::new();
        pack_value(&mut p, &v);
        let bytes = p.into_inner();
        prop_assert_eq!(bytes[1], 0x69, "a non-empty zone id selects the DateTimeZoneId tag");

        let mut u = Unpacker::new(&bytes);
        let decoded = unpack_value(&mut u).expect("decode must succeed");
        let Value::ZonedDateTime(out) = decoded else {
            unreachable!("a DateTimeZoneId decodes to a ZonedDateTime")
        };

        // The UTC instant the wire carries survives untouched — this part held even while the
        // decoder was wrong, which is exactly why the defect was silent.
        let wire_utc = input.local.epoch_seconds - i64::from(input.offset_seconds);
        prop_assert_eq!(
            out.local.epoch_seconds - i64::from(out.offset_seconds),
            wire_utc,
            "the UTC instant must be preserved"
        );
        // The part that was wrong: the wall clock must be shifted into the zone.
        let expected_offset = graphus_core::timezone::offset_at_instant(&out.zone_id, wire_utc)
            .expect("the decoded zone id is in the embedded database");
        prop_assert_eq!(out.offset_seconds, expected_offset, "offset at the instant");
        prop_assert_eq!(
            out.local.epoch_seconds,
            wire_utc + i64::from(expected_offset),
            "the wall clock must be the instant localized to the zone, not the raw UTC clock"
        );
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

/// Guards the guard.
///
/// `rmp` #908 survived for as long as it did because the zone-id generator pinned
/// `offset_seconds` to `0`: the property test ran thousands of cases and none of them could
/// distinguish a decoder that localizes from one that hard-codes the offset to zero. A generator
/// that cannot produce the failing input is worse than no generator, because it reads as coverage.
///
/// So the generator's own reach is asserted: over a deterministic sample it must yield offsets
/// that are positive, negative, and not a whole number of hours, and it must cover the zone list.
/// If a future edit narrows it back down, this fails instead of quietly going vacuous.
#[test]
fn zone_id_strategy_reaches_non_zero_and_sub_hour_offsets() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use std::collections::BTreeSet;

    let strategy = zoned_by_zone_id();
    let mut runner = TestRunner::deterministic();
    let mut offsets = BTreeSet::new();
    let mut zones = BTreeSet::new();
    for _ in 0..1024 {
        let value = strategy
            .new_tree(&mut runner)
            .expect("the strategy always produces a value")
            .current();
        let Value::ZonedDateTime(z) = value else {
            panic!("the zone-id strategy must produce ZonedDateTime values");
        };
        // Every generated value must be self-consistent: the wall clock is the UTC instant it
        // encodes to, shifted by the offset it carries.
        let utc = z.local.epoch_seconds - i64::from(z.offset_seconds);
        assert_eq!(
            graphus_core::timezone::offset_at_instant(&z.zone_id, utc).expect("known zone"),
            z.offset_seconds,
            "generated {} at {utc} must carry the offset its zone is really in",
            z.zone_id
        );
        offsets.insert(z.offset_seconds);
        zones.insert(z.zone_id.clone());
    }

    assert!(
        offsets.iter().any(|&o| o > 0),
        "the generator must reach positive offsets, saw {offsets:?}"
    );
    assert!(
        offsets.iter().any(|&o| o < 0),
        "the generator must reach negative offsets, saw {offsets:?}"
    );
    assert!(
        offsets.iter().any(|&o| o % 3600 != 0),
        "the generator must reach sub-hour offsets (+05:45, +12:45, -03:30, …), saw {offsets:?}"
    );
    assert_eq!(
        zones.len(),
        NAMED_ZONES.len(),
        "the sample must cover every zone in NAMED_ZONES, saw {zones:?}"
    );
}
