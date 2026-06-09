//! Order property tests for the order-preserving key encoding (`04-technical-design.md` §6.2,
//! §7.6): for random value pairs across every supported type, the encoded byte order must equal
//! Cypher value order, **both ways**.
//!
//! ```text
//! encode(a).cmp(encode(b)) == cypher_cmp(a, b)
//! ```
//!
//! The reference order ([`cypher_cmp`]) is the openCypher global orderability (CIP2016-06-14
//! §Orderability, the TCK-enforced source) restricted to the index-encodable value classes:
//!
//! ```text
//! ZonedDateTime < LocalDateTime < Date < ZonedTime < LocalTime < Duration < STRING < BOOLEAN < NUMBER
//! ```
//!
//! (note the openCypher quirk `STRING < BOOLEAN < NUMBER`), with the `Bytes` extension slotted just
//! above `STRING`, numbers compared numerically across `INTEGER`/`FLOAT`, strings by codepoint, and
//! `NaN` the largest float. This reference is written **independently** of the encoder, so the test
//! is a genuine cross-check. Values are generated with [`graphus_sim::SimRng`] for deterministic,
//! reproducible runs.
//!
//! Earlier this oracle (and the encoder) used `BOOLEAN < NUMBER < STRING`, which was a confirmed
//! cross-type ordering bug against the CIP; both were corrected together and this 50k-pair test now
//! validates against the right global order.

use std::cmp::Ordering;

use graphus_core::value::temporal::NANOS_PER_DAY;
use graphus_core::{
    Date, Duration, LocalDateTime, LocalTime, Value, ZonedDateTime, ZonedTime, capability::Rng,
};
use graphus_index::keycodec::{encode_composite, encode_single};
use graphus_sim::SimRng;

/// The reference value-class rank (ascending), used to order values of different classes — the
/// openCypher orderability restricted to encodable classes (CIP2016-06-14 §Orderability).
fn class_rank(v: &Value) -> u8 {
    match v {
        Value::ZonedDateTime(_) => 0,
        Value::LocalDateTime(_) => 1,
        Value::Date(_) => 2,
        Value::ZonedTime(_) => 3,
        Value::LocalTime(_) => 4,
        Value::Duration(_) => 5,
        Value::String(_) => 6,
        Value::Bytes(_) => 7, // non-CIP extension, just above STRING
        Value::Boolean(_) => 8,
        Value::Integer(_) | Value::Float(_) => 9,
        other => panic!("unindexable value in order test: {other:?}"),
    }
}

/// The average nanoseconds per month used to order durations (mirrors the encoder's
/// `30.436875` days/month, expressed in nanoseconds). Written independently here.
const AVG_NANOS_PER_MONTH: i128 = 30_436_875 * 1_000_000;

/// The reference ordering key for a `Duration`: its approximate normalised length in nanoseconds.
fn duration_nanos(d: &Duration) -> i128 {
    i128::from(d.months) * AVG_NANOS_PER_MONTH
        + i128::from(d.days) * i128::from(NANOS_PER_DAY)
        + i128::from(d.seconds) * 1_000_000_000
        + i128::from(d.nanos)
}

/// The reference UTC instant (nanoseconds) a `ZonedTime` denotes: `local - offset`.
fn zoned_time_instant(zt: &ZonedTime) -> i64 {
    (zt.time.nanos_of_day as i64).wrapping_sub(i64::from(zt.offset_seconds) * 1_000_000_000)
}

/// Reference comparison for two values **of the same temporal class**.
fn temporal_cmp(a: &Value, b: &Value) -> Ordering {
    match (a, b) {
        (Value::Date(x), Value::Date(y)) => x.days_since_epoch.cmp(&y.days_since_epoch),
        (Value::LocalTime(x), Value::LocalTime(y)) => x.nanos_of_day.cmp(&y.nanos_of_day),
        (Value::ZonedTime(x), Value::ZonedTime(y)) => zoned_time_instant(x)
            .cmp(&zoned_time_instant(y))
            .then(x.offset_seconds.cmp(&y.offset_seconds)),
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
        (Value::Duration(x), Value::Duration(y)) => duration_nanos(x).cmp(&duration_nanos(y)),
        _ => unreachable!("temporal_cmp on a non-temporal or mismatched pair"),
    }
}

/// The numeric value of an `INTEGER`/`FLOAT` as `f64` (the domain Cypher mixes them in).
fn num(v: &Value) -> f64 {
    match v {
        Value::Integer(i) => *i as f64,
        Value::Float(f) => *f,
        _ => unreachable!("num() on a non-number"),
    }
}

/// A total order over two `f64`s consistent with the encoding: `-inf < … < -0 < +0 < … < NaN`.
/// `-0.0` sorts just below `+0.0` (the *ordering* rule; equality is a separate concern, `04 §7.6`).
fn total_f64(a: f64, b: f64) -> Ordering {
    fn rank(x: f64) -> (u8, u64) {
        if x.is_nan() {
            (3, 0) // NaN is the largest
        } else {
            // Map to the same monotonic key the encoder uses, so the reference is bit-faithful.
            let bits = x.to_bits();
            let mono = if bits & 0x8000_0000_0000_0000 != 0 {
                !bits
            } else {
                bits ^ 0x8000_0000_0000_0000
            };
            (1, mono)
        }
    }
    rank(a).cmp(&rank(b))
}

/// The reference Cypher order over two indexable values.
fn cypher_cmp(a: &Value, b: &Value) -> Ordering {
    let (ra, rb) = (class_rank(a), class_rank(b));
    if ra != rb {
        return ra.cmp(&rb);
    }
    match (a, b) {
        (Value::Boolean(x), Value::Boolean(y)) => x.cmp(y),
        (Value::String(x), Value::String(y)) => x.as_bytes().cmp(y.as_bytes()),
        (Value::Bytes(x), Value::Bytes(y)) => x.cmp(y),
        (Value::Date(_), Value::Date(_))
        | (Value::LocalTime(_), Value::LocalTime(_))
        | (Value::ZonedTime(_), Value::ZonedTime(_))
        | (Value::LocalDateTime(_), Value::LocalDateTime(_))
        | (Value::ZonedDateTime(_), Value::ZonedDateTime(_))
        | (Value::Duration(_), Value::Duration(_)) => temporal_cmp(a, b),
        _ => {
            // Both numbers: compare numerically; on a magnitude tie, INTEGER sorts before FLOAT,
            // matching the encoder's deterministic sub-tag tie-break.
            let by_value = total_f64(num(a), num(b));
            if by_value != Ordering::Equal {
                by_value
            } else {
                let sub = |v: &Value| matches!(v, Value::Float(_)) as u8;
                sub(a).cmp(&sub(b))
            }
        }
    }
}

/// The byte order of two encoded single values.
fn enc_cmp(a: &Value, b: &Value) -> Ordering {
    encode_single(a).unwrap().cmp(&encode_single(b).unwrap())
}

/// A small signed `i64` biased toward edge cases.
fn gen_i64(rng: &mut SimRng) -> i64 {
    match rng.next_u64() % 6 {
        0 => i64::MIN,
        1 => i64::MAX,
        2 => 0,
        3 => -1,
        4 => 1,
        _ => rng.next_u64() as i64,
    }
}

/// A valid nanoseconds-of-day value (`0 ..= NANOS_PER_DAY - 1`), biased toward edges.
fn gen_nanos_of_day(rng: &mut SimRng) -> u64 {
    match rng.next_u64() % 4 {
        0 => 0,
        1 => NANOS_PER_DAY - 1,
        2 => 3600 * 1_000_000_000, // 01:00
        _ => rng.next_u64() % NANOS_PER_DAY,
    }
}

/// A plausible UTC offset in seconds (`±18h`), biased toward common/edge offsets.
fn gen_offset(rng: &mut SimRng) -> i32 {
    match rng.next_u64() % 6 {
        0 => 0,
        1 => 3600,    // +01:00
        2 => -3600,   // -01:00
        3 => 64_800,  // +18:00
        4 => -64_800, // -18:00
        _ => ((rng.next_u64() % 129_600) as i64 - 64_800) as i32,
    }
}

/// Generates a random indexable value, biased toward edge cases (zeros, signs, specials, empty and
/// embedded-null strings, and every temporal class).
fn gen_value(rng: &mut SimRng) -> Value {
    let r = rng.next_u64();
    match r % 16 {
        0 => Value::Boolean(r & 0x100 != 0),
        1 | 2 => Value::Integer(gen_i64(rng)),
        3 | 4 => {
            // Floats including specials and signed zeros.
            let pick = rng.next_u64() % 8;
            let f = match pick {
                0 => f64::NEG_INFINITY,
                1 => f64::INFINITY,
                2 => f64::NAN,
                3 => 0.0,
                4 => -0.0,
                5 => 1.0,
                6 => -1.5,
                _ => f64::from_bits(rng.next_u64()),
            };
            Value::Float(f)
        }
        5 | 6 => {
            // Strings: empty, prefixes, embedded NUL, multi-byte.
            let pick = rng.next_u64() % 7;
            let s = match pick {
                0 => String::new(),
                1 => "a".to_owned(),
                2 => "ab".to_owned(),
                3 => "b".to_owned(),
                4 => "a\u{0}b".to_owned(), // embedded NUL (escape framing)
                5 => "é".to_owned(),       // multi-byte
                _ => {
                    let n = (rng.next_u64() % 6) as usize;
                    (0..n)
                        .map(|_| (b'a' + (rng.next_u64() % 4) as u8) as char)
                        .collect()
                }
            };
            Value::String(s)
        }
        7 => {
            let n = (rng.next_u64() % 5) as usize;
            let b: Vec<u8> = (0..n).map(|_| (rng.next_u64() & 0xFF) as u8).collect();
            Value::Bytes(b)
        }
        8 => Value::Date(Date {
            days_since_epoch: gen_i64(rng) as i32,
        }),
        9 => Value::LocalTime(LocalTime {
            nanos_of_day: gen_nanos_of_day(rng),
        }),
        10 => Value::ZonedTime(ZonedTime {
            time: LocalTime {
                nanos_of_day: gen_nanos_of_day(rng),
            },
            offset_seconds: gen_offset(rng),
        }),
        11 => Value::LocalDateTime(LocalDateTime {
            epoch_seconds: gen_i64(rng),
            nanos: (rng.next_u64() % 1_000_000_000) as u32,
        }),
        12 | 13 => Value::ZonedDateTime(ZonedDateTime {
            local: LocalDateTime {
                epoch_seconds: gen_i64(rng),
                nanos: (rng.next_u64() % 1_000_000_000) as u32,
            },
            offset_seconds: gen_offset(rng),
            // Zone id from a tiny alphabet incl. empty and embedded-NUL for prefix-free framing.
            zone_id: match rng.next_u64() % 4 {
                0 => String::new(),
                1 => "Europe/Lisbon".to_owned(),
                2 => "a\u{0}b".to_owned(),
                _ => "Z".to_owned(),
            },
        }),
        _ => Value::Duration(Duration {
            months: gen_i64(rng) / 1_000_000, // keep the i128 length well within range
            days: gen_i64(rng) / 1_000_000,
            seconds: gen_i64(rng),
            nanos: (rng.next_u64() % 2_000_000_000) as i32 - 1_000_000_000,
        }),
    }
}

#[test]
fn encoded_byte_order_equals_cypher_value_order() {
    let mut rng = SimRng::new(0xC0FFEE);
    for _ in 0..50_000 {
        let a = gen_value(&mut rng);
        let b = gen_value(&mut rng);
        let want = cypher_cmp(&a, &b);
        let got = enc_cmp(&a, &b);
        assert_eq!(
            got, want,
            "order mismatch: encode({a:?}).cmp(encode({b:?})) = {got:?}, cypher = {want:?}"
        );
    }
}

#[test]
fn encoding_is_consistent_for_equal_magnitudes() {
    // 1 (INTEGER) and 1.0 (FLOAT) are numerically equal in Cypher; the encoding must still be a
    // total order (deterministic, antisymmetric), which the sub-tag tie-break provides.
    let one_i = Value::Integer(1);
    let one_f = Value::Float(1.0);
    assert_eq!(enc_cmp(&one_i, &one_f), Ordering::Less); // INTEGER sub-tag < FLOAT sub-tag
    assert_eq!(enc_cmp(&one_f, &one_i), Ordering::Greater);
    assert_eq!(enc_cmp(&one_i, &one_i), Ordering::Equal);
}

#[test]
fn composite_byte_order_equals_tuple_order() {
    // Two-field composite keys: lexicographic byte order must equal field-tuple order, including
    // the prefix-free framing for variable-width strings.
    let mut rng = SimRng::new(0xBEEF);
    for _ in 0..20_000 {
        let a = [gen_value(&mut rng), gen_value(&mut rng)];
        let b = [gen_value(&mut rng), gen_value(&mut rng)];
        let want = match cypher_cmp(&a[0], &b[0]) {
            Ordering::Equal => cypher_cmp(&a[1], &b[1]),
            other => other,
        };
        let got = encode_composite(&a)
            .unwrap()
            .cmp(&encode_composite(&b).unwrap());
        assert_eq!(
            got, want,
            "composite order mismatch: {a:?} vs {b:?}: got {got:?}, want {want:?}"
        );
    }
}

#[test]
fn string_prefix_framing_is_prefix_free_in_composites() {
    // The classic prefix hazard: ("a", X) vs ("ab", Y). Without prefix-free framing the
    // concatenation could mis-sort. Assert the framing fixes it for adversarial pairs.
    let a = [
        Value::String("a".to_owned()),
        Value::String("zzzz".to_owned()),
    ];
    let b = [Value::String("ab".to_owned()), Value::String("".to_owned())];
    // "a" < "ab" so ("a", …) < ("ab", …) regardless of the second field.
    assert_eq!(
        encode_composite(&a)
            .unwrap()
            .cmp(&encode_composite(&b).unwrap()),
        Ordering::Less
    );
}
