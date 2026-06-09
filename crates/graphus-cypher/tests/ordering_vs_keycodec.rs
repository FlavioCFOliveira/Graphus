//! Cross-validation: the Cypher value **ordering** ([`graphus_cypher::ordering::cmp_values`]) must
//! agree byte-for-byte with the order-preserving index key encoding
//! ([`graphus_index::keycodec`]) for every index-encodable value class.
//!
//! ```text
//! cmp_values(a, b) == encode_single(a).cmp(encode_single(b))
//! ```
//!
//! The two implementations are written **independently** (one is a comparator, the other a byte
//! serialiser), so this is a genuine cross-check — and it is the proof that a memcmp B+-tree
//! returns rows in exactly Cypher order (openCypher CIP2016-06-14 §Orderability;
//! `04-technical-design.md` §7.6). Restricted to the encodable classes: `{temporals} < STRING <
//! BOOLEAN < NUMBER` plus the `Bytes` extension. `null`, `list` and `map` are excluded because they
//! are not index-encodable (`encode_single` rejects them), so the cross-check covers exactly the
//! classes both sides define.

use std::cmp::Ordering;

use graphus_core::value::temporal::NANOS_PER_DAY;
use graphus_core::{
    Date, Duration, LocalDateTime, LocalTime, Value, ZonedDateTime, ZonedTime, capability::Rng,
};
use graphus_cypher::ordering::cmp_values;
use graphus_index::keycodec::encode_single;
use graphus_sim::SimRng;

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

/// A valid nanoseconds-of-day value (`0 ..= NANOS_PER_DAY - 1`).
fn gen_nanos_of_day(rng: &mut SimRng) -> u64 {
    match rng.next_u64() % 4 {
        0 => 0,
        1 => NANOS_PER_DAY - 1,
        2 => 3600 * 1_000_000_000,
        _ => rng.next_u64() % NANOS_PER_DAY,
    }
}

/// A plausible UTC offset in seconds (`±18h`).
fn gen_offset(rng: &mut SimRng) -> i32 {
    match rng.next_u64() % 6 {
        0 => 0,
        1 => 3600,
        2 => -3600,
        3 => 64_800,
        4 => -64_800,
        _ => ((rng.next_u64() % 129_600) as i64 - 64_800) as i32,
    }
}

/// Generates a random **index-encodable** value across every encodable class, biased to edges.
fn gen_encodable(rng: &mut SimRng) -> Value {
    let r = rng.next_u64();
    match r % 14 {
        0 => Value::Boolean(r & 0x100 != 0),
        1 | 2 => Value::Integer(gen_i64(rng)),
        3 | 4 => {
            let f = match rng.next_u64() % 8 {
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
        5 => {
            let s = match rng.next_u64() % 7 {
                0 => String::new(),
                1 => "a".to_owned(),
                2 => "ab".to_owned(),
                3 => "b".to_owned(),
                4 => "a\u{0}b".to_owned(),
                5 => "é".to_owned(),
                _ => {
                    let n = (rng.next_u64() % 6) as usize;
                    (0..n)
                        .map(|_| (b'a' + (rng.next_u64() % 4) as u8) as char)
                        .collect()
                }
            };
            Value::String(s)
        }
        6 => {
            let n = (rng.next_u64() % 5) as usize;
            Value::Bytes((0..n).map(|_| (rng.next_u64() & 0xFF) as u8).collect())
        }
        7 => Value::Date(Date {
            days_since_epoch: gen_i64(rng) as i32,
        }),
        8 => Value::LocalTime(LocalTime {
            nanos_of_day: gen_nanos_of_day(rng),
        }),
        9 => Value::ZonedTime(ZonedTime {
            time: LocalTime {
                nanos_of_day: gen_nanos_of_day(rng),
            },
            offset_seconds: gen_offset(rng),
        }),
        10 => Value::LocalDateTime(LocalDateTime {
            epoch_seconds: gen_i64(rng),
            nanos: (rng.next_u64() % 1_000_000_000) as u32,
        }),
        11 | 12 => Value::ZonedDateTime(ZonedDateTime {
            local: LocalDateTime {
                epoch_seconds: gen_i64(rng),
                nanos: (rng.next_u64() % 1_000_000_000) as u32,
            },
            offset_seconds: gen_offset(rng),
            zone_id: match rng.next_u64() % 4 {
                0 => String::new(),
                1 => "Europe/Lisbon".to_owned(),
                2 => "a\u{0}b".to_owned(),
                _ => "Z".to_owned(),
            },
        }),
        _ => Value::Duration(Duration {
            months: gen_i64(rng) / 1_000_000,
            days: gen_i64(rng) / 1_000_000,
            seconds: gen_i64(rng),
            nanos: (rng.next_u64() % 2_000_000_000) as i32 - 1_000_000_000,
        }),
    }
}

#[test]
fn cypher_ordering_equals_keycodec_byte_order() {
    let mut rng = SimRng::new(0xCAFE_F00D);
    for _ in 0..100_000 {
        let a = gen_encodable(&mut rng);
        let b = gen_encodable(&mut rng);
        let by_cmp = cmp_values(&a, &b);
        let ea = encode_single(&a).expect("encodable value must encode");
        let eb = encode_single(&b).expect("encodable value must encode");
        let by_bytes = ea.cmp(&eb);
        assert_eq!(
            by_cmp, by_bytes,
            "ordering/keycodec disagree: cmp_values({a:?},{b:?}) = {by_cmp:?}, byte order = {by_bytes:?}"
        );
    }
}

#[test]
fn cross_class_pairs_agree_at_the_class_boundary() {
    // One representative per encodable class, in the CIP ascending order, then assert *both*
    // cmp_values and the byte order agree on every ordered pair (a strict-increasing chain).
    let chain = [
        Value::ZonedDateTime(ZonedDateTime::default()),
        Value::LocalDateTime(LocalDateTime::default()),
        Value::Date(Date::default()),
        Value::ZonedTime(ZonedTime::default()),
        Value::LocalTime(LocalTime::default()),
        Value::Duration(Duration::default()),
        Value::String("zzz".to_owned()),
        Value::Bytes(vec![0xFF]),
        Value::Boolean(true),
        Value::Integer(i64::MIN),
    ];
    for w in chain.windows(2) {
        let cmp = cmp_values(&w[0], &w[1]);
        assert_eq!(
            cmp,
            Ordering::Less,
            "cmp_values chain broke at {:?} < {:?}",
            w[0],
            w[1]
        );
        let bytes = encode_single(&w[0])
            .unwrap()
            .cmp(&encode_single(&w[1]).unwrap());
        assert_eq!(
            bytes,
            Ordering::Less,
            "byte chain broke at {:?} < {:?}",
            w[0],
            w[1]
        );
    }
}
