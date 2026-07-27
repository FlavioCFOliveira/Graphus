//! Cross-validation: the Cypher value **ordering** ([`graphus_cypher::ordering::cmp_values`]) must
//! agree byte-for-byte with the order-preserving index key encoding
//! ([`graphus_index::keycodec`]) for every index-encodable value class.
//!
//! ```text
//! cmp_values(a, b) == encode_single(a).cmp(encode_single(b))
//! ```
//!
//! — with **one documented exception**, two numbers sharing a key magnitude, set out below.
//!
//! The two implementations are written **independently** (one is a comparator, the other a byte
//! serialiser), so this is a genuine cross-check — and it is the proof that a memcmp B+-tree
//! returns rows in exactly Cypher order (openCypher CIP2016-06-14 §Orderability;
//! `04-technical-design.md` §7.6). Restricted to the encodable classes: `{temporals} < STRING <
//! BOOLEAN < NUMBER` plus the `Bytes` extension. `null`, `list` and `map` are excluded because they
//! are not index-encodable (`encode_single` rejects them), so the cross-check covers exactly the
//! classes both sides define.
//!
//! # The one documented exception: large integers share a key magnitude (`rmp` task #894)
//!
//! `keycodec::encode_integer` puts an `i64` on the shared `f64` **magnitude** line and appends an
//! `INTEGER`-before-`FLOAT` tie-break byte. That projection is lossy above 2^53, so distinct values
//! can land on one magnitude — `Integer(2^54+3)` and `Integer(2^54+5)` (which round to the same
//! double), or `Integer(2^53+1)` and `Float(2^53.0)`. `cmp_values` orders each pair strictly and
//! **exactly**, so inside one magnitude the byte order is a coarsening (and, for the mixed pair,
//! an inversion — the `FLOAT` tie-break byte sorts above the `INTEGER` one while 2^53 is the
//! *smaller* number). The equality is therefore asserted for every pair **except** two numbers that
//! share a key magnitude, and what holds there instead is asserted separately:
//!
//! * [`key_magnitude_order_implies_exact_order`] — a strictly smaller key magnitude always implies a
//!   strictly smaller exact value (rounding is monotone). This is the property every index range
//!   seek's candidate-superset argument rests on, and it bounds the exception to *within* one
//!   magnitude.
//! * [`same_magnitude_numbers_are_the_documented_exception`] — the collisions and the inversion,
//!   pinned by name so the exception is executable documentation rather than a gap the random
//!   generator happens never to hit.

use std::cmp::Ordering;

use graphus_core::value::spatial::{Crs, Point};
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

/// A random spatial point (any CRS, edge-biased coordinates) — `rmp` task #73.
fn gen_point(rng: &mut SimRng) -> Value {
    let coord = |rng: &mut SimRng| match rng.next_u64() % 7 {
        0 => 0.0,
        1 => -0.0,
        2 => f64::NEG_INFINITY,
        3 => f64::INFINITY,
        4 => f64::NAN,
        5 => 1.5,
        _ => f64::from_bits(rng.next_u64()),
    };
    let p = match rng.next_u64() % 4 {
        0 => Point::new_2d(Crs::Cartesian, coord(rng), coord(rng)),
        1 => Point::new_3d(Crs::Cartesian3D, coord(rng), coord(rng), coord(rng)),
        2 => Point::new_2d(Crs::Wgs84, coord(rng), coord(rng)),
        _ => Point::new_3d(Crs::Wgs84_3D, coord(rng), coord(rng), coord(rng)),
    };
    Value::Point(p)
}

/// Generates a random **index-encodable** value across every encodable class, biased to edges.
fn gen_encodable(rng: &mut SimRng) -> Value {
    let r = rng.next_u64();
    match r % 15 {
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
            days_since_epoch: gen_i64(rng),
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
        11 | 12 => Value::zoned_date_time(ZonedDateTime {
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
        13 => Value::Duration(Duration {
            months: gen_i64(rng) / 1_000_000,
            days: gen_i64(rng) / 1_000_000,
            seconds: gen_i64(rng),
            nanos: (rng.next_u64() % 2_000_000_000) as i32 - 1_000_000_000,
        }),
        _ => gen_point(rng),
    }
}

/// Whether `v` is one of the two numeric classes (the only ones the keycodec puts on a shared,
/// lossy magnitude line).
fn is_number(v: &Value) -> bool {
    matches!(v, Value::Integer(_) | Value::Float(_))
}

/// The **key magnitude** of an encoded number: its encoding minus the trailing numtag tie-break
/// byte, i.e. `tag::NUMBER` followed by the 8 order-preserving `f64` bits. Comparing these compares
/// exactly the `f64` line the two numeric classes share (with every `NaN` already canonicalised by
/// the encoder).
fn key_magnitude(encoded: &[u8]) -> &[u8] {
    &encoded[..encoded.len() - 1]
}

#[test]
fn cypher_ordering_equals_keycodec_byte_order() {
    let mut rng = SimRng::new(0xCAFE_F00D);
    for _ in 0..100_000 {
        let a = gen_encodable(&mut rng);
        let b = gen_encodable(&mut rng);
        let ea = encode_single(&a).expect("encodable value must encode");
        let eb = encode_single(&b).expect("encodable value must encode");
        // The documented exception (`rmp` #894, see the module docs): two numbers on one key
        // magnitude, where the lossy `i64 → f64` projection makes the byte order coarser than — and
        // for a mixed pair inverted against — the exact comparison. What holds there is asserted by
        // the two tests below.
        if is_number(&a) && is_number(&b) && key_magnitude(&ea) == key_magnitude(&eb) {
            continue;
        }
        let by_cmp = cmp_values(&a, &b);
        let by_bytes = ea.cmp(&eb);
        assert_eq!(
            by_cmp, by_bytes,
            "ordering/keycodec disagree: cmp_values({a:?},{b:?}) = {by_cmp:?}, byte order = {by_bytes:?}"
        );
    }
}

/// **The invariant every index range seek rests on** (`rmp` task #894): a strictly smaller key
/// magnitude implies a strictly smaller *exact* value.
///
/// Rounding to nearest is monotone, so `round(a) < round(b)` forces `a < b`; the converse does not
/// hold (two different numbers may round together), which is exactly why the exception above is a
/// *coarsening within one magnitude* and never a disagreement across magnitudes. A range seek's
/// candidate set is a B+-tree slice cut at key boundaries, so this is what guarantees the slice
/// cannot omit a row whose value satisfies the predicate — as long as the cut is not made *inside* a
/// magnitude, which is what `index_set`'s `exclusive_upper_key_is_lossy` prevents.
#[test]
fn key_magnitude_order_implies_exact_order() {
    let mut rng = SimRng::new(0x5EED_1234);
    let mut checked = 0_u32;
    for _ in 0..200_000 {
        let a = gen_encodable(&mut rng);
        let b = gen_encodable(&mut rng);
        if !is_number(&a) || !is_number(&b) {
            continue;
        }
        let ea = encode_single(&a).expect("encodable");
        let eb = encode_single(&b).expect("encodable");
        if key_magnitude(&ea) < key_magnitude(&eb) {
            assert_eq!(
                cmp_values(&a, &b),
                Ordering::Less,
                "a smaller key magnitude must imply a smaller exact value: {a:?} vs {b:?}"
            );
            checked += 1;
        }
    }
    assert!(
        checked > 1_000,
        "NON-VACUITY: only {checked} magnitude-ordered numeric pairs were generated"
    );

    // Directed cases across the 2^53 straddle, where the generator is sparse.
    let p53: i64 = 1 << 53;
    #[allow(clippy::cast_precision_loss)]
    let directed: [(Value, Value); 5] = [
        (Value::Integer(p53 - 1), Value::Float(p53 as f64)),
        (Value::Float((p53 - 2) as f64), Value::Integer(p53 + 1)),
        (Value::Integer(p53 + 1), Value::Float((p53 + 2) as f64)),
        (Value::Integer(i64::MAX), Value::Float(f64::INFINITY)),
        (Value::Float(f64::NEG_INFINITY), Value::Integer(i64::MIN)),
    ];
    for (a, b) in directed {
        let (ea, eb) = (encode_single(&a).unwrap(), encode_single(&b).unwrap());
        assert!(
            key_magnitude(&ea) < key_magnitude(&eb),
            "fixture must have ordered magnitudes: {a:?} vs {b:?}"
        );
        assert_eq!(cmp_values(&a, &b), Ordering::Less, "{a:?} < {b:?}");
    }
}

/// The exception itself, pinned by name (`rmp` task #894): within one key magnitude the byte order
/// is **not** the Cypher order, and this test exists so that fact is executable documentation rather
/// than a silent gap. Every index path re-checks its candidates against `cmp_values` /
/// `equality::equals`, so this coarsening costs re-check work and never a wrong row.
#[test]
fn same_magnitude_numbers_are_the_documented_exception() {
    let p53: i64 = 1 << 53;
    #[allow(clippy::cast_precision_loss)]
    let p53f = p53 as f64;
    let base: i64 = 1 << 54;
    #[allow(clippy::cast_precision_loss)]
    let mid = (base + 4) as f64;

    // (a) COARSENING: two distinct large integers share one key entirely, yet are strictly ordered.
    let (lo, hi) = (Value::Integer(base + 3), Value::Integer(base + 5));
    assert_eq!(
        encode_single(&lo).unwrap(),
        encode_single(&hi).unwrap(),
        "2^54+3 and 2^54+5 round to the same double, so they share one index key"
    );
    assert_eq!(cmp_values(&lo, &hi), Ordering::Less, "but 2^54+3 < 2^54+5");

    // (b) INVERSION: the FLOAT tie-break byte sorts above the INTEGER one, while the float is the
    // smaller number. This is the pair `rmp` #894 made exact.
    let (f53, i53p1) = (Value::Float(p53f), Value::Integer(p53 + 1));
    assert_eq!(
        key_magnitude(&encode_single(&f53).unwrap()),
        key_magnitude(&encode_single(&i53p1).unwrap()),
        "Float(2^53) and Integer(2^53+1) share one key magnitude"
    );
    assert_eq!(
        encode_single(&f53)
            .unwrap()
            .cmp(&encode_single(&i53p1).unwrap()),
        Ordering::Greater,
        "byte order puts the FLOAT above (the numtag tie-break)"
    );
    assert_eq!(
        cmp_values(&f53, &i53p1),
        Ordering::Less,
        "but 2^53.0 is the SMALLER number — the documented inversion"
    );

    // (c) The tie-break is only reached for genuinely equal numbers, where both agree.
    let (i53, f53b) = (Value::Integer(p53), Value::Float(p53f));
    assert_eq!(
        cmp_values(&i53, &f53b),
        Ordering::Less,
        "INTEGER before FLOAT"
    );
    assert_eq!(
        encode_single(&i53)
            .unwrap()
            .cmp(&encode_single(&f53b).unwrap()),
        Ordering::Less,
        "and the byte order agrees when the numbers really are equal"
    );

    // (d) An integer either side of the double it shares a magnitude with.
    assert_eq!(
        cmp_values(&Value::Integer(base + 3), &Value::Float(mid)),
        Ordering::Less
    );
    assert_eq!(
        cmp_values(&Value::Integer(base + 5), &Value::Float(mid)),
        Ordering::Greater
    );
}

#[test]
fn cross_class_pairs_agree_at_the_class_boundary() {
    // One representative per encodable class, in the CIP ascending order, then assert *both*
    // cmp_values and the byte order agree on every ordered pair (a strict-increasing chain).
    let chain = [
        // POINT is the lowest encodable class (`… < PATH < POINT < {temporals} < STRING < …`).
        Value::Point(Point::new_3d(Crs::Wgs84_3D, f64::MAX, f64::MAX, f64::MAX)),
        Value::zoned_date_time(ZonedDateTime::default()),
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
