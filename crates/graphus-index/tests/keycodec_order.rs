//! Order property tests for the order-preserving key encoding (`04-technical-design.md` §6.2,
//! §7.6): for random value pairs across every supported type, the encoded byte order must equal
//! Cypher value order, **both ways**.
//!
//! ```text
//! encode(a).cmp(encode(b)) == cypher_cmp(a, b)
//! ```
//!
//! The reference order ([`cypher_cmp`]) is the Cypher `ORDER BY` total order (`04 §7.6`) restricted
//! to the indexable scalar value classes: `BOOLEAN < NUMBER < STRING < BYTES`, numbers compared
//! numerically across `INTEGER`/`FLOAT`, strings by codepoint, with `NaN` the largest float. This
//! is the same order the encoding is *derived* from, so the test is a genuine cross-check (the
//! encoder and the reference are written independently). Values are generated with
//! [`graphus_sim::SimRng`] for deterministic, reproducible runs.

use std::cmp::Ordering;

use graphus_core::Value;
use graphus_core::capability::Rng;
use graphus_index::keycodec::{encode_composite, encode_single};
use graphus_sim::SimRng;

/// The reference Cypher value-class rank (ascending), used to order values of different classes.
fn class_rank(v: &Value) -> u8 {
    match v {
        Value::Boolean(_) => 0,
        Value::Integer(_) | Value::Float(_) => 1,
        Value::String(_) => 2,
        Value::Bytes(_) => 3,
        other => panic!("unindexable value in order test: {other:?}"),
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

/// The reference Cypher order over two indexable scalars.
fn cypher_cmp(a: &Value, b: &Value) -> Ordering {
    let (ra, rb) = (class_rank(a), class_rank(b));
    if ra != rb {
        return ra.cmp(&rb);
    }
    match (a, b) {
        (Value::Boolean(x), Value::Boolean(y)) => x.cmp(y),
        (Value::String(x), Value::String(y)) => x.as_bytes().cmp(y.as_bytes()),
        (Value::Bytes(x), Value::Bytes(y)) => x.cmp(y),
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

/// Generates a random indexable scalar, biased toward edge cases (zeros, signs, specials, empty
/// and embedded-null strings).
fn gen_value(rng: &mut SimRng) -> Value {
    let r = rng.next_u64();
    match r % 8 {
        0 => Value::Boolean(r & 0x100 != 0),
        1 | 2 => {
            // Integers including extremes and around zero.
            let pick = rng.next_u64() % 6;
            let i = match pick {
                0 => i64::MIN,
                1 => i64::MAX,
                2 => 0,
                3 => -1,
                4 => 1,
                _ => rng.next_u64() as i64,
            };
            Value::Integer(i)
        }
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
        _ => {
            let n = (rng.next_u64() % 5) as usize;
            let b: Vec<u8> = (0..n).map(|_| (rng.next_u64() & 0xFF) as u8).collect();
            Value::Bytes(b)
        }
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
