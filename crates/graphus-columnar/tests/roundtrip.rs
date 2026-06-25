//! Property-based round-trip exactness for every columnar codec: encode∘decode == identity for
//! arbitrary inputs (the inviolable correctness contract of a lossless compression foundation).

use graphus_columnar::{bitpack, decode_bool, dictionary, encode_bool, gorilla, integer};
use proptest::prelude::*;

proptest! {
    #[test]
    fn integer_round_trip(values in prop::collection::vec(any::<i64>(), 0..512)) {
        let enc = integer::encode_i64(&values);
        prop_assert_eq!(integer::decode_i64(&enc, values.len()).unwrap(), values);
    }

    #[test]
    fn integer_bounded_round_trip(values in prop::collection::vec(0i64..1000, 0..512)) {
        let enc = integer::encode_i64(&values);
        prop_assert_eq!(integer::decode_i64(&enc, values.len()).unwrap(), values);
    }

    #[test]
    fn float_round_trip(values in prop::collection::vec(any::<f64>(), 0..512)) {
        let enc = gorilla::encode(&values);
        let dec = gorilla::decode(&enc, values.len()).unwrap();
        prop_assert_eq!(dec.len(), values.len());
        for (a, b) in dec.iter().zip(&values) {
            prop_assert_eq!(a.to_bits(), b.to_bits()); // exact, incl. NaN/±0/inf
        }
    }

    #[test]
    fn dictionary_round_trip(values in prop::collection::vec(
        prop::collection::vec(any::<u8>(), 0..8), 0..512)) {
        let enc = dictionary::encode(&values);
        prop_assert_eq!(dictionary::decode(&enc, values.len()).unwrap(), values);
    }

    #[test]
    fn bool_round_trip(values in prop::collection::vec(any::<bool>(), 0..1024)) {
        let enc = encode_bool(&values);
        prop_assert_eq!(decode_bool(&enc, values.len()).unwrap(), values);
    }

    #[test]
    fn bitpack_round_trip(values in prop::collection::vec(0u64..(1<<20), 0..512)) {
        let width = 20;
        let enc = bitpack::pack(&values, width);
        prop_assert_eq!(bitpack::unpack(&enc, values.len(), width).unwrap(), values);
    }

    // ----- Adversarial fuzz: a malformed blob must NEVER panic / OOM-abort (`04 §11.4`, rmp #402).
    // Every decoder is fed arbitrary bytes with an arbitrary (but bounded) declared count; the only
    // acceptable outcomes are a value or a `DecodeError` — a panic/abort fails the proptest process.

    #[test]
    fn integer_decode_never_panics_on_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..256),
        count in 0usize..4096,
    ) {
        let _ = integer::decode_i64(&bytes, count);
    }

    #[test]
    fn gorilla_decode_never_panics_on_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..256),
        count in 0usize..4096,
    ) {
        let _ = gorilla::decode(&bytes, count);
    }

    #[test]
    fn dictionary_decode_never_panics_on_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..256),
        count in 0usize..4096,
    ) {
        let _ = dictionary::decode(&bytes, count);
        let _ = dictionary::decode_codes(&bytes, count);
    }

    #[test]
    fn bitpack_unpack_never_panics_on_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..256),
        count in 0usize..4096,
        width in 0u32..=64,
    ) {
        let _ = bitpack::unpack(&bytes, count, width);
    }

    #[test]
    fn bool_decode_never_panics_on_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..256),
        count in 0usize..4096,
    ) {
        let _ = decode_bool(&bytes, count);
    }
}
