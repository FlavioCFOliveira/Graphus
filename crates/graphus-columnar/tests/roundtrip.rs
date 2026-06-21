//! Property-based round-trip exactness for every columnar codec: encode∘decode == identity for
//! arbitrary inputs (the inviolable correctness contract of a lossless compression foundation).

use graphus_columnar::{bitpack, decode_bool, dictionary, encode_bool, gorilla, integer};
use proptest::prelude::*;

proptest! {
    #[test]
    fn integer_round_trip(values in prop::collection::vec(any::<i64>(), 0..512)) {
        let enc = integer::encode_i64(&values);
        prop_assert_eq!(integer::decode_i64(&enc, values.len()), values);
    }

    #[test]
    fn integer_bounded_round_trip(values in prop::collection::vec(0i64..1000, 0..512)) {
        let enc = integer::encode_i64(&values);
        prop_assert_eq!(integer::decode_i64(&enc, values.len()), values);
    }

    #[test]
    fn float_round_trip(values in prop::collection::vec(any::<f64>(), 0..512)) {
        let enc = gorilla::encode(&values);
        let dec = gorilla::decode(&enc, values.len());
        prop_assert_eq!(dec.len(), values.len());
        for (a, b) in dec.iter().zip(&values) {
            prop_assert_eq!(a.to_bits(), b.to_bits()); // exact, incl. NaN/±0/inf
        }
    }

    #[test]
    fn dictionary_round_trip(values in prop::collection::vec(
        prop::collection::vec(any::<u8>(), 0..8), 0..512)) {
        let enc = dictionary::encode(&values);
        prop_assert_eq!(dictionary::decode(&enc, values.len()), values);
    }

    #[test]
    fn bool_round_trip(values in prop::collection::vec(any::<bool>(), 0..1024)) {
        let enc = encode_bool(&values);
        prop_assert_eq!(decode_bool(&enc, values.len()), values);
    }

    #[test]
    fn bitpack_round_trip(values in prop::collection::vec(0u64..(1<<20), 0..512)) {
        let width = 20;
        let enc = bitpack::pack(&values, width);
        prop_assert_eq!(bitpack::unpack(&enc, values.len(), width), values);
    }
}
