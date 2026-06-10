//! Property-based invariants for the **order-preserving** index key codec (`rmp` task #27, the
//! verification arsenal's proptest TR).
//!
//! The memcmp B+-tree returns rows in exactly openCypher orderability order **iff** the key encoding
//! is order-preserving: `cmp_values(a, b) == encode_single(a).cmp(encode_single(b))` for every
//! index-encodable value (CIP2016-06-14 §Orderability; `04 §7.6`). A deterministic 100k-iteration
//! cross-check already lives next door in `ordering_vs_keycodec.rs`; this adds the `proptest`
//! formulation, whose extra value is **shrinking** — a regression is reported as the *minimal*
//! disagreeing value pair, far easier to debug than a random 64-bit blob.
//!
//! It lives in `graphus-cypher`'s test suite (not `graphus-index`'s) because it needs both
//! [`cmp_values`] (defined here) and [`encode_single`] (in `graphus-index`); `graphus-cypher` already
//! dev-depends on `graphus-index`, whereas the reverse edge would be a dependency cycle.
//!
//! Two further intrinsic invariants are checked, independent of the comparator:
//!
//! - **Total order on bytes**: `encode_single(v)` is deterministic (a value's encoding compares
//!   `Equal` to itself) and antisymmetric (swapping operands reverses the byte order).
//! - **Prefix-free composite framing**: a 2-tuple's encoding equals the concatenation of its fields'
//!   encodings, and lexicographic byte order over composites equals tuple order — the property that
//!   makes leading-prefix range scans correct (`04 §6.2`).

use std::cmp::Ordering;

use graphus_core::Value;
use graphus_cypher::ordering::cmp_values;
use graphus_index::keycodec::{encode_composite, encode_single};
use proptest::prelude::*;

/// A strategy over the **index-encodable** scalar classes (the subset both `cmp_values` and the key
/// codec define): `Boolean`, `Integer`, `Float`, `String`, `Bytes`. `null`/`List`/`Map` are excluded
/// because `encode_single` rejects them (not index-encodable); the temporal classes are covered by
/// the deterministic neighbour test. Here we focus on the scalar core, where shrinking is most
/// informative.
fn encodable_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<bool>().prop_map(Value::Boolean),
        any::<i64>().prop_map(Value::Integer),
        // Arbitrary float bit patterns (NaN / ±inf / ±0 / subnormal) so order-preservation is tested
        // at every IEEE-754 edge the codec must normalise.
        any::<u64>().prop_map(|b| Value::Float(f64::from_bits(b))),
        proptest::string::string_regex(".{0,24}")
            .expect("regex")
            .prop_map(Value::String),
        prop::collection::vec(any::<u8>(), 0..24).prop_map(Value::Bytes),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// The headline cross-check: Cypher orderability equals the key codec's byte order, for every
    /// encodable pair. This is the proof a memcmp B+-tree returns Cypher-ordered rows.
    #[test]
    fn cypher_order_equals_byte_order(a in encodable_value(), b in encodable_value()) {
        let by_cmp = cmp_values(&a, &b);
        let ea = encode_single(&a).expect("encodable value encodes");
        let eb = encode_single(&b).expect("encodable value encodes");
        let by_bytes = ea.cmp(&eb);
        prop_assert_eq!(
            by_cmp, by_bytes,
            "ordering/keycodec disagree: cmp_values({:?}, {:?}) = {:?}, byte order = {:?}",
            a, b, by_cmp, by_bytes
        );
    }

    /// The byte order is a total order: encoding is deterministic (a value compares `Equal` to
    /// itself) and antisymmetric (swapping operands reverses the result).
    #[test]
    fn byte_order_is_total(a in encodable_value(), b in encodable_value()) {
        let ea = encode_single(&a).expect("encodes");
        let eb = encode_single(&b).expect("encodes");
        prop_assert_eq!(ea.cmp(&ea), Ordering::Equal);
        prop_assert_eq!(ea.cmp(&eb), eb.cmp(&ea).reverse());
    }

    /// Composite framing is prefix-free: the 2-tuple encoding is the concatenation of the field
    /// encodings, and lexicographic byte order over composites equals tuple (field-lexicographic)
    /// order — the invariant that makes composite-index range scans correct.
    #[test]
    fn composite_byte_order_equals_tuple_order(
        a0 in encodable_value(), a1 in encodable_value(),
        b0 in encodable_value(), b1 in encodable_value(),
    ) {
        let ca = encode_composite(&[a0.clone(), a1.clone()]).expect("encodes");
        let cb = encode_composite(&[b0.clone(), b1.clone()]).expect("encodes");

        // Prefix-free concatenation: composite == field0 ++ field1.
        let mut manual = encode_single(&a0).expect("encodes");
        manual.extend_from_slice(&encode_single(&a1).expect("encodes"));
        prop_assert_eq!(&ca, &manual, "composite must be the concatenation of field encodings");

        // Tuple order: compare by field0, then field1 — must equal the byte order of the composite.
        let tuple_order = match cmp_values(&a0, &b0) {
            Ordering::Equal => cmp_values(&a1, &b1),
            other => other,
        };
        prop_assert_eq!(
            ca.cmp(&cb), tuple_order,
            "composite byte order must equal tuple order for ([{:?},{:?}] vs [{:?},{:?}])",
            a0, a1, b0, b1
        );
    }
}
