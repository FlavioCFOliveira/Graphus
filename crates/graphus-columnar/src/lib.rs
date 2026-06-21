//! # graphus-columnar
//!
//! Native, **dependency-light, round-trip-exact** columnar value codecs — the compression foundation
//! for Graphus's *complementary* columnar paths (bulk/cold export, the time-series cold tier,
//! zone-maps, column segments). It deliberately pulls **no external crates**: Graphus already
//! hand-rolls its on-disk codecs (`graphus-storage::{propenc,valenc}`), and a graph database server
//! that must run on Raspberry Pi as well as a server keeps its dependency tree (and binary) lean.
//!
//! It is a **leaf** crate: nothing in the authoritative write path (`graphus-storage`, `graphus-wal`,
//! `graphus-txn`) depends on it, so it adds zero risk to ACID/MVCC/recovery. Consumers map a logical
//! column of values to one of the typed encoders below, pick the codec that fits the column's shape,
//! and store the self-describing blob alongside a row count.
//!
//! ## Codecs
//! - [`integer`] — Frame-of-Reference / Delta / Double-Delta for `i64` columns (auto-selected).
//!   Monotonic fixed-cadence columns (IoT timestamps/sequence numbers) collapse to ~constant size.
//! - [`dictionary`] — low-cardinality byte-string columns (labels, enum-like properties, repeated
//!   names): a sorted dictionary + bit-packed codes; equality/`GROUP BY` can run on the codes.
//! - [`gorilla`] — Gorilla XOR for `f64` columns (slowly-varying sensor readings).
//! - [`bitpack`] — the fixed-width bit-packing primitive the integer/dictionary codecs build on;
//!   also the direct codec for boolean columns ([`encode_bool`]).
//!
//! Every codec is **exact** (lossless, bit-for-bit) and proptest-validated (`tests/roundtrip.rs`).

pub mod bitpack;
pub mod dictionary;
pub mod gorilla;
pub mod integer;

/// Encodes a boolean column as one bit per value (8x denser than one byte each).
#[must_use]
pub fn encode_bool(values: &[bool]) -> Vec<u8> {
    let bits: Vec<u64> = values.iter().map(|&b| u64::from(b)).collect();
    bitpack::pack(&bits, 1)
}

/// Decodes `count` booleans produced by [`encode_bool`].
#[must_use]
pub fn decode_bool(bytes: &[u8], count: usize) -> Vec<bool> {
    bitpack::unpack(bytes, count, 1)
        .into_iter()
        .map(|b| b != 0)
        .collect()
}

/// The codec families, recorded as a one-byte tag when a consumer stores a typed column so it can
/// dispatch on decode. (Consumers that always know the column type statically need not use this.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CodecKind {
    /// [`integer`] `i64` column (FOR / Delta / Double-Delta — self-describing within the blob).
    Integer = 1,
    /// [`gorilla`] `f64` column.
    Float = 2,
    /// [`dictionary`] byte-string column.
    Dictionary = 3,
    /// [`encode_bool`] boolean column.
    Bool = 4,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bool_round_trip() {
        let values: Vec<bool> = (0..1000).map(|i| i % 3 == 0).collect();
        let enc = encode_bool(&values);
        // 1000 bits = 125 bytes vs 1000 bytes raw.
        assert!(enc.len() <= 126);
        assert_eq!(decode_bool(&enc, values.len()), values);
    }
}
