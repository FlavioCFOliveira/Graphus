//! **Dictionary** codec for byte-string columns (the big win for low-cardinality strings: labels,
//! enum-like properties, repeated names).
//!
//! Distinct values are collected into a dictionary (sorted for deterministic output); each row is
//! replaced by a bit-packed integer **code** into that dictionary. A column of N rows with D
//! distinct values costs `D` stored strings + `N·⌈log2 D⌉` bits — versus N full copies in the row
//! store. Equality and `GROUP BY` can run directly on the integer codes (no string compares) — the
//! late-materialization property column-stores exploit. Round-trip exact.

use crate::bitpack::{bits_required, pack, unpack};

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn get_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

/// Dictionary-encodes a column of byte-strings into a single self-describing blob.
#[must_use]
pub fn encode(values: &[Vec<u8>]) -> Vec<u8> {
    // Build the sorted distinct dictionary and a value→code map.
    let mut distinct: Vec<&[u8]> = values.iter().map(Vec::as_slice).collect();
    distinct.sort_unstable();
    distinct.dedup();
    let code_of = |v: &[u8]| -> u64 {
        distinct.partition_point(|d| *d < v) as u64 // binary search: distinct is sorted
    };
    let codes: Vec<u64> = values.iter().map(|v| code_of(v)).collect();
    let width = bits_required(distinct.len().saturating_sub(1) as u64);

    let mut out = Vec::new();
    put_u32(&mut out, distinct.len() as u32);
    for d in &distinct {
        put_u32(&mut out, d.len() as u32);
        out.extend_from_slice(d);
    }
    out.push(width as u8);
    out.extend_from_slice(&pack(&codes, width));
    out
}

/// Decodes `count` byte-string values produced by [`encode`].
#[must_use]
pub fn decode(bytes: &[u8], count: usize) -> Vec<Vec<u8>> {
    let num = get_u32(bytes, 0) as usize;
    let mut pos = 4usize;
    let mut dict: Vec<Vec<u8>> = Vec::with_capacity(num);
    for _ in 0..num {
        let len = get_u32(bytes, pos) as usize;
        pos += 4;
        dict.push(bytes[pos..pos + len].to_vec());
        pos += len;
    }
    let width = u32::from(bytes[pos]);
    pos += 1;
    let codes = unpack(&bytes[pos..], count, width);
    codes.into_iter().map(|c| dict[c as usize].clone()).collect()
}

/// The number of distinct values in `values` — the signal a caller uses to decide whether dictionary
/// encoding pays (low cardinality) versus storing raw (high/unique cardinality).
#[must_use]
pub fn cardinality(values: &[Vec<u8>]) -> usize {
    let mut d: Vec<&[u8]> = values.iter().map(Vec::as_slice).collect();
    d.sort_unstable();
    d.dedup();
    d.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn round_trip_and_compression() {
        let cities = ["Lisbon", "Porto", "Madrid", "Lisbon", "Porto", "Lisbon"];
        let values: Vec<Vec<u8>> = cities.iter().map(|s| b(s)).collect();
        let enc = encode(&values);
        assert_eq!(decode(&enc, values.len()), values);
        assert_eq!(cardinality(&values), 3);
    }

    #[test]
    fn low_cardinality_over_many_rows_compresses_hard() {
        // 10k rows, 4 distinct categories → ~2-bit codes + 4 small strings.
        let cats = [b("gold"), b("silver"), b("bronze"), b("none")];
        let values: Vec<Vec<u8>> = (0..10_000).map(|i| cats[i % 4].clone()).collect();
        let raw: usize = values.iter().map(Vec::len).sum();
        let enc = encode(&values);
        assert_eq!(decode(&enc, values.len()), values);
        assert!(enc.len() * 4 < raw, "dict must beat 4x on 4-category data: {} vs {raw}", enc.len());
    }

    #[test]
    fn empty_and_single() {
        assert_eq!(decode(&encode(&[]), 0), Vec::<Vec<u8>>::new());
        let one = vec![b("only")];
        assert_eq!(decode(&encode(&one), 1), one);
    }
}
