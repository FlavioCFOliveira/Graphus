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
    codes
        .into_iter()
        .map(|c| dict[c as usize].clone())
        .collect()
}

/// Decodes a dictionary-encoded column to its **raw codes and dictionary**, *without* materializing
/// one owned value per row — the late-materialization primitive (`rmp` task #375).
///
/// Returns `(codes, dict)` where `codes[i]` is the dictionary index of row `i` and `dict[c]` is the
/// `c`-th distinct value. A consumer doing equality / `GROUP BY` folds on the integer `codes`
/// (no string compares, no per-row `String` rebuild) and materializes a row's value — `dict[code]` —
/// only when it is actually needed (e.g. a fresh, snapshot-visible candidate).
///
/// # The canonical-dictionary guarantee (why code-equality ⟺ value-equality)
///
/// [`encode`] builds `dict` by `sort_unstable()` **then** `dedup()`, so it is **canonical**: sorted
/// ascending and free of duplicates. Two distinct codes therefore index two *distinct* byte strings,
/// and equal byte strings always share one code. Hence on this column:
///
/// * `codes[i] == codes[j]` **iff** `dict[codes[i]] == dict[codes[j]]` (fold equality / grouping on
///   the codes with no false merges and no false splits), and
/// * the code order is the byte-lexicographic value order (a code comparison is a value comparison).
///
/// `decode(bytes, count)` is exactly `decode_codes(bytes, count).codes.map(|c| dict[c].clone())`, so
/// the two readers never diverge by a byte.
#[must_use]
pub fn decode_codes(bytes: &[u8], count: usize) -> (Vec<u32>, Vec<Vec<u8>>) {
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
    let codes = unpack(&bytes[pos..], count, width)
        .into_iter()
        .map(|c| c as u32)
        .collect();
    (codes, dict)
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
        assert!(
            enc.len() * 4 < raw,
            "dict must beat 4x on 4-category data: {} vs {raw}",
            enc.len()
        );
    }

    #[test]
    fn empty_and_single() {
        assert_eq!(decode(&encode(&[]), 0), Vec::<Vec<u8>>::new());
        let one = vec![b("only")];
        assert_eq!(decode(&encode(&one), 1), one);
    }

    #[test]
    fn decode_codes_is_consistent_with_decode_and_canonical() {
        let cities = ["Lisbon", "Porto", "Madrid", "Lisbon", "Porto", "Lisbon"];
        let values: Vec<Vec<u8>> = cities.iter().map(|s| b(s)).collect();
        let enc = encode(&values);
        let (codes, dict) = decode_codes(&enc, values.len());

        // 1. The dictionary is canonical: sorted ascending and deduplicated.
        assert_eq!(dict.len(), cardinality(&values));
        assert!(
            dict.windows(2).all(|w| w[0] < w[1]),
            "dict must be sorted, deduped"
        );

        // 2. Late materialization (dict[code]) reproduces `decode` byte-for-byte.
        let materialized: Vec<Vec<u8>> = codes.iter().map(|&c| dict[c as usize].clone()).collect();
        assert_eq!(materialized, decode(&enc, values.len()));
        assert_eq!(materialized, values);

        // 3. code-equality ⟺ value-equality (the fold-on-codes soundness property).
        for i in 0..values.len() {
            for j in 0..values.len() {
                assert_eq!(codes[i] == codes[j], values[i] == values[j]);
            }
        }
    }

    #[test]
    fn decode_codes_empty_and_single() {
        let (c, d) = decode_codes(&encode(&[]), 0);
        assert!(c.is_empty() && d.is_empty());
        let one = vec![b("only")];
        let (c, d) = decode_codes(&encode(&one), 1);
        assert_eq!(c, vec![0]);
        assert_eq!(d, one);
    }
}
