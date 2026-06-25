//! **Dictionary** codec for byte-string columns (the big win for low-cardinality strings: labels,
//! enum-like properties, repeated names).
//!
//! Distinct values are collected into a dictionary (sorted for deterministic output); each row is
//! replaced by a bit-packed integer **code** into that dictionary. A column of N rows with D
//! distinct values costs `D` stored strings + `N·⌈log2 D⌉` bits — versus N full copies in the row
//! store. Equality and `GROUP BY` can run directly on the integer codes (no string compares) — the
//! late-materialization property column-stores exploit. Round-trip exact.

use crate::DecodeError;
use crate::bitpack::{bits_required, pack, unpack};

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Reads a little-endian `u32` at `at`, or [`DecodeError::Truncated`] if `b` is too short (replaces a
/// panicking fixed-offset slice on untrusted input — `04 §11.4`).
fn get_u32(b: &[u8], at: usize, what: &'static str) -> Result<u32, DecodeError> {
    let end = at.checked_add(4).filter(|&e| e <= b.len());
    match end {
        Some(e) => Ok(u32::from_le_bytes(b[at..e].try_into().expect("4 bytes"))),
        None => Err(DecodeError::Truncated { what }),
    }
}

/// The parsed dictionary header: `(dict, code_width, codes_payload)` — the deduped dictionary
/// entries, the bit-packed code width, and the remaining code stream.
type DictHeader<'a> = (Vec<Vec<u8>>, u32, &'a [u8]);

/// Reads the dictionary header from `bytes`, bounds-checked against the buffer. Shared by [`decode`]
/// and [`decode_codes`] so both readers parse the dictionary identically and reject the same
/// malformed blobs.
///
/// Every `with_capacity` is clamped to the bytes that remain, so a forged entry count cannot trigger
/// an OOM-abort.
fn read_dict_header(bytes: &[u8]) -> Result<DictHeader<'_>, DecodeError> {
    let num = get_u32(bytes, 0, "dictionary entry count")? as usize;
    let mut pos = 4usize;
    // Clamp: there can be at most one entry per remaining byte (each costs a 4-byte length prefix),
    // so a `num` larger than that is corrupt — cap the pre-allocation accordingly.
    let cap = num.min(bytes.len().saturating_sub(pos));
    let mut dict: Vec<Vec<u8>> = Vec::with_capacity(cap);
    for _ in 0..num {
        let len = get_u32(bytes, pos, "dictionary entry length")? as usize;
        pos += 4;
        let end =
            pos.checked_add(len)
                .filter(|&e| e <= bytes.len())
                .ok_or(DecodeError::Truncated {
                    what: "dictionary entry bytes",
                })?;
        dict.push(bytes[pos..end].to_vec());
        pos = end;
    }
    let width = u32::from(*bytes.get(pos).ok_or(DecodeError::Truncated {
        what: "dictionary code width",
    })?);
    pos += 1;
    Ok((dict, width, &bytes[pos..]))
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

    // The entry count and code width are written into `u32`/`u8` header fields; a dictionary with
    // more than `u32::MAX` distinct values (or a code width > 64) would silently truncate and corrupt
    // the blob. Such a column is astronomically larger than any real graph, so this is a programming
    // invariant, asserted rather than handled.
    assert!(
        distinct.len() <= u32::MAX as usize,
        "dictionary cardinality {} exceeds the u32 code/count field",
        distinct.len()
    );

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
///
/// `bytes` may be **untrusted**: a truncated blob, an over-long entry length, or a code that indexes
/// past the dictionary is reported as [`DecodeError`] rather than panicking (`04 §11.4`).
///
/// # Errors
/// Returns [`DecodeError::Truncated`] for a short/over-long blob or [`DecodeError::BadCode`] if a row
/// code is `>=` the dictionary length.
pub fn decode(bytes: &[u8], count: usize) -> Result<Vec<Vec<u8>>, DecodeError> {
    let (dict, width, codes_payload) = read_dict_header(bytes)?;
    let codes = unpack(codes_payload, count, width)?;
    let mut out = Vec::with_capacity(codes.len());
    for c in codes {
        let entry = dict.get(c as usize).ok_or(DecodeError::BadCode {
            code: c,
            dict_len: dict.len(),
        })?;
        out.push(entry.clone());
    }
    Ok(out)
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
///
/// # Errors
/// Returns [`DecodeError::Truncated`] for a short/over-long blob, or [`DecodeError::BadCode`] if a row
/// code is `>=` the dictionary length (so the caller's later `dict[code]` indexing cannot panic).
pub fn decode_codes(bytes: &[u8], count: usize) -> Result<(Vec<u32>, Vec<Vec<u8>>), DecodeError> {
    let (dict, width, codes_payload) = read_dict_header(bytes)?;
    let raw = unpack(codes_payload, count, width)?;
    let mut codes = Vec::with_capacity(raw.len());
    for c in raw {
        // Validate every code against the dictionary now, so the caller's `dict[code]` is total.
        if c as usize >= dict.len() {
            return Err(DecodeError::BadCode {
                code: c,
                dict_len: dict.len(),
            });
        }
        codes.push(c as u32);
    }
    Ok((codes, dict))
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
        assert_eq!(decode(&enc, values.len()).unwrap(), values);
        assert_eq!(cardinality(&values), 3);
    }

    #[test]
    fn low_cardinality_over_many_rows_compresses_hard() {
        // 10k rows, 4 distinct categories → ~2-bit codes + 4 small strings.
        let cats = [b("gold"), b("silver"), b("bronze"), b("none")];
        let values: Vec<Vec<u8>> = (0..10_000).map(|i| cats[i % 4].clone()).collect();
        let raw: usize = values.iter().map(Vec::len).sum();
        let enc = encode(&values);
        assert_eq!(decode(&enc, values.len()).unwrap(), values);
        assert!(
            enc.len() * 4 < raw,
            "dict must beat 4x on 4-category data: {} vs {raw}",
            enc.len()
        );
    }

    #[test]
    fn empty_and_single() {
        assert_eq!(decode(&encode(&[]), 0).unwrap(), Vec::<Vec<u8>>::new());
        let one = vec![b("only")];
        assert_eq!(decode(&encode(&one), 1).unwrap(), one);
    }

    #[test]
    fn decode_rejects_malformed_blobs_without_panic_or_oom() {
        // Entry count 0xFFFFFFFF over a 4-byte buffer: must error up front, never allocate 4 GiB
        // (the confirmed `dictionary.rs` OOM/OOB repro from rmp #402).
        let bomb = 0xFFFF_FFFFu32.to_le_bytes();
        assert!(matches!(
            decode(&bomb, 0),
            Err(DecodeError::Truncated { .. })
        ));
        assert!(matches!(
            decode_codes(&bomb, 0),
            Err(DecodeError::Truncated { .. })
        ));
        // An entry whose declared length runs past the buffer end → Truncated.
        let mut over = Vec::new();
        put_u32(&mut over, 1); // one entry
        put_u32(&mut over, 0xFFFF_FFFF); // ...of 4 GiB (absent)
        assert!(matches!(
            decode(&over, 0),
            Err(DecodeError::Truncated { .. })
        ));
        // A valid dictionary header but a code that indexes past the (1-entry) dict → BadCode.
        // Build: num=1, len=1, byte 'x', width=8, one code byte = 5 (out of range).
        let mut blob = Vec::new();
        put_u32(&mut blob, 1);
        put_u32(&mut blob, 1);
        blob.push(b'x');
        blob.push(8); // width
        blob.push(5); // code 5 >= dict_len 1
        assert!(matches!(
            decode(&blob, 1),
            Err(DecodeError::BadCode {
                code: 5,
                dict_len: 1
            })
        ));
        assert!(matches!(
            decode_codes(&blob, 1),
            Err(DecodeError::BadCode {
                code: 5,
                dict_len: 1
            })
        ));
        // Empty buffer → Truncated (no entry count to read).
        assert!(matches!(decode(&[], 0), Err(DecodeError::Truncated { .. })));
    }

    #[test]
    fn decode_codes_is_consistent_with_decode_and_canonical() {
        let cities = ["Lisbon", "Porto", "Madrid", "Lisbon", "Porto", "Lisbon"];
        let values: Vec<Vec<u8>> = cities.iter().map(|s| b(s)).collect();
        let enc = encode(&values);
        let (codes, dict) = decode_codes(&enc, values.len()).unwrap();

        // 1. The dictionary is canonical: sorted ascending and deduplicated.
        assert_eq!(dict.len(), cardinality(&values));
        assert!(
            dict.windows(2).all(|w| w[0] < w[1]),
            "dict must be sorted, deduped"
        );

        // 2. Late materialization (dict[code]) reproduces `decode` byte-for-byte.
        let materialized: Vec<Vec<u8>> = codes.iter().map(|&c| dict[c as usize].clone()).collect();
        assert_eq!(materialized, decode(&enc, values.len()).unwrap());
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
        let (c, d) = decode_codes(&encode(&[]), 0).unwrap();
        assert!(c.is_empty() && d.is_empty());
        let one = vec![b("only")];
        let (c, d) = decode_codes(&encode(&one), 1).unwrap();
        assert_eq!(c, vec![0]);
        assert_eq!(d, one);
    }
}
