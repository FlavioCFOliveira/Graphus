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

/// A failure decoding a columnar blob. The codecs are total functions on **well-formed** input
/// (every `encode`/`decode` round-trips); this error is the **controlled** outcome for a malformed,
/// truncated, or adversarial blob, so a decoder never panics or aborts on bad bytes
/// (`specification/04-technical-design.md` §11.4: a malformed input is a controlled error, never a
/// panic/abort). A decoder reads only header counts/widths it has range-checked against the bytes it
/// actually holds, and clamps every speculative `Vec::with_capacity` to the bytes remaining, so an
/// attacker-controlled length can neither over-read nor trigger an OOM-abort.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The blob ended before a field the header said was present (an out-of-bounds read was avoided).
    Truncated {
        /// What the decoder was reading when it ran out of bytes.
        what: &'static str,
    },
    /// A header byte names something this build cannot decode (e.g. an unknown integer sub-scheme).
    BadScheme {
        /// The offending scheme/tag byte.
        scheme: u8,
    },
    /// A dictionary code (row → dictionary index) is `>=` the dictionary length (corrupt blob).
    BadCode {
        /// The out-of-range code.
        code: u64,
        /// The dictionary length it must be `<`.
        dict_len: usize,
    },
    /// A self-describing field holds a value that cannot occur in any well-formed blob (e.g. a
    /// Gorilla per-value header declaring `leading + meaningful > 64` bits).
    Corrupt {
        /// What was inconsistent.
        what: &'static str,
    },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { what } => {
                write!(f, "columnar: blob truncated while reading {what}")
            }
            Self::BadScheme { scheme } => write!(f, "columnar: unknown codec scheme byte {scheme}"),
            Self::BadCode { code, dict_len } => write!(
                f,
                "columnar: dictionary code {code} out of range (dictionary has {dict_len} entries)"
            ),
            Self::Corrupt { what } => write!(f, "columnar: corrupt blob: {what}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encodes a boolean column as one bit per value (8x denser than one byte each).
#[must_use]
pub fn encode_bool(values: &[bool]) -> Vec<u8> {
    let bits: Vec<u64> = values.iter().map(|&b| u64::from(b)).collect();
    bitpack::pack(&bits, 1)
}

/// Decodes `count` booleans produced by [`encode_bool`].
///
/// # Errors
/// Returns [`DecodeError::Truncated`] if `bytes` is shorter than the `count` one-bit values require.
pub fn decode_bool(bytes: &[u8], count: usize) -> Result<Vec<bool>, DecodeError> {
    Ok(bitpack::unpack(bytes, count, 1)?
        .into_iter()
        .map(|b| b != 0)
        .collect())
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
        assert_eq!(decode_bool(&enc, values.len()).unwrap(), values);
    }

    #[test]
    fn decode_bool_truncated_is_error_not_panic() {
        // A bitmap that claims more bits than its bytes can hold must error, never read OOB.
        assert_eq!(
            decode_bool(&[0xFF], 1000),
            Err(DecodeError::Truncated {
                what: "bit-packed values"
            })
        );
        // Zero bytes, zero count is still fine.
        assert_eq!(decode_bool(&[], 0), Ok(Vec::new()));
    }
}
