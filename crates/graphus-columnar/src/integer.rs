//! Self-describing **integer column** codec: Frame-of-Reference, Delta, and Double-Delta, each
//! reduced to a bit-packed residual stream, with automatic selection of the smallest encoding.
//!
//! - **Frame-of-Reference (FOR):** subtract the column minimum, bit-pack the offsets. Best for a
//!   bounded-range column (e.g. an `age`, a small enum-like integer).
//! - **Delta:** store the first value, bit-pack the (zig-zag) consecutive differences. Best for a
//!   slowly-changing or sorted column.
//! - **Double-Delta:** store the first value and first delta, bit-pack the (zig-zag) second-order
//!   differences. Best for a **monotonic, fixed-cadence** column — exactly the IoT timestamp/seq
//!   case (`ts = base + i*tick` ⇒ all double-deltas are `0` ⇒ ~0 payload).
//!
//! The encoder tries all three and keeps the smallest; the first byte records the winner, so
//! [`decode_i64`] is self-describing. Round-trip exact (tested here + by crate proptests). Encodings
//! of `u64` columns go through [`encode_i64`] after a reversible `as i64` reinterpret by the caller.

use crate::DecodeError;
use crate::bitpack::{bits_required, pack, unpack};

const FOR: u8 = 0;
const DELTA: u8 = 1;
const DOUBLE_DELTA: u8 = 2;

/// Zig-zag maps a signed integer to an unsigned one so small-magnitude values (positive *or*
/// negative) get small codes: `0,-1,1,-2,2 → 0,1,2,3,4`.
fn zigzag(n: i64) -> u64 {
    ((n << 1) ^ (n >> 63)) as u64
}
fn unzigzag(z: u64) -> i64 {
    ((z >> 1) as i64) ^ -((z & 1) as i64)
}

/// Frame-of-Reference pack of unsigned values: returns `(min, width, payload)`.
fn for_pack(vals: &[u64]) -> (u64, u32, Vec<u8>) {
    let min = vals.iter().copied().min().unwrap_or(0);
    let max_off = vals.iter().map(|&v| v - min).max().unwrap_or(0);
    let width = bits_required(max_off);
    let offs: Vec<u64> = vals.iter().map(|&v| v - min).collect();
    (min, width, pack(&offs, width))
}
fn for_unpack(min: u64, width: u32, payload: &[u8], count: usize) -> Result<Vec<u64>, DecodeError> {
    Ok(unpack(payload, count, width)?
        .into_iter()
        .map(|o| min.wrapping_add(o))
        .collect())
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Reads a little-endian `u64` at `at`, or [`DecodeError::Truncated`] if `b` is too short (replaces
/// a panicking fixed-offset slice on untrusted input).
fn get_u64(b: &[u8], at: usize, what: &'static str) -> Result<u64, DecodeError> {
    let end = at.checked_add(8).filter(|&e| e <= b.len());
    match end {
        Some(e) => Ok(u64::from_le_bytes(b[at..e].try_into().expect("8 bytes"))),
        None => Err(DecodeError::Truncated { what }),
    }
}

/// Reads the `width` byte at `at`, or [`DecodeError::Truncated`].
fn get_width(b: &[u8], at: usize) -> Result<u32, DecodeError> {
    b.get(at)
        .map(|&w| u32::from(w))
        .ok_or(DecodeError::Truncated { what: "bit width" })
}

fn encode_for(values: &[i64]) -> Vec<u8> {
    let u: Vec<u64> = values.iter().map(|&v| v as u64).collect();
    let (min, width, payload) = for_pack(&u);
    let mut out = Vec::with_capacity(payload.len() + 10);
    out.push(FOR);
    put_u64(&mut out, min);
    out.push(width as u8);
    out.extend_from_slice(&payload);
    out
}

fn encode_delta(values: &[i64]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(DELTA);
    put_u64(&mut out, values[0] as u64);
    let zz: Vec<u64> = (1..values.len())
        .map(|i| zigzag(values[i].wrapping_sub(values[i - 1])))
        .collect();
    let (min, width, payload) = for_pack(&zz);
    put_u64(&mut out, min);
    out.push(width as u8);
    out.extend_from_slice(&payload);
    out
}

fn encode_double_delta(values: &[i64]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(DOUBLE_DELTA);
    put_u64(&mut out, values[0] as u64);
    let d1 = if values.len() >= 2 {
        values[1].wrapping_sub(values[0])
    } else {
        0
    };
    put_u64(&mut out, d1 as u64);
    let zz: Vec<u64> = (2..values.len())
        .map(|i| {
            let d = values[i].wrapping_sub(values[i - 1]);
            let prev = values[i - 1].wrapping_sub(values[i - 2]);
            zigzag(d.wrapping_sub(prev))
        })
        .collect();
    let (min, width, payload) = for_pack(&zz);
    put_u64(&mut out, min);
    out.push(width as u8);
    out.extend_from_slice(&payload);
    out
}

/// Encodes an `i64` column, choosing the smallest of FOR / Delta / Double-Delta. Empty input
/// encodes as a single FOR header (decodes back to an empty column given `count == 0`).
#[must_use]
pub fn encode_i64(values: &[i64]) -> Vec<u8> {
    if values.is_empty() {
        return vec![FOR, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    }
    let a = encode_for(values);
    if values.len() == 1 {
        return a;
    }
    let b = encode_delta(values);
    let c = encode_double_delta(values);
    [a, b, c]
        .into_iter()
        .min_by_key(Vec::len)
        .expect("non-empty")
}

/// Decodes an `i64` column of `count` values produced by [`encode_i64`].
///
/// `bytes` may be **untrusted**: a truncated blob, an unknown scheme byte, or a payload too short for
/// the declared width is reported as [`DecodeError`] rather than panicking
/// (`specification/04-technical-design.md` §11.4).
///
/// # Errors
/// Returns [`DecodeError::Truncated`] if the blob ends before a field it must read, or
/// [`DecodeError::BadScheme`] if the leading scheme byte is not FOR / Delta / Double-Delta.
pub fn decode_i64(bytes: &[u8], count: usize) -> Result<Vec<i64>, DecodeError> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let scheme = *bytes.first().ok_or(DecodeError::Truncated {
        what: "integer scheme byte",
    })?;
    match scheme {
        FOR => {
            let min = get_u64(bytes, 1, "FOR min")?;
            let width = get_width(bytes, 9)?;
            let payload = bytes.get(10..).unwrap_or(&[]);
            Ok(for_unpack(min, width, payload, count)?
                .into_iter()
                .map(|u| u as i64)
                .collect())
        }
        DELTA => {
            let first = get_u64(bytes, 1, "Delta first")? as i64;
            let min = get_u64(bytes, 9, "Delta min")?;
            let width = get_width(bytes, 17)?;
            let payload = bytes.get(18..).unwrap_or(&[]);
            let zz = for_unpack(min, width, payload, count - 1)?;
            let mut out = Vec::with_capacity(count);
            out.push(first);
            let mut cur = first;
            for z in zz {
                cur = cur.wrapping_add(unzigzag(z));
                out.push(cur);
            }
            Ok(out)
        }
        DOUBLE_DELTA => {
            let first = get_u64(bytes, 1, "Double-Delta first")? as i64;
            let d1 = get_u64(bytes, 9, "Double-Delta d1")? as i64;
            let min = get_u64(bytes, 17, "Double-Delta min")?;
            let width = get_width(bytes, 25)?;
            let nzz = count.saturating_sub(2);
            let payload = bytes.get(26..).unwrap_or(&[]);
            let zz = for_unpack(min, width, payload, nzz)?;
            let mut out = Vec::with_capacity(count);
            out.push(first);
            if count >= 2 {
                let mut cur = first.wrapping_add(d1);
                out.push(cur);
                let mut delta = d1;
                for z in zz {
                    delta = delta.wrapping_add(unzigzag(z));
                    cur = cur.wrapping_add(delta);
                    out.push(cur);
                }
            }
            Ok(out)
        }
        other => Err(DecodeError::BadScheme { scheme: other }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(values: &[i64]) {
        let enc = encode_i64(values);
        assert_eq!(
            decode_i64(&enc, values.len()).unwrap(),
            values,
            "round-trip"
        );
    }

    #[test]
    fn round_trips() {
        rt(&[]);
        rt(&[42]);
        rt(&[0, 0, 0, 0]);
        rt(&[1, 2, 3, 4, 5]); // delta-friendly
        rt(&[-5, -4, -3, -2]); // negatives
        rt(&[100, 100, 100, 200, 200]); // FOR-friendly
        rt(&[i64::MIN, 0, i64::MAX]); // extremes
        rt(&[10, 20, 5, 99, 1, 1000, -1000]);
    }

    #[test]
    fn monotonic_fixed_cadence_is_tiny() {
        // ts = base + i*tick — the IoT timestamp case. Perfect linear cadence makes the *first*-order
        // deltas constant (DELTA: residual width 0) and the second-order deltas zero (DOUBLE_DELTA:
        // also width 0); encode_i64 keeps whichever is smallest (DELTA here, being one seed shorter).
        // The property that matters: a ~constant-size encoding of a 32 KB raw column.
        let base = 1_781_000_000_000i64;
        let tick = 250i64;
        let values: Vec<i64> = (0..4096).map(|i| base + i * tick).collect();
        let enc = encode_i64(&values);
        let scheme = enc[0];
        assert!(
            scheme == DELTA || scheme == DOUBLE_DELTA,
            "linear cadence picks a delta scheme, got {scheme}"
        );
        // 4096 values, raw 8 bytes each = 32768 B; encoded must be a tiny fraction.
        assert!(
            enc.len() < 64,
            "delta of fixed cadence is ~constant size, got {}",
            enc.len()
        );
        assert_eq!(decode_i64(&enc, values.len()).unwrap(), values);
    }

    #[test]
    fn decode_rejects_malformed_blobs_without_panic() {
        // Unknown scheme byte → BadScheme (was a `panic!`).
        assert_eq!(
            decode_i64(&[99, 0, 0, 0, 0, 0, 0, 0, 0, 0], 1),
            Err(DecodeError::BadScheme { scheme: 99 })
        );
        // Empty blob but non-zero count → Truncated, never an index panic.
        assert!(matches!(
            decode_i64(&[], 5),
            Err(DecodeError::Truncated { .. })
        ));
        // FOR header present but payload too short for the declared width → Truncated.
        // scheme=FOR, min=0 (8 bytes), width=64 → needs 64*8 payload bytes that are absent.
        let mut blob = vec![FOR];
        blob.extend_from_slice(&0u64.to_le_bytes());
        blob.push(64);
        assert!(matches!(
            decode_i64(&blob, 8),
            Err(DecodeError::Truncated { .. })
        ));
        // A forged huge count over a tiny payload must error up front, not OOM-abort.
        assert!(decode_i64(&blob, usize::MAX / 8).is_err());
    }

    #[test]
    fn bounded_range_uses_for_and_compresses() {
        let values: Vec<i64> = (0..1000).map(|i| 20 + (i % 50)).collect(); // range 50 → ~6 bits
        let enc = encode_i64(&values);
        assert!(
            enc.len() < values.len() * 8 / 4,
            "FOR should beat 4x on a 6-bit column"
        );
        assert_eq!(decode_i64(&enc, values.len()).unwrap(), values);
    }
}
