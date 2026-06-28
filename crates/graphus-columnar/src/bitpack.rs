//! Fixed-width **bit-packing** of `u64` values — the primitive every integer columnar codec in this
//! crate composes on top of.
//!
//! A column of `u64`s whose values all fit in `width` bits (`0..=64`) is packed into a dense
//! little-endian bit stream: value `i` occupies bits `[i*width, (i+1)*width)`, least-significant
//! bit first, spanning `u64` lanes as needed. `width == 0` encodes a column whose every value is
//! `0` in **zero** payload bytes (the all-equal-to-zero degenerate case the Frame-of-Reference codec
//! relies on). Decoding is the exact inverse — round-trip tested below and by the crate proptests.
//!
//! This is the same mechanic ClickHouse/Parquet/Kùzu use for their bit-packed integer columns; it is
//! hand-rolled here to keep Graphus dependency-light (the project already hand-rolls its on-disk
//! codecs in `graphus-storage::{propenc,valenc}`).

/// The minimum number of bits needed to represent `max` (0 needs 0 bits — an all-zero column).
#[must_use]
pub fn bits_required(max: u64) -> u32 {
    if max == 0 {
        0
    } else {
        64 - max.leading_zeros()
    }
}

/// Packs `values` at `width` bits each into a fresh byte buffer. `width` must be `0..=64` and every
/// value must fit in `width` bits (the codecs that call this guarantee both).
#[must_use]
pub fn pack(values: &[u64], width: u32) -> Vec<u8> {
    debug_assert!(width <= 64);
    if width == 0 {
        return Vec::new();
    }
    let total_bits = (values.len() as u64) * u64::from(width);
    let total_bytes = total_bits.div_ceil(8) as usize;
    let mut out = vec![0u8; total_bytes];
    let mut bit_pos: u64 = 0;
    for &v in values {
        debug_assert!(
            width == 64 || v < (1u64 << width),
            "value {v} exceeds width {width}"
        );
        let mut remaining = width;
        let mut value = v;
        while remaining > 0 {
            let byte_idx = (bit_pos / 8) as usize;
            let bit_off = (bit_pos % 8) as u32;
            let free = 8 - bit_off; // bits free in this byte
            let take = remaining.min(free);
            let mask = if take == 64 {
                u64::MAX
            } else {
                (1u64 << take) - 1
            };
            let chunk = (value & mask) as u8;
            out[byte_idx] |= chunk << bit_off;
            value >>= take;
            remaining -= take;
            bit_pos += u64::from(take);
        }
    }
    out
}

/// The hard upper bound on the element count any `unpack` will materialize, regardless of `width`.
///
/// Every on-disk columnar format that feeds this primitive frames its row/element count in a **`u32`**
/// field (`dictionary` entry/code counts, `.gcol` `nrows`, the cold-segment `count`), so a count above
/// [`u32::MAX`] cannot originate from a well-formed blob and is the signature of a forged
/// `usize`-level value. It is the **only** bound available for a `width == 0` column — whose payload is
/// empty by construction (see [`pack`]), so the buffer length cannot bound `count` — so an absurd
/// width-0 `count` would otherwise drive `vec![0; count]` into an unbounded OOM-abort. Capping at
/// `u32::MAX` rejects that while never rejecting a count any valid blob can express
/// (`specification/04-technical-design.md` §11.4).
const MAX_UNPACK_COUNT: usize = u32::MAX as usize;

/// Unpacks `count` values of `width` bits each from `bytes` (the inverse of [`pack`]).
///
/// `bytes` may be **untrusted**: a `count`/`width` that would read past the buffer is reported as
/// [`DecodeError::Truncated`] rather than panicking, and the result capacity is clamped to what the
/// buffer can actually hold so a forged `count` cannot trigger an OOM-abort
/// (`specification/04-technical-design.md` §11.4).
///
/// # Errors
/// Returns [`DecodeError::Truncated`] if `bytes` is shorter than `count * width` bits require, or if a
/// `width == 0` column declares a `count` above [`MAX_UNPACK_COUNT`] (a forged, payload-unbounded
/// count whose only bound is the structural `u32` count field of every columnar format).
pub fn unpack(bytes: &[u8], count: usize, width: u32) -> Result<Vec<u64>, crate::DecodeError> {
    // `width` arrives from a one-byte header field on the untrusted path; a value > 64 cannot occur
    // in any blob `pack` produced and would overflow the `chunk << filled` shift below, so it is a
    // controlled error rather than a panic (`04 §11.4`).
    if width > 64 {
        return Err(crate::DecodeError::Corrupt {
            what: "bit-pack width exceeds 64",
        });
    }
    if width == 0 {
        // Zero-width: every value is 0 and the payload is empty, so `count` is *not* bounded by the
        // buffer length (the `needed_bytes > bytes.len()` gate below would always pass for it). Guard
        // the unbounded `vec![0; count]` against a forged count here, *before* allocating: a count
        // above the `u32` ceiling every columnar format frames its count in cannot come from a
        // well-formed blob, so it is a controlled error rather than an OOM-abort (`04 §11.4`, rmp
        // #438). Within the ceiling, `count` zeros are produced exactly (the documented happy path —
        // a width-0 FOR / single-value dictionary column).
        if count > MAX_UNPACK_COUNT {
            return Err(crate::DecodeError::Truncated {
                what: "bit-packed values",
            });
        }
        return Ok(vec![0; count]);
    }
    // The exact number of payload bytes `count` values of `width` bits occupy. Validate it up front
    // so the per-value loop can never index out of range, and so a forged `count` cannot make us
    // pre-allocate gigabytes for a tiny buffer.
    let total_bits = (count as u64).saturating_mul(u64::from(width));
    let needed_bytes = total_bits.div_ceil(8) as usize;
    if needed_bytes > bytes.len() {
        return Err(crate::DecodeError::Truncated {
            what: "bit-packed values",
        });
    }
    // Capacity is clamped to `count` only after we have proven the buffer is large enough for it.
    let mut out = Vec::with_capacity(count);
    let mut bit_pos: u64 = 0;
    for _ in 0..count {
        let mut value: u64 = 0;
        let mut filled = 0u32;
        while filled < width {
            let byte_idx = (bit_pos / 8) as usize;
            let bit_off = (bit_pos % 8) as u32;
            let free = 8 - bit_off;
            let take = (width - filled).min(free);
            let mask = ((1u16 << take) - 1) as u8;
            let chunk = (bytes[byte_idx] >> bit_off) & mask;
            value |= u64::from(chunk) << filled;
            filled += take;
            bit_pos += u64::from(take);
        }
        out.push(value);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_required_boundaries() {
        assert_eq!(bits_required(0), 0);
        assert_eq!(bits_required(1), 1);
        assert_eq!(bits_required(2), 2);
        assert_eq!(bits_required(255), 8);
        assert_eq!(bits_required(256), 9);
        assert_eq!(bits_required(u64::MAX), 64);
    }

    #[test]
    fn round_trip_small_widths() {
        for width in 0..=12u32 {
            let cap = if width == 0 { 1 } else { 1u64 << width };
            let values: Vec<u64> = (0..200u64).map(|i| i % cap).collect();
            let packed = pack(&values, width);
            assert_eq!(
                unpack(&packed, values.len(), width).unwrap(),
                values,
                "width {width}"
            );
        }
    }

    #[test]
    fn round_trip_full_width() {
        let values = vec![0, 1, u64::MAX, u64::MAX / 2, 42, u64::MAX - 1];
        let packed = pack(&values, 64);
        assert_eq!(unpack(&packed, values.len(), 64).unwrap(), values);
    }

    #[test]
    fn zero_width_is_empty_payload() {
        let values = vec![0u64; 1000];
        let packed = pack(&values, 0);
        assert!(packed.is_empty());
        assert_eq!(unpack(&packed, 1000, 0).unwrap(), values);
    }

    #[test]
    fn unpack_rejects_a_short_buffer_without_panic_or_oom() {
        // 1 byte holds 8 one-bit values; asking for 9 must error, not read OOB.
        assert!(unpack(&[0u8], 9, 1).is_err());
        // A forged huge count over a tiny buffer must error up front (no multi-GB pre-allocation).
        assert!(unpack(&[0u8; 4], usize::MAX / 64, 64).is_err());
        // Exactly-fitting buffers still decode.
        assert_eq!(unpack(&[0xFFu8], 8, 1).unwrap(), vec![1u64; 8]);
    }

    /// `width == 0` is the degenerate all-zero column: its payload is empty, so the buffer length
    /// cannot bound `count`. A forged, payload-unbounded `count` must be rejected *before* the
    /// `vec![0; count]` allocation, not drive an OOM-abort (`rmp` #438, `04 §11.4`). The bound is the
    /// `u32` ceiling every columnar format frames its count in: anything above it cannot come from a
    /// well-formed blob, while every legitimate width-0 count (incl. zero payload, large count) decodes.
    #[test]
    fn unpack_width_zero_rejects_a_forged_unbounded_count() {
        // The exact gate from the defect report: an empty payload with a `usize::MAX` count is the
        // FOR-width-0 / dictionary-width-0 OOM bomb — it must be a controlled error, not an abort.
        assert!(unpack(&[], usize::MAX, 0).is_err());
        // Just past the ceiling errors; the ceiling and anything below it (any count a u32-framed blob
        // can express) still decodes to that many zeros from an empty payload — the happy path.
        assert!(unpack(&[], MAX_UNPACK_COUNT + 1, 0).is_err());
        assert_eq!(unpack(&[], 0, 0).unwrap(), Vec::<u64>::new());
        assert_eq!(unpack(&[], 1000, 0).unwrap(), vec![0u64; 1000]);
        // A non-empty payload is ignored for width 0 (no bytes are read), and the count still governs.
        assert_eq!(unpack(&[0xFF; 4], 5, 0).unwrap(), vec![0u64; 5]);
    }
}
