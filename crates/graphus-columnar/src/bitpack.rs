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

/// Unpacks `count` values of `width` bits each from `bytes` (the inverse of [`pack`]).
#[must_use]
pub fn unpack(bytes: &[u8], count: usize, width: u32) -> Vec<u64> {
    debug_assert!(width <= 64);
    let mut out = Vec::with_capacity(count);
    if width == 0 {
        out.resize(count, 0);
        return out;
    }
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
    out
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
                unpack(&packed, values.len(), width),
                values,
                "width {width}"
            );
        }
    }

    #[test]
    fn round_trip_full_width() {
        let values = vec![0, 1, u64::MAX, u64::MAX / 2, 42, u64::MAX - 1];
        let packed = pack(&values, 64);
        assert_eq!(unpack(&packed, values.len(), 64), values);
    }

    #[test]
    fn zero_width_is_empty_payload() {
        let values = vec![0u64; 1000];
        let packed = pack(&values, 0);
        assert!(packed.is_empty());
        assert_eq!(unpack(&packed, 1000, 0), values);
    }
}
