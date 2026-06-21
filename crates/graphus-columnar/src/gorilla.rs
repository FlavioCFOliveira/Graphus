//! **Gorilla-style XOR** codec for `f64` columns (Facebook's Gorilla, VLDB 2016).
//!
//! Consecutive values are XOR-ed; a slowly-varying sensor reading XORs to a value with many leading
//! and trailing zero bits, so only the handful of *meaningful* bits in the middle are stored. An
//! unchanged value (`xor == 0`) costs a single bit. This is the canonical time-series float codec
//! (the IoT `value` column). This is the exact "store leading+meaningful length per change" variant
//! (a touch simpler than the windowed Gorilla, identical compression on the all-zero/constant cases,
//! slightly more bits on noisy data — but always round-trip exact).

/// MSB-first bit writer over a growing byte buffer.
struct BitWriter {
    bytes: Vec<u8>,
    cur: u8,
    nbits: u8, // bits filled in `cur` (0..8)
}
impl BitWriter {
    fn new() -> Self {
        Self { bytes: Vec::new(), cur: 0, nbits: 0 }
    }
    fn put_bit(&mut self, bit: u8) {
        self.cur = (self.cur << 1) | (bit & 1);
        self.nbits += 1;
        if self.nbits == 8 {
            self.bytes.push(self.cur);
            self.cur = 0;
            self.nbits = 0;
        }
    }
    /// Writes the low `count` bits of `value`, most-significant first.
    fn put_bits(&mut self, value: u64, count: u32) {
        for i in (0..count).rev() {
            self.put_bit(((value >> i) & 1) as u8);
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.cur <<= 8 - self.nbits; // left-align the final partial byte
            self.bytes.push(self.cur);
        }
        self.bytes
    }
}

struct BitReader<'a> {
    bytes: &'a [u8],
    byte: usize,
    bit: u8, // next bit index within the current byte (0 = MSB)
}
impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, byte: 0, bit: 0 }
    }
    fn get_bit(&mut self) -> u8 {
        let b = (self.bytes[self.byte] >> (7 - self.bit)) & 1;
        self.bit += 1;
        if self.bit == 8 {
            self.bit = 0;
            self.byte += 1;
        }
        b
    }
    fn get_bits(&mut self, count: u32) -> u64 {
        let mut v = 0u64;
        for _ in 0..count {
            v = (v << 1) | u64::from(self.get_bit());
        }
        v
    }
}

/// Encodes an `f64` column. `NaN`/`±inf`/`-0.0` round-trip exactly (XOR is on the raw bit pattern).
#[must_use]
pub fn encode(values: &[f64]) -> Vec<u8> {
    let mut w = BitWriter::new();
    let mut prev: u64 = 0;
    for (i, &v) in values.iter().enumerate() {
        let bits = v.to_bits();
        if i == 0 {
            w.put_bits(bits, 64);
        } else {
            let xor = bits ^ prev;
            if xor == 0 {
                w.put_bit(0);
            } else {
                w.put_bit(1);
                let lz = xor.leading_zeros().min(63); // 6 bits (0..=63)
                let tz = xor.trailing_zeros();
                let meaningful = 64 - lz - tz; // 1..=64
                w.put_bits(u64::from(lz), 6);
                w.put_bits(u64::from(meaningful - 1), 6); // store len-1 in 6 bits (1..=64)
                w.put_bits(xor >> tz, meaningful);
            }
        }
        prev = bits;
    }
    w.finish()
}

/// Decodes `count` `f64` values produced by [`encode`].
#[must_use]
pub fn decode(bytes: &[u8], count: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(count);
    if count == 0 {
        return out;
    }
    let mut r = BitReader::new(bytes);
    let mut prev = r.get_bits(64);
    out.push(f64::from_bits(prev));
    for _ in 1..count {
        if r.get_bit() == 0 {
            out.push(f64::from_bits(prev));
        } else {
            let lz = r.get_bits(6) as u32;
            let meaningful = (r.get_bits(6) as u32) + 1;
            let tz = 64 - lz - meaningful;
            let mantissa = r.get_bits(meaningful);
            let xor = mantissa << tz;
            prev ^= xor;
            out.push(f64::from_bits(prev));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(values: &[f64]) {
        let enc = encode(values);
        let dec = decode(&enc, values.len());
        assert_eq!(dec.len(), values.len());
        for (a, b) in dec.iter().zip(values) {
            assert_eq!(a.to_bits(), b.to_bits(), "exact bit round-trip");
        }
    }

    #[test]
    fn round_trips_including_specials() {
        rt(&[]);
        rt(&[1.5]);
        rt(&[0.0, -0.0, 1.0, -1.0]);
        rt(&[f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.0]);
        rt(&[21.5, 21.6, 21.6, 21.7, 21.4, 21.4, 21.4]); // slow sensor drift
        rt(&[1e300, -1e-300, 3.14159, 2.71828]);
    }

    #[test]
    fn constant_and_slow_series_compress() {
        let constant = vec![42.0f64; 4096];
        let enc = encode(&constant);
        // first 64 bits + 4095 single 0-bits ≈ 8 + 512 bytes, vs 32768 raw → >50x.
        assert!(enc.len() * 50 < constant.len() * 8, "constant series must compress hard: {}", enc.len());
        rt(&constant);
    }
}
