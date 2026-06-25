//! Compression measurement for the cold tier (`rmp` task #332): cold-segment bytes/reading vs the
//! authoritative row-store footprint of the same readings. Not a correctness gate (`#[ignore]`); run
//! with `--release --ignored --nocapture`.

use graphus_coldstore::{ColdSegment, Reading};

/// The row-store footprint of one `:Reading`: one node record (`NODE_RECORD_SIZE = 65`) plus four
/// property records (`PROP_RECORD_SIZE = 46`) for `seq`/`ts`/`value`/`sensor` — 65 + 4·46 = 249 bytes,
/// excluding the per-value MVCC settling and the `strings.store` overflow the sensor string also needs
/// (so this UNDER-counts the row store, making the ratio conservative).
const ROW_BYTES_PER_READING: usize = 65 + 4 * 46;

#[test]
#[ignore = "measurement, not a correctness gate; run with --release --ignored --nocapture"]
fn measure_cold_segment_compression() {
    const N: i64 = 100_000;
    // A realistic IoT window: monotonic seq, regular 10-unit cadence ts, slowly-varying value, and a
    // low-cardinality sensor id — the shape the double-delta / Gorilla / dictionary codecs target.
    let readings: Vec<Reading> = (0..N)
        .map(|i| Reading {
            seq: i,
            ts: 1_700_000_000 + i * 10,
            // A smooth-ish signal: Gorilla compresses the shared exponent/mantissa prefix of neighbours.
            value: 20.0 + ((i % 50) as f64) * 0.1,
            sensor: format!("sensor-{}", i % 8),
        })
        .collect();

    let seg = ColdSegment::encode(&readings);
    let cold_bytes = seg.encoded_len();
    let row_bytes = readings.len() * ROW_BYTES_PER_READING;
    let ratio = row_bytes as f64 / cold_bytes as f64;

    eprintln!("\n=== rmp #332 measurement: cold tier compression (N={N} IoT readings) ===");
    eprintln!(
        "row store (authoritative): {row_bytes} B  (~{ROW_BYTES_PER_READING} B/reading: 1 node + 4 props)"
    );
    eprintln!(
        "cold segment (encoded)   : {cold_bytes} B  (~{:.2} B/reading)",
        cold_bytes as f64 / N as f64
    );
    eprintln!("overall compression vs row records: {ratio:.1}x");
    // Round-trip sanity at scale.
    assert_eq!(seg.decode_all().unwrap().len(), N as usize);
    assert!(
        ratio >= 20.0,
        "cold tier must hit the ~20-90x compression thesis (got {ratio:.1}x)"
    );
}
