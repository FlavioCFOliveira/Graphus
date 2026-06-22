//! Property + fuzz tests for the cold-tier segment (`rmp` task #332): the round-trip must be exact
//! for arbitrary readings, a range scan must always equal the row filter, and decoding an arbitrary
//! byte buffer must never panic (it returns a clean error). This fuzz-hardens the segment framing on
//! top of `graphus-columnar`'s own codec proptests.

use graphus_coldstore::{ColdSegment, Reading};
use proptest::prelude::*;

fn arb_reading() -> impl Strategy<Value = Reading> {
    (
        any::<i64>(),
        any::<i64>(),
        any::<f64>(),
        prop_oneof![
            Just("temp".to_string()),
            Just("humidity".to_string()),
            Just("pressure".to_string()),
            "[a-z]{1,8}",
        ],
    )
        .prop_map(|(seq, ts, value, sensor)| Reading {
            seq,
            ts,
            value,
            sensor,
        })
}

/// A reading whose `value` is never NaN, so structural equality is well-defined (NaN != NaN). The
/// Gorilla codec still round-trips a NaN bit-pattern exactly, but a test asserting `==` must avoid it.
fn arb_reading_no_nan() -> impl Strategy<Value = Reading> {
    arb_reading().prop_map(|mut r| {
        if r.value.is_nan() {
            r.value = 0.0;
        }
        r
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Encode → decode reproduces the input exactly for arbitrary (non-NaN-value) readings.
    #[test]
    fn round_trip_is_exact(readings in prop::collection::vec(arb_reading_no_nan(), 0..200)) {
        let seg = ColdSegment::encode(&readings);
        prop_assert_eq!(seg.decode_all(), readings);
    }

    /// to_bytes → from_bytes → decode reproduces the input exactly.
    #[test]
    fn byte_round_trip_is_exact(readings in prop::collection::vec(arb_reading_no_nan(), 0..200)) {
        let seg = ColdSegment::encode(&readings);
        let back = ColdSegment::from_bytes(&seg.to_bytes()).expect("valid");
        prop_assert_eq!(back.decode_all(), readings);
    }

    /// A ts-range scan always equals filtering the decoded rows by the same range.
    #[test]
    fn range_scan_equals_filter(
        readings in prop::collection::vec(arb_reading_no_nan(), 0..200),
        lo in any::<i64>(),
        hi in any::<i64>(),
    ) {
        let (lo, hi) = (lo.min(hi), lo.max(hi));
        let seg = ColdSegment::encode(&readings);
        let mut expect: Vec<Reading> = readings.into_iter().filter(|r| r.ts >= lo && r.ts <= hi).collect();
        let mut got = seg.scan_ts_range(lo, hi);
        expect.sort_by(|a, b| (a.seq, a.ts).cmp(&(b.seq, b.ts)));
        got.sort_by(|a, b| (a.seq, a.ts).cmp(&(b.seq, b.ts)));
        prop_assert_eq!(got, expect);
    }

    /// Decoding an ARBITRARY byte buffer never panics — it returns a segment or a clean error.
    #[test]
    fn arbitrary_bytes_never_panic(buf in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = ColdSegment::from_bytes(&buf); // must not panic
    }

    /// Even a buffer that starts with a valid header prefix decodes without panicking.
    #[test]
    fn corrupted_real_segment_never_panics(
        readings in prop::collection::vec(arb_reading_no_nan(), 1..50),
        cut in 0usize..64,
    ) {
        let mut bytes = ColdSegment::encode(&readings).to_bytes();
        let n = bytes.len().saturating_sub(cut);
        bytes.truncate(n);
        if let Ok(seg) = ColdSegment::from_bytes(&bytes) {
            // If it parsed, decoding/scanning must also not panic.
            let _ = seg.decode_all();
            let _ = seg.scan_ts_range(i64::MIN, i64::MAX);
        }
    }
}
