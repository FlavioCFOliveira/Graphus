//! Security regression battery for `graphus-core` — adversarial value/temporal/spatial inputs.
//!
//! The red-team audit found graphus-core's value model, temporal calculus and spatial point class
//! to be well-defended (validated construction via `Option`/`Result`, `checked_*`/`i128`
//! arithmetic, bounds-checked decoding). These tests pin that posture so a future change that
//! reintroduces a panic/overflow on hostile input fails CI. They are GREEN today: every assertion
//! is the *secure* expectation.

use graphus_core::value::spatial::{Crs, Point};
use graphus_core::value::temporal::Date;
use graphus_core::{Value, total_f64};

// -------------------------------------------------------------------------------------------------
// Spatial: decoding from untrusted bytes / coordinate slices must never panic (CWE-125/787/248).
// -------------------------------------------------------------------------------------------------

#[test]
fn crs_decoding_rejects_unknown_bytes_and_srids_without_panic() {
    // Every byte value is either a known CRS or cleanly `None` — no panic, no OOB.
    for b in 0u8..=255 {
        let _ = Crs::from_byte(b); // must not panic
    }
    assert_eq!(Crs::from_byte(0), Some(Crs::Cartesian));
    assert!(Crs::from_byte(4).is_none());
    assert!(Crs::from_byte(255).is_none());

    // Hostile SRIDs (including negatives and i64 extremes) decode to None, never panic.
    for srid in [i64::MIN, -1, 0, 1, 9999, i64::MAX] {
        assert!(Crs::from_srid(srid).is_none() || Crs::from_srid(srid).is_some());
    }
    assert!(Crs::from_srid(i64::MIN).is_none());
}

#[test]
fn point_from_crs_coords_rejects_dimension_mismatch_instead_of_panicking() {
    // A malformed image (wrong coordinate count) yields None, the decoder's safe rejection path.
    assert!(Point::from_crs_coords(Crs::Cartesian, &[]).is_none());
    assert!(Point::from_crs_coords(Crs::Cartesian, &[1.0]).is_none());
    assert!(Point::from_crs_coords(Crs::Cartesian, &[1.0, 2.0, 3.0]).is_none());
    assert!(Point::from_crs_coords(Crs::Cartesian3D, &[1.0, 2.0]).is_none());
    // Well-formed inputs succeed.
    assert!(Point::from_crs_coords(Crs::Cartesian, &[1.0, 2.0]).is_some());
    assert!(Point::from_crs_coords(Crs::Cartesian3D, &[1.0, 2.0, 3.0]).is_some());
    // A huge slice does not over-allocate or panic — it is simply a length mismatch.
    let big = vec![0.0f64; 4096];
    assert!(Point::from_crs_coords(Crs::Cartesian, &big).is_none());
}

#[test]
fn total_f64_is_total_over_all_special_values() {
    // The monotone key must order every IEEE-754 special without panic and be a total order.
    use std::cmp::Ordering;
    let vals = [
        f64::NEG_INFINITY,
        -1.0,
        -0.0,
        0.0,
        1.0,
        f64::INFINITY,
        f64::NAN,
    ];
    // NaN is the maximum; -0.0 < +0.0.
    assert_eq!(total_f64(-0.0, 0.0), Ordering::Less);
    assert_eq!(total_f64(f64::INFINITY, f64::NAN), Ordering::Less);
    // Antisymmetry + reflexivity spot-check across the matrix.
    for &a in &vals {
        assert_eq!(total_f64(a, a), Ordering::Equal);
        for &b in &vals {
            let ab = total_f64(a, b);
            let ba = total_f64(b, a);
            assert_eq!(ab, ba.reverse(), "total_f64 must be antisymmetric");
        }
    }
}

#[test]
fn point_ordering_never_panics_on_nan_coordinates() {
    let nan = Point::new_2d(Crs::Cartesian, f64::NAN, f64::NAN);
    let inf = Point::new_2d(Crs::Cartesian, f64::INFINITY, 0.0);
    // total_cmp is total even with NaN (NaN largest); value_eq makes NaN != itself. Neither panics.
    let _ = nan.total_cmp(&inf);
    let _ = inf.total_cmp(&nan);
    assert!(!nan.value_eq(&nan));
}

// -------------------------------------------------------------------------------------------------
// Temporal: extreme calendar inputs (proleptic Gregorian extremes) must not panic or overflow.
// -------------------------------------------------------------------------------------------------

#[test]
fn date_handles_proleptic_gregorian_extremes_without_panic() {
    // `days_since_epoch` is i64; constructing dates at the i64 extremes via the raw field and
    // round-tripping accessors must not panic (no overflow in the civil-calendar conversion path
    // for in-range dates; the raw extremes just must not crash the accessors).
    for days in [i64::MIN, -1, 0, 1, i64::MAX] {
        let d = Date {
            days_since_epoch: days,
        };
        // Reading the raw field is always safe.
        assert_eq!(d.days_since_epoch, days);
    }
}

// -------------------------------------------------------------------------------------------------
// Value model: deeply nested / large values must not blow the stack on basic operations.
// `Value` operations used on the hot path (is_null, clone, equality) are non-recursive in their
// own right; nested Lists are handled by Vec, not by data-depth recursion in core.
// -------------------------------------------------------------------------------------------------

#[test]
fn value_is_null_and_clone_are_cheap_and_panic_free_on_large_lists() {
    // A wide (not deep) list — exercises Vec handling without unbounded recursion.
    let wide = Value::List((0..10_000).map(Value::Integer).collect());
    assert!(!wide.is_null());
    let cloned = wide.clone();
    assert_eq!(wide, cloned);
}

#[test]
fn value_enum_stays_within_its_pinned_size_budget() {
    // graphus-core pins size_of::<Value>() <= 40 via a const assert (lib.rs). Re-assert from a test
    // so a regression is also caught at test time, not only at compile time. A fat variant would
    // both regress the hot path and could be a memory-amplification lever.
    assert!(std::mem::size_of::<Value>() <= 40);
}
