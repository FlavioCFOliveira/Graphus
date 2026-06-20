//! Hermetic cargo mirror of the iot-timeseries storage-reclamation proof (`rmp #299`).
//!
//! This runs in the DEFAULT `cargo test` (gated on the `churn` feature, which the workspace enables
//! for this dev-only crate) so the example's headline invariant — the **storage footprint PLATEAUS
//! under sustained churn** — is regression-guarded on every test run, not only when an operator runs
//! `examples/iot-timeseries/run.sh`.
//!
//! It reuses the exact in-process churn engine the example drives ([`graphus_iot_gen::churn`]), at a
//! deliberately **small, fast** config (total-ingested ≫ window, but few ticks) so it stays well
//! within a unit-test budget while still ingesting many× the retention window.
//!
//! # What is asserted (and what is not)
//!
//! - **Storage plateau (STRONG, deterministic):** for a fixed seed+profile the in-memory DST device's
//!   page high-water is byte-reproducible, so the post-warmup footprint band must be FLAT
//!   (`plateau_ratio == 1.0` — exactly equal min/max here, since reclamation fully recycles slots) and
//!   the run must ingest `>= 3×` the window. A footprint that drifts is a genuine reclamation
//!   regression and fails the test.
//! - **Steady-state live count (deterministic):** every post-warmup tick's live `:Reading` count must
//!   sit in `[window, window + rate)`.
//! - **RAM stability (DOCUMENTED, not asserted):** process RSS in this single-process inline driver is
//!   a high-water of allocator reservations (glibc retains freed arenas), so it is noisy and climbs
//!   even though the engine's durable state is fully reclaimed. The *footprint plateau* above is the
//!   real bounded-resource signal; RSS is left to the `iot_evidence` report (informational). See the
//!   honest note there and in `examples/iot-timeseries/README.md`.

#![cfg(feature = "churn")]

use graphus_iot_gen::GenConfig;
use graphus_iot_gen::churn::run_churn;

/// A tiny, fast config that still makes the plateau unambiguous: total-ingested is 10× the window,
/// across enough ticks that the post-warmup steady state is observed for many ticks. Sized for a
/// unit-test budget (a fraction of a second in release; comfortably fast in the dev test build).
fn tiny() -> GenConfig {
    GenConfig {
        seed: 0xC0FF_EE15_600D_5EED,
        sensors: 6,
        rate: 25,
        window: 50,
        ticks: 20,
    }
}

#[test]
fn footprint_plateaus_under_sustained_churn() {
    let cfg = tiny();
    let out = run_churn(cfg.clone(), /* gc_enabled = */ true);

    // The run must ingest many times the window for the plateau to mean anything (#296).
    assert!(
        out.ingest_to_window() >= 3.0,
        "test config too small: ingested {:.1}× the window (need >= 3×)",
        out.ingest_to_window()
    );
    assert_eq!(
        out.total_ingested(),
        cfg.rate * cfg.ticks,
        "every tick ingests `rate` readings"
    );

    // STRONG, deterministic plateau: with the in-memory DST device, full reclamation recycles every
    // freed slot, so the post-warmup footprint is EXACTLY flat — min == max, ratio == 1.0. (We assert
    // exact flatness rather than a loose band because for a fixed seed+profile the footprint is
    // byte-reproducible; any drift is a real reclamation regression.)
    assert!(
        out.steady_min_bytes > 0,
        "a post-warmup footprint band must have been observed"
    );
    assert_eq!(
        out.steady_min_bytes, out.steady_max_bytes,
        "footprint must be FLAT post-warmup (reclaimed slots fully reused); band=[{}, {}]B",
        out.steady_min_bytes, out.steady_max_bytes
    );
    assert!(
        (out.plateau_ratio() - 1.0).abs() < f64::EPSILON,
        "plateau_ratio must be exactly 1.0, got {:.6}",
        out.plateau_ratio()
    );

    // And the late-run footprint must equal the post-warmup footprint despite ingesting 10× the
    // window — i.e. NOT linear growth. The high-water equals the plateau (no later spike).
    let final_footprint = out
        .samples
        .last()
        .expect("ran at least one tick")
        .footprint_bytes;
    assert_eq!(
        final_footprint, out.steady_max_bytes,
        "the final-tick footprint must equal the plateau (no late growth)"
    );
    assert_eq!(
        out.footprint_high_water_bytes, out.steady_max_bytes,
        "footprint high-water must equal the plateau (the warmup ramp never exceeds steady state here)"
    );
}

#[test]
fn steady_state_live_count_holds_in_window_band() {
    let cfg = tiny();
    let out = run_churn(cfg.clone(), true);

    let band_lo = cfg.window;
    let band_hi = cfg.window + cfg.rate;
    let mut observed = 0u64;
    for s in &out.samples {
        if s.tick >= out.warmup_ticks {
            observed += 1;
            assert!(
                s.live_readings >= band_lo && s.live_readings < band_hi,
                "tick {} live={} outside steady band [{}, {})",
                s.tick,
                s.live_readings,
                band_lo,
                band_hi
            );
        }
    }
    assert!(
        observed > 0,
        "the run must observe at least one post-warmup steady-state tick"
    );
}

/// The honest contrast: with GC DISABLED the footprint must NOT plateau — it grows with
/// total-ingested. This proves the plateau is *caused by* the reclamation pass (and that the workload
/// would otherwise leak), so the GC-enabled plateau is a real reclamation signal, not a no-op.
#[test]
fn without_gc_the_footprint_does_not_plateau() {
    let cfg = tiny();
    let out = run_churn(cfg.clone(), /* gc_enabled = */ false);

    let first = out.samples.first().expect("ran a tick").footprint_bytes;
    let last = out.samples.last().expect("ran a tick").footprint_bytes;
    assert!(
        last > first,
        "without GC the footprint must grow (tombstones accrue): first={first}B last={last}B"
    );
    // The post-warmup band must be strictly wider than the GC-enabled (flat) case: max > min.
    assert!(
        out.steady_max_bytes > out.steady_min_bytes,
        "without GC the post-warmup footprint must still be growing, not flat: band=[{}, {}]B",
        out.steady_min_bytes,
        out.steady_max_bytes
    );
}
