//! Determinism contract for the time-series IoT generator (`rmp` task #294 AC: "generator is
//! deterministic per seed/rate").
//!
//! The generator's whole value as an example fixture is reproducibility: the same [`GenConfig`] must
//! produce a **byte-identical** Cypher churn stream on every run, host, and platform, so the
//! example's steady-state + reclamation claims are pinned to a fixed input. These tests assert that
//! the emitted text is stable, that distinct seeds/rates/windows diverge, and that the retention
//! policy is configurable and behaves as a sliding window.

use graphus_iot_gen::{GenConfig, Generator};

fn base() -> GenConfig {
    GenConfig {
        seed: 7,
        sensors: 6,
        rate: 20,
        window: 100,
        ticks: 30,
    }
}

#[test]
fn byte_identical_across_repeated_generation() {
    let a = Generator::new(base()).emit_all();
    let b = Generator::new(base()).emit_all();
    assert_eq!(a, b, "identical config must yield byte-identical streams");
    // And independently of how many times a single generator is asked (emit_all is non-consuming).
    let g = Generator::new(base());
    assert_eq!(g.emit_all(), g.emit_all());
}

#[test]
fn the_fast_profile_is_stable() {
    let a = Generator::new(GenConfig::fast()).emit_all();
    let b = Generator::new(GenConfig::fast()).emit_all();
    assert_eq!(a, b);
    assert!(a.contains("total_readings="));
}

#[test]
fn distinct_knobs_diverge() {
    let baseline = Generator::new(base()).emit_all();

    let mut seed = base();
    seed.seed = 8;
    assert_ne!(
        baseline,
        Generator::new(seed).emit_all(),
        "seed changes value jitter + sensor pick"
    );

    let mut rate = base();
    rate.rate = 21;
    assert_ne!(
        baseline,
        Generator::new(rate).emit_all(),
        "rate changes per-tick batch size"
    );

    let mut window = base();
    window.window = 80;
    assert_ne!(
        baseline,
        Generator::new(window).emit_all(),
        "window changes the retention cutoffs"
    );
}

#[test]
fn retention_window_is_configurable() {
    // The retention window is a first-class knob: the same seed/rate with a different window yields a
    // different delete cadence, and the steady-state live target equals the window.
    for window in [50u64, 100, 250] {
        let mut c = base();
        c.window = window;
        let mut g = Generator::new(c.clone());
        let mut saw_delete = false;
        while let Some(t) = g.tick() {
            if let Some(cutoff) = (t.delete.is_some()).then_some(t.delete_cutoff) {
                saw_delete = true;
                // cutoff = next_seq - window, so live = next_seq - cutoff = window (+ within a tick).
                assert_eq!(t.next_seq - cutoff, window);
            }
        }
        assert!(
            saw_delete,
            "a run longer than the window must age readings out"
        );
    }
}

#[test]
fn total_readings_matches_rate_times_ticks() {
    let c = base();
    let mut g = Generator::new(c.clone());
    let mut count = 0u64;
    while let Some(t) = g.tick() {
        count += t.inserts.len() as u64;
    }
    assert_eq!(count, c.total_readings());
    assert_eq!(count, c.rate * c.ticks);
}
