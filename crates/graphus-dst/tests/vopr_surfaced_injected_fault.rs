//! Regression: an engine-**surfaced injected latent-sector-error** read-back is SAFE, not a
//! durability violation — while a SILENT committed-data discrepancy stays UNSAFE (`rmp` #480).
//!
//! ## The false positive this pins closed
//!
//! VOPR safety seed **47251** runs the contended interleaver under injected disk faults + crashes
//! ([`VoprConfig::safety`]). On that seed the harness arms a **latent sector error** on a live store
//! page; the end-of-run reference-model read-back then hard-fails with the device's
//! `"latent sector error: page N unreadable"` signal. That is the engine doing exactly the right
//! thing — it refused to serve bytes from a page the harness deliberately made unreadable rather than
//! silently returning wrong/missing committed data, **upholding** the "surface, never corrupt"
//! durability contract. The pre-#480 oracle conflated this engine-surfaced injected fault with an
//! engine bug and flagged the seed UNSAFE (`reference-model-equivalence`): a false positive that
//! masked the regime's ability to detect real committed-data loss (it shares the crash×fault regime
//! with genuine-loss seeds).
//!
//! ## What this test proves
//!
//! 1. Seed 47251 is now **SAFE**.
//! 2. The reason is *positively tied* to an injected fault: the run's oracle verdict IS a read-back
//!    failure carrying the device's latent-sector-error signature ([`SurfacedFault`]), and the page it
//!    names is in the run's `latent_fault_pages` — the set of pages the harness itself armed with a
//!    latent sector error. So the run is SAFE *because* the engine surfaced an injected fault, not
//!    because the oracle went blind.
//! 3. The classifier is conservative: the same surfaced verdict tied against an **empty** armed set is
//!    NOT excused (it would still be a violation), proving the tie — not mere leniency — is what makes
//!    47251 SAFE.
//! 4. Determinism: the same seed replays an identical [`SafetyReport`].

use graphus_dst::vopr::{VoprConfig, run_safety};
use graphus_dst::vopr_oracle::{OracleError, is_surfaced_injected_latent_fault};

const SURFACED_FAULT_SEED: u64 = 47251;

#[test]
fn seed_47251_engine_surfaced_injected_latent_fault_is_safe_and_tied() {
    let cfg = VoprConfig::safety(SURFACED_FAULT_SEED);
    let report = run_safety(cfg);

    // 1. The seed is SAFE under the four-property bundle.
    assert!(
        report.safe,
        "seed {SURFACED_FAULT_SEED} must be SAFE (engine surfaced an injected latent sector error, \
         not a durability bug); violations: {:?}",
        report.violations
    );

    // 2. The engine genuinely SURFACED a fault: the reference-model read-back DID hard-fail (so this
    //    is the false-positive regime, not a trivially clean run), and it carries the device's
    //    latent-sector-error signature naming a page the harness armed.
    let oracle =
        report.run.oracle.as_ref().expect(
            "the read-back must have surfaced a fault on this seed (it hard-failed on an LSE)",
        );
    let OracleError::ReadBack {
        surfaced: Some(sf), ..
    } = oracle
    else {
        panic!("expected a surfaced latent-sector-error read-back, got: {oracle:?}");
    };
    assert!(
        report.run.latent_fault_pages.contains(&sf.page),
        "the surfaced unreadable page {} must be one the harness armed with a latent sector error \
         (armed pages: {:?}) — the positive tie that makes this SAFE",
        sf.page,
        report.run.latent_fault_pages
    );

    // 3. Conservatism: the SAME surfaced verdict, tied against an EMPTY armed-page set, is NOT excused.
    //    This proves the tie to an injected fault — not blanket leniency on read errors — is load
    //    bearing: without the armed page, the very same failure would still be a violation.
    assert!(
        is_surfaced_injected_latent_fault(oracle, &report.run.latent_fault_pages),
        "the classifier must excuse this surfaced-injected-fault verdict against the real armed set"
    );
    assert!(
        !is_surfaced_injected_latent_fault(oracle, &[]),
        "the classifier must NOT excuse the same verdict when no fault was armed (conservative)"
    );

    // 4. Determinism: same seed ⇒ identical report.
    assert_eq!(
        report,
        run_safety(cfg),
        "seed {SURFACED_FAULT_SEED} must replay identically"
    );
}
