//! Regression: an engine-**surfaced injected latent-sector-error** read-back is SAFE, not a
//! durability violation — while a SILENT committed-data discrepancy stays UNSAFE (`rmp` #480).
//!
//! ## The false positive this pins closed
//!
//! A VOPR safety seed runs the contended interleaver under injected disk faults + crashes
//! ([`VoprConfig::safety`]). On the pinned seed the harness arms a **latent sector error** on a live
//! store page; the end-of-run reference-model read-back then hard-fails with the device's
//! `"latent sector error: page N unreadable"` signal. That is the engine doing exactly the right
//! thing — it refused to serve bytes from a page the harness deliberately made unreadable rather than
//! silently returning wrong/missing committed data, **upholding** the "surface, never corrupt"
//! durability contract. The pre-#480 oracle conflated this engine-surfaced injected fault with an
//! engine bug and flagged the seed UNSAFE (`reference-model-equivalence`): a false positive that
//! masked the regime's ability to detect real committed-data loss (it shares the crash×fault regime
//! with genuine-loss seeds).
//!
//! ## Why this pin is LAYOUT-COUPLED — and why the seed changed (47251 → 702583 → 173047)
//!
//! The disk-fault scheduler arms every latent sector error within the store's **first 64 pages**
//! (`FaultBudget::disk_page_span == 64`) — the header / catalog / `Statistics` / early-data region.
//! The seed-derived fault plan is a **pure function of the seed** and does not depend on the store's
//! byte layout, but *which armed page the reference-model read-back actually reads from the device*
//! does. So this pin is coupled to the on-disk layout of those low pages: any change that shifts them
//! can move the seed's fault off a read-back page and silently stop exercising the surfaced-fault path.
//!
//! That has now happened twice. The original pin, **seed 47251**, surfaced a latent sector error on
//! store **page 3** and was SAFE + tied. The index-completeness work (rmp #647 / #657 / #663 / #666 /
//! #669 / #671) appended six new durable trailing blocks to the `Statistics` on-disk image (composite,
//! text-trigram, relationship+multi-label fulltext, spatial, relationship-composite and vector index
//! catalogs — all append-last, backward-compatible, no format-version bump). Those blocks grew the
//! catalog region and shifted the early-data pages, so seed 47251 still armed the *same* latent pages
//! `[3, 23, 34, 43]` (the fault plan is unchanged) but none of them was read back from the device any
//! more — its oracle verdict became `None` (SAFE, but the surfaced-fault path no longer taken). Seed
//! **702583** replaced it.
//!
//! The **undo area** (rmp #966) shifted them again, for the same reason plus one more: it appends a
//! trailing block to the durable catalog *and* adds two new fixed-record stores (`undo.store`,
//! `commit.store`) whose device pages land in the same low-page region the fault scheduler arms. Seed
//! 702583 regressed to exactly the documented signature — still SAFE, but `oracle == None`. Seed
//! **173047** is the smallest `VoprConfig::safety` seed that reproduces the scenario under the current
//! layout: it surfaces a latent sector error on an armed page (page 5, armed set `[5, 55]`), SAFE +
//! tied.
//!
//! **Ruled out at this re-pin, empirically rather than by assumption:** the fault-arming mechanism is
//! intact. A sweep of seeds `1..=173_047` found **153 949** runs with a non-empty `latent_fault_pages`
//! set — the scheduler still arms latent sector errors at the same rate — and the committed-data-loss
//! detector is untouched. Only the page the seed's fault lands on moved.
//!
//! **If a future storage-format change shifts the first ~64 store pages again and this test regresses
//! to an `oracle == None` panic at the "must have surfaced a fault" assertion, re-pin it:** sweep
//! [`VoprConfig::safety`] seeds for one whose [`SafetyReport`] has `safe == true` and
//! `run.oracle == Some(OracleError::ReadBack { surfaced: Some(sf), .. })` with
//! `sf.page ∈ run.latent_fault_pages`, and prefer the smallest. (Ruled out at re-pin time: the change
//! is a benign layout shift, not weakened fault-surfacing — the arming mechanism stays intact across
//! seeds and the committed-data-loss detector still flags every silent multiset/count/neighbour
//! divergence; only the *page* the seed's fault lands on moved.)
//!
//! ## What this test proves
//!
//! 1. Seed 173047 is **SAFE**.
//! 2. The reason is *positively tied* to an injected fault: the run's oracle verdict IS a read-back
//!    failure carrying the device's latent-sector-error signature ([`SurfacedFault`]), and the page it
//!    names is in the run's `latent_fault_pages` — the set of pages the harness itself armed with a
//!    latent sector error. So the run is SAFE *because* the engine surfaced an injected fault, not
//!    because the oracle went blind.
//! 3. The classifier is conservative: the same surfaced verdict tied against an **empty** armed set is
//!    NOT excused (it would still be a violation), proving the tie — not mere leniency — is what makes
//!    173047 SAFE.
//! 4. Determinism: the same seed replays an identical [`SafetyReport`].

use graphus_dst::vopr::{VoprConfig, run_safety};
use graphus_dst::vopr_oracle::{OracleError, is_surfaced_injected_latent_fault};

/// The VOPR safety seed that, under the *current* store byte layout, surfaces an injected latent
/// sector error on an armed page (page 5) — SAFE + tied. LAYOUT-COUPLED: see the module docs for how
/// to re-pin if a storage-format change shifts the first ~64 store pages and moves the fault away.
/// (Was 47251 before the rmp #647/#657.. `Statistics` catalog additions, then 702583 before the
/// rmp #966 undo area added two stores and a trailing catalog block.)
const SURFACED_FAULT_SEED: u64 = 173_047;

#[test]
fn seed_173047_engine_surfaced_injected_latent_fault_is_safe_and_tied() {
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
    let oracle = report.run.oracle.as_ref().expect(
        "the read-back must have surfaced a fault on this seed (it hard-failed on an LSE) — if this \
         panics after a storage-format change, the layout shifted the fault off a read-back page; \
         re-pin SURFACED_FAULT_SEED per the module docs",
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
