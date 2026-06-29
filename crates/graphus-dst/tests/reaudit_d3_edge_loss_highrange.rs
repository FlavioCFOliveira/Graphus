//! Re-audit D3 (sprint-42 #485): pin the **high-range** committed-EDGE-loss seeds and the
//! **atomicity** seed that the #479 investigation surfaced as residual but that NO standing
//! regression test covers.
//!
//! ## Why this file exists (the coverage gap it closes)
//!
//! The #479 audit recorded a residual set of crash×disk-fault seeds whose recovered state was missing
//! a committed `:KNOWS` relationship (`EdgeMultisetMismatch{model:1,engine:0}`) — a silent ACID
//! **durability** loss — plus one **atomicity** seed (`5018816`). The committed regression test
//! `vopr_safety_teeth::safety_committed_edge_loss_seeds_are_safe_under_fault_then_crash` pins only a
//! "representative LOW-range subset" (`489, 578, 2723, 5030, 8751, 10412, 15676`). The seven
//! **5-million-range** edge-loss seeds and the atomicity seed were left **unpinned** — so a future
//! change could silently reintroduce the loss on exactly those seeds and CI would stay green.
//!
//! These seeds are closed on HEAD by the #468 rel-chain corpse high-water floor
//! (`RecordStore::open` → `floor_high_water_over_mapped_corpses`) and the #479 alloc-time page-map +
//! exception-safe rollback. This test makes that coverage a standing gate.
//!
//! ## Assertion strength (stronger than the #483 pin)
//!
//! For each seed it asserts not only `safe`, but that the run is SAFE for the *right reason*: any
//! non-`None` reference-model oracle verdict must be an engine-**surfaced injected latent-sector-error**
//! (the only outcome `evaluate_safety` excuses — "surface, never corrupt") positively tied to a page
//! the harness armed this run. A **silent** `EdgeMultisetMismatch` / `NodeMultisetMismatch` /
//! `CountMismatch` (the exact committed-data-loss shapes) can therefore never pass. It also asserts the
//! committed-or-nothing node probe (`persisted_nodes == created_nodes`) and **non-vacuity** (crashes
//! AND faults actually fired), and re-checks determinism.

use graphus_dst::vopr::{VoprConfig, run_safety};
use graphus_dst::{OracleError, is_surfaced_injected_latent_fault};

/// The seven 5-million-range seeds the #479 audit observed as `EdgeMultisetMismatch` on its (pre-#468)
/// worktree baseline, plus the one `atomicity` seed (`5018816`). None is pinned by any other test.
const HIGH_RANGE_EDGE_AND_ATOMICITY_SEEDS: [u64; 8] = [
    5001407, 5003146, 5003252, 5004732, 5005272, 5009788, 5013286, // edge-loss
    5018816, // atomicity (persisted != created)
];

#[test]
fn high_range_committed_edge_and_atomicity_seeds_are_safe_under_fault_then_crash() {
    for seed in HIGH_RANGE_EDGE_AND_ATOMICITY_SEEDS {
        let cfg = VoprConfig::safety(seed);
        let r = run_safety(cfg);

        // (1) The four-property bundle must hold.
        assert!(
            r.safe,
            "seed {seed} must be SAFE (no committed-edge loss / atomicity breach under \
             crash + disk-fault); violations: {:?}",
            r.violations
        );

        // (2) SAFE for the RIGHT reason: a non-None oracle verdict is permitted ONLY when it is an
        //     engine-surfaced injected latent-sector-error tied to a page the harness armed. A silent
        //     committed-data discrepancy (the loss shapes) carries no surfaced error and can never be
        //     excused — so this rejects the regression even if some future change made `safe` lie.
        if let Some(err) = &r.run.oracle {
            assert!(
                is_surfaced_injected_latent_fault(err, &r.run.latent_fault_pages),
                "seed {seed}: the only non-None oracle verdict allowed is a surfaced injected LSE; \
                 got a SILENT divergence (committed-data loss): {err:?}"
            );
            // Belt + suspenders: it must NOT be one of the silent loss variants.
            assert!(
                !matches!(
                    err,
                    OracleError::EdgeMultisetMismatch { .. }
                        | OracleError::NodeMultisetMismatch { .. }
                        | OracleError::CountMismatch { .. }
                        | OracleError::NeighborMismatch { .. }
                ),
                "seed {seed}: a silent multiset/count divergence is committed-data loss: {err:?}"
            );
        }

        // (3) Committed-or-nothing node probe — the atomicity invariant seed 5018816 broke.
        assert_eq!(
            r.run.persisted_nodes, r.run.created_nodes,
            "seed {seed}: every committed :Person create must survive (persisted {} != created {})",
            r.run.persisted_nodes, r.run.created_nodes
        );

        // (4) Non-vacuity: the dangerous regime (crash × injected fault) genuinely fired.
        assert!(
            r.run.crash_restarts > 0,
            "seed {seed}: the run must actually crash + recover (else the pin is vacuous)"
        );
        assert!(
            r.run.disk_faults + r.run.clock_faults + r.run.transport_faults > 0,
            "seed {seed}: the run must actually inject faults (else the pin is vacuous)"
        );

        // (5) Determinism: identical verdict on replay.
        assert_eq!(r, run_safety(cfg), "seed {seed} must be deterministic");
    }
}
