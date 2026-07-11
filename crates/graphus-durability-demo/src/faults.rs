//! The **full fault catalogue** matrix (`rmp` #698): every [`FaultKind`] the DST simulator can
//! physically inject through the engine, driven over a seed range and asserted SAFE.
//!
//! # Why this module exists
//!
//! The example's headline sweep (`crate::run_sweep`, the VOPR safety oracle) crashes the engine and
//! rebuilds it from the durable WAL prefix onto a **fresh** device. That is the *easiest* ARIES case:
//! nothing was stolen home, nothing was torn, nothing was reordered — recovery only has to redo. The
//! hard cases live in [`graphus_dst::harness`], which drives the same `RecordStore` engine through the
//! whole [`FaultKind`] catalogue, and the example never called it. This module does.
//!
//! | Fault | What recovery must do |
//! |-------|-----------------------|
//! | `crash(no-force)` | redo every acked commit from the durable WAL onto an empty device |
//! | `crash(steal)` | **undo** the uncommitted dirty pages that were flushed home before the crash |
//! | `torn-wal-tail` | stop cleanly at the last intact record — a half-written record is not a commit |
//! | `torn-data-page` | repair the torn home page from the **doublewrite buffer** *before* ARIES redo reads its `page_lsn` |
//! | `write-reordering` | reconstruct every committed page a non-atomic sync failed to persist |
//! | `write-io-error(full-engine)` | **surface** the hard error and the checksum-rejected read — never serve or commit corrupt data |
//!
//! Each `(seed, fault)` cell is a pure function of its inputs, so the matrix is fully deterministic and
//! is re-run once per cell to prove it (same inputs ⇒ identical report).
//!
//! The one fault the catalogue does **not** physically inject is recorded honestly rather than hidden:
//! [`graphus_dst::DeferredFault::FsyncEio`] (the controlled-PANIC fsyncgate path), covered by a
//! `graphus-wal` unit test — see [`deferred`].

use graphus_dst::fault::DeferredFault;
use graphus_dst::harness::{ScenarioReport, run_with_fault};
use graphus_dst::{DetRng, FaultKind};

/// Every fault the harness physically injects through the full `RecordStore` engine, in a stable
/// order (the order the report prints them in).
#[must_use]
pub fn all_kinds() -> [FaultKind; 6] {
    [
        FaultKind::Crash { steal: false },
        FaultKind::Crash { steal: true },
        FaultKind::TornWalTail,
        FaultKind::TornDataPage,
        FaultKind::WriteReordering,
        FaultKind::WriteIoError,
    ]
}

/// The faults the catalogue **plans but does not physically inject**, with the reason — reported so
/// the gap is visible instead of silently skipped.
#[must_use]
pub fn deferred() -> Vec<(&'static str, &'static str)> {
    DeferredFault::all()
        .iter()
        .map(|f| (f.label(), f.reason()))
        .collect()
}

/// The verdict for one fault kind across the seed range.
#[derive(Debug, Clone)]
pub struct FaultVerdict {
    /// The fault's stable label (e.g. `crash(steal)`).
    pub label: &'static str,
    /// Seeds run for this fault.
    pub seeds: u64,
    /// Seeds whose invariants all held after recovery.
    pub safe: u64,
    /// Seeds that violated an invariant, with the first failure's rendering (the reproducer list).
    pub unsafe_seeds: Vec<(u64, String)>,
    /// Seeds whose re-run produced a different report (a determinism breach).
    pub nondeterministic: Vec<u64>,
    /// Seeds that exercised the contract non-vacuously (an acked commit AND work discarded/undone).
    pub non_vacuous: u64,
    /// Acknowledged commits recovery had to preserve across the range.
    pub acked_commits: u64,
    /// Transactions ARIES undo rolled back across the range (the *loser* set — the undo work the
    /// no-force crash never produces).
    pub recovery_losers: u64,
    /// Seeds where recovery observed a truncated/torn log tail.
    pub tail_truncated: u64,
}

impl FaultVerdict {
    /// `true` iff every seed was safe and deterministic for this fault.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.unsafe_seeds.is_empty() && self.nondeterministic.is_empty()
    }
}

/// The whole matrix's verdict.
#[derive(Debug, Clone)]
pub struct FaultMatrix {
    /// The first seed (inclusive).
    pub start: u64,
    /// Seeds per fault kind.
    pub seeds: u64,
    /// One verdict per [`FaultKind`], in [`all_kinds`] order.
    pub verdicts: Vec<FaultVerdict>,
}

impl FaultMatrix {
    /// `true` iff EVERY fault kind was safe and deterministic on every seed.
    #[must_use]
    pub fn all_safe(&self) -> bool {
        self.verdicts.iter().all(FaultVerdict::passed)
    }

    /// Total cells (fault × seed) executed.
    #[must_use]
    pub fn cells(&self) -> u64 {
        self.seeds * self.verdicts.len() as u64
    }
}

/// Runs one `(seed, fault)` cell: the seeded workload, the fault, ARIES recovery, and the invariant
/// check — through the full `RecordStore` engine.
///
/// The RNG is seeded by `seed` and **not** advanced past a fault-selection draw (the harness's
/// `run_scenario` consumes one draw to pick the fault; forcing the fault means we do not), so a cell is
/// reproducible from `(seed, fault)` alone.
#[must_use]
pub fn run_cell(seed: u64, fault: FaultKind) -> ScenarioReport {
    let mut rng = DetRng::new(seed);
    run_with_fault(seed, fault, &mut rng)
}

/// Drives the whole catalogue over `start..start+seeds`, re-running every cell once to certify
/// determinism. A pure function of its inputs.
#[must_use]
pub fn run_matrix(start: u64, seeds: u64) -> FaultMatrix {
    let verdicts = all_kinds()
        .into_iter()
        .map(|fault| {
            let mut v = FaultVerdict {
                label: fault.label(),
                seeds,
                safe: 0,
                unsafe_seeds: Vec::new(),
                nondeterministic: Vec::new(),
                non_vacuous: 0,
                acked_commits: 0,
                recovery_losers: 0,
                tail_truncated: 0,
            };
            for seed in start..start.saturating_add(seeds) {
                let first = run_cell(seed, fault);
                let second = run_cell(seed, fault);
                if first != second {
                    v.nondeterministic.push(seed);
                }
                match &first.result {
                    Ok(()) => v.safe += 1,
                    Err(e) => v.unsafe_seeds.push((seed, format!("{e:?}"))),
                }
                if first.non_vacuous {
                    v.non_vacuous += 1;
                }
                v.acked_commits += first.ledger.acknowledged_commits();
                v.recovery_losers += first.recovery_losers as u64;
                if first.tail_truncated {
                    v.tail_truncated += 1;
                }
            }
            v
        })
        .collect();

    FaultMatrix {
        start,
        seeds,
        verdicts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Acceptance (`rmp` #698).** Every fault in the catalogue — including the ones the example never
    /// used to exercise (steal/undo, torn WAL tail, torn data page + doublewrite repair, write
    /// reordering, write I/O error) — must recover SAFE and deterministically.
    #[test]
    fn every_fault_kind_recovers_safely_and_deterministically() {
        let m = run_matrix(1, 8);
        assert_eq!(m.verdicts.len(), 6, "the whole catalogue must be driven");
        for v in &m.verdicts {
            assert!(
                v.passed(),
                "fault {} must be safe + deterministic: unsafe={:?} nondet={:?}",
                v.label,
                v.unsafe_seeds,
                v.nondeterministic
            );
            assert_eq!(
                v.safe, v.seeds,
                "fault {}: every seed must be safe",
                v.label
            );
        }
        assert!(m.all_safe());
        assert_eq!(m.cells(), 48);
    }

    /// The matrix must be **non-vacuous** where it matters: the steal crash must actually produce undo
    /// work (recovery losers), and the torn-WAL-tail fault must actually truncate a tail. Without this,
    /// a matrix of no-op scenarios would trivially "pass".
    #[test]
    fn the_hard_faults_actually_exercise_their_recovery_path() {
        let m = run_matrix(1, 12);
        let steal = m
            .verdicts
            .iter()
            .find(|v| v.label == FaultKind::Crash { steal: true }.label())
            .expect("steal crash present");
        assert!(
            steal.recovery_losers > 0,
            "the steal crash must give ARIES undo real work (uncommitted pages stolen home)"
        );
        assert!(
            steal.non_vacuous > 0,
            "the steal crash must exercise the contract non-vacuously"
        );

        let torn = m
            .verdicts
            .iter()
            .find(|v| v.label == FaultKind::TornWalTail.label())
            .expect("torn-wal-tail present");
        assert!(
            torn.tail_truncated > 0,
            "the torn-WAL-tail fault must actually leave recovery a truncated tail"
        );
    }

    /// A cell is reproducible from `(seed, fault)` alone — the one-line reproducer contract.
    #[test]
    fn a_cell_is_a_pure_function_of_seed_and_fault() {
        for fault in all_kinds() {
            let a = run_cell(3, fault);
            let b = run_cell(3, fault);
            assert_eq!(a, b, "fault {} must replay identically", fault.label());
        }
    }

    /// The deferred fault is reported with its reason — the catalogue is honest about what it does not
    /// physically inject.
    #[test]
    fn the_deferred_fault_is_declared_with_a_reason() {
        let d = deferred();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].0, "fsync-eio");
        assert!(d[0].1.len() > 20, "a deferred fault must state why");
    }
}
