//! `vopr_fault` — the **unified fault scheduler** for the VOPR interleaver (rmp #236;
//! `04-technical-design.md` §11; decision `D-dst-investment`).
//!
//! This is the capstone of the composable fault APIs built in rmp #231–#235. It does not reinvent any
//! fault model; it *schedules* them on the VOPR interleaver's single timeline. A [`FaultScheduler`]
//! decides, from the master seed under a bounded [`FaultBudget`], **when** (which scheduler instants)
//! and **which** fault to inject, and folds every decision into the canonical run trace so the fault
//! schedule is part of the reproducible run.
//!
//! This is distinct from the scenario-level [`crate::fault`] catalogue (which classifies crash /
//! torn-WAL / write-I/O faults for the storage-recovery harness). Here the faults are *interleaved
//! with live, overlapping transactions* on the [`SimScheduler`](graphus_sim::SimScheduler) timeline,
//! not applied as a single post-workload crash.
//!
//! # The single timeline
//!
//! The VOPR loop drives every virtual client's transaction step off one
//! [`SimScheduler`](graphus_sim::SimScheduler); the **dispatched-step ordinal** is the canonical
//! timeline (it advances by exactly one each scheduler step and its total is bounded and known up
//! front, unlike the stochastic logical-time sum). The fault scheduler pre-plans a sorted list of
//! `(fire_step, FaultEvent)` ordinals over the run's step horizon (drawn entirely up front from a
//! dedicated fault RNG). The main loop drains every fault whose `fire_step` has been reached *as* it
//! processes each workload step, so faults fire **interleaved with** — and therefore *during* — open,
//! overlapping transactions, on the one deterministic timeline.
//!
//! # Determinism without perturbing the workload
//!
//! All fault choices are drawn from a **dedicated** [`SimRng`] seeded as `master_seed ^ FAULT_TAG`,
//! *not* from the scheduler's workload RNG. The fault schedule is therefore a pure function of the
//! master seed (same seed ⇒ identical schedule), yet it does not consume draws from the workload
//! stream, so wiring fault scheduling in does not silently reshape an existing seed's workload. The
//! two streams compose deterministically: one seed reproduces both bit-for-bit.
//!
//! # What each fault kind does, and the honest transport status
//!
//! * **Disk** ([`VoprFaultKind::Disk`]) — armed on the *live* engine device mid-workload via the
//!   `dst`-gated [`LocalEngine::with_device_mut`](graphus_server::engine::LocalEngine::with_device_mut)
//!   seam: a seeded [`graphus_io::FaultPlan`] (bit-rot / misdirected read / latent sector error) under
//!   an intensity cap. **Fully woven.**
//! * **Clock** ([`VoprFaultKind::Clock`]) — perturbs the time the engine reads. The engine's clock is a
//!   [`FaultyClock`](graphus_sim::FaultyClock) over the [`SharedClock`](graphus_sim::SharedClock); a
//!   clock fault *intensifies* the active [`ClockFaultPlan`] (forward jumps / regressions) for the rest
//!   of the run. **Fully woven** (the engine reads the faulted clock on every timestamping path).
//! * **Transport** ([`VoprFaultKind::Transport`]) — a seeded [`graphus_sim::TransportFaultPlan`]
//!   decision. The current VOPR driver is **in-process** (`LocalEngine` direct calls, no
//!   [`SimNet`](graphus_sim::SimNet)), so there is no byte stream to reset mid-message. Rather than fake
//!   it, the scheduler still *plans and folds* the transport-fault decision into the trace and tally
//!   (so the budget and reproducibility cover it), but the physical injection is a **documented seam**:
//!   it fires only under a SimNet-backed driver. See [`FaultScheduler::take_transport_plan`].
//!
//! This split is the rmp #236 honesty requirement: disk + clock are physically injected; transport is
//! scheduled, budgeted, traced and left as a clean SimNet seam — never faked.

use graphus_core::PageId;
use graphus_core::capability::Rng;
use graphus_io::FaultPlan;
use graphus_sim::{ClockFaultPlan, SimRng, TransportFaultPlan};

/// Domain-separation tag mixed into the master seed to derive the fault RNG, so fault choices never
/// consume draws from the scheduler's workload RNG (the two streams stay independent yet both replay
/// from the one master seed). The literal spells `"FAULT236"`.
const FAULT_TAG: u64 = 0x4641_554C_5432_3336;

/// The kinds of fault the unified VOPR scheduler can inject, one per planned firing instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoprFaultKind {
    /// A live disk-corruption fault armed on the running engine's device.
    Disk,
    /// A clock perturbation (forward jump / regression) intensifying the engine's faulty clock.
    Clock,
    /// A transport fault (planned + traced; physically fires only under a SimNet driver).
    Transport,
}

impl VoprFaultKind {
    /// A stable byte token for the canonical trace (so the *kind* of each injected fault folds in).
    fn token(self) -> &'static [u8] {
        match self {
            VoprFaultKind::Disk => b"FAULT:DISK",
            VoprFaultKind::Clock => b"FAULT:CLOCK",
            VoprFaultKind::Transport => b"FAULT:XPORT",
        }
    }
}

/// A seeded, bounded budget on fault injection: it stresses the workload while keeping the chaos
/// **recoverable** (never a guaranteed total wipe), so the engine can still make progress and uphold
/// its recovery/ACID contract. Every field is bounded with a sane default; build fluently.
///
/// The budget caps both the **rate** (how many faults fire over the run) and the **intensity** (how
/// aggressive any single device/clock fault is), and weights which kinds are eligible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultBudget {
    /// Hard cap on the total number of faults injected over the whole run (the rate cap). `0` disables
    /// fault injection entirely (the legacy fault-free run).
    pub max_faults: u32,
    /// Relative weight of disk faults in the per-slot kind draw (`0` ⇒ never disk).
    pub disk_weight: u32,
    /// Relative weight of clock faults in the per-slot kind draw (`0` ⇒ never clock).
    pub clock_weight: u32,
    /// Relative weight of transport faults in the per-slot kind draw (`0` ⇒ never transport).
    pub transport_weight: u32,
    /// Intensity cap for a disk fault: the maximum number of distinct pages a single armed
    /// [`FaultPlan`] may target (bit-rot byte count is itself bounded inside the plan). Keeping this
    /// small per slot is what makes the corruption *recoverable* — a checksum catches a handful of
    /// bad pages rather than the whole store being shredded at once.
    pub disk_max_pages: u32,
    /// Intensity cap for a clock fault: the maximum forward-jump / regression magnitude (ns) a clock
    /// fault may add to the active plan. Bounded so the clock stays hostile-but-finite (never sent to
    /// infinity or to zero), exactly the [`FaultyClock`](graphus_sim::FaultyClock) contract.
    pub clock_max_ns: u64,
    /// The highest device page id a disk fault will target. Faults beyond the live store's page range
    /// are harmless no-ops (the page is never read), so this is bounded to the simulated pool to keep
    /// faults landing on live data. Sane default sized for the harness's small pools.
    pub disk_page_span: u32,
}

impl Default for FaultBudget {
    /// A balanced, recoverable default: a handful of faults across all three kinds, each bounded so
    /// the engine survives and recovers (the consistency probe must still pass). Disk weighted highest
    /// because it is the fault the storage spine is most directly contracted to recover from.
    fn default() -> Self {
        Self {
            max_faults: 8,
            disk_weight: 3,
            clock_weight: 2,
            transport_weight: 1,
            disk_max_pages: 2,
            clock_max_ns: 5_000,
            disk_page_span: 64,
        }
    }
}

impl FaultBudget {
    /// A budget that injects **no** faults (the legacy fault-free VOPR run). Useful to certify that
    /// wiring the scheduler in is zero-impact when disabled.
    #[must_use]
    pub fn none() -> Self {
        Self {
            max_faults: 0,
            ..Self::default()
        }
    }

    /// Sets the total fault rate cap (faults per run).
    #[must_use]
    pub fn with_max_faults(mut self, max: u32) -> Self {
        self.max_faults = max;
        self
    }

    /// Sets the per-kind weights (disk, clock, transport) for the slot draw. A zero weight makes that
    /// kind ineligible. All-zero is treated as no faults (nothing is eligible).
    #[must_use]
    pub fn with_weights(mut self, disk: u32, clock: u32, transport: u32) -> Self {
        self.disk_weight = disk;
        self.clock_weight = clock;
        self.transport_weight = transport;
        self
    }

    /// Sets the disk intensity caps: the maximum pages a single fault targets and the page-id span it
    /// draws targets from.
    #[must_use]
    pub fn with_disk_intensity(mut self, max_pages: u32, page_span: u32) -> Self {
        self.disk_max_pages = max_pages;
        self.disk_page_span = page_span;
        self
    }

    /// Sets the clock intensity cap: the maximum jump/regression magnitude (ns) a clock fault adds.
    #[must_use]
    pub fn with_clock_intensity(mut self, max_ns: u64) -> Self {
        self.clock_max_ns = max_ns;
        self
    }

    /// Total kind weight; `0` ⇒ no kind is eligible (equivalent to no faults).
    fn total_weight(&self) -> u32 {
        self.disk_weight
            .saturating_add(self.clock_weight)
            .saturating_add(self.transport_weight)
    }
}

/// One planned fault: the dispatched-step ordinal it fires at, its kind, and the seed that makes its
/// concrete effect (which pages, how big a jump) a pure function of the master seed.
#[derive(Debug, Clone, Copy)]
struct FaultEvent {
    /// Dispatched-step ordinal at or after which this fault fires (the canonical timeline index).
    fire_step: u64,
    kind: VoprFaultKind,
    /// A per-event seed (derived from the fault RNG) that drives this fault's concrete parameters.
    seed: u64,
}

/// The deterministic, seed-driven plan of which faults fire when, bounded by a [`FaultBudget`].
///
/// All firing ordinals and kinds are drawn **up front** from a dedicated fault RNG (`master ^
/// FAULT_TAG`), then sorted by `(fire_step, kind, seed)` into a stable order. At run time the loop calls
/// [`drain_due`](Self::drain_due) with the current dispatched-step ordinal to pull every fault that has
/// come due, in that canonical order — so the fault schedule is a pure function of the master seed and
/// folds into the trace identically every replay.
pub struct FaultScheduler {
    budget: FaultBudget,
    /// Planned faults in canonical fire order; consumed front-to-back as time advances (`cursor` is the
    /// next un-fired index).
    events: Vec<FaultEvent>,
    cursor: usize,
    /// The active clock-fault plan, intensified each time a [`VoprFaultKind::Clock`] fault fires. The
    /// engine reads through a [`FaultyClock`](graphus_sim::FaultyClock) built over the *initial* value
    /// of this plan; clock faults raise the jump/regress probabilities and bounds so later reads grow
    /// hostile.
    clock_plan: ClockFaultPlan,
    /// The most recently planned transport fault, exposed via
    /// [`take_transport_plan`](Self::take_transport_plan) for a SimNet driver to arm. `None` until a
    /// transport fault fires.
    pending_transport: Option<TransportFaultPlan>,
    /// Tally of faults injected, by kind (folded into the [`VoprReport`](crate::vopr::VoprReport)).
    injected_disk: u32,
    injected_clock: u32,
    injected_transport: u32,
}

impl FaultScheduler {
    /// Plans the full fault schedule for `master_seed` under `budget` over a run that dispatches
    /// `step_horizon` workload steps (the bounded, deterministic step count `≈ clients *
    /// ops_per_client`). Faults are spread across `[0, step_horizon)` so they land *during* the
    /// workload, on real interleaved steps, not after it. Using the step ordinal — rather than the
    /// stochastic logical-time sum — guarantees every planned fault actually comes due (the loop always
    /// dispatches that many steps), so the budgeted fault count is honoured exactly.
    ///
    /// With `budget.max_faults == 0` (or no eligible kind) the schedule is empty and the scheduler is
    /// inert — the run is the legacy fault-free run, bit-for-bit.
    #[must_use]
    pub fn plan(master_seed: u64, budget: FaultBudget, step_horizon: u64) -> Self {
        let mut rng = SimRng::new(master_seed ^ FAULT_TAG);
        let total_weight = budget.total_weight();
        let horizon = step_horizon.max(1);

        let mut events = Vec::new();
        if budget.max_faults > 0 && total_weight > 0 {
            for _ in 0..budget.max_faults {
                // Spread the firing step uniformly over the horizon (every fault gets its own draw, so
                // distinct seeds spread faults differently).
                let fire_step = rng.below(horizon);
                let kind = pick_kind(&mut rng, &budget, total_weight);
                let seed = rng.next_u64();
                events.push(FaultEvent {
                    fire_step,
                    kind,
                    seed,
                });
            }
            // Canonical order: by fire step, then a stable kind tiebreak, then a per-event seed — a
            // total order so replay drains faults identically regardless of draw order.
            events.sort_by_key(|e| (e.fire_step, kind_rank(e.kind), e.seed));
        }

        Self {
            budget,
            events,
            cursor: 0,
            clock_plan: ClockFaultPlan::new(master_seed ^ FAULT_TAG ^ 0xC10C),
            pending_transport: None,
            injected_disk: 0,
            injected_clock: 0,
            injected_transport: 0,
        }
    }

    /// Whether this scheduler will ever inject a fault (an inert scheduler is the legacy run).
    #[must_use]
    pub fn is_inert(&self) -> bool {
        self.events.is_empty()
    }

    /// The clock-fault plan the engine's [`FaultyClock`](graphus_sim::FaultyClock) is built over at run
    /// start. Initially inert (no clock fault has fired yet); the engine's reads grow hostile only as
    /// [`VoprFaultKind::Clock`] faults fire and re-arm the engine's clock from the
    /// [`drain_due`](Self::drain_due) `rearm_clock` hook.
    #[must_use]
    pub fn initial_clock_plan(&self) -> ClockFaultPlan {
        self.clock_plan.clone()
    }

    /// Drains every planned fault that has come due at `step` (the current dispatched-step ordinal),
    /// applying each via the provided hooks and folding its `(kind, effect)` into the canonical trace
    /// via `fold`. Returns the number of faults fired this call.
    ///
    /// * `arm_disk` arms a seeded [`FaultPlan`] on the live device (the `dst` seam); it returns whether
    ///   the device was reachable (the engine still live) so a fault on a spent engine is not tallied.
    /// * `rearm_clock` is handed the freshly-intensified [`ClockFaultPlan`] so the caller can rebuild the
    ///   engine's [`FaultyClock`](graphus_sim::FaultyClock) over it.
    /// * `fold` folds a stable token sequence into the run trace.
    ///
    /// All three hooks are deterministic; the order of application is the canonical fault order, so the
    /// trace fold is identical on replay.
    pub fn drain_due(
        &mut self,
        step: u64,
        mut arm_disk: impl FnMut(FaultPlan) -> bool,
        mut rearm_clock: impl FnMut(ClockFaultPlan),
        mut fold: impl FnMut(&[u8], u64),
    ) -> u32 {
        let mut fired = 0;
        while self.cursor < self.events.len() && self.events[self.cursor].fire_step <= step {
            let ev = self.events[self.cursor];
            self.cursor += 1;
            let effect = match ev.kind {
                VoprFaultKind::Disk => {
                    let plan = self.build_disk_plan(ev.seed);
                    if arm_disk(plan) {
                        self.injected_disk += 1;
                        ev.seed
                    } else {
                        // Engine already spent — record the *attempt* so the trace still reflects the
                        // planned schedule, but do not tally it as injected.
                        0
                    }
                }
                VoprFaultKind::Clock => {
                    self.intensify_clock(ev.seed);
                    rearm_clock(self.clock_plan.clone());
                    self.injected_clock += 1;
                    ev.seed
                }
                VoprFaultKind::Transport => {
                    self.pending_transport = Some(self.build_transport_plan(ev.seed));
                    self.injected_transport += 1;
                    ev.seed
                }
            };
            fold(ev.kind.token(), ev.fire_step);
            fold(b"#", effect);
            fired += 1;
        }
        fired
    }

    /// Takes the most recently planned transport fault, if any, for a **SimNet-backed** driver to arm
    /// via [`SimNet::arm_transport_fault`](graphus_sim::SimNet::arm_transport_fault). The current
    /// in-process VOPR driver has no byte stream, so this returns `Some` (the planned, traced fault) but
    /// the loop has nothing to physically arm it on — it is the documented SimNet seam (rmp #236). When
    /// the driver is swapped to SimNet Bolt/REST sessions, the loop pulls this and arms it on the link.
    #[must_use]
    pub fn take_transport_plan(&mut self) -> Option<TransportFaultPlan> {
        self.pending_transport.take()
    }

    /// The per-kind injected-fault tally `(disk, clock, transport)`.
    #[must_use]
    pub fn tally(&self) -> (u32, u32, u32) {
        (
            self.injected_disk,
            self.injected_clock,
            self.injected_transport,
        )
    }

    /// Total faults injected (physically armed disk + clock + planned transport).
    #[must_use]
    pub fn total_injected(&self) -> u32 {
        self.injected_disk + self.injected_clock + self.injected_transport
    }

    /// Builds a bounded, recoverable disk [`FaultPlan`] for one fault slot from `seed`: up to
    /// `disk_max_pages` distinct target pages within `disk_page_span`, each armed with a *survivable*
    /// corruption (bit-rot the checksum catches, a misdirected read, or a latent sector error). Capacity
    /// / write-reordering faults are deliberately omitted from the per-slot plan so the workload keeps
    /// making progress (the chaos stays recoverable, never a guaranteed wipe).
    fn build_disk_plan(&self, seed: u64) -> FaultPlan {
        let mut rng = SimRng::new(seed);
        let mut plan = FaultPlan::new(seed);
        let span = self.budget.disk_page_span.max(1) as u64;
        let pages = rng.range_inclusive(1, u64::from(self.budget.disk_max_pages.max(1)));
        for _ in 0..pages {
            let page = PageId(rng.below(span));
            match rng.below(3) {
                0 => {
                    // Bit-rot: flip a small, bounded number of bytes (a checksum must catch it).
                    let flips = rng.range_inclusive(1, 8) as usize;
                    plan = plan.with_bit_rot(page, flips);
                }
                1 => {
                    // Misdirected read: serve another page's bytes (the page-id checksum catches it).
                    let other = PageId(rng.below(span));
                    plan = plan.with_misdirected_read(page, other);
                }
                _ => {
                    // Latent sector error: the page becomes unreadable (a hard read error to recover).
                    plan = plan.with_latent_sector_error(page);
                }
            }
        }
        plan
    }

    /// Intensifies the active clock plan from `seed`, bounded by `clock_max_ns`. Each clock fault raises
    /// the forward-jump and regression probabilities and bounds (never beyond the cap), so the engine's
    /// clock grows progressively more hostile while staying finite — the [`FaultyClock`] contract.
    fn intensify_clock(&mut self, seed: u64) {
        let mut rng = SimRng::new(seed);
        let cap = self.budget.clock_max_ns.max(1);
        let jump_bound = rng.range_inclusive(1, cap);
        let regress_bound = rng.range_inclusive(1, cap);
        // Probabilities climb toward (but never reach) certainty as faults accumulate.
        let permille = 200 + 100 * self.injected_clock.min(7);
        let skew = rng.range_inclusive(0, cap / 4);
        self.clock_plan = ClockFaultPlan::new(seed)
            .with_skew(skew)
            .with_forward_jumps(permille, jump_bound)
            .with_regressions(permille, regress_bound);
    }

    /// Builds a bounded transport [`TransportFaultPlan`] for one fault slot from `seed` (for a SimNet
    /// driver to arm). Picks one of the three transport pathologies at a small, bounded byte offset so
    /// the reader still terminates (never an unbounded hang).
    fn build_transport_plan(&self, seed: u64) -> TransportFaultPlan {
        let mut rng = SimRng::new(seed);
        let bound = rng.range_inclusive(16, 256);
        match rng.below(3) {
            0 => TransportFaultPlan::new(seed).drop_in_message(bound),
            1 => TransportFaultPlan::new(seed).truncate_then_stall(bound),
            _ => TransportFaultPlan::new(seed).slow_consumer(bound),
        }
    }
}

/// Picks a fault kind weighted by the budget, drawing a single value in `0..total_weight`.
fn pick_kind(rng: &mut SimRng, budget: &FaultBudget, total_weight: u32) -> VoprFaultKind {
    let pick = rng.below(u64::from(total_weight)) as u32;
    if pick < budget.disk_weight {
        VoprFaultKind::Disk
    } else if pick < budget.disk_weight + budget.clock_weight {
        VoprFaultKind::Clock
    } else {
        VoprFaultKind::Transport
    }
}

/// A stable rank for the canonical sort tiebreak (independent of enum declaration order changes).
fn kind_rank(kind: VoprFaultKind) -> u8 {
    match kind {
        VoprFaultKind::Disk => 0,
        VoprFaultKind::Clock => 1,
        VoprFaultKind::Transport => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inert_budget_plans_no_faults() {
        let s = FaultScheduler::plan(7, FaultBudget::none(), 1_000_000);
        assert!(s.is_inert(), "a zero-max budget plans no faults");
        assert_eq!(s.total_injected(), 0);
    }

    #[test]
    fn same_seed_same_schedule() {
        let budget = FaultBudget::default();
        let a = FaultScheduler::plan(42, budget, 500_000);
        let b = FaultScheduler::plan(42, budget, 500_000);
        // The planned event streams must be identical (fire times + kinds + seeds).
        let av: Vec<_> = a
            .events
            .iter()
            .map(|e| (e.fire_step, kind_rank(e.kind), e.seed))
            .collect();
        let bv: Vec<_> = b
            .events
            .iter()
            .map(|e| (e.fire_step, kind_rank(e.kind), e.seed))
            .collect();
        assert_eq!(av, bv, "same seed ⇒ identical fault schedule");
        assert!(!av.is_empty(), "the default budget plans real faults");
    }

    #[test]
    fn distinct_seeds_distinct_schedules() {
        let budget = FaultBudget::default();
        let a = FaultScheduler::plan(1, budget, 500_000);
        let b = FaultScheduler::plan(2, budget, 500_000);
        let av: Vec<_> = a.events.iter().map(|e| (e.fire_step, e.seed)).collect();
        let bv: Vec<_> = b.events.iter().map(|e| (e.fire_step, e.seed)).collect();
        assert_ne!(av, bv, "different seeds ⇒ different fault schedules");
    }

    #[test]
    fn budget_bounds_the_fault_count() {
        let budget = FaultBudget::default().with_max_faults(5);
        let s = FaultScheduler::plan(99, budget, 1_000_000);
        assert!(
            s.events.len() <= 5,
            "the budget caps the planned fault count (got {})",
            s.events.len()
        );
    }

    #[test]
    fn drain_fires_due_faults_in_order_and_tallies() {
        let budget = FaultBudget::default().with_max_faults(6);
        let mut s = FaultScheduler::plan(123, budget, 1_000);
        let mut fired_times = Vec::new();
        // Drain over the whole horizon in one shot; the engine is always "live" here.
        s.drain_due(
            u64::MAX,
            |_plan| true,
            |_plan| {},
            |tok, t| {
                if tok.starts_with(b"FAULT:") {
                    fired_times.push(t);
                }
            },
        );
        // Faults fired in non-decreasing fire-time order (the canonical sort).
        let mut sorted = fired_times.clone();
        sorted.sort_unstable();
        assert_eq!(fired_times, sorted, "faults fire in canonical time order");
        let (d, c, t) = s.tally();
        assert_eq!(
            d + c + t,
            fired_times.len() as u32,
            "every fired fault is tallied by kind"
        );
        assert!(s.total_injected() > 0, "the default mix injects faults");
    }

    #[test]
    fn weights_can_select_a_single_kind() {
        // Disk-only weights ⇒ every planned fault is a disk fault.
        let budget = FaultBudget::default().with_weights(1, 0, 0);
        let s = FaultScheduler::plan(55, budget, 10_000);
        assert!(s.events.iter().all(|e| e.kind == VoprFaultKind::Disk));
        // Transport-only ⇒ all transport.
        let budget = FaultBudget::default().with_weights(0, 0, 1);
        let s = FaultScheduler::plan(55, budget, 10_000);
        assert!(s.events.iter().all(|e| e.kind == VoprFaultKind::Transport));
    }

    #[test]
    fn disk_plan_is_a_pure_function_of_its_seed() {
        let budget = FaultBudget::default().with_disk_intensity(1, 8);
        let s = FaultScheduler::plan(77, budget, 1_000);
        let p1 = s.build_disk_plan(0xABCD);
        let p2 = s.build_disk_plan(0xABCD);
        assert_eq!(
            format!("{p1:?}"),
            format!("{p2:?}"),
            "a disk plan is a pure function of its seed"
        );
    }
}
