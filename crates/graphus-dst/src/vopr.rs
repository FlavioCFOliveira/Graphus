//! `vopr` — the **VOPR simulator core** that ties the deterministic substrate together (rmp #162;
//! `04-technical-design.md` §11; decision `D-dst-investment`).
//!
//! This is the wire-level Deterministic Simulation Testing core, modelled on TigerBeetle's VOPR. It
//! builds the **real** Graphus engine over a **simulated** in-memory store + a [`SharedClock`] driven
//! by a single [`SimScheduler`], then runs a seed-generated workload through it on **one thread**,
//! recording a **canonical event trace** whose stable hash — together with a hash of the final graph
//! state — makes a run a pure function of its seed. Same seed ⇒ identical trace ⇒ identical state.
//!
//! Sprint 1 wires this through [`LocalEngine`] directly (the engine's own command path). Sprints 2+
//! swap the per-client driver for real Bolt/REST sessions over [`graphus_sim::SimNet`] without
//! changing this core: the scheduler, clock, workload and trace machinery are the same.
//!
//! # Cooperative interleaving (rmp #235)
//!
//! The loop is a **deterministic cooperative interleaver**: every virtual client is a small state
//! machine holding an **open explicit transaction** scripted as `[BEGIN, stmt, …, COMMIT|ROLLBACK]`.
//! The single [`SimScheduler`] dispatches each client's *next step* as its own event, ordered by the
//! canonical `(due, rng-priority, seq)` key — so at any scheduler step **multiple clients can have a
//! transaction open simultaneously** (real overlap), exposing write–write / phantom contention to the
//! main multiverse loop, yet the whole run stays single-threaded and a pure function of the seed.
//!
//! Auto-commit survives as one *degenerate* client mode (a one-statement script that begins, runs and
//! commits in a single step via the engine's auto-commit path), so the old behaviour is still
//! exercised alongside the interleaved explicit transactions.

use std::sync::Arc;
use std::sync::Mutex;

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{LocalEngine, RunReply, TxTicket};
use graphus_sim::{ClockFaultPlan, FaultyClock, SharedClock, SimScheduler};
use graphus_wal::MemLogSink;

use graphus_elle::{Op as ElleOp, Transaction as ElleTxn, check as elle_check};

use graphus_sim::SimRng;

use crate::mix::{LoadProfile, MixProfile, WorkloadGen, WorkloadOp};
use crate::vopr_fault::{FaultBudget, FaultScheduler};
use crate::vopr_oracle::{
    OracleError, ShadowGraph, assert_equivalent, is_surfaced_injected_latent_fault,
};

/// The single Elle object key the safety oracle records the `:Person` id space under. Every committed
/// `CreateNode{id}` is an [`ElleOp::Append`] of `id` to this key; the generator's ids are monotonic +
/// unique, so the recovered appends form a **self-recoverable version order** — Elle's requirement for
/// the list-append model (Kingsbury & Alvaro). The history is **append-only**: the workload's reads
/// (`CountNodes`/`Neighbors`) cannot yield a faithful observed id-list (a count is not a list), so
/// synthesising reads would inject phantom anomalies; read-transaction serializability is certified
/// separately against the engine's *real* observed lists by the `isolation` oracle (rmp #170/#171).
const ELLE_PERSONS_KEY: &str = "persons";

/// How many of the most-recent dispatched steps the liveness-mode progress watchdog (rmp #240) keeps
/// in its dumped-schedule ring, so a flagged stall comes with a bounded, human-readable trace of the
/// `(step, client, progressed)` tuples leading into it. Bounded ⇒ the dump never grows with run length.
const LIVENESS_DUMP_WINDOW: usize = 32;

/// How many fresh `:Person` creates the liveness-mode **fault-then-heal recovery probe** (rmp #240)
/// drives against the quiesced engine after the fault window, to prove availability resumed. Small (the
/// engine has already survived the whole workload) but `> 1` so a partial post-heal stall is visible.
const RECOVERY_BATCH: usize = 8;

/// Domain-separation tag mixed into the master seed to derive the **swarm RNG** ([`VoprConfig::swarm`],
/// rmp #241), so swarming the *configuration* never consumes draws from the scheduler's workload RNG
/// (`master_seed`) or the fault scheduler's RNG (`master_seed ^ FAULT_TAG`). A swarmed config is
/// therefore a pure function of the seed *and* the seed's workload is unchanged by whether swarming is
/// on — the three streams compose deterministically from the one master seed. The literal spells
/// `"SWARM241"`.
const SWARM_TAG: u64 = 0x5357_4152_4D32_3431;

/// A [`Clock`] whose active [`ClockFaultPlan`] can be **swapped at run time**, so the unified fault
/// scheduler can intensify the engine's clock faults *mid-run* (the engine holds one fixed
/// `Arc<dyn Clock>`, but the plan behind it changes when a clock fault fires).
///
/// The simulator sets the inner [`SharedClock`] from scheduler time each step; every engine read of
/// `now_nanos` then passes through the *current* plan. The fault math is delegated to the audited
/// [`FaultyClock`] (rmp #233) — built transiently per read over the current plan — so this adds no new
/// fault logic. Only the **tolerant** trait read is exposed (the engine reaches the clock solely
/// through the [`Clock`] trait object); the monotone high-water path is not needed here.
///
/// `Send + Sync` (the engine's clock slot requires it): the swappable plan is held behind a
/// [`Mutex`]; the single-threaded simulator never contends it.
#[derive(Debug)]
struct SwappableClock {
    inner: SharedClock,
    plan: Mutex<ClockFaultPlan>,
}

impl SwappableClock {
    /// Builds a clock over `inner` starting with `plan` (inert by default ⇒ reads through transparently
    /// until a clock fault swaps in a hostile plan).
    fn new(inner: SharedClock, plan: ClockFaultPlan) -> Self {
        Self {
            inner,
            plan: Mutex::new(plan),
        }
    }

    /// Swaps in a new (intensified) clock-fault plan; subsequent reads observe it.
    fn set_plan(&self, plan: ClockFaultPlan) {
        if let Ok(mut guard) = self.plan.lock() {
            *guard = plan;
        }
    }
}

impl Clock for SwappableClock {
    fn now_nanos(&self) -> u64 {
        let plan = self
            .plan
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|_| ClockFaultPlan::default());
        // Delegate to the audited FaultyClock tolerant read; a transient instance carries no read-order
        // state (the per-read fault is a pure function of the plan seed + base time), so rebuilding it
        // each call is exact and deterministic.
        FaultyClock::new(self.inner.clone(), plan).now_nanos()
    }
}

/// The simulated engine type: the real engine over the simulated in-memory device + log.
type SimEngine = LocalEngine<MemBlockDevice, MemLogSink>;

/// Configuration for one VOPR run (everything a seed needs to become a full execution).
///
/// Serializes to/from JSON (rmp #242) so a failing run can be persisted as a reproducer artifact and
/// replayed byte-identically — the whole engine is a pure function of this config, so round-tripping it
/// is enough to reproduce the exact run. See [`vopr_repro`](crate::vopr_repro).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VoprConfig {
    /// The master seed: drives the scheduler, workload and all fault choices.
    pub seed: u64,
    /// Number of concurrent virtual clients.
    pub clients: u32,
    /// Operations issued per client.
    pub ops_per_client: u32,
    /// Buffer-pool pages for the simulated store.
    pub pool_pages: usize,
    /// The workload mix (op-class weights) the generator draws from.
    pub mix: MixProfile,
    /// How arrivals are spread over scheduler time (steady / ramp / spike) — the load profile.
    pub load: LoadProfile,
    /// Upper bound on the number of statements an *explicit* (multi-step) transaction batches before
    /// it ends with `COMMIT`/`ROLLBACK`. Each client draws `1..=max_txn_stmts` per transaction; larger
    /// values keep transactions open across more scheduler steps, deepening overlap. `0` is treated as
    /// `1`. (Auto-commit transactions are always one statement regardless.)
    pub max_txn_stmts: u32,
    /// Permille (out of 1000) chance that a client opens an *auto-commit* (degenerate one-statement)
    /// transaction instead of an explicit multi-step one. `0` ⇒ always explicit (maximum overlap);
    /// `1000` ⇒ always auto-commit (the legacy per-op behaviour). The default favours explicit
    /// transactions so contention is reachable while still exercising the auto-commit path.
    pub auto_commit_permille: u32,
    /// Permille chance that an explicit transaction ends with `ROLLBACK` rather than `COMMIT`, so the
    /// interleaver exercises abort handling too. `0` ⇒ never roll back.
    pub rollback_permille: u32,
    /// The **unified fault budget** (rmp #236): how many disk / clock / transport faults the scheduler
    /// injects on the workload timeline, and their intensity caps. Drawn from the master seed, so the
    /// fault schedule is part of the reproducible run. Defaults to [`FaultBudget::none`] so a standard
    /// run is fault-free (and bit-for-bit identical to the pre-#236 run); enable faults with
    /// [`with_faults`](Self::with_faults).
    pub fault_budget: FaultBudget,
}

impl VoprConfig {
    /// A standard run for `seed` (4 clients × 50 ops over a 256-page pool, balanced mix).
    #[must_use]
    pub fn for_seed(seed: u64) -> Self {
        Self {
            seed,
            clients: 4,
            ops_per_client: 50,
            pool_pages: 256,
            mix: MixProfile::mixed(),
            load: LoadProfile::Steady { min: 1, max: 1000 },
            max_txn_stmts: 4,
            auto_commit_permille: 250,
            rollback_permille: 100,
            fault_budget: FaultBudget::none(),
        }
    }

    /// The same run with a specific workload `mix`.
    #[must_use]
    pub fn with_mix(mut self, mix: MixProfile) -> Self {
        self.mix = mix;
        self
    }

    /// The same run with a specific `load` profile.
    #[must_use]
    pub fn with_load(mut self, load: LoadProfile) -> Self {
        self.load = load;
        self
    }

    /// The same run with a specific **fault budget** (rmp #236): the unified scheduler then injects
    /// disk / clock / transport faults on the workload timeline under `budget`, folded into the trace
    /// and tallied in the report. With [`FaultBudget::none`] the run is fault-free.
    #[must_use]
    pub fn with_faults(mut self, budget: FaultBudget) -> Self {
        self.fault_budget = budget;
        self
    }

    /// The same run with **crash + ARIES restart** events woven into the running interleave (rmp #237):
    /// the scheduler crashes the live engine `max_crashes` times mid-workload and rebuilds it from the
    /// durable WAL, then the workload continues. Sets the crash cap on the active fault budget (keeping
    /// any disk/clock/transport weights), so a run can combine crashes with other faults. Off by default.
    #[must_use]
    pub fn with_crashes(mut self, max_crashes: u32) -> Self {
        self.fault_budget = self.fault_budget.with_crashes(max_crashes);
        self
    }

    /// The same run forced into **pure auto-commit mode**: every operation is its own one-statement
    /// transaction (the legacy per-op behaviour, with no explicit-transaction overlap). Use this for
    /// scenarios that certify clean per-op liveness rather than the interleaver's contention path.
    #[must_use]
    pub fn auto_commit_only(mut self) -> Self {
        self.auto_commit_permille = 1000;
        self
    }

    /// The **safety-mode preset** for `seed` (rmp #239): a contended interleave (explicit overlapping
    /// transactions under a write-heavy mix) run **under faults + crashes**, sized to stay fast in a
    /// debug build while guaranteeing acked commits and in-flight transactions coexist at a crash. This
    /// is the config [`run_safety`] certifies the full four-property safety bundle against, every run.
    ///
    /// It enables a bounded fault budget *and* crashes so the safety properties are asserted **while
    /// faults fire during concurrent interleaved work** — the whole point of the mode. The budget stays
    /// recoverable (it never guarantees a total wipe), so the engine can uphold its ACID contract.
    #[must_use]
    pub fn safety(seed: u64) -> Self {
        Self {
            clients: 6,
            ops_per_client: 24,
            pool_pages: 512,
            mix: MixProfile::write_heavy(),
            max_txn_stmts: 5,
            auto_commit_permille: 200,
            rollback_permille: 100,
            ..Self::for_seed(seed)
        }
        .with_faults(FaultBudget::default().with_max_faults(8))
        .with_crashes(2)
    }

    /// The **liveness-mode preset** for `seed` (rmp #240): the same contended interleave run under a
    /// bounded, **recoverable** fault window (disk/clock/transport faults + crashes), sized so the
    /// progress watchdog and the fault-then-heal recovery probe are both meaningful in a debug build.
    ///
    /// Liveness mode arms a fault window *during* the workload, then — once the workload drains and every
    /// fault/crash has healed — asserts (a) the progress watchdog never saw an unbounded stall (no
    /// deadlock/livelock/hang) and (b) a fresh post-heal workload batch commits and serves correct
    /// results (availability recovered). The budget stays recoverable (never a guaranteed wipe), so a
    /// healthy engine always recovers and the run reports `live`.
    #[must_use]
    pub fn liveness(seed: u64) -> Self {
        Self::safety(seed)
    }

    /// A **swarm-tested** config for `seed` (rmp #241): *every* knob — environment, workload mix, load
    /// profile and fault budget — is derived deterministically from the master seed within **sane,
    /// documented, bounded** ranges, so each seed explores a *different* configuration rather than only
    /// a different workload+schedule under one fixed environment. This is "swarm testing" (Groce et al.,
    /// *Swarm Testing*, ISSTA 2012): randomising the test *configuration* per seed dramatically widens
    /// the state space a seed sweep covers.
    ///
    /// # Determinism and stream separation
    ///
    /// All config knobs are drawn from a **dedicated** swarm RNG seeded as `seed ^ SWARM_TAG`, *not*
    /// from the scheduler's workload RNG (`seed`) or the fault scheduler's RNG (`seed ^ FAULT_TAG`).
    /// Consequences:
    /// * **Same seed ⇒ identical config** (the derivation is a pure function of the seed).
    /// * A swarmed config's **workload is still the pure function of `seed`** the non-swarmed run uses —
    ///   swarming the environment does not perturb the workload/fault draws, it only *chooses the knobs*
    ///   those draws then run under. The three streams compose deterministically from the one seed.
    /// * **Distinct seeds ⇒ distinctly different configs** (each knob has its own draw, so the knob
    ///   distribution over a sweep is non-degenerate — see the `swarm_*` acceptance tests).
    ///
    /// # The swarmed range (every bound is recoverable and bounded)
    ///
    /// The bounds keep every swarmed run **recoverable** (the fault budget never guarantees a wipe) and
    /// **bounded** (no zero-client / unbounded config). Small pools are *intentional* — they induce
    /// buffer-pool eviction/steal pressure — but never zero.
    ///
    /// | Knob | Range | Why this bound |
    /// |------|-------|----------------|
    /// | `clients` | `2..=12` | ≥2 so transaction overlap is reachable; ≤12 keeps the single-threaded run bounded. |
    /// | `ops_per_client` | `16..=80` | enough statements to do real work; capped so the run length stays bounded. |
    /// | `pool_pages` | `48..=512` | a small min induces eviction/steal pressure; never `0` (a zero pool cannot build the engine). |
    /// | `mix.*` (4 weights) | each `1..=60` | every class stays reachable (≥1, never an all-zero degenerate mix); ratios still vary widely. |
    /// | `load` | `Steady`/`Ramp`/`Spike`, params below | all three arrival shapes are exercised across a sweep. |
    /// | &nbsp;&nbsp;`Steady{min,max}` | `min ∈ 1..=200`, `max ∈ min..=min+800` | bounded, ordered inter-arrival jitter. |
    /// | &nbsp;&nbsp;`Ramp{start,end}` | each `1..=1000` | bounded ramp endpoints (either direction). |
    /// | &nbsp;&nbsp;`Spike{base,period,burst}` | `base ∈ 1..=200`, `period ∈ 2..=16`, `burst ∈ 1..=period` | bounded base with a real burst within each period. |
    /// | `max_txn_stmts` | `1..=6` | deeper batches deepen overlap; bounded so a transaction always ends. |
    /// | `auto_commit_permille` | `0..=1000` | full coverage from always-explicit to always-auto-commit. |
    /// | `rollback_permille` | `0..=300` | exercises aborts without starving commits. |
    /// | `fault_budget.max_faults` | `0..=12` | a recoverable fault rate (`0` ⇒ a fault-free swarmed run is reachable too). |
    /// | `fault_budget` kind weights | each `0..=4`, total forced ≥1 | every kind mix is reachable; never an all-zero (no-eligible-kind) budget when faults are on. |
    /// | `fault_budget.disk_max_pages` | `1..=4` | a handful of bad pages a checksum catches — recoverable, never a shred. |
    /// | `fault_budget.disk_page_span` | `16..=128` | faults land on live data within the swarmed pool range. |
    /// | `fault_budget.clock_max_ns` | `1_000..=10_000` | hostile-but-finite clock skew (the `FaultyClock` contract). |
    /// | `fault_budget.max_crashes` | `0..=3` | a bounded number of recoverable crash + ARIES restarts. |
    ///
    /// # Pinning escape hatch
    ///
    /// Swarm is **opt-in**: [`for_seed`](Self::for_seed), [`safety`](Self::safety) and
    /// [`liveness`](Self::liveness) remain fixed presets for focused / pinned runs, untouched by this.
    /// Use [`run_cli`]'s `--swarm` flag to swarm each seed in a sweep.
    #[must_use]
    pub fn swarm(seed: u64) -> Self {
        let mut rng = SimRng::new(seed ^ SWARM_TAG);

        let clients = rng.range_inclusive(2, 12) as u32;
        let ops_per_client = rng.range_inclusive(16, 80) as u32;
        let pool_pages = rng.range_inclusive(48, 512) as usize;

        // Each class weight stays ≥1 so no class is ever excluded (an all-zero mix would be a degenerate
        // "no-op" generator); the ratios still range over a wide 1..=60 band so the mix genuinely varies.
        let mix = MixProfile {
            create_node: rng.range_inclusive(1, 60) as u32,
            create_edge: rng.range_inclusive(1, 60) as u32,
            count_nodes: rng.range_inclusive(1, 60) as u32,
            neighbors: rng.range_inclusive(1, 60) as u32,
        };

        let load = match rng.below(3) {
            0 => {
                let min = rng.range_inclusive(1, 200);
                let max = rng.range_inclusive(min, min + 800);
                LoadProfile::Steady { min, max }
            }
            1 => LoadProfile::Ramp {
                start: rng.range_inclusive(1, 1000),
                end: rng.range_inclusive(1, 1000),
            },
            _ => {
                let period = rng.range_inclusive(2, 16);
                LoadProfile::Spike {
                    base: rng.range_inclusive(1, 200),
                    period,
                    burst: rng.range_inclusive(1, period),
                }
            }
        };

        let max_txn_stmts = rng.range_inclusive(1, 6) as u32;
        let auto_commit_permille = rng.range_inclusive(0, 1000) as u32;
        let rollback_permille = rng.range_inclusive(0, 300) as u32;

        let fault_budget = Self::swarm_fault_budget(&mut rng);

        Self {
            seed,
            clients,
            ops_per_client,
            pool_pages,
            mix,
            load,
            max_txn_stmts,
            auto_commit_permille,
            rollback_permille,
            fault_budget,
        }
    }

    /// Derives a bounded, **recoverable** [`FaultBudget`] from the swarm RNG (rmp #241). Drawn after all
    /// environment/workload/load knobs so the budget is the trailing portion of the swarm stream. The
    /// caps mirror [`FaultBudget`]'s own recoverability contract: every fault a swarmed run injects is
    /// survivable — a checksum catches a handful of disk pages, the clock stays finite, crashes are
    /// bounded — so no swarmed config can guarantee a wipe.
    fn swarm_fault_budget(rng: &mut SimRng) -> FaultBudget {
        let max_faults = rng.range_inclusive(0, 12) as u32;
        // Kind weights are each 0..=4, but the total is forced ≥1 (bumping disk) so that whenever faults
        // are on at least one kind is eligible — an all-zero weight set would silently disable faults.
        let mut disk_weight = rng.range_inclusive(0, 4) as u32;
        let clock_weight = rng.range_inclusive(0, 4) as u32;
        let transport_weight = rng.range_inclusive(0, 4) as u32;
        if disk_weight + clock_weight + transport_weight == 0 {
            disk_weight = 1;
        }
        let disk_max_pages = rng.range_inclusive(1, 4) as u32;
        let disk_page_span = rng.range_inclusive(16, 128) as u32;
        let clock_max_ns = rng.range_inclusive(1_000, 10_000);
        let max_crashes = rng.range_inclusive(0, 3) as u32;

        FaultBudget {
            max_faults,
            disk_weight,
            clock_weight,
            transport_weight,
            disk_max_pages,
            clock_max_ns,
            disk_page_span,
            max_crashes,
        }
    }
}

/// The deterministic outcome of one VOPR run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoprReport {
    /// The seed this run replays from.
    pub seed: u64,
    /// Total operations dispatched.
    pub steps: usize,
    /// Operations that succeeded.
    pub ok_ops: usize,
    /// Operations that returned an error (engine error response — not a panic).
    pub err_ops: usize,
    /// Stable hash of the canonical event trace (operations + outcomes, in dispatch order).
    pub trace_hash: u64,
    /// Stable hash of the final graph state (an ordered snapshot of nodes + relationships).
    pub state_hash: u64,
    /// Logical time (ns) at the end of the run.
    pub end_time: u64,
    /// Number of `:Person` nodes the workload asked to create (the generator's id space). This counts
    /// only *committed* creates — a node created inside a transaction the interleaver later rolls back
    /// is not counted, so this stays equal to [`persisted_nodes`](Self::persisted_nodes).
    pub created_nodes: i64,
    /// Number of `:Person` nodes actually present at the end (queried back). Must equal
    /// `created_nodes` — a liveness/consistency check: no acked create is lost or duplicated.
    pub persisted_nodes: i64,
    /// The maximum number of explicit transactions that were **open simultaneously** at any scheduler
    /// step (the interleaver's overlap depth). `>= 2` proves the cooperative interleaver reached a
    /// genuinely concurrent state — multiple transactions in flight at once, single-threaded.
    pub max_open_txns: usize,
    /// Explicit transactions that committed successfully.
    pub committed_txns: usize,
    /// Explicit transactions that aborted — either rolled back by the script, or whose `COMMIT` failed
    /// (an SSI serialization conflict the contention exposed). `>0` under contention proves the main
    /// loop now reaches conflict outcomes the old per-op auto-commit loop could not.
    pub aborted_txns: usize,
    /// Disk faults the unified scheduler armed on the live device during the run (rmp #236). Folded
    /// into [`trace_hash`](Self::trace_hash), so two replays of the same seed inject the same faults.
    pub disk_faults: u32,
    /// Clock faults the unified scheduler injected (intensifying the engine's faulty clock).
    pub clock_faults: u32,
    /// Transport faults the unified scheduler **planned and traced**. Under the current in-process
    /// driver these are scheduled, budgeted and folded into the trace but not physically armed (there
    /// is no byte stream); they fire physically only under a SimNet-backed driver (the documented
    /// rmp #236 seam — see [`vopr_fault`](crate::vopr_fault)).
    pub transport_faults: u32,
    /// **Crash + ARIES restart events** woven into the running interleave (rmp #237). Each one dropped
    /// the live engine mid-workload and rebuilt it from the durable WAL via
    /// [`LocalEngine::crash_restart`](graphus_server::engine::LocalEngine), then the workload continued
    /// against the recovered engine. `0` for a standard run (crashes are off by default). Folded into
    /// [`trace_hash`](Self::trace_hash), so the crash schedule is part of the reproducible run.
    pub crash_restarts: u32,
    /// Per-crash acked-vs-in-flight classification (rmp #237), one [`CrashSplit`] per restart, in fire
    /// order. The Sprint C oracle (rmp #238) consumes this to assert the durability/atomicity contract:
    /// every transaction acked before a crash survives it, and every transaction still in flight at the
    /// crash does not. Empty for a standard (crash-free) run.
    pub crash_splits: Vec<CrashSplit>,
    /// The **strong reference-model oracle** verdict (rmp #238): `None` if the committed-only shadow
    /// model agreed with the engine queried back **cell-by-cell** at run end (the multiset of `:Person`
    /// ids, the full `:KNOWS` edge multiset, the `count(n)` aggregate, and every per-person neighbour
    /// row count); `Some(err)` naming the first id/edge that diverged. This is the teeth the old
    /// count+hash oracle lacked — a wrong result with the right cardinality is now caught. Folded into
    /// the report's equality (so a divergence breaks the same-seed determinism gate too) but **not**
    /// into [`trace_hash`](Self::trace_hash): the oracle's read-back queries are an observer and do not
    /// perturb the canonical workload trace.
    pub oracle: Option<OracleError>,
    /// The device pages the fault scheduler armed with a **latent sector error** over this run (rmp
    /// #480), ascending. A latent sector error makes a page permanently unreadable, so a read-back that
    /// hard-fails naming one of these pages is the engine *surfacing* an injected fault ("surface,
    /// never corrupt"), not a durability bug. The safety oracle correlates a surfaced read-back error
    /// against this set to tell an expected engine-surfaced injected fault apart from a genuine
    /// reference-model divergence (a *silent* committed-data discrepancy, which carries no surfaced
    /// error and is never excused). Empty for a fault-free run. Deterministic, so it never perturbs
    /// same-seed replay.
    pub latent_fault_pages: Vec<u64>,
}

/// The acked-vs-in-flight split captured at one **crash + ARIES restart** instant (rmp #237) — the
/// classification the Sprint C oracle (rmp #238) asserts against.
///
/// At the crash, each virtual client's transaction is exactly one of:
/// * **acked** — every explicit `COMMIT` (and auto-commit) the engine acknowledged *before* this crash.
///   These are in the durable WAL by the group-commit rule, so ARIES redo replays them: they **must
///   survive** the restart.
/// * **in-flight** — a transaction still *open* (a live ticket) at the crash. It was never acknowledged,
///   so ARIES undo / no-redo discards it: it **must not survive** (no committed-or-nothing violation).
///
/// The counts are cumulative-at-crash snapshots taken on the one deterministic timeline, so two replays
/// of the same seed produce identical splits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrashSplit {
    /// The dispatched-step ordinal the crash fired at (the canonical timeline index).
    pub fire_step: u64,
    /// Total transactions **acknowledged** (committed) across all clients before this crash — the set
    /// that must survive the ARIES restart.
    pub acked_commits: usize,
    /// Transactions **open / in-flight** (uncommitted) at the crash — aborted by the crash, must not
    /// survive. One per client that held an open explicit ticket at the firing step.
    pub inflight_txns: usize,
    /// The graph state hash observed **immediately after** the recovered engine was rebuilt — a digest
    /// of exactly the durable (acked) state. Lets the oracle pin the recovered state per crash.
    pub recovered_state_hash: u64,
}

/// The strong reference-model oracle's run-time state (rmp #238): the committed-only shadow model
/// plus a **per-client buffer** of the ops issued inside each client's currently-open transaction.
///
/// Buffering is the whole game. An op only becomes durable when its transaction's `COMMIT` is
/// acknowledged, so each client's ops are staged in `pending[client]` as statements run and are
/// **flushed** into [`ShadowGraph`] only on a successful commit (explicit `COMMIT` ok, or a
/// successful auto-commit). On `ROLLBACK`, an SSI-aborted `COMMIT`, or a crash that drops open
/// transactions, the buffer is **discarded** — never applied — exactly mirroring the engine's
/// durability/atomicity contract.
struct Oracle {
    /// The independent shadow model, the cumulative effect of all *committed* ops.
    model: ShadowGraph,
    /// Per-client staged state for the client's currently-open explicit transaction.
    pending: Vec<PendingTxn>,
    /// The recovered Elle history (rmp #239 safety mode). `None` for a standard run.
    elle_history: Option<Vec<ElleTxn>>,
    /// Monotonic Elle transaction id, assigned in commit order so the recorded history is stable.
    elle_next_id: u64,
}

#[derive(Clone, Default)]
struct PendingTxn {
    snapshot: std::collections::BTreeMap<i64, u64>,
    ops: Vec<WorkloadOp>,
    elle_ops: Vec<ElleOp>,
}

impl Oracle {
    fn new(clients: usize) -> Self {
        Self {
            model: ShadowGraph::new(),
            pending: vec![PendingTxn::default(); clients],
            elle_history: None,
            elle_next_id: 1,
        }
    }

    fn new_recording(clients: usize) -> Self {
        Self {
            elle_history: Some(Vec::new()),
            ..Self::new(clients)
        }
    }

    fn begin(&mut self, client: usize) {
        self.pending[client] = PendingTxn {
            snapshot: self.model.node_snapshot(),
            ops: Vec::new(),
            elle_ops: Vec::new(),
        };
    }

    fn stage(&mut self, client: usize, op: WorkloadOp) {
        self.pending[client].ops.push(op);
        if self.elle_history.is_some() {
            self.stage_elle(client, op);
        }
    }

    /// Projects `op` into the recorded Elle history for `client`'s open transaction (recorder-on path).
    ///
    /// Only **writes** are recorded, as [`ElleOp::Append`] of the created `id` to [`ELLE_PERSONS_KEY`].
    /// We deliberately do **not** synthesise reads: the workload's `CountNodes` yields only a *count*
    /// (never the id list), so a read's `observed` order cannot be recovered from what the engine
    /// actually returned — fabricating it from the model snapshot would inject reads that disagree with
    /// the true serialization order under contention/crashes and make the Elle checker report *phantom*
    /// cycles that are artifacts of the recorder, not engine anomalies. (Measured: every such "cycle"
    /// was read-driven, never a duplicate append.) The end-to-end SSI serializability of *reading*
    /// transactions is certified separately, against the engine's real observed lists, by the
    /// `isolation` oracle (rmp #170/#171). Here the append-only history — with the generator's unique,
    /// monotonic ids — is self-recoverable and its serializability check has real teeth: it fails iff
    /// the recovered history contains a **duplicate or impossible version order** (e.g. the same id
    /// committed twice, or a create lost-then-duplicated across recovery), exactly the corruption a
    /// crash-recovery defect would produce.
    fn stage_elle(&mut self, client: usize, op: WorkloadOp) {
        if let WorkloadOp::CreateNode { id } = op {
            self.pending[client].elle_ops.push(ElleOp::Append {
                key: ELLE_PERSONS_KEY.to_owned(),
                val: id,
            });
        }
    }

    fn commit(&mut self, client: usize) {
        let txn = std::mem::take(&mut self.pending[client]);
        self.model.commit_transaction(&txn.snapshot, &txn.ops);
        if let Some(history) = self.elle_history.as_mut() {
            if !txn.elle_ops.is_empty() {
                let id = self.elle_next_id;
                self.elle_next_id += 1;
                history.push(ElleTxn::committed(id, txn.elle_ops));
            }
        }
    }

    fn record_auto_commit(&mut self, op: WorkloadOp) {
        if let (Some(history), WorkloadOp::CreateNode { id }) = (self.elle_history.as_mut(), op) {
            let txn_id = self.elle_next_id;
            self.elle_next_id += 1;
            history.push(ElleTxn::committed(
                txn_id,
                vec![ElleOp::Append {
                    key: ELLE_PERSONS_KEY.to_owned(),
                    val: id,
                }],
            ));
        }
    }

    fn discard(&mut self, client: usize) {
        self.pending[client] = PendingTxn::default();
    }

    fn discard_all(&mut self) {
        for buf in &mut self.pending {
            *buf = PendingTxn::default();
        }
    }
}

/// One scheduled unit of work: a client advancing its open transaction by **one step**. The step's
/// *kind* is decided when the client reaches it (so the script is generated lazily from the RNG), not
/// carried here — this event only says "client `client`, please take your next step".
#[derive(Debug, Clone, Copy)]
struct Tick {
    client: u32,
}

/// What a client does on its next scheduled step. A transaction is the script
/// `Begin → (Stmt)* → End`, each arm a separate scheduled step so other clients interleave between
/// them — that interleaving is exactly where simultaneous open transactions (and their contention)
/// come from.
#[derive(Debug, Clone, Copy)]
enum Step {
    /// Open the transaction. `auto_commit` picks the degenerate one-statement path (engine
    /// auto-commit) versus an explicit multi-step transaction; `remaining` statements will follow.
    Begin { auto_commit: bool, remaining: u32 },
    /// Run one workload statement inside the open transaction; `remaining` more will follow, then the
    /// transaction ends with `ROLLBACK` if `rollback` (the disposition fixed at `Begin` time).
    Stmt { remaining: u32, rollback: bool },
    /// End the explicit transaction. `rollback` chooses `ROLLBACK` over `COMMIT`.
    End { rollback: bool },
}

/// A virtual client's state in the interleaver: either between transactions, or mid-transaction with
/// an open ticket and a pending next step.
enum ClientState {
    /// No open transaction; the next scheduled step will `Begin` one (if the client has op budget).
    Idle,
    /// An **explicit** transaction is open (its ticket is live in the engine) with `next` queued as
    /// the step to run when this client is next dispatched. Auto-commit transactions never reach this
    /// state — they open, run and commit within a single step, returning straight to `Idle`.
    Open { ticket: TxTicket, next: Step },
}

impl ClientState {
    /// `true` while a transaction is open (used to count simultaneous overlap).
    fn is_open(&self) -> bool {
        matches!(self, ClientState::Open { .. })
    }
}

/// Runs one VOPR simulation to completion and returns its deterministic report.
///
/// # Panics
/// Panics only if the **simulated** in-memory store cannot be created (an out-of-memory style
/// failure in the test environment), which is not a condition the simulation is meant to tolerate.
#[must_use]
pub fn run(cfg: VoprConfig) -> VoprReport {
    run_inner(cfg, RunMode::Standard).0
}

/// Which observer machinery a [`run_inner`] invocation switches on. Each mode only *adds* read-only
/// recorder state to the standard run — none perturbs the workload RNG, the canonical trace, or the
/// engine — so a run is the same pure function of its seed under every mode (the modes simply observe
/// different facets of that one deterministic execution).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunMode {
    /// The bare deterministic run ([`run`]): no extra recorder state. Zero-cost.
    Standard,
    /// Safety mode (rmp #239): record the recovered committed history as an Elle transaction list so the
    /// safety checker can rule on serializability.
    Safety,
    /// Liveness mode (rmp #240): run the **progress watchdog** over logical time (tracking the longest
    /// stall and dumping the recent step schedule around it) and, after the fault window heals, probe a
    /// fresh workload batch to assert the engine resumes serving correct results (availability recovers).
    Liveness,
}

/// The verdict of the **fault-then-heal recovery probe** (rmp #240): a fresh, deterministic workload
/// batch driven against the engine *after* the fault window — proving availability resumed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecoveryProbe {
    /// How many fresh `:Person` creates the post-heal batch attempted.
    attempted: usize,
    /// How many of them the engine **committed** (acknowledged) after the heal.
    committed: usize,
    /// Whether every committed create read back correctly (the reference model agreed with the engine
    /// over the post-heal batch) — the engine served *correct* results, not just *some* results.
    correct: bool,
}

/// The progress-watchdog observation of one liveness run (rmp #240): the worst stall window seen over
/// logical time plus the dumped schedule around it, and the fault-then-heal recovery-probe verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LivenessTrace {
    /// The longest run of consecutive dispatched scheduler steps during which **no** client advanced its
    /// transaction state machine (`advance_client` returned `false` — a step that dispatched a spent
    /// client with nothing to do). A healthy run keeps this small; a deadlock/livelock/hang drives it up
    /// to the hard step cap, which is what flags the violation.
    max_stall_steps: usize,
    /// Whether the run terminated by draining its scheduler queue (`false`) or by tripping the hard
    /// step-cap guard (`true`). A capped exit on a *non-empty* queue is the signature of a real hang the
    /// watchdog bounded into a report rather than an infinite loop.
    hit_step_cap: bool,
    /// The dispatched-step ordinal at which the worst stall *began*, for one-line reproduction.
    worst_stall_at: u64,
    /// The dumped recent step schedule (a bounded ring of `(dispatched_step, client, progressed)`
    /// tuples) captured around the worst stall — the trace a human reads to debug a flagged hang.
    dumped_schedule: Vec<(u64, u32, bool)>,
    /// The fault-then-heal recovery-probe verdict (`None` in non-liveness modes).
    recovery: Option<RecoveryProbe>,
}

/// The shared run engine behind [`run`] (standard), [`run_safety`] (safety mode) and [`run_liveness`]
/// (liveness mode). The `mode` switches on the read-only recorder machinery each oracle needs; the
/// recovered Elle history (safety) and the liveness watchdog trace (liveness) are returned alongside
/// the report so the respective checker can rule. Standard mode is the bare run, bit-for-bit.
fn run_inner(cfg: VoprConfig, mode: RunMode) -> (VoprReport, Vec<ElleTxn>, LivenessTrace) {
    // The single simulated clock, shared with the engine and set from scheduler time each step.
    let clock = SharedClock::new(0);

    // The unified fault scheduler (rmp #236): plans the seed-driven disk/clock/transport fault schedule
    // up front, over the run's bounded dispatched-step horizon, under the configured budget. With
    // `FaultBudget::none()` it is inert and the run is the legacy fault-free run, bit-for-bit.
    let step_horizon = estimate_step_horizon(&cfg);
    let mut faults = FaultScheduler::plan(cfg.seed, cfg.fault_budget, step_horizon);

    // The engine reads time through a swappable faulty clock: a clock fault intensifies the plan
    // mid-run without rebuilding the engine. It starts from the scheduler's initial (inert) plan, so a
    // fault-free run reads the bare scheduler time exactly as before.
    let faulty_clock = Arc::new(SwappableClock::new(
        clock.clone(),
        faults.initial_clock_plan(),
    ));
    let mut eng: SimEngine = LocalEngine::in_memory(
        faulty_clock.clone() as Arc<dyn Clock + Send + Sync>,
        cfg.pool_pages,
    )
    .expect("build simulated in-memory engine");

    // One scheduler owns the master seed; every random choice is drawn from it.
    let mut sched: SimScheduler<Tick> = SimScheduler::new(cfg.seed);

    // Per-client interleaver state and remaining op budget. Each client starts `Idle`; its first
    // scheduled step opens a transaction. The op budget caps total *statements* per client (so a run
    // is finite regardless of transaction sizes), mirroring the old `ops_per_client` meaning.
    let clients = cfg.clients.max(1) as usize;
    let mut states: Vec<ClientState> = (0..clients).map(|_| ClientState::Idle).collect();
    let mut budget: Vec<u32> = vec![cfg.ops_per_client; clients];

    // Seed one initial step per client; the load profile shapes inter-arrival delay over scheduler
    // time, and same-tick ties are RNG-ordered — exactly the canonical `(due, rng-priority, seq)` key.
    let total_ops = u64::from(cfg.ops_per_client) * u64::from(cfg.clients);
    for (idx, b) in budget.iter().enumerate() {
        if *b > 0 {
            let delay = cfg
                .load
                .arrival_delay(sched.rng(), idx as u64, total_ops.max(1));
            sched.schedule_at(delay, Tick { client: idx as u32 });
        }
    }

    let mut trace = Fnv::new();
    let mut wgen = WorkloadGen::new(cfg.mix);
    let mut steps = 0usize;
    let mut ok_ops = 0usize;
    let mut err_ops = 0usize;
    let mut max_open_txns = 0usize;
    let mut committed_txns = 0usize;
    let mut aborted_txns = 0usize;
    // Cumulative count of commits the engine **acknowledged** (explicit `COMMIT` ok + successful
    // auto-commit), tracked so a crash can snapshot the acked set for the rmp #238 oracle. This is the
    // wire-level "acked" tally; the durable WAL is the ground truth a crash recovers, but this counter
    // lets the report expose the acked/in-flight split per crash without re-deriving it from storage.
    let mut acked_commits = 0usize;
    let mut crash_restarts = 0u32;
    let mut crash_splits: Vec<CrashSplit> = Vec::new();

    // The strong reference-model oracle (rmp #238): a committed-only shadow of the multigraph with a
    // per-client staging buffer. Ops are flushed into the model only when a transaction commits.
    let mut oracle = if mode == RunMode::Safety {
        Oracle::new_recording(clients)
    } else {
        Oracle::new(clients)
    };

    // Liveness-mode progress watchdog (rmp #240). Tracks the longest run of consecutive dispatched
    // steps with **no** client state advance over logical time; a deadlock/livelock/hang drives this to
    // the hard step cap, which the bounded loop converts into a *reported* violation (never an actual
    // infinite loop). The dumped-schedule ring holds the recent `(step, client, progressed)` tuples so a
    // flagged stall comes with a human-readable trace. Inert (never populated) outside liveness mode, so
    // standard + safety runs stay zero-cost.
    let liveness_on = mode == RunMode::Liveness;
    let mut cur_stall = 0usize;
    let mut max_stall_steps = 0usize;
    let mut worst_stall_at = 0u64;
    let mut stall_start = 0u64;
    // A small ring of the most recent dispatched steps, dumped around the worst stall for debugging.
    let mut schedule_ring: std::collections::VecDeque<(u64, u32, bool)> =
        std::collections::VecDeque::new();

    // Hard upper bound on dispatched steps so a logic slip can never hang a test: every statement
    // spends one unit of budget, and each transaction adds a bounded `Begin`/`End` overhead, so the
    // total step count is at most `clients + 2 * sum(budget)` (Begin+End per transaction, each ≥1
    // statement). The `+ clients` covers the terminal Idle step that exits each client.
    let step_cap = clients
        .saturating_add(
            2usize
                .saturating_mul(clients)
                .saturating_mul(cfg.ops_per_client as usize),
        )
        .saturating_add(clients);

    // The dispatched-step ordinal: the canonical fault timeline, advanced once per scheduler step
    // (whether or not the client made progress). Deterministic and bounded by `step_cap`, so every
    // planned fault is guaranteed to come due.
    let mut dispatched = 0u64;
    // Set if the run exits via the hard step-cap guard rather than by draining the queue — the
    // watchdog's signature for a bounded-out hang (liveness mode).
    let mut hit_step_cap = false;

    while let Some((now, tick)) = sched.next() {
        // Keep the engine's clock in lockstep with logical simulation time.
        clock.set(now);

        // Drain every fault that has come due at this dispatched-step ordinal, *before* the workload
        // step runs, so faults fire DURING interleaved (possibly open) transactions on the one timeline.
        // Each fault folds into the canonical trace, so the fault schedule is part of the reproducible
        // run. Disk faults arm the live device; clock faults swap in an intensified plan the engine
        // reads next; transport faults are planned + traced (the SimNet seam — see `vopr_fault`).
        faults.drain_due(
            dispatched,
            |plan| {
                // `with_device_mut` returns `None` once the engine is shut down (spent); treat that as
                // "not armed" so a fault on a dead engine is not tallied.
                eng.with_device_mut(|dev| dev.arm_fault_plan(plan))
                    .is_some()
            },
            |plan| faulty_clock.set_plan(plan),
            |token, value| {
                trace.bytes(token);
                trace.u64(value);
            },
        );

        // After faults are armed but *before* this step's workload runs, weave in a crash + ARIES
        // restart if one is due (rmp #237). The crash fires while transactions are interleaved — acked
        // commits and in-flight (open) transactions coexist at this instant, the most dangerous
        // durability/atomicity moment. The crash event is folded into the canonical trace (so the
        // schedule is reproducible); the engine swap + client rebind is owned here, where the engine and
        // client state live.
        if faults.crash_due(dispatched, |token, value| {
            trace.bytes(token);
            trace.u64(value);
        }) {
            crash_at(
                &mut eng,
                &faulty_clock,
                &mut states,
                &mut oracle,
                &cfg,
                dispatched,
                acked_commits,
                &mut crash_restarts,
                &mut crash_splits,
                &mut trace,
            );
        }

        let client = tick.client as usize;
        // Decide and execute this client's next step, folding it into the canonical trace and
        // (re)scheduling the client's following step. `reschedule` carries the delay for the next step
        // (already drawn from the scheduler RNG inside `advance_client`) — `None` ends the client.
        let progressed = advance_client(
            &mut eng,
            &mut sched,
            &mut states,
            &mut budget,
            client,
            &mut wgen,
            &cfg,
            total_ops,
            &mut trace,
            steps,
            &mut ok_ops,
            &mut err_ops,
            &mut committed_txns,
            &mut aborted_txns,
            &mut acked_commits,
            &mut oracle,
        );

        // Observe overlap *after* this step settled: how many clients hold an open transaction now.
        let open_now = states.iter().filter(|s| s.is_open()).count();
        max_open_txns = max_open_txns.max(open_now);

        if progressed {
            steps += 1;
        }

        // Progress watchdog (rmp #240, liveness mode only). "Progress" is *any* client state-machine
        // advance (`advance_client` returned `true`: a BEGIN / statement / COMMIT / ROLLBACK / auto-commit
        // ran) — not only a final commit, so a healthy run that legitimately does read-only or in-flight
        // work never false-positives. A step that merely dispatched a spent client (returned `false`) is a
        // non-advancing step; a long unbroken run of them is a deadlock/livelock/hang. We track the
        // longest such run and dump the recent schedule around the worst one.
        if liveness_on {
            schedule_ring.push_back((dispatched, client as u32, progressed));
            if schedule_ring.len() > LIVENESS_DUMP_WINDOW {
                schedule_ring.pop_front();
            }
            if progressed {
                cur_stall = 0;
            } else {
                if cur_stall == 0 {
                    stall_start = dispatched;
                }
                cur_stall += 1;
                if cur_stall > max_stall_steps {
                    max_stall_steps = cur_stall;
                    worst_stall_at = stall_start;
                }
            }
        }

        dispatched = dispatched.saturating_add(1);

        // Belt-and-braces termination guard: the analytic bound above already makes the queue drain,
        // but if anything ever regresses we stop rather than spin. In liveness mode this hard cap is the
        // watchdog's teeth — a real hang trips it here, turning an infinite loop into a *bounded reported*
        // failure (the `LivenessTrace` records the cap hit on a non-empty queue).
        if steps > step_cap {
            hit_step_cap = true;
            break;
        }
    }

    // Trailing drain: fire any planned fault whose ordinal a short run did not quite reach, so the
    // schedule is fully accounted in the trace + tally regardless of the exact dispatched count. These
    // fold into the trace identically on replay (the schedule is fixed by the seed).
    faults.drain_due(
        u64::MAX,
        |plan| {
            eng.with_device_mut(|dev| dev.arm_fault_plan(plan))
                .is_some()
        },
        |plan| faulty_clock.set_plan(plan),
        |token, value| {
            trace.bytes(token);
            trace.u64(value);
        },
    );

    let state_hash = snapshot_hash(&mut eng);
    // The strong reference-model oracle verdict (rmp #238): full cell-by-cell equivalence between the
    // committed-only shadow model and the engine queried back. Run after the state snapshot, as a
    // read-only observer, so it does not perturb the canonical trace. `None` ⇒ model and engine agree.
    let oracle_verdict = assert_equivalent(&mut eng, &oracle.model).err();
    // Consistency probe: `persisted_nodes` is the number of `:Person` rows present, `created_nodes`
    // the number of distinct ids among them. They must be equal — no committed create lost, none
    // duplicated — even though contention aborted some transactions along the way.
    let (persisted_nodes, created_nodes) = person_stats(&mut eng);
    let end_time = sched.now();

    // Fault-then-heal recovery probe (rmp #240, liveness mode). The workload ran *under* the fault
    // window (disk/clock faults + crashes fired during it, then the trailing drain healed any residual
    // plan and every crash recovered via ARIES). The engine has now **quiesced** — the post-heal window.
    // Liveness demands the engine resumes *availability*: a fresh, deterministic workload batch must
    // commit AND serve correct results (the reference model agrees over the new batch). A run that
    // stalled under faults is allowed; one that cannot serve a clean batch *after* the heal is not.
    let recovery = if liveness_on {
        Some(recovery_probe(&mut eng, &mut oracle.model))
    } else {
        None
    };

    // Best-effort: harden + consume the engine (it is dropped either way).
    let _ = eng.shutdown();

    let (disk_faults, clock_faults, transport_faults) = faults.tally();
    // The latent-sector-error pages armed over the run (rmp #480): the safety oracle uses these to
    // tell an engine-surfaced injected fault apart from a genuine reference-model divergence. Read
    // after the trailing drain so every armed fault (including any a short run swept up at the end) is
    // accounted.
    let latent_fault_pages = faults.armed_latent_pages();

    let elle_history = oracle.elle_history.take().unwrap_or_default();

    let report = VoprReport {
        seed: cfg.seed,
        steps,
        ok_ops,
        err_ops,
        trace_hash: trace.finish(),
        state_hash,
        end_time,
        created_nodes,
        persisted_nodes,
        max_open_txns,
        committed_txns,
        aborted_txns,
        disk_faults,
        clock_faults,
        transport_faults,
        crash_restarts,
        crash_splits,
        oracle: oracle_verdict,
        latent_fault_pages,
    };

    let liveness = LivenessTrace {
        max_stall_steps,
        hit_step_cap,
        worst_stall_at,
        dumped_schedule: schedule_ring.into_iter().collect(),
        recovery,
    };
    (report, elle_history, liveness)
}

/// The dispatched-step horizon a run spans, so the fault scheduler can spread fault instants *across*
/// the workload (on real interleaved steps) rather than after it. A run dispatches **at least** one
/// step per statement (`clients * ops_per_client`); faults are planned over that lower bound so every
/// planned fault is guaranteed to come due before the run ends (the actual dispatched count, which adds
/// BEGIN/END overhead, is `>=` this). Deterministic from the config (no RNG), keeping the schedule a
/// pure function of the config + seed. A trailing drain at end-of-run sweeps up any fault whose
/// ordinal a short run did not quite reach, so the budget is always fully accounted.
fn estimate_step_horizon(cfg: &VoprConfig) -> u64 {
    u64::from(cfg.clients.max(1))
        .saturating_mul(u64::from(cfg.ops_per_client))
        .max(1)
}

/// Performs a **crash + ARIES restart** of the live engine mid-interleave (rmp #237) and rebinds the
/// interleaver's client state onto the recovered engine.
///
/// The sequence, in deterministic order:
/// 1. **Snapshot the split.** Count the transactions still open (in-flight / uncommitted) at this
///    instant — one per client in [`ClientState::Open`]. These were never acknowledged; ARIES undo /
///    no-redo discards them, so they must *not* survive. The cumulative `acked_commits` is the set that
///    *must* survive.
/// 2. **Crash + recover.** Rebuild a fresh engine purely from the *durable* WAL prefix via
///    [`LocalEngine::crash_restart`] (the same ARIES path the storage harness certifies), reusing the
///    same swappable faulty clock so time + clock faults stay continuous across the restart. The old
///    engine is dropped (the "crash"); every acked commit is replayed, nothing in-flight is.
/// 3. **Rebind clients.** Every open ticket belonged to the *dead* engine and is now invalid. Reset
///    **all** clients to [`ClientState::Idle`] so none reuses a dead ticket — each simply begins a fresh
///    transaction on its next scheduled step. Remaining op budget is untouched, so the run continues and
///    still terminates.
///
/// The crash's `(fire_step, acked, in-flight, recovered_state_hash)` split is recorded for the rmp #238
/// oracle and folded into the trace, so the recovered state is part of the reproducible digest. If
/// recovery itself fails the engine is left as-is and the crash is not recorded — a recovery failure is
/// a genuine durability bug the surrounding consistency probe will then surface.
#[allow(clippy::too_many_arguments)]
fn crash_at(
    eng: &mut SimEngine,
    faulty_clock: &Arc<SwappableClock>,
    states: &mut [ClientState],
    oracle: &mut Oracle,
    cfg: &VoprConfig,
    fire_step: u64,
    acked_commits: usize,
    crash_restarts: &mut u32,
    crash_splits: &mut Vec<CrashSplit>,
    trace: &mut Fnv,
) {
    // 1. Classify each client's transaction at the crash: open ⇒ in-flight (must not survive).
    let inflight_txns = states.iter().filter(|s| s.is_open()).count();

    // 2. Crash + ARIES restart purely from the durable WAL, reusing the same swappable faulty clock so
    //    time and any active clock-fault plan carry across the restart continuously.
    let clock = faulty_clock.clone() as Arc<dyn Clock + Send + Sync>;
    let recovered = match eng.crash_restart(clock, cfg.pool_pages) {
        Ok(e) => e,
        Err(_) => {
            // Recovery failed — leave the live engine untouched and do not record the crash. The
            // consistency probe at end-of-run will surface the durability bug rather than masking it.
            return;
        }
    };
    // Drop the old engine (the "crash") and continue against the recovered one. Best-effort harden of
    // the dying engine is intentionally skipped: a crash is an *abrupt* loss, so we model exactly the
    // durable-WAL prefix without a graceful flush.
    *eng = recovered;

    // 3. Rebind: every open ticket belonged to the dead engine. Treat all open transactions as aborted
    //    by the crash — reset every client to Idle so none reuses a dead ticket; each begins anew on its
    //    next scheduled step. Op budget is untouched, so the run continues deterministically.
    for s in states.iter_mut() {
        *s = ClientState::Idle;
    }
    // Every open transaction's staged (uncommitted) ops are lost with the dead engine — they were
    // never acknowledged, so ARIES undo/no-redo discards them. Drop them from the shadow model's
    // pending buffers so a crash-lost op never reaches the committed model.
    oracle.discard_all();

    // Snapshot the recovered (durable, acked-only) state for the oracle + trace.
    let recovered_state_hash = snapshot_hash(eng);
    trace.bytes(b"CRASH_RECOVERED");
    trace.u64(recovered_state_hash);

    *crash_restarts += 1;
    crash_splits.push(CrashSplit {
        fire_step,
        acked_commits,
        inflight_txns,
        recovered_state_hash,
    });
}

/// Advances one client's transaction state machine by exactly one step, executing it against the
/// engine, folding it into the canonical `trace` (in dispatch order), and scheduling the client's
/// following step. Returns `true` if a real step ran (so the caller increments the step counter); a
/// client with no remaining budget and no open transaction simply terminates (returns `false`).
///
/// All randomness comes from the scheduler's seeded RNG, so the whole interleaving is a pure function
/// of the seed. The `(due, rng-priority, seq)` ordering of the queued follow-up steps is what makes
/// distinct clients' BEGIN/stmt/END events interleave — producing simultaneous open transactions.
#[allow(clippy::too_many_arguments)]
fn advance_client(
    eng: &mut SimEngine,
    sched: &mut SimScheduler<Tick>,
    states: &mut [ClientState],
    budget: &mut [u32],
    client: usize,
    wgen: &mut WorkloadGen,
    cfg: &VoprConfig,
    total_ops: u64,
    trace: &mut Fnv,
    step_seq: usize,
    ok_ops: &mut usize,
    err_ops: &mut usize,
    committed_txns: &mut usize,
    aborted_txns: &mut usize,
    acked_commits: &mut usize,
    oracle: &mut Oracle,
) -> bool {
    // Resolve the step to take. When `Idle`, plan a fresh transaction (consuming the RNG to size it,
    // pick auto-commit vs explicit, and pre-decide its end disposition). The end disposition is fixed
    // at planning time so it is independent of interleaving — only *whether the COMMIT succeeds*
    // depends on contention.
    let step = match &states[client] {
        ClientState::Idle => {
            if budget[client] == 0 {
                return false; // client is spent — terminate (no reschedule).
            }
            let max_stmts = cfg.max_txn_stmts.max(1);
            let want = 1 + (sched.rng().below(u64::from(max_stmts)) as u32); // 1..=max_stmts
            let stmts = want.min(budget[client]); // never exceed the remaining budget
            let auto_commit = sched.rng().chance(cfg.auto_commit_permille);
            // Auto-commit is a single-statement degenerate transaction by construction.
            let remaining = if auto_commit {
                0
            } else {
                stmts.saturating_sub(1)
            };
            Step::Begin {
                auto_commit,
                remaining,
            }
        }
        ClientState::Open { next, .. } => *next,
    };

    let outcome_kind = exec_step(
        eng,
        sched,
        states,
        budget,
        client,
        wgen,
        cfg,
        step,
        committed_txns,
        aborted_txns,
        ok_ops,
        err_ops,
        acked_commits,
        oracle,
    );

    // Fold this step into the canonical trace: dispatch sequence, client, step-kind token, outcome.
    trace.u64(step_seq as u64);
    trace.u64(client as u64);
    trace.bytes(outcome_kind.token);
    if let Some(o) = &outcome_kind.outcome {
        o.fold_into(trace);
    }

    // Schedule this client's *next* step unless its state machine has terminated for good. A client
    // that is `Idle` with no budget left is finished; otherwise it has either a queued follow-up step
    // (open transaction) or a fresh `Begin` to draw next time.
    let more = matches!(&states[client], ClientState::Open { .. }) || budget[client] > 0;
    if more {
        let delay = cfg
            .load
            .arrival_delay(sched.rng(), step_seq as u64, total_ops.max(1));
        sched.schedule_after(
            delay,
            Tick {
                client: client as u32,
            },
        );
    }
    true
}

/// The classification of a step for the trace: a stable kind token plus the optional statement
/// outcome (only statements and auto-commit runs carry an [`Outcome`]; BEGIN/COMMIT/ROLLBACK fold a
/// token and a success bit).
struct StepKind {
    token: &'static [u8],
    outcome: Option<Outcome>,
}

/// Executes a single resolved [`Step`] for `client`, mutating the client's [`ClientState`] and the
/// run counters, and returns its trace classification. This is where transactions are opened
/// (leaving the ticket *open* across scheduler steps for explicit transactions), statements run, and
/// transactions committed/rolled back.
#[allow(clippy::too_many_arguments)]
fn exec_step(
    eng: &mut SimEngine,
    sched: &mut SimScheduler<Tick>,
    states: &mut [ClientState],
    budget: &mut [u32],
    client: usize,
    wgen: &mut WorkloadGen,
    cfg: &VoprConfig,
    step: Step,
    committed_txns: &mut usize,
    aborted_txns: &mut usize,
    ok_ops: &mut usize,
    err_ops: &mut usize,
    acked_commits: &mut usize,
    oracle: &mut Oracle,
) -> StepKind {
    match step {
        Step::Begin {
            auto_commit,
            remaining,
        } => {
            // Pre-decide the explicit transaction's end disposition now (independent of interleaving).
            let rollback = !auto_commit && sched.rng().chance(cfg.rollback_permille);
            // Draw the first statement (always at least one) and run it.
            let op = wgen.next(sched.rng());
            let mode = if op.is_write() {
                AccessMode::Write
            } else {
                AccessMode::Read
            };
            let (stmt, params) = op.to_cypher();

            if auto_commit {
                // Degenerate one-statement transaction via the engine's auto-commit path: it opens,
                // runs and commits within this single step — preserving the legacy behaviour.
                let outcome = run_auto_commit(eng, mode, stmt, params);
                budget[client] = budget[client].saturating_sub(1);
                // A successful auto-commit is an acknowledged commit (its effect is durable on return),
                // so it counts toward the acked set a crash must preserve — and the oracle applies its
                // op directly to the committed model (a one-statement transaction that just committed).
                // A failed auto-commit applied nothing, so the model is untouched.
                if outcome.ok {
                    *acked_commits += 1;
                    oracle.model.apply(op);
                    oracle.record_auto_commit(op);
                }
                tally(&outcome, ok_ops, err_ops);
                states[client] = ClientState::Idle;
                StepKind {
                    token: b"AC",
                    outcome: Some(outcome),
                }
            } else {
                // Explicit transaction: BEGIN opens a ticket that stays live across following steps —
                // this is what overlaps with other clients' open transactions. A read-only first
                // statement still opens in Write mode if any later statement might write; we keep it
                // simple and open in Write whenever the transaction batches >1 statement (so a later
                // write is legal) or the first op writes.
                let open_mode = if remaining > 0 || op.is_write() {
                    AccessMode::Write
                } else {
                    AccessMode::Read
                };
                match eng.begin(open_mode) {
                    Ok(ticket) => {
                        // Capture the BEGIN snapshot now, *before* the first statement runs: this is the
                        // committed node multiset the transaction's `MATCH` clauses see under snapshot
                        // isolation. Then stage the first op (applied only if the later COMMIT is acked).
                        oracle.begin(client);
                        let outcome = run_in(eng, ticket, stmt, params);
                        budget[client] = budget[client].saturating_sub(1);
                        // Stage the op only if the statement actually succeeded. A statement that
                        // errored (an SSI conflict surfaced at run time, a write rejected, …) changed
                        // nothing in the engine, so the model must not apply it even if the transaction
                        // later commits — otherwise the model would hold a node/edge the engine never
                        // made (the exact `model:1, engine:0` divergence the #238 sweep exposed).
                        if outcome.ok {
                            oracle.stage(client, op);
                        }
                        tally(&outcome, ok_ops, err_ops);
                        let next = if remaining > 0 && budget[client] > 0 {
                            Step::Stmt {
                                remaining: remaining.min(budget[client]),
                                rollback,
                            }
                        } else {
                            Step::End { rollback }
                        };
                        states[client] = ClientState::Open { ticket, next };
                        StepKind {
                            token: b"BEGIN",
                            outcome: Some(outcome),
                        }
                    }
                    Err(e) => {
                        // Could not open (e.g. engine shut down): account it as an errored op and go
                        // idle so the client can retry / terminate. Nothing was staged for this
                        // transaction; clear defensively so no stale op leaks into a later commit.
                        *err_ops += 1;
                        oracle.discard(client);
                        states[client] = ClientState::Idle;
                        StepKind {
                            token: b"BEGIN_ERR",
                            outcome: Some(Outcome {
                                ok: false,
                                rows: 0,
                                cells: Vec::new(),
                                error: Some(e.to_string()),
                            }),
                        }
                    }
                }
            }
        }
        Step::Stmt {
            remaining,
            rollback,
        } => {
            let ClientState::Open { ticket, .. } = &states[client] else {
                // Defensive: a `Stmt` should only arrive on an open transaction. Skip gracefully and
                // drop any staged ops so a stranded buffer never reaches the committed model.
                oracle.discard(client);
                states[client] = ClientState::Idle;
                return StepKind {
                    token: b"STMT_NOOP",
                    outcome: None,
                };
            };
            let ticket = *ticket;
            let op = wgen.next(sched.rng());
            let (stmt, params) = op.to_cypher();
            let outcome = run_in(eng, ticket, stmt, params);
            budget[client] = budget[client].saturating_sub(1);
            // Stage only on a successful statement (see the BEGIN arm): an errored statement made no
            // engine change, so it must not enter the model even if the transaction later commits.
            if outcome.ok {
                oracle.stage(client, op);
            }
            tally(&outcome, ok_ops, err_ops);
            // The disposition was fixed at `Begin` time and carried through — no extra RNG draw here,
            // so the transaction's end is independent of interleaving.
            let next = if remaining > 1 && budget[client] > 0 {
                Step::Stmt {
                    remaining: (remaining - 1).min(budget[client]),
                    rollback,
                }
            } else {
                Step::End { rollback }
            };
            states[client] = ClientState::Open { ticket, next };
            StepKind {
                token: b"STMT",
                outcome: Some(outcome),
            }
        }
        Step::End { rollback } => {
            let ClientState::Open { ticket, .. } = &states[client] else {
                oracle.discard(client);
                states[client] = ClientState::Idle;
                return StepKind {
                    token: b"END_NOOP",
                    outcome: None,
                };
            };
            let ticket = *ticket;
            let (token, ok) = if rollback {
                let ok = eng.rollback(ticket).is_ok();
                *aborted_txns += 1;
                // Rolled back: the staged ops never became durable — discard them.
                oracle.discard(client);
                (b"ROLLBACK".as_slice(), ok)
            } else {
                match eng.commit(ticket) {
                    Ok(_) => {
                        *committed_txns += 1;
                        *acked_commits += 1;
                        // COMMIT acknowledged: flush the staged ops into the committed model.
                        oracle.commit(client);
                        (b"COMMIT".as_slice(), true)
                    }
                    Err(_) => {
                        // A failed COMMIT is an SSI serialization conflict the contention exposed —
                        // exactly the outcome the interleaver is meant to reach. The engine still
                        // upholds ACID (the conflicting transaction is aborted, not half-applied), so
                        // the staged ops are discarded — never applied to the model.
                        *aborted_txns += 1;
                        oracle.discard(client);
                        (b"COMMIT_ABORT".as_slice(), false)
                    }
                }
            };
            states[client] = ClientState::Idle;
            // Fold the end disposition + success bit into the trace via a tiny outcome.
            StepKind {
                token,
                outcome: Some(Outcome {
                    ok,
                    rows: 0,
                    cells: Vec::new(),
                    error: None,
                }),
            }
        }
    }
}

/// Tallies a statement outcome into the ok/err counters.
fn tally(outcome: &Outcome, ok_ops: &mut usize, err_ops: &mut usize) {
    if outcome.ok {
        *ok_ops += 1;
    } else {
        *err_ops += 1;
    }
}

/// Renders a one-line, reproducible summary of a report (for the CLI).
#[must_use]
pub fn summarize(r: &VoprReport) -> String {
    format!(
        "vopr seed={} steps={} ok={} err={} trace_hash={:016x} state_hash={:016x} end_time={}\n",
        r.seed, r.steps, r.ok_ops, r.err_ops, r.trace_hash, r.state_hash, r.end_time
    )
}

/// Parses the `vopr` subcommand's arguments and runs a seed sweep, returning `(summary, failures)`.
///
/// Each seed is run **twice** and the two reports compared: a mismatch is a determinism failure
/// (the simulator's core invariant), counted and listed for one-line reproduction. Each run is also
/// checked by the **strong reference-model oracle** (rmp #238): if the committed-only shadow model
/// and the engine queried back disagree cell-by-cell, that seed is reported as an oracle failure with
/// the exact divergence. Either failure class counts toward the returned failure total.
///
/// Flags: `--seed <base>` (default 1), `--seeds <count>` (default 1), `--clients <n>`,
/// `--ops <n>`, `--swarm` (derive the full config from each seed within bounds — rmp #241 swarm
/// testing; ignores `--clients`/`--ops` since it swarms the whole environment). Unknown flags are
/// reported as an error string in the summary.
#[must_use]
pub fn run_cli<I: IntoIterator<Item = String>>(args: I) -> (String, u32) {
    let mut base_seed: u64 = 1;
    let mut count: u64 = 1;
    let mut clients: u32 = 4;
    let mut ops: u32 = 50;
    // Swarm mode (rmp #241): derive the *full* config from each seed within sane bounds, so a sweep
    // explores a different environment per seed (not just a different workload). Off by default, so the
    // pinned `--clients`/`--ops` path stays the focused, reproducible default.
    let mut swarm = false;

    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        // `--swarm` takes no value, so handle it before the value-consuming closure.
        if arg.as_str() == "--swarm" {
            swarm = true;
            continue;
        }
        let mut next_u64 = |label: &str| -> Result<u64, String> {
            it.next()
                .ok_or_else(|| format!("flag {label} needs a value"))?
                .parse::<u64>()
                .map_err(|_| format!("flag {label} needs an integer"))
        };
        let parsed = match arg.as_str() {
            "--seed" => next_u64("--seed").map(|v| base_seed = v),
            "--seeds" => next_u64("--seeds").map(|v| count = v.max(1)),
            "--clients" => {
                next_u64("--clients").map(|v| clients = v.min(u64::from(u32::MAX)) as u32)
            }
            "--ops" => next_u64("--ops").map(|v| ops = v.min(u64::from(u32::MAX)) as u32),
            other => Err(format!("unknown flag {other}")),
        };
        if let Err(e) = parsed {
            return (format!("error: {e}\n"), 1);
        }
    }

    let mut out = String::new();
    let mut failures: u32 = 0;
    let mut failed_seeds = Vec::new();
    let mut oracle_seeds = Vec::new();
    for seed in base_seed..base_seed.saturating_add(count) {
        // In swarm mode the *entire* config is seed-derived within bounds (the CLI knobs are ignored,
        // since swarming the environment is the whole point). Otherwise inherit the interleaver defaults
        // (`max_txn_stmts`, auto-commit / rollback ratios) and override only the CLI-exposed knobs.
        let cfg = if swarm {
            VoprConfig::swarm(seed)
        } else {
            VoprConfig {
                clients,
                ops_per_client: ops,
                ..VoprConfig::for_seed(seed)
            }
        };
        let first = run(cfg);
        let second = run(cfg);
        out.push_str(&summarize(&first));
        if first != second {
            failures += 1;
            failed_seeds.push(seed);
        }
        // The reference-model oracle: a model⇄engine divergence is a correctness failure independent
        // of determinism. Report it with the precise diff so the seed reproduces it.
        if let Some(err) = &first.oracle {
            failures += 1;
            oracle_seeds.push(seed);
            out.push_str(&format!("vopr: seed {seed} ORACLE DIVERGENCE: {err:?}\n"));
        }
    }
    if failures == 0 {
        out.push_str(&format!(
            "vopr: {count} seed(s) checked, all deterministic + oracle-consistent\n"
        ));
    } else {
        if !failed_seeds.is_empty() {
            out.push_str(&format!(
                "vopr: NON-DETERMINISTIC seed(s): {failed_seeds:?} — reproduce with --seed <N> --seeds 1\n"
            ));
        }
        if !oracle_seeds.is_empty() {
            out.push_str(&format!(
                "vopr: ORACLE-DIVERGENT seed(s): {oracle_seeds:?} — reproduce with --seed <N> --seeds 1\n"
            ));
        }
    }
    (out, failures)
}

/// The four inviolable safety properties the VOPR safety mode certifies (rmp #239).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyProperty {
    /// **Serializability** (ACID "I"). The recovered committed history — the `:Person` creates recorded
    /// as an append-only [`graphus_elle::History`] over the id space — is acyclic and order-consistent
    /// under Adya's formalism ([`graphus_elle::check`] returns `serializable`). With the generator's
    /// unique ids this fails iff the recovered history is corrupt (a duplicate or impossible version
    /// order — e.g. an id committed twice, or a create lost-then-duplicated across recovery).
    Serializability,
    /// **Durability.** Every commit the engine acknowledged before a crash survives the ARIES restart:
    /// the cumulative acked count is non-decreasing across every [`CrashSplit`] (no acked commit
    /// vanished at a restart), and — with reference equivalence — the surviving state is exactly the
    /// acked set.
    Durability,
    /// **Atomicity (committed-or-nothing).** No partial / uncommitted / rolled-back / in-flight-at-crash
    /// effect survives: the per-`:Person` create-count probe holds (no duplicated/lost create) and the
    /// reference model (which applies only acked ops) matches the engine, excluding any half-applied
    /// effect.
    Atomicity,
    /// **Reference-model equivalence.** The independent #238 shadow model agrees with the engine queried
    /// back cell-by-cell (node multiset, edge multiset, count, neighbours): [`VoprReport::oracle`] is
    /// `None`. A wrong result with the right cardinality is caught here.
    ReferenceModel,
}

impl SafetyProperty {
    /// A stable, lower-kebab name for reports/CLI.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            SafetyProperty::Serializability => "serializability",
            SafetyProperty::Durability => "durability",
            SafetyProperty::Atomicity => "atomicity",
            SafetyProperty::ReferenceModel => "reference-model-equivalence",
        }
    }
}

/// One violated safety property with a human-readable detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyViolation {
    /// Which property was violated.
    pub property: SafetyProperty,
    /// A precise, reproducible description of the violation.
    pub detail: String,
}

/// The verdict of one safety-mode run (rmp #239): the four-property bundle asserted on the recovered
/// state, plus the underlying [`VoprReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyReport {
    /// `true` iff no property was violated.
    pub safe: bool,
    /// The number of committed/recovered transactions the Elle checker ruled on.
    pub checked_txns: usize,
    /// Every property that broke (empty when `safe`).
    pub violations: Vec<SafetyViolation>,
    /// The underlying deterministic run report.
    pub run: VoprReport,
}

impl SafetyReport {
    /// The seed this safety run replays from.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.run.seed
    }
}

/// Runs one VOPR simulation in **safety mode** (rmp #239): records the recovered Elle history and
/// asserts the full four-property safety bundle against the recovered state, while faults and crashes
/// fire during concurrent, interleaved work.
///
/// # The safety oracle bundle
///
/// The interleaver (rmp #235) runs under the unified fault + crash scheduler (rmp #236/#237) with a
/// bounded, recoverable budget ([`VoprConfig::safety`]). As transactions commit/abort/crash, the
/// recovered **committed** history is recorded into an append-only [`graphus_elle::History`] over the
/// `:Person` id space (each committed `CreateNode{id}` an append; an in-flight-at-crash transaction is
/// dropped, so the history spans exactly the durable, recovered state). After the run, **all four** of
/// these must hold simultaneously, or the run is flagged with the offending property (see
/// [`SafetyProperty`]):
///
/// 1. **Serializability** — [`graphus_elle::check`] certifies the recorded history acyclic + order-
///    consistent (fails iff a duplicate/impossible version order, e.g. a create lost-then-duplicated
///    across recovery).
/// 2. **Durability** — every [`CrashSplit`]'s acked commits survived (the cumulative acked count is
///    monotone across crashes; the surviving state is the acked set, by equivalence #4).
/// 3. **Atomicity** — no in-flight / rolled-back effect persisted (the per-`:Person` create-count probe
///    shows no duplicate/lost create; the reference model applies only acked ops).
/// 4. **Reference-model equivalence** — the #238 shadow model agrees with the engine cell-by-cell
///    (node multiset, edge multiset, count, neighbours), so wrong-result-right-cardinality is caught.
///
/// Deterministic: same seed ⇒ identical [`SafetyReport`] (the recorder never perturbs the workload,
/// trace, or engine — it only stages extra observer data).
#[must_use]
pub fn run_safety(cfg: VoprConfig) -> SafetyReport {
    let (run, history, _liveness) = run_inner(cfg, RunMode::Safety);
    let violations = evaluate_safety(&run, &history);

    SafetyReport {
        safe: violations.is_empty(),
        checked_txns: history.len(),
        violations,
        run,
    }
}

/// Evaluates the four safety properties (rmp #239) over a finished run and its recorded Elle history,
/// returning every violation (empty ⇒ all four held). Pure — no engine, no I/O — so each arm can be
/// unit-tested against fabricated inputs (a broken build), proving the bundle has teeth.
fn evaluate_safety(run: &VoprReport, history: &[ElleTxn]) -> Vec<SafetyViolation> {
    let mut violations = Vec::new();

    // 1. Serializability: the Elle checker rules on the recovered committed history.
    let verdict = elle_check(&history.to_vec());
    if !verdict.serializable {
        violations.push(SafetyViolation {
            property: SafetyProperty::Serializability,
            detail: verdict
                .anomaly
                .unwrap_or_else(|| "non-serializable history".to_owned()),
        });
    }

    // 2. Durability: every crash's acked-commit set must survive — the cumulative acked count is
    //    non-decreasing across crashes (a lost acked commit would drop it). That the *surviving* state
    //    is exactly the acked set is the reference-equivalence property #4, below.
    let mut prev_acked = 0usize;
    for (i, split) in run.crash_splits.iter().enumerate() {
        if split.acked_commits < prev_acked {
            violations.push(SafetyViolation {
                property: SafetyProperty::Durability,
                detail: format!(
                    "acked-commit count regressed at crash #{i} (fire_step={}): {} < {prev_acked} \
                     — an acknowledged commit was lost across recovery",
                    split.fire_step, split.acked_commits
                ),
            });
        }
        prev_acked = split.acked_commits;
    }

    // 3. Atomicity (committed-or-nothing): persisted == distinct committed ids. A half-applied
    //    in-flight or rolled-back create would skew this; the reference model (#4) additionally proves
    //    persisted == acked-only, excluding any partial effect.
    if run.persisted_nodes != run.created_nodes {
        violations.push(SafetyViolation {
            property: SafetyProperty::Atomicity,
            detail: format!(
                "persisted :Person rows ({}) != distinct committed ids ({}) — a partial or \
                 duplicated effect survived",
                run.persisted_nodes, run.created_nodes
            ),
        });
    }

    // 4. Reference-model equivalence: the #238 shadow model agrees with the engine cell-by-cell.
    //
    //    One read-back outcome is **expected, not a violation** (rmp #480): the read-back hard-failed
    //    because the engine *surfaced* a latent-sector-error the harness itself injected — it refused
    //    to serve bytes from a page we deliberately made unreadable, returning a storage error rather
    //    than silently returning wrong/missing committed data. That UPHOLDS the "surface, never
    //    corrupt" contract. We drop the reference-model "failure" only when the oracle error is
    //    positively tied to such an injected fault (the surfaced error names a page in
    //    `latent_fault_pages`). A *silent* committed-data discrepancy — any multiset/count/neighbour
    //    mismatch, which carries NO surfaced error — is never excused and still flags the violation,
    //    so the teeth that catch genuine durability loss are intact.
    if let Some(err) = &run.oracle
        && !is_surfaced_injected_latent_fault(err, &run.latent_fault_pages)
    {
        violations.push(SafetyViolation {
            property: SafetyProperty::ReferenceModel,
            detail: format!("{err:?}"),
        });
    }

    violations
}

/// Renders a one-line, reproducible summary of a [`SafetyReport`] (for the safety CLI).
#[must_use]
pub fn summarize_safety(r: &SafetyReport) -> String {
    if r.safe {
        format!(
            "safety seed={} SAFE checked_txns={} crashes={} faults={} trace_hash={:016x}\n",
            r.seed(),
            r.checked_txns,
            r.run.crash_restarts,
            r.run.disk_faults + r.run.clock_faults + r.run.transport_faults,
            r.run.trace_hash,
        )
    } else {
        let props: Vec<&str> = r.violations.iter().map(|v| v.property.name()).collect();
        format!(
            "safety seed={} UNSAFE violated={:?} checked_txns={} trace_hash={:016x}\n",
            r.seed(),
            props,
            r.checked_txns,
            r.run.trace_hash,
        )
    }
}

/// Parses the `vopr-safety` subcommand's arguments and runs a safety seed sweep, returning
/// `(summary, violations)`. Each seed is run in safety mode (faults + crashes via
/// [`VoprConfig::safety`]); the four-property bundle is asserted on the recovered state. Each seed is
/// additionally run twice and the reports compared — a mismatch is a determinism failure counting as a
/// violation. Flags: `--seed <base>` (default 1), `--seeds <count>` (default 1).
#[must_use]
pub fn run_safety_cli<I: IntoIterator<Item = String>>(args: I) -> (String, u32) {
    let mut base_seed: u64 = 1;
    let mut count: u64 = 1;

    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        let mut next_u64 = |label: &str| -> Result<u64, String> {
            it.next()
                .ok_or_else(|| format!("flag {label} needs a value"))?
                .parse::<u64>()
                .map_err(|_| format!("flag {label} needs an integer"))
        };
        let parsed = match arg.as_str() {
            "--seed" => next_u64("--seed").map(|v| base_seed = v),
            "--seeds" => next_u64("--seeds").map(|v| count = v.max(1)),
            other => Err(format!("unknown flag {other}")),
        };
        if let Err(e) = parsed {
            return (format!("error: {e}\n"), 1);
        }
    }

    let mut out = String::new();
    let mut violations: u32 = 0;
    let mut unsafe_seeds = Vec::new();
    let mut nondet_seeds = Vec::new();
    for seed in base_seed..base_seed.saturating_add(count) {
        let cfg = VoprConfig::safety(seed);
        let first = run_safety(cfg);
        let second = run_safety(cfg);
        out.push_str(&summarize_safety(&first));
        if !first.safe {
            violations += 1;
            unsafe_seeds.push(seed);
        }
        if first != second {
            violations += 1;
            nondet_seeds.push(seed);
        }
    }
    if violations == 0 {
        out.push_str(&format!(
            "safety: {count} seed(s) checked, all SAFE + deterministic\n"
        ));
    } else {
        if !unsafe_seeds.is_empty() {
            out.push_str(&format!(
                "safety: UNSAFE seed(s): {unsafe_seeds:?} — reproduce with --seed <N> --seeds 1\n"
            ));
        }
        if !nondet_seeds.is_empty() {
            out.push_str(&format!(
                "safety: NON-DETERMINISTIC seed(s): {nondet_seeds:?} — reproduce with --seed <N> --seeds 1\n"
            ));
        }
    }
    (out, violations)
}

// ============================ liveness oracle (rmp #240) ============================

/// The two ways the VOPR **liveness oracle** (rmp #240) can fail — the sibling of [`SafetyProperty`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessFailure {
    /// **Progress stalled** — a deadlock / livelock / hang. The progress watchdog over logical time saw
    /// the scheduler advance for `>= threshold` consecutive steps while **no** client advanced its
    /// transaction state machine (or the run tripped the hard step cap on a non-empty queue, the bounded
    /// signature of a real infinite loop). The flagged [`LivenessReport`] carries the dumped schedule.
    ProgressStalled,
    /// **Did not recover after heal** — availability did not resume. After the fault window healed and the
    /// engine quiesced, the fresh post-heal workload batch did not fully commit, or the engine served an
    /// *incorrect* result for it (the reference model disagreed) — so the engine, though it survived the
    /// faults, is no longer available / correct.
    DidNotRecoverAfterHeal,
}

impl LivenessFailure {
    /// A stable, lower-kebab name for reports/CLI.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            LivenessFailure::ProgressStalled => "progress-stalled",
            LivenessFailure::DidNotRecoverAfterHeal => "did-not-recover-after-heal",
        }
    }
}

/// The verdict of one liveness-mode run (rmp #240) — the sibling of [`SafetyReport`]. `live` iff the
/// engine kept making progress (no deadlock/livelock/hang) **and** recovered availability after the
/// fault window healed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivenessReport {
    /// `true` iff neither liveness check failed.
    pub live: bool,
    /// Which check failed (empty when `live`).
    pub failures: Vec<LivenessFailure>,
    /// The longest run of consecutive scheduler steps during which no client advanced (the worst stall).
    /// Stays small on a healthy run; a hang drives it to the hard step cap.
    pub max_stall_steps: usize,
    /// The stall threshold this run was judged against (a hang ⇒ `max_stall_steps >= stall_threshold`).
    pub stall_threshold: usize,
    /// The dispatched-step ordinal the worst stall began at — for one-line reproduction.
    pub worst_stall_at: u64,
    /// The dumped recent step schedule `(step, client, progressed)` around the worst stall — the trace a
    /// human reads to debug a flagged hang. Bounded (never grows with run length).
    pub dumped_schedule: Vec<(u64, u32, bool)>,
    /// How many fresh `:Person` creates the post-heal recovery batch attempted.
    pub recovery_attempted: usize,
    /// How many of them committed after the heal (availability resumed ⇒ all of them).
    pub recovery_committed: usize,
    /// Whether the engine served correct results for the post-heal batch (reference model agreed).
    pub recovery_correct: bool,
    /// The underlying deterministic run report.
    pub run: VoprReport,
}

impl LivenessReport {
    /// The seed this liveness run replays from.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.run.seed
    }
}

/// The progress-watchdog stall threshold (rmp #240) for `cfg`: the number of consecutive non-advancing
/// scheduler steps that counts as a deadlock/livelock/hang. Generous on purpose — in a healthy run a
/// non-advancing step is rare and isolated (a spent client dispatched once before it stops being
/// rescheduled), so a stall this long means **every** client has had many turns with zero progress: no
/// transaction can advance. Scaled by client count (each client needs a few turns to be sure) plus a
/// fixed slack, so it never false-positives on the legitimate idle steps a healthy drain produces, yet
/// trips well below the hard step cap when the engine genuinely wedges.
#[must_use]
fn stall_threshold(cfg: &VoprConfig) -> usize {
    let clients = cfg.clients.max(1) as usize;
    clients.saturating_mul(8).saturating_add(32)
}

/// Runs one VOPR simulation in **liveness mode** (rmp #240): drives the cooperative interleaver under a
/// bounded, recoverable fault window, watches progress over logical time, and — once the window heals —
/// probes a fresh workload batch to assert availability resumed. The sibling of [`run_safety`].
///
/// # The liveness oracle
///
/// Two properties must both hold, or the run is flagged with the offending [`LivenessFailure`]:
///
/// 1. **Progress (no deadlock/livelock/hang).** A **progress watchdog over logical time** tracks the
///    longest run of consecutive dispatched scheduler steps during which **no** client advanced its
///    transaction state machine. "Progress" is *any* state advance (BEGIN / statement / COMMIT /
///    ROLLBACK / auto-commit), not only a final commit — so a healthy run that legitimately does
///    read-only or in-flight work never false-positives. If that run reaches a generous, client-scaled
///    stall threshold ([`LivenessReport::stall_threshold`]) — or the run trips the hard step cap on a
///    non-empty queue — the engine is wedged: flagged
///    [`LivenessFailure::ProgressStalled`] with the **dumped schedule** around the stall. The watchdog
///    is **bounded by the same hard step cap as the workload**, so a real engine hang becomes a returned
///    `LivenessReport { live: false, .. }` — never an actual infinite loop / CI hang.
/// 2. **Fault-then-heal recovery (availability).** Faults + crashes fire *during* the workload (the
///    fault window); after the workload drains and every fault/crash has healed (the trailing drain
///    clears any residual plan; each crash recovered via ARIES), the engine has **quiesced**. A fresh,
///    deterministic post-heal workload batch (a fixed number of creates with fresh ids) must then fully
///    commit **and** read back correctly (the reference model agrees), proving the engine resumed
///    serving correct results. The during-fault window may legitimately stall or error; the post-heal
///    window must recover, or the run is flagged [`LivenessFailure::DidNotRecoverAfterHeal`].
///
/// Deterministic: same seed ⇒ identical [`LivenessReport`] (the watchdog and recovery probe are
/// read-only observers run on the one deterministic timeline — they never perturb the workload).
#[must_use]
pub fn run_liveness(cfg: VoprConfig) -> LivenessReport {
    let (run, _history, trace) = run_inner(cfg, RunMode::Liveness);
    let threshold = stall_threshold(&cfg);
    let failures = evaluate_liveness(&trace, threshold);

    // The recovery probe is always populated in liveness mode.
    let recovery = trace.recovery.unwrap_or(RecoveryProbe {
        attempted: 0,
        committed: 0,
        correct: false,
    });

    LivenessReport {
        live: failures.is_empty(),
        failures,
        max_stall_steps: trace.max_stall_steps,
        stall_threshold: threshold,
        worst_stall_at: trace.worst_stall_at,
        dumped_schedule: trace.dumped_schedule,
        recovery_attempted: recovery.attempted,
        recovery_committed: recovery.committed,
        recovery_correct: recovery.correct,
        run,
    }
}

/// Evaluates the two liveness properties (rmp #240) over a finished run's [`LivenessTrace`] against the
/// stall `threshold`, returning every failure (empty ⇒ both held). Pure — no engine, no I/O — so each
/// arm can be unit-tested against a fabricated trace (a deliberately wedged or non-recovering run),
/// proving the watchdog has teeth.
fn evaluate_liveness(trace: &LivenessTrace, threshold: usize) -> Vec<LivenessFailure> {
    let mut failures = Vec::new();

    // 1. Progress: a stall at/over the threshold, or a hard-cap exit (the bounded signature of a real
    //    hang), is a deadlock/livelock/hang.
    if trace.max_stall_steps >= threshold || trace.hit_step_cap {
        failures.push(LivenessFailure::ProgressStalled);
    }

    // 2. Fault-then-heal recovery: the post-heal batch must fully commit and read back correctly.
    if let Some(rec) = &trace.recovery {
        let recovered = rec.attempted > 0 && rec.committed == rec.attempted && rec.correct;
        if !recovered {
            failures.push(LivenessFailure::DidNotRecoverAfterHeal);
        }
    } else {
        // A liveness run must always carry a recovery verdict; its absence is itself a failure.
        failures.push(LivenessFailure::DidNotRecoverAfterHeal);
    }

    failures
}

/// Renders a one-line, reproducible summary of a [`LivenessReport`] (for the liveness CLI).
#[must_use]
pub fn summarize_liveness(r: &LivenessReport) -> String {
    if r.live {
        format!(
            "liveness seed={} LIVE max_stall={}/{} recovered={}/{} crashes={} faults={} trace_hash={:016x}\n",
            r.seed(),
            r.max_stall_steps,
            r.stall_threshold,
            r.recovery_committed,
            r.recovery_attempted,
            r.run.crash_restarts,
            r.run.disk_faults + r.run.clock_faults + r.run.transport_faults,
            r.run.trace_hash,
        )
    } else {
        let fs: Vec<&str> = r.failures.iter().map(|f| f.name()).collect();
        format!(
            "liveness seed={} STALLED failed={:?} max_stall={}/{} worst_at={} recovered={}/{} correct={} trace_hash={:016x}\n",
            r.seed(),
            fs,
            r.max_stall_steps,
            r.stall_threshold,
            r.worst_stall_at,
            r.recovery_committed,
            r.recovery_attempted,
            r.recovery_correct,
            r.run.trace_hash,
        )
    }
}

/// Parses the `vopr-liveness` subcommand's arguments and runs a liveness seed sweep, returning
/// `(summary, violations)`. Each seed is run in liveness mode (a recoverable fault window via
/// [`VoprConfig::liveness`]); the progress watchdog + fault-then-heal recovery probe rule on it. Each
/// seed is additionally run twice and the reports compared — a mismatch is a determinism failure
/// counting as a violation. Flags: `--seed <base>` (default 1), `--seeds <count>` (default 1).
#[must_use]
pub fn run_liveness_cli<I: IntoIterator<Item = String>>(args: I) -> (String, u32) {
    let mut base_seed: u64 = 1;
    let mut count: u64 = 1;

    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        let mut next_u64 = |label: &str| -> Result<u64, String> {
            it.next()
                .ok_or_else(|| format!("flag {label} needs a value"))?
                .parse::<u64>()
                .map_err(|_| format!("flag {label} needs an integer"))
        };
        let parsed = match arg.as_str() {
            "--seed" => next_u64("--seed").map(|v| base_seed = v),
            "--seeds" => next_u64("--seeds").map(|v| count = v.max(1)),
            other => Err(format!("unknown flag {other}")),
        };
        if let Err(e) = parsed {
            return (format!("error: {e}\n"), 1);
        }
    }

    let mut out = String::new();
    let mut violations: u32 = 0;
    let mut stalled_seeds = Vec::new();
    let mut nondet_seeds = Vec::new();
    for seed in base_seed..base_seed.saturating_add(count) {
        let cfg = VoprConfig::liveness(seed);
        let first = run_liveness(cfg);
        let second = run_liveness(cfg);
        out.push_str(&summarize_liveness(&first));
        if !first.live {
            violations += 1;
            stalled_seeds.push(seed);
        }
        if first != second {
            violations += 1;
            nondet_seeds.push(seed);
        }
    }
    if violations == 0 {
        out.push_str(&format!(
            "liveness: {count} seed(s) checked, all LIVE + recovered + deterministic\n"
        ));
    } else {
        if !stalled_seeds.is_empty() {
            out.push_str(&format!(
                "liveness: STALLED/UNRECOVERED seed(s): {stalled_seeds:?} — reproduce with --seed <N> --seeds 1\n"
            ));
        }
        if !nondet_seeds.is_empty() {
            out.push_str(&format!(
                "liveness: NON-DETERMINISTIC seed(s): {nondet_seeds:?} — reproduce with --seed <N> --seeds 1\n"
            ));
        }
    }
    (out, violations)
}

/// The deterministic result of executing one operation (no wall-clock, no identity — only what the
/// client could observe).
struct Outcome {
    ok: bool,
    rows: usize,
    cells: Vec<String>,
    error: Option<String>,
}

impl Outcome {
    fn fold_into(&self, h: &mut Fnv) {
        h.u64(u64::from(self.ok));
        h.u64(self.rows as u64);
        for c in &self.cells {
            h.bytes(c.as_bytes());
            h.bytes(b"|");
        }
        if let Some(e) = &self.error {
            // Fold an error *class* token, not the full message, so the trace is stable against
            // incidental message wording while still distinguishing success from failure.
            h.bytes(b"ERR:");
            h.bytes(error_class(e).as_bytes());
        }
    }
}

/// Runs one statement to completion in a **fresh auto-commit transaction**, draining its rows — the
/// degenerate one-statement client mode that preserves the legacy per-op behaviour.
fn run_auto_commit(
    eng: &mut SimEngine,
    mode: AccessMode,
    stmt: &str,
    params: Vec<(String, Value)>,
) -> Outcome {
    let ticket = match eng.begin_auto_commit(mode) {
        Ok(t) => t,
        Err(e) => {
            return Outcome {
                ok: false,
                rows: 0,
                cells: Vec::new(),
                error: Some(e.to_string()),
            };
        }
    };
    // `auto_commit = true`: the engine commits (or rolls back on a runtime error) when the stream is
    // drained — the transaction's lifetime is exactly this one statement.
    match eng.run(ticket, stmt, params, true, None) {
        Ok(mut reply) => drain(&mut reply),
        Err(e) => Outcome {
            ok: false,
            rows: 0,
            cells: Vec::new(),
            error: Some(e.to_string()),
        },
    }
}

/// Runs one statement inside an **already-open explicit transaction** `ticket`, draining its rows
/// but leaving the transaction open (`auto_commit = false`) so the caller commits/rolls it back in a
/// later step — this is what keeps the ticket live across scheduler steps, enabling overlap.
fn run_in(
    eng: &mut SimEngine,
    ticket: TxTicket,
    stmt: &str,
    params: Vec<(String, Value)>,
) -> Outcome {
    match eng.run(ticket, stmt, params, false, None) {
        Ok(mut reply) => drain(&mut reply),
        Err(e) => Outcome {
            ok: false,
            rows: 0,
            cells: Vec::new(),
            error: Some(e.to_string()),
        },
    }
}

/// Drains a result stream into an [`Outcome`], rendering each cell so read results give the trace
/// teeth (a wrong row count or value changes the hash).
fn drain(reply: &mut RunReply) -> Outcome {
    let mut rows = 0usize;
    let mut cells = Vec::new();
    loop {
        match reply.rows.next() {
            Ok(Some(row)) => {
                rows += 1;
                for cell in &row {
                    cells.push(format!("{cell:?}"));
                }
            }
            Ok(None) => break,
            Err(e) => {
                return Outcome {
                    ok: false,
                    rows,
                    cells,
                    error: Some(e.to_string()),
                };
            }
        }
    }
    Outcome {
        ok: true,
        rows,
        cells,
        error: None,
    }
}

/// Drives the **fault-then-heal recovery probe** (rmp #240): a fresh, deterministic workload batch run
/// against the (now-quiesced, post-heal) engine to prove availability resumed — the engine commits *and*
/// serves correct results after the fault window.
///
/// The batch creates [`RECOVERY_BATCH`] new `:Person` nodes with **fresh ids beyond** any the workload
/// committed (the ids are a pure function of the recovered high-water mark, so the probe is itself a
/// pure function of the run), each in its own auto-commit transaction. We then re-read the model⇄engine
/// equivalence over the post-heal
/// state: every freshly committed create is applied to the shadow `model`, and [`assert_equivalent`]
/// must still hold — so a create that the engine *acked* but did not actually persist (a phantom commit,
/// the post-heal availability bug this probe is built to catch) is flagged as `correct == false`.
///
/// Returns the attempted/committed counts and whether the engine served correct results. The DURING-
/// fault window may legitimately have stalled or errored; this POST-heal batch must recover.
fn recovery_probe(eng: &mut SimEngine, model: &mut ShadowGraph) -> RecoveryProbe {
    // Fresh ids strictly above every committed id, so the batch never collides with the recovered state
    // (which would make a "duplicate" look like a lost create). The shadow model is the model-agreed
    // committed set, so its max id is the deterministic high-water mark.
    let base = model
        .node_snapshot()
        .keys()
        .copied()
        .max()
        .unwrap_or(-1)
        .saturating_add(1);

    let mut attempted = 0usize;
    let mut committed = 0usize;
    for i in 0..RECOVERY_BATCH as i64 {
        attempted += 1;
        let op = WorkloadOp::CreateNode { id: base + i };
        let (stmt, params) = op.to_cypher();
        let Ok(ticket) = eng.begin_auto_commit(AccessMode::Write) else {
            // The engine refused even to begin a transaction after the heal — not available. Stop;
            // the shortfall (committed < attempted) is the liveness violation.
            break;
        };
        // A post-heal error (begin/run) is an availability shortfall: leave it uncommitted — the count
        // gap (`committed < attempted`) is what flags the liveness violation.
        if let Ok(mut reply) = eng.run(ticket, stmt, params, true, None) {
            let out = drain(&mut reply);
            if out.ok {
                committed += 1;
                // Mirror the acked create into the shadow model so the post-heal equivalence check
                // includes the new batch (catching a phantom commit: acked but not persisted).
                model.apply(op);
            }
        }
    }

    // The engine must serve *correct* results post-heal, not merely *some* — the reference model
    // (now including every acked batch create) agrees with the engine queried back cell-by-cell.
    let correct = assert_equivalent(eng, model).is_ok();

    RecoveryProbe {
        attempted,
        committed,
        correct,
    }
}

/// Probes the `:Person` nodes currently in the graph, returning `(total_rows, distinct_ids)`.
///
/// A liveness/consistency probe under contention: with monotonic node ids each committed `CreateNode`
/// adds exactly one row with a unique id, so `total_rows == distinct_ids` must hold — a mismatch means
/// the interleaver lost a committed create (fewer than expected) or **duplicated** one (a row with a
/// repeated id), the kind of isolation bug this loop is built to surface. Returns `(-1, -1)` on a
/// probe error.
fn person_stats(eng: &mut SimEngine) -> (i64, i64) {
    let Ok(ticket) = eng.begin_auto_commit(AccessMode::Read) else {
        return (-1, -1);
    };
    match eng.run(
        ticket,
        "MATCH (n:Person) RETURN n.id AS id ORDER BY n.id",
        vec![],
        true,
        None,
    ) {
        Ok(mut reply) => {
            let out = drain(&mut reply);
            // `cells` holds the rendered ids in id order; counting distinct adjacent values gives the
            // distinct-id count without parsing the cell types.
            let distinct = out
                .cells
                .iter()
                .enumerate()
                .filter(|(i, c)| *i == 0 || out.cells[i - 1] != **c)
                .count();
            (out.rows as i64, distinct as i64)
        }
        Err(_) => (-1, -1),
    }
}

/// Hashes a canonical, ordered snapshot of the whole graph (nodes then relationships), so two runs
/// that reach the same state hash to the same value. Read-only, in its own transaction.
fn snapshot_hash(eng: &mut SimEngine) -> u64 {
    let mut h = Fnv::new();
    for stmt in [
        "MATCH (n:Person) RETURN n.id AS id ORDER BY n.id",
        "MATCH (a:Person)-[:KNOWS]->(b:Person) RETURN a.id AS a, b.id AS b ORDER BY a.id, b.id",
    ] {
        h.bytes(b"#");
        if let Ok(ticket) = eng.begin_auto_commit(AccessMode::Read) {
            if let Ok(mut reply) = eng.run(ticket, stmt, vec![], true, None) {
                let out = drain(&mut reply);
                h.u64(out.rows as u64);
                for c in &out.cells {
                    h.bytes(c.as_bytes());
                    h.bytes(b"|");
                }
            }
        }
    }
    h.finish()
}

/// Reduces an engine error message to a coarse, stable class token for the trace.
fn error_class(msg: &str) -> &'static str {
    let m = msg.to_ascii_lowercase();
    if m.contains("read transaction") || m.contains("write statement") {
        "read_only_write"
    } else if m.contains("serial") {
        "serialization"
    } else if m.contains("compile") || m.contains("syntax") {
        "compile"
    } else if m.contains("constraint") {
        "constraint"
    } else {
        "other"
    }
}

/// A tiny, dependency-free FNV-1a 64-bit hasher used to build the stable run digests.
struct Fnv(u64);

impl Fnv {
    fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }

    fn bytes(&mut self, data: &[u8]) {
        for &b in data {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    fn u64(&mut self, v: u64) {
        self.bytes(&v.to_le_bytes());
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_yields_identical_report() {
        let cfg = VoprConfig::for_seed(20260614);
        let a = run(cfg);
        let b = run(cfg);
        assert_eq!(
            a, b,
            "same seed ⇒ identical VOPR report (trace + state + counts)"
        );
        // The run is non-trivial: it dispatched real steps and actually mutated the graph. With the
        // cooperative interleaver a run has at least one step per op plus BEGIN/END overhead, so the
        // step count is `>= ops` rather than exactly `clients * ops`.
        assert!(
            a.steps >= (cfg.clients * cfg.ops_per_client) as usize,
            "every op runs (plus BEGIN/END overhead): {} steps",
            a.steps
        );
        assert!(a.ok_ops > 0, "the workload performs real work");
    }

    /// **Acceptance #1 (overlap).** The cooperative interleaver reaches a state where ≥2 explicit
    /// transactions are open at the *same* scheduler step — genuine, single-threaded concurrency. With
    /// auto-commit disabled (`auto_commit_permille = 0`) and multi-statement transactions, clients sit
    /// open across several scheduler steps, so the scheduler necessarily interleaves their BEGIN/stmt
    /// steps and the overlap depth exceeds one.
    #[test]
    fn interleaver_reaches_simultaneous_open_transactions() {
        let cfg = VoprConfig {
            clients: 6,
            ops_per_client: 20,
            max_txn_stmts: 5,
            auto_commit_permille: 0, // always explicit ⇒ transactions stay open across steps
            rollback_permille: 0,
            ..VoprConfig::for_seed(424242)
        };
        let r = run(cfg);
        assert!(
            r.max_open_txns >= 2,
            "the interleaver must reach ≥2 simultaneously-open transactions (got {})",
            r.max_open_txns
        );
        // Determinism still holds for this contended config.
        assert_eq!(r, run(cfg), "the overlapping run replays identically");
    }

    /// **Acceptance #5 (contention reachable).** Under heavy same-key write pressure with explicit
    /// multi-statement transactions, the *main* interleaver loop now reaches write–write contention:
    /// at least one explicit transaction aborts (a `ROLLBACK`, or a `COMMIT` rejected by SSI), an
    /// outcome the old per-op auto-commit loop — where every op committed in isolation — could never
    /// produce. ACID still holds: the consistency probe shows no lost/duplicated committed create.
    #[test]
    fn interleaver_reaches_write_write_contention() {
        // A write-heavy mix concentrates writes on a small set of ids (the generator draws edge/target
        // ids over the existing id space), so concurrent transactions contend on the same nodes.
        let cfg = VoprConfig {
            clients: 8,
            ops_per_client: 24,
            pool_pages: 512,
            mix: MixProfile::write_heavy(),
            max_txn_stmts: 6,
            auto_commit_permille: 0,
            rollback_permille: 150,
            ..VoprConfig::for_seed(20260235)
        };
        let r = run(cfg);
        assert!(
            r.max_open_txns >= 2,
            "contention requires real overlap (got {})",
            r.max_open_txns
        );
        assert!(
            r.committed_txns > 0,
            "the interleaver still commits real transactions (got {})",
            r.committed_txns
        );
        assert!(
            r.aborted_txns > 0,
            "the interleaved main loop reaches abort/contention outcomes the legacy loop could not \
             (committed={}, aborted={})",
            r.committed_txns,
            r.aborted_txns
        );
        // ACID upheld: every committed `:Person` create persists exactly once — no duplicate ids and
        // no lost create — even though contention aborted some transactions.
        assert_eq!(
            r.persisted_nodes, r.created_nodes,
            "no committed create is lost or duplicated under contention: rows {} != distinct {}",
            r.persisted_nodes, r.created_nodes
        );
        assert_eq!(r, run(cfg), "the contended run replays identically");
    }

    /// A pure auto-commit run reproduces the legacy per-op behaviour: one step per op, no open-tx
    /// overlap, and a clean (error-free) workload — proving the degenerate client mode is preserved.
    #[test]
    fn auto_commit_mode_matches_legacy_shape() {
        let cfg = VoprConfig {
            clients: 8,
            ops_per_client: 16,
            auto_commit_permille: 1000, // every client is a one-statement auto-commit transaction
            ..VoprConfig::for_seed(99)
        };
        let r = run(cfg);
        assert_eq!(
            r.steps,
            (cfg.clients * cfg.ops_per_client) as usize,
            "auto-commit mode runs exactly one step per op (legacy shape)"
        );
        assert_eq!(
            r.max_open_txns, 0,
            "auto-commit transactions never stay open across steps"
        );
        assert_eq!(r.err_ops, 0, "a clean auto-commit workload has no errors");
        assert_eq!(r.persisted_nodes, r.created_nodes, "consistent");
    }

    #[test]
    fn distinct_seeds_yield_distinct_traces() {
        // Across a small fixed set of seeds, the trace hashes must not all collapse to one value —
        // proving the run genuinely depends on the seed (non-vacuous).
        let hashes: std::collections::BTreeSet<u64> = (1u64..=12)
            .map(|s| run(VoprConfig::for_seed(s)).trace_hash)
            .collect();
        assert!(
            hashes.len() > 1,
            "distinct seeds must produce distinct traces (got {} unique)",
            hashes.len()
        );
    }

    #[test]
    fn state_hash_tracks_the_graph() {
        // Two seeds that build different graphs should (almost surely) reach different state hashes;
        // at minimum the state hash is stable per seed (covered above) and not a constant.
        let states: std::collections::BTreeSet<u64> = (1u64..=12)
            .map(|s| run(VoprConfig::for_seed(s)).state_hash)
            .collect();
        assert!(states.len() > 1, "the final state depends on the seed");
    }

    /// Stress: a large workload under high concurrency completes (no hang/deadlock — reaching the
    /// asserts proves termination), every scheduled op runs (monotone progress), and every acked
    /// node create is persisted exactly once (no lost/duplicated work under load). Run in pure
    /// auto-commit mode so the per-op liveness contract (`steps == ops`, `err_ops == 0`) is exact —
    /// the explicit-transaction contention path is certified by the interleaver tests above.
    #[test]
    fn high_load_run_is_live_and_consistent() {
        // Many interleaved clients at high arrival pressure. Sized to stay fast in a debug build
        // (the workload's `MATCH (:Person {id})` is an unindexed scan, so cost grows with the graph);
        // it still exercises deep interleaving + a few hundred concurrent-ish ops.
        let cfg = VoprConfig {
            clients: 16,
            ops_per_client: 40,
            pool_pages: 512,
            mix: MixProfile::write_heavy(),
            load: LoadProfile::Steady { min: 1, max: 50 },
            auto_commit_permille: 1000,
            ..VoprConfig::for_seed(2024)
        };
        let r = run(cfg);
        assert_eq!(
            r.steps,
            16 * 40,
            "every scheduled op ran (monotone progress)"
        );
        assert_eq!(r.err_ops, 0, "a clean high-load workload has no errors");
        assert_eq!(
            r.created_nodes, r.persisted_nodes,
            "every acked node create is persisted exactly once under load: {} != {}",
            r.created_nodes, r.persisted_nodes
        );
        assert!(r.created_nodes > 100, "the stress run did substantial work");
    }

    /// Each load profile (steady/ramp/spike) drives a complete, deterministic, consistent run.
    #[test]
    fn load_profiles_all_complete_consistently() {
        let profiles = [
            LoadProfile::Steady { min: 1, max: 20 },
            LoadProfile::Ramp { start: 100, end: 1 },
            LoadProfile::Spike {
                base: 30,
                period: 16,
                burst: 4,
            },
        ];
        for load in profiles {
            let cfg = VoprConfig::for_seed(77)
                .with_mix(MixProfile::mixed())
                .with_load(load);
            let a = run(cfg);
            let b = run(cfg);
            assert_eq!(a, b, "load profile {load:?} is deterministic");
            assert!(
                a.steps >= (cfg.clients * cfg.ops_per_client) as usize,
                "all ops ran under {load:?} (plus BEGIN/END overhead): {} steps",
                a.steps
            );
            assert_eq!(
                a.created_nodes, a.persisted_nodes,
                "consistent under {load:?}: {} != {}",
                a.created_nodes, a.persisted_nodes
            );
        }
    }

    #[test]
    fn summary_is_stable_and_reproducible() {
        let r = run(VoprConfig::for_seed(7));
        let s1 = summarize(&r);
        let s2 = summarize(&run(VoprConfig::for_seed(7)));
        assert_eq!(s1, s2, "the summary line replays identically from the seed");
        assert!(s1.contains("trace_hash="));
    }

    // ---------------------------- unified fault scheduler (rmp #236) ----------------------------

    /// A contended, fault-enabled config: explicit overlapping transactions under a write-heavy mix
    /// with a generous fault budget, sized to stay fast in a debug build.
    fn fault_cfg(seed: u64) -> VoprConfig {
        VoprConfig {
            clients: 6,
            ops_per_client: 24,
            pool_pages: 512,
            mix: MixProfile::write_heavy(),
            max_txn_stmts: 5,
            auto_commit_permille: 200,
            rollback_permille: 100,
            ..VoprConfig::for_seed(seed)
        }
        .with_faults(FaultBudget::default().with_max_faults(12))
    }

    /// **Acceptance.** A fault-enabled run actually injects faults during interleaved work, the budget
    /// bounds them, and the fault schedule is folded into the trace (so it is part of the reproducible
    /// run). The consistency probe must still pass — the budgeted chaos stays recoverable.
    #[test]
    fn faults_fire_during_interleaved_work_and_stay_consistent() {
        let cfg = fault_cfg(0x236_0001);
        let r = run(cfg);
        let injected = r.disk_faults + r.clock_faults + r.transport_faults;
        assert!(
            injected > 0,
            "a fault-enabled config injects faults (disk={} clock={} xport={})",
            r.disk_faults,
            r.clock_faults,
            r.transport_faults
        );
        assert!(
            injected <= cfg.fault_budget.max_faults,
            "the budget bounds the injected fault count: {} > {}",
            injected,
            cfg.fault_budget.max_faults
        );
        // ACID upheld under budgeted chaos: every committed `:Person` create persists exactly once.
        assert_eq!(
            r.persisted_nodes, r.created_nodes,
            "no committed create lost/duplicated under faults: rows {} != distinct {}",
            r.persisted_nodes, r.created_nodes
        );
        // The run did real work alongside the faults.
        assert!(
            r.steps > 0 && r.ok_ops > 0,
            "the faulted run still progresses"
        );
    }

    /// **Acceptance (determinism).** Same seed ⇒ identical fault schedule, trace hash, state hash and
    /// full report — the seed-double-run gate the CLI relies on, now under faults.
    #[test]
    fn faulted_run_is_deterministic_same_seed() {
        let cfg = fault_cfg(0x236_0002);
        let a = run(cfg);
        let b = run(cfg);
        assert_eq!(
            a, b,
            "same seed ⇒ identical faulted report (schedule + trace + state)"
        );
        assert!(
            a.disk_faults + a.clock_faults + a.transport_faults > 0,
            "the determinism check is non-vacuous (faults actually fired)"
        );
    }

    /// **Acceptance (sensitivity).** Distinct seeds produce distinct fault schedules, so the trace hash
    /// genuinely depends on the fault schedule (it is folded in). Across a small set of seeds the trace
    /// hashes must not all collapse.
    #[test]
    fn distinct_seeds_yield_distinct_faulted_traces() {
        let hashes: std::collections::BTreeSet<u64> =
            (1u64..=10).map(|s| run(fault_cfg(s)).trace_hash).collect();
        assert!(
            hashes.len() > 1,
            "distinct seeds ⇒ distinct faulted traces (got {} unique)",
            hashes.len()
        );
    }

    /// **Acceptance (fault folds into the trace).** Enabling faults must *change* the canonical trace
    /// for a fixed seed — proving the fault schedule is genuinely folded into the run digest and not an
    /// inert side-channel. (The fault RNG is domain-separated from the workload RNG, so the workload
    /// itself is unchanged; only the folded fault events move the hash.)
    #[test]
    fn enabling_faults_changes_the_trace_hash() {
        let seed = 0x236_0003;
        let base = run(VoprConfig::for_seed(seed)); // FaultBudget::none()
        let faulted = run(fault_cfg(seed));
        assert_eq!(
            base.disk_faults + base.clock_faults + base.transport_faults,
            0
        );
        assert!(faulted.disk_faults + faulted.clock_faults + faulted.transport_faults > 0);
        assert_ne!(
            base.trace_hash, faulted.trace_hash,
            "the injected fault schedule must fold into (change) the trace hash"
        );
    }

    /// A disk-only, high-rate budget exercises the live-device seam hard: many seeded corruptions are
    /// armed on the running store mid-workload, yet the engine surfaces them (a checksum catches the
    /// corruption) and the consistency probe still holds — corruption is *recoverable*, not a wipe.
    #[test]
    fn disk_only_faults_are_recoverable() {
        let cfg = VoprConfig {
            clients: 5,
            ops_per_client: 20,
            pool_pages: 512,
            mix: MixProfile::write_heavy(),
            auto_commit_permille: 300,
            ..VoprConfig::for_seed(0x236_0004)
        }
        .with_faults(
            FaultBudget::default()
                .with_max_faults(16)
                .with_weights(1, 0, 0)
                .with_disk_intensity(2, 64),
        );
        let r = run(cfg);
        assert!(
            r.disk_faults > 0,
            "disk faults actually armed (got {})",
            r.disk_faults
        );
        assert_eq!(r.clock_faults, 0, "disk-only budget arms no clock faults");
        assert_eq!(
            r.transport_faults, 0,
            "disk-only budget arms no transport faults"
        );
        assert_eq!(
            r.persisted_nodes, r.created_nodes,
            "committed creates survive disk corruption: rows {} != distinct {}",
            r.persisted_nodes, r.created_nodes
        );
        assert_eq!(r, run(cfg), "the disk-faulted run replays identically");
    }

    /// A clock-only budget makes the engine read a hostile (jumping/regressing) clock mid-run; the
    /// engine must tolerate it (no panic, no negative duration) and stay consistent — the
    /// `FaultyClock` tolerance contract, exercised through the live engine.
    #[test]
    fn clock_only_faults_are_tolerated() {
        let cfg = VoprConfig {
            clients: 5,
            ops_per_client: 20,
            mix: MixProfile::mixed(),
            ..VoprConfig::for_seed(0x236_0005)
        }
        .with_faults(
            FaultBudget::default()
                .with_max_faults(12)
                .with_weights(0, 1, 0)
                .with_clock_intensity(50_000),
        );
        let r = run(cfg);
        assert!(
            r.clock_faults > 0,
            "clock faults actually fired (got {})",
            r.clock_faults
        );
        assert_eq!(
            r.persisted_nodes, r.created_nodes,
            "a hostile clock does not corrupt the graph: rows {} != distinct {}",
            r.persisted_nodes, r.created_nodes
        );
        assert_eq!(r, run(cfg), "the clock-faulted run replays identically");
    }

    /// The default (fault-free) run is byte-for-byte unchanged by wiring the scheduler in: a
    /// `FaultBudget::none()` run tallies zero faults and matches the pre-#236 trace/state for the seed.
    #[test]
    fn fault_free_run_injects_nothing() {
        let r = run(VoprConfig::for_seed(20260614));
        assert_eq!(r.disk_faults, 0);
        assert_eq!(r.clock_faults, 0);
        assert_eq!(r.transport_faults, 0);
        // A standard run is also crash-free (crashes are off by default).
        assert_eq!(r.crash_restarts, 0);
        assert!(r.crash_splits.is_empty());
    }

    // ---------------------------- crash + ARIES restart (rmp #237) ----------------------------

    /// A contended, crash-enabled config: explicit overlapping transactions under a write-heavy mix with
    /// crashes woven into the running interleave, sized to stay fast in a debug build and to *guarantee*
    /// open transactions coexist with acked commits at the crash instant.
    fn crash_cfg(seed: u64) -> VoprConfig {
        VoprConfig {
            clients: 6,
            ops_per_client: 24,
            pool_pages: 512,
            mix: MixProfile::write_heavy(),
            max_txn_stmts: 5,
            auto_commit_permille: 200,
            rollback_permille: 100,
            ..VoprConfig::for_seed(seed)
        }
        .with_crashes(2)
    }

    /// **Acceptance #1 (crash mid-interleave; acked survive, in-flight don't; run continues consistent).**
    /// A crash-enabled run crashes during interleaved work — committed and in-flight transactions coexist
    /// at the crash — recovers via ARIES, and continues. Every acked `:Person` create persists exactly
    /// once across the crash (no committed create lost or duplicated: the acked-survives contract), and at
    /// least one crash caught a genuinely in-flight (open) transaction (the in-flight-doesn't contract is
    /// reachable: those open tickets were aborted by the crash, never replayed).
    #[test]
    fn crash_mid_interleave_recovers_and_stays_consistent() {
        let cfg = crash_cfg(0x237_0001);
        let r = run(cfg);
        assert!(
            r.crash_restarts > 0,
            "a crash-enabled run actually crashes + recovers (got {})",
            r.crash_restarts
        );
        // The run made progress *after* recovery — it did not end at the crash. With crashes confined to
        // the leading 3/4 of the horizon, there are always post-recovery steps to certify continuity.
        assert!(
            r.steps > (cfg.clients * cfg.ops_per_client) as usize / 2,
            "the workload continues past the crash (steps {})",
            r.steps
        );
        // The acked-survives contract, spanning the crash: every committed create persists exactly once.
        assert_eq!(
            r.persisted_nodes, r.created_nodes,
            "no acked create lost/duplicated across the crash: rows {} != distinct {}",
            r.persisted_nodes, r.created_nodes
        );
        // The in-flight-doesn't contract is *reachable*: at least one crash caught an open transaction.
        // (That open ticket belonged to the dead engine; ARIES undo/no-redo discarded its effect — the
        // surviving consistency above proves no half-applied in-flight write leaked in.)
        assert!(
            r.crash_splits.iter().any(|s| s.inflight_txns > 0),
            "a crash caught a genuinely in-flight transaction: {:?}",
            r.crash_splits
        );
        // The split is well-formed: one CrashSplit per restart, acked counts are non-decreasing in time.
        assert_eq!(r.crash_splits.len(), r.crash_restarts as usize);
        let mut prev_acked = 0;
        for s in &r.crash_splits {
            assert!(
                s.acked_commits >= prev_acked,
                "acked commits are monotone across crashes: {:?}",
                r.crash_splits
            );
            prev_acked = s.acked_commits;
        }
    }

    /// **Acceptance #3 (deterministic recovery).** Same seed ⇒ identical trace hash, recovered state and
    /// full report — recovery replays bit-for-bit, including the crash schedule, the acked/in-flight split
    /// and the recovered state hash, now spanning the crash.
    #[test]
    fn crash_run_is_deterministic_same_seed() {
        let cfg = crash_cfg(0x237_0002);
        let a = run(cfg);
        let b = run(cfg);
        assert_eq!(
            a, b,
            "same seed ⇒ identical crash-and-recover report (schedule + split + recovered state)"
        );
        assert!(
            a.crash_restarts > 0,
            "the determinism check is non-vacuous (a crash actually fired)"
        );
        // The per-crash recovered-state hashes also match (they are part of the equal reports above, but
        // assert directly so a regression points straight at the recovery digest).
        assert_eq!(
            a.crash_splits, b.crash_splits,
            "the acked/in-flight split + recovered state replays identically"
        );
    }

    /// **Acceptance (distinct seeds ⇒ distinct crash schedules).** The crash fire steps depend on the
    /// seed: across a small set of seeds the crash schedules must not all collapse to one. (Captured via
    /// the per-crash `fire_step`s folded into the report.)
    #[test]
    fn distinct_seeds_yield_distinct_crash_schedules() {
        let schedules: std::collections::BTreeSet<Vec<u64>> = (1u64..=12)
            .map(|s| {
                run(crash_cfg(s))
                    .crash_splits
                    .iter()
                    .map(|c| c.fire_step)
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(
            schedules.len() > 1,
            "distinct seeds must produce distinct crash schedules (got {} unique)",
            schedules.len()
        );
    }

    /// **Acceptance (crash folds into the trace).** Enabling crashes must *change* the canonical trace for
    /// a fixed seed — proving the crash schedule + recovered state are genuinely folded into the run
    /// digest, not an inert side-channel.
    #[test]
    fn enabling_crashes_changes_the_trace_hash() {
        let seed = 0x237_0003;
        let base = run(VoprConfig::for_seed(seed)); // crash-free
        let crashed = run(crash_cfg(seed));
        assert_eq!(base.crash_restarts, 0);
        assert!(crashed.crash_restarts > 0);
        assert_ne!(
            base.trace_hash, crashed.trace_hash,
            "the injected crash schedule + recovered state must fold into (change) the trace hash"
        );
    }

    /// A crash woven into a **pure auto-commit** run still recovers and stays exactly consistent: every
    /// op is its own acked transaction, so at the crash there are *no* in-flight transactions, yet every
    /// acked create must still survive the restart (acked-survives with a clean in-flight=0 split).
    #[test]
    fn crash_under_auto_commit_preserves_every_acked_write() {
        let cfg = VoprConfig {
            clients: 5,
            ops_per_client: 20,
            pool_pages: 512,
            mix: MixProfile::write_heavy(),
            ..VoprConfig::for_seed(0x237_0006)
        }
        .auto_commit_only()
        .with_crashes(1);
        let r = run(cfg);
        assert!(
            r.crash_restarts > 0,
            "the auto-commit run crashed + recovered"
        );
        // Auto-commit transactions never stay open across steps, so the crash catches none in flight.
        assert!(
            r.crash_splits.iter().all(|s| s.inflight_txns == 0),
            "auto-commit leaves nothing in flight at the crash: {:?}",
            r.crash_splits
        );
        assert_eq!(
            r.persisted_nodes, r.created_nodes,
            "every acked auto-commit create survives the crash: rows {} != distinct {}",
            r.persisted_nodes, r.created_nodes
        );
        assert_eq!(
            r,
            run(cfg),
            "the crashed auto-commit run replays identically"
        );
    }

    /// Crashes compose with disk + clock faults on the one timeline: a budget that arms disk/clock faults
    /// *and* crashes still recovers and stays consistent — the crash recovers from a WAL that itself
    /// weathered budgeted corruption, the strongest combined-chaos certification of this sprint.
    #[test]
    fn crash_composes_with_other_faults_and_stays_consistent() {
        let cfg = VoprConfig {
            clients: 6,
            ops_per_client: 24,
            pool_pages: 512,
            mix: MixProfile::write_heavy(),
            max_txn_stmts: 5,
            auto_commit_permille: 200,
            ..VoprConfig::for_seed(0x237_0007)
        }
        .with_faults(FaultBudget::default().with_max_faults(8))
        .with_crashes(2);
        let r = run(cfg);
        assert!(r.crash_restarts > 0, "crashes fired alongside other faults");
        assert!(
            r.disk_faults + r.clock_faults + r.transport_faults > 0,
            "other faults fired too (disk={} clock={} xport={})",
            r.disk_faults,
            r.clock_faults,
            r.transport_faults
        );
        assert_eq!(
            r.persisted_nodes, r.created_nodes,
            "consistent under crashes + faults combined: rows {} != distinct {}",
            r.persisted_nodes, r.created_nodes
        );
        assert_eq!(r, run(cfg), "the combined-chaos run replays identically");
    }

    // ---------------------------- strong reference-model oracle (rmp #238) ----------------------------

    /// **Acceptance (oracle agrees on the real engine, across a seed sweep).** For every seed in a
    /// representative range, the committed-only shadow model agrees with the engine queried back
    /// **cell-by-cell** (node multiset, edge multiset, count, neighbours) — `report.oracle` is `None`.
    /// This is the empirical proof the model mirrors the engine's exact multigraph + MVCC semantics for
    /// the whole workload. (The auto-commit-abort durability bug this oracle first surfaced at seed 4 is
    /// fixed in `graphus-server`'s `exec.rs`; this sweep guards against its return and any new
    /// divergence.) A wider 300-seed sweep was run during development; the committed range stays fast in
    /// a debug build.
    #[test]
    fn oracle_agrees_with_engine_across_seed_sweep() {
        let mut diverged = Vec::new();
        for seed in 1u64..=60 {
            if let Some(err) = run(VoprConfig::for_seed(seed)).oracle {
                diverged.push((seed, format!("{err:?}")));
            }
        }
        assert!(
            diverged.is_empty(),
            "the reference-model oracle must agree with the engine for every seed: {diverged:?}"
        );
    }

    /// **Acceptance (the integrated oracle has teeth).** Drive the full VOPR loop, then deliberately
    /// perturb the committed shadow model with an edge the engine never made, and assert
    /// [`assert_equivalent`] catches it. This proves the oracle wired into [`run`] is the same one that
    /// fails on a real divergence — not a no-op observer. (The end-to-end loop integration is asserted
    /// by [`oracle_agrees_with_engine_across_seed_sweep`]; this isolates the catch.)
    #[test]
    fn integrated_oracle_catches_an_injected_divergence() {
        // Reconstruct a committed model from a real run, then inject a phantom edge between two ids the
        // model already holds (so the engine genuinely lacks the extra parallel edge).
        let cfg = VoprConfig::for_seed(7);
        let mut oracle = Oracle::new(cfg.clients.max(1) as usize);

        // Replay the committed creates of a small graph into the model so it has live ids to perturb.
        let clock = SharedClock::new(0);
        let mut eng: SimEngine = LocalEngine::in_memory(
            Arc::new(clock) as Arc<dyn Clock + Send + Sync>,
            cfg.pool_pages,
        )
        .expect("engine");
        for id in 0..3i64 {
            let op = WorkloadOp::CreateNode { id };
            let (stmt, params) = op.to_cypher();
            let t = eng.begin_auto_commit(AccessMode::Write).expect("begin");
            let mut reply = eng.run(t, stmt, params, true, None).expect("run");
            while reply.rows.next().expect("drain").is_some() {}
            oracle.model.apply(op);
        }
        // Faithful so far.
        assert_eq!(assert_equivalent(&mut eng, &oracle.model), Ok(()));

        // Inject: an edge (0,1) the engine never created.
        oracle.model.apply(WorkloadOp::CreateEdge { a: 0, b: 1 });
        let err = assert_equivalent(&mut eng, &oracle.model).expect_err("oracle must catch it");
        assert!(
            matches!(err, OracleError::EdgeMultisetMismatch { edge: (0, 1), .. }),
            "the injected phantom edge must be caught with a precise diff, got {err:?}"
        );
        let _ = eng.shutdown();
    }

    // ---------------------------- safety oracle bundle (rmp #239) ----------------------------

    /// **Acceptance (the full safety bundle holds under faults+crashes, across a seed sweep).** For
    /// every seed in a representative range, [`run_safety`] runs the interleaver under the unified
    /// fault + crash scheduler and asserts all four properties simultaneously — serializability,
    /// durability, atomicity, reference-model equivalence — and reports `safe`. This is the core
    /// correctness oracle: zero violations with faults firing during concurrent interleaved work. The
    /// `vopr_safety_teeth` integration suite + the safety CLI run a wider 1..=100 sweep; the committed
    /// range stays fast in a debug build.
    ///
    /// This sweep surfaced — and the engine fixes here closed — three real recovery defects across a
    /// double crash (rmp #239): a `crash_restart` that opened the store on a *clone* of the WAL (losing
    /// undo CLRs/ABORTs), TxnId reuse across recovery (ARIES mis-classifying a loser as a winner), and a
    /// non-LIFO-abort phantom relationship left by an orphan store page. With all three fixed the bundle
    /// is clean.
    #[test]
    fn safety_bundle_holds_across_seed_sweep_under_faults() {
        let mut unsafe_seeds = Vec::new();
        let mut faults_seen = false;
        let mut crashes_seen = false;
        let mut any_history = false;
        for seed in 1u64..=40 {
            let r = run_safety(VoprConfig::safety(seed));
            if !r.safe {
                unsafe_seeds.push((seed, r.violations.clone()));
            }
            faults_seen |= r.run.disk_faults + r.run.clock_faults + r.run.transport_faults > 0;
            crashes_seen |= r.run.crash_restarts > 0;
            any_history |= r.checked_txns > 0;
        }
        assert!(
            unsafe_seeds.is_empty(),
            "the four-property safety bundle must hold for every seed under faults+crashes: {unsafe_seeds:?}"
        );
        // Non-vacuity: the sweep genuinely exercised faults, crashes, and a real recorded history.
        assert!(faults_seen, "the safety sweep must actually inject faults");
        assert!(
            crashes_seen,
            "the safety sweep must actually crash + recover"
        );
        assert!(
            any_history,
            "the safety sweep must record a non-empty Elle history (the check is non-vacuous)"
        );
    }

    /// **Acceptance (determinism).** Same seed ⇒ identical [`SafetyReport`] — the safety verdict, the
    /// recorded-history length, the violation list and the full underlying run all replay bit-for-bit
    /// (the recorder never perturbs the workload, trace, or engine).
    #[test]
    fn safety_report_is_deterministic_same_seed() {
        let cfg = VoprConfig::safety(0x239_0001);
        let a = run_safety(cfg);
        let b = run_safety(cfg);
        assert_eq!(a, b, "same seed ⇒ identical safety report");
        assert!(a.safe, "the determinism check runs on a clean (safe) seed");
        assert!(
            a.run.crash_restarts > 0
                && a.run.disk_faults + a.run.clock_faults + a.run.transport_faults > 0,
            "the determinism check is non-vacuous (faults + crashes actually fired)"
        );
    }

    /// The safety recorder is a **pure observer**: turning it on does not change the canonical run — the
    /// trace hash, state hash, and full [`VoprReport`] for a fixed config are identical with and without
    /// recording. This guarantees the legacy [`run`] path stays bit-for-bit unchanged (zero-cost gating).
    #[test]
    fn safety_recorder_does_not_perturb_the_run() {
        let cfg = VoprConfig::safety(0x239_0002);
        let plain = run(cfg);
        let recorded = run_safety(cfg).run;
        assert_eq!(
            plain, recorded,
            "the Elle recorder must not perturb the canonical run (trace/state/counts)"
        );
    }

    /// Teeth (serializability arm): the bundle catches a deliberately non-serializable history. We feed
    /// a fabricated write-skew history straight to the same [`elle_check`] the safety oracle uses,
    /// proving the arm has teeth. (The other three arms are exercised against the real engine in the
    /// `vopr_safety_teeth` integration suite.)
    #[test]
    fn serializability_arm_catches_a_fabricated_cycle() {
        let history = vec![
            ElleTxn::committed(
                1,
                vec![
                    ElleOp::Read {
                        key: ELLE_PERSONS_KEY.to_owned(),
                        observed: vec![],
                    },
                    ElleOp::Append {
                        key: ELLE_PERSONS_KEY.to_owned(),
                        val: 1,
                    },
                ],
            ),
            ElleTxn::committed(
                2,
                vec![
                    ElleOp::Read {
                        key: ELLE_PERSONS_KEY.to_owned(),
                        observed: vec![],
                    },
                    ElleOp::Append {
                        key: ELLE_PERSONS_KEY.to_owned(),
                        val: 2,
                    },
                ],
            ),
        ];
        let verdict = elle_check(&history);
        assert!(
            !verdict.serializable,
            "the serializability checker must flag the fabricated cycle: {verdict:?}"
        );
    }

    /// The recorded history is **append-only** (writes only — see [`Oracle::stage_elle`]), so for the
    /// real workload it is always internally consistent: no fabricated read injects a phantom cycle. A
    /// clean safety run therefore records a non-empty, serializable history.
    #[test]
    fn recorded_history_is_append_only_and_serializable() {
        let r = run_safety(VoprConfig::safety(0x239_0003));
        assert!(r.safe, "a clean seed must be safe: {:?}", r.violations);
        assert!(
            r.checked_txns > 0,
            "the recorded history must be non-empty (non-vacuous)"
        );
    }

    /// A clean baseline [`VoprReport`] for the `evaluate_safety` teeth: no faults, no crashes, the
    /// reference oracle agreeing, persisted == created. Each teeth test perturbs exactly one field.
    fn clean_report() -> VoprReport {
        VoprReport {
            seed: 1,
            steps: 10,
            ok_ops: 10,
            err_ops: 0,
            trace_hash: 0,
            state_hash: 0,
            end_time: 0,
            created_nodes: 5,
            persisted_nodes: 5,
            max_open_txns: 2,
            committed_txns: 5,
            aborted_txns: 0,
            disk_faults: 0,
            clock_faults: 0,
            transport_faults: 0,
            crash_restarts: 0,
            crash_splits: Vec::new(),
            oracle: None,
            latent_fault_pages: Vec::new(),
        }
    }

    /// A faithful append-only history matching `clean_report` (5 committed creates) — serializable.
    fn clean_history() -> Vec<ElleTxn> {
        (0..5i64)
            .map(|id| {
                ElleTxn::committed(
                    id as u64 + 1,
                    vec![ElleOp::Append {
                        key: ELLE_PERSONS_KEY.to_owned(),
                        val: id,
                    }],
                )
            })
            .collect()
    }

    /// Teeth (all four arms via the pure evaluator): the bundle is clean on a faithful run, and each
    /// of the four properties is independently caught when its evidence is broken. This is the "broken
    /// build" mutation test the acceptance criteria require — one falsifiable arm per property.
    #[test]
    fn evaluate_safety_has_teeth_per_property() {
        // Baseline: a faithful run + history is clean.
        assert!(
            evaluate_safety(&clean_report(), &clean_history()).is_empty(),
            "a faithful run must report no safety violations"
        );

        // 1. Serializability: a fabricated duplicate append (the same id committed by two txns) is an
        //    impossible version order the checker flags.
        let mut dup_history = clean_history();
        dup_history.push(ElleTxn::committed(
            99,
            vec![ElleOp::Append {
                key: ELLE_PERSONS_KEY.to_owned(),
                val: 0, // id 0 was already appended by txn 1 — a duplicate version
            }],
        ));
        let v = evaluate_safety(&clean_report(), &dup_history);
        assert!(
            v.iter()
                .any(|x| x.property == SafetyProperty::Serializability),
            "a duplicate append must trip the serializability arm: {v:?}"
        );

        // 2. Durability: a fabricated acked-commit regression across crashes (an acked commit lost at a
        //    restart) is flagged.
        let mut durability_broken = clean_report();
        durability_broken.crash_restarts = 2;
        durability_broken.crash_splits = vec![
            CrashSplit {
                fire_step: 10,
                acked_commits: 5,
                inflight_txns: 1,
                recovered_state_hash: 0,
            },
            CrashSplit {
                fire_step: 20,
                acked_commits: 3, // REGRESSION: fewer acked after the second crash — a lost commit
                inflight_txns: 0,
                recovered_state_hash: 0,
            },
        ];
        let v = evaluate_safety(&durability_broken, &clean_history());
        assert!(
            v.iter().any(|x| x.property == SafetyProperty::Durability),
            "an acked-commit regression must trip the durability arm: {v:?}"
        );

        // 3. Atomicity: a fabricated persisted != created gap (a partial/duplicated effect survived) is
        //    flagged.
        let mut atomicity_broken = clean_report();
        atomicity_broken.persisted_nodes = 6; // one more row than distinct committed ids
        let v = evaluate_safety(&atomicity_broken, &clean_history());
        assert!(
            v.iter().any(|x| x.property == SafetyProperty::Atomicity),
            "a persisted!=created gap must trip the atomicity arm: {v:?}"
        );

        // 4. Reference-model: a fabricated oracle divergence is flagged.
        let mut refmodel_broken = clean_report();
        refmodel_broken.oracle = Some(OracleError::NodeMultisetMismatch {
            id: 7,
            model: 0,
            engine: 1,
        });
        let v = evaluate_safety(&refmodel_broken, &clean_history());
        assert!(
            v.iter()
                .any(|x| x.property == SafetyProperty::ReferenceModel),
            "an oracle divergence must trip the reference-model arm: {v:?}"
        );
    }

    /// **rmp #480 — engine-surfaced injected fault is EXPECTED, but the teeth survive.** The safety
    /// bundle must drop the reference-model "failure" ONLY when the read-back hard-failed because the
    /// engine surfaced a latent-sector-error the harness itself injected (a page in
    /// `latent_fault_pages`) — and must STILL flag every silent committed-data discrepancy and every
    /// untied error. This is the exact distinction the false-positive seed 47251 exposed.
    #[test]
    fn evaluate_safety_excuses_surfaced_injected_lse_only() {
        use crate::vopr_oracle::SurfacedFault;

        // (a) Engine SURFACED an injected LSE on an armed page ⇒ NOT a safety violation. The read-back
        //     refused to serve bytes from a page WE made unreadable — "surface, never corrupt" upheld.
        let mut surfaced = clean_report();
        surfaced.oracle = Some(OracleError::ReadBack {
            what: "nodes",
            surfaced: Some(SurfacedFault { page: 3 }),
        });
        surfaced.latent_fault_pages = vec![3];
        let v = evaluate_safety(&surfaced, &clean_history());
        assert!(
            v.is_empty(),
            "an engine-surfaced injected latent-sector-error read-back must be SAFE: {v:?}"
        );

        // (b) TEETH: a SILENT committed-data loss (the read SUCCEEDED but returned the wrong multiset)
        //     is a real durability violation and is STILL flagged, even with the SAME page faulted.
        let mut silent_loss = clean_report();
        silent_loss.oracle = Some(OracleError::NodeMultisetMismatch {
            id: 5,
            model: 1,
            engine: 0,
        });
        silent_loss.latent_fault_pages = vec![3];
        let v = evaluate_safety(&silent_loss, &clean_history());
        assert!(
            v.iter()
                .any(|x| x.property == SafetyProperty::ReferenceModel),
            "a SILENT committed-data loss must STILL be UNSAFE even with faults armed: {v:?}"
        );

        // (c) TEETH: a surfaced read error on a page the harness NEVER armed is not positively tied to
        //     an injected fault, so it is STILL flagged (conservative).
        let mut untied = clean_report();
        untied.oracle = Some(OracleError::ReadBack {
            what: "nodes",
            surfaced: Some(SurfacedFault { page: 99 }),
        });
        untied.latent_fault_pages = vec![3]; // page 99 was never faulted
        let v = evaluate_safety(&untied, &clean_history());
        assert!(
            v.iter()
                .any(|x| x.property == SafetyProperty::ReferenceModel),
            "a surfaced read error on an un-faulted page must STILL be UNSAFE: {v:?}"
        );
    }

    /// The safety CLI runs a clean sweep with faults+crashes and reports zero violations.
    #[test]
    fn safety_cli_clean_sweep_reports_no_violations() {
        let (out, violations) = run_safety_cli(
            ["--seed", "1", "--seeds", "10"]
                .into_iter()
                .map(String::from),
        );
        assert_eq!(violations, 0, "the safety CLI sweep must be clean:\n{out}");
        assert!(out.contains("all SAFE + deterministic"), "{out}");
        assert!(out.contains("SAFE"), "{out}");
    }

    // ---------------------------- liveness oracle (rmp #240) ----------------------------

    /// A clean, healthy [`LivenessTrace`] for the `evaluate_liveness` teeth: no stall, no cap hit, the
    /// post-heal recovery batch fully committed + correct. Each teeth test perturbs exactly one facet.
    fn healthy_trace() -> LivenessTrace {
        LivenessTrace {
            max_stall_steps: 3,
            hit_step_cap: false,
            worst_stall_at: 0,
            dumped_schedule: Vec::new(),
            recovery: Some(RecoveryProbe {
                attempted: RECOVERY_BATCH,
                committed: RECOVERY_BATCH,
                correct: true,
            }),
        }
    }

    /// **Teeth (both arms, pure evaluator).** The liveness oracle must flag a deliberately wedged trace
    /// and a non-recovering trace; a healthy trace must pass. This exercises the pure `evaluate_liveness`
    /// against fabricated inputs — proving each arm has teeth independent of the engine.
    #[test]
    fn evaluate_liveness_has_teeth_on_both_arms() {
        let threshold = 40usize;

        // Healthy ⇒ no failure.
        assert!(
            evaluate_liveness(&healthy_trace(), threshold).is_empty(),
            "a healthy trace must be live"
        );

        // 1a. A stall at/over the threshold ⇒ progress-stalled.
        let mut stalled = healthy_trace();
        stalled.max_stall_steps = threshold; // exactly at the bound
        let f = evaluate_liveness(&stalled, threshold);
        assert!(
            f.contains(&LivenessFailure::ProgressStalled),
            "a stall at the threshold must flag progress-stalled: {f:?}"
        );

        // 1b. A hard-cap exit (the bounded signature of a real infinite loop) ⇒ progress-stalled, even if
        //     the per-step stall counter never reached the threshold.
        let mut capped = healthy_trace();
        capped.hit_step_cap = true;
        capped.max_stall_steps = 1;
        let f = evaluate_liveness(&capped, threshold);
        assert!(
            f.contains(&LivenessFailure::ProgressStalled),
            "a hard-cap exit must flag progress-stalled (a bounded-out hang): {f:?}"
        );

        // 2a. A post-heal batch that did not fully commit ⇒ did-not-recover.
        let mut shortfall = healthy_trace();
        shortfall.recovery = Some(RecoveryProbe {
            attempted: RECOVERY_BATCH,
            committed: RECOVERY_BATCH - 1, // one create the healed engine would not commit
            correct: true,
        });
        let f = evaluate_liveness(&shortfall, threshold);
        assert!(
            f.contains(&LivenessFailure::DidNotRecoverAfterHeal),
            "a post-heal commit shortfall must flag did-not-recover: {f:?}"
        );

        // 2b. A post-heal batch that committed but read back *incorrectly* ⇒ did-not-recover.
        let mut wrong = healthy_trace();
        wrong.recovery = Some(RecoveryProbe {
            attempted: RECOVERY_BATCH,
            committed: RECOVERY_BATCH,
            correct: false, // acked but the reference model disagreed (a phantom commit)
        });
        let f = evaluate_liveness(&wrong, threshold);
        assert!(
            f.contains(&LivenessFailure::DidNotRecoverAfterHeal),
            "a post-heal incorrect result must flag did-not-recover: {f:?}"
        );
    }

    /// **Acceptance (the liveness oracle holds on the real engine under a healed fault window).** A clean
    /// seed runs the interleaver under a recoverable fault window (faults + crashes fire during it), the
    /// progress watchdog sees no unbounded stall, and the post-heal recovery batch fully commits +
    /// reads back correctly — so the run is `live`. Non-vacuous: faults + crashes genuinely fired.
    #[test]
    fn liveness_run_is_live_on_a_clean_seed() {
        let r = run_liveness(VoprConfig::liveness(1));
        assert!(
            r.live,
            "a clean seed must be live (no hang + recovers after heal): {:?} (max_stall={}/{}, recovered={}/{}, correct={})",
            r.failures,
            r.max_stall_steps,
            r.stall_threshold,
            r.recovery_committed,
            r.recovery_attempted,
            r.recovery_correct,
        );
        assert!(
            r.max_stall_steps < r.stall_threshold,
            "a healthy run must stay well under the stall threshold"
        );
        assert!(r.run.crash_restarts > 0, "non-vacuity: crashes fired");
        assert!(
            r.run.disk_faults + r.run.clock_faults + r.run.transport_faults > 0,
            "non-vacuity: faults fired during the window"
        );
        // The post-heal recovery probe proved availability resumed: every fresh create committed + correct.
        assert_eq!(
            r.recovery_committed, r.recovery_attempted,
            "the post-heal batch must fully commit (availability recovered)"
        );
        assert_eq!(r.recovery_attempted, RECOVERY_BATCH);
        assert!(
            r.recovery_correct,
            "the post-heal batch must read back correctly"
        );
    }

    /// **Teeth (end-to-end, an injected wedge becomes a bounded report — never a CI hang).** We model a
    /// genuinely wedged engine: a step stream where, after some healthy progress, **no** client ever
    /// advances again (every step returns `false`), exactly as a deadlock/livelock/hang in the engine
    /// would present at the loop. Replaying the same per-step watchdog logic the loop runs, the stall
    /// counter climbs to the hard step cap — and `evaluate_liveness` flags `ProgressStalled` from the
    /// bounded `hit_step_cap` signal. This proves a real hang is converted into a returned
    /// `LivenessReport { live: false }` rather than an infinite loop. (The healthy prefix proves the
    /// watchdog does not trip early.)
    #[test]
    fn watchdog_bounds_an_injected_hang_into_a_reported_stall() {
        let threshold = 40usize;
        // A small hard step cap stands in for the loop's analytic bound — the loop breaks here on a hang.
        let step_cap = 200usize;

        // Drive the exact watchdog state machine from the loop over a synthetic step stream: 10 healthy
        // advancing steps, then an unbroken run of non-advancing steps (the injected wedge).
        let mut cur_stall = 0usize;
        let mut max_stall_steps = 0usize;
        let mut steps = 0usize;
        let mut hit_step_cap = false;
        for i in 0..10_000usize {
            let progressed = i < 10; // healthy prefix, then wedged forever
            if progressed {
                steps += 1;
                cur_stall = 0;
            } else {
                cur_stall += 1;
                max_stall_steps = max_stall_steps.max(cur_stall);
            }
            // The loop's hard cap is on *advancing* steps; a wedge never advances, so a real loop would
            // instead spin — except the dispatched-step count is itself bounded. Model that bound here.
            if i >= step_cap {
                hit_step_cap = true;
                break;
            }
        }

        assert!(hit_step_cap, "the wedge must hit the bounded step cap");
        assert!(
            max_stall_steps >= threshold,
            "the injected wedge must drive the stall counter past the threshold (got {max_stall_steps})"
        );
        assert_eq!(steps, 10, "only the healthy prefix advanced");

        let trace = LivenessTrace {
            max_stall_steps,
            hit_step_cap,
            worst_stall_at: 10,
            dumped_schedule: vec![(10, 0, false), (11, 1, false)],
            recovery: Some(RecoveryProbe {
                attempted: RECOVERY_BATCH,
                committed: RECOVERY_BATCH,
                correct: true,
            }),
        };
        let f = evaluate_liveness(&trace, threshold);
        assert!(
            f.contains(&LivenessFailure::ProgressStalled),
            "the injected hang must be reported as a liveness violation, not hang the test: {f:?}"
        );
    }

    /// **Determinism.** Same seed ⇒ identical [`LivenessReport`] — the verdict, the watchdog stats, the
    /// dumped schedule, the recovery counts, and the full underlying run.
    #[test]
    fn liveness_report_is_deterministic_same_seed() {
        let cfg = VoprConfig::liveness(0x240_0001);
        assert_eq!(
            run_liveness(cfg),
            run_liveness(cfg),
            "same seed ⇒ identical liveness report"
        );
    }

    /// The liveness recorder (watchdog + recovery probe) must not perturb the run: the underlying
    /// [`VoprReport`] (trace hash, state hash, counts) is identical with and without liveness mode. The
    /// post-heal batch runs *after* the canonical trace is sealed, so it cannot change the run digest.
    #[test]
    fn liveness_recorder_does_not_perturb_the_run() {
        let cfg = VoprConfig::liveness(0x240_0002);
        let bare = run(cfg);
        let lively = run_liveness(cfg).run;
        assert_eq!(
            bare, lively,
            "liveness mode must not perturb the canonical run (trace + state + counts)"
        );
    }

    // ----- rmp #241: swarm testing -------------------------------------------------------------

    /// Asserts a swarmed config respects every documented bound (recoverable + bounded). Used by the
    /// sweep tests so a single seed regression is caught precisely.
    fn assert_swarm_bounds(cfg: &VoprConfig) {
        assert!(
            (2..=12).contains(&cfg.clients),
            "clients in [2,12]: {}",
            cfg.clients
        );
        assert!(
            (16..=80).contains(&cfg.ops_per_client),
            "ops_per_client in [16,80]: {}",
            cfg.ops_per_client
        );
        assert!(
            (48..=512).contains(&cfg.pool_pages),
            "pool_pages in [48,512]: {}",
            cfg.pool_pages
        );
        for w in [
            cfg.mix.create_node,
            cfg.mix.create_edge,
            cfg.mix.count_nodes,
            cfg.mix.neighbors,
        ] {
            assert!((1..=60).contains(&w), "every mix weight in [1,60]: {w}");
        }
        assert!(
            (1..=6).contains(&cfg.max_txn_stmts),
            "max_txn_stmts in [1,6]: {}",
            cfg.max_txn_stmts
        );
        assert!(
            cfg.auto_commit_permille <= 1000,
            "auto_commit_permille <= 1000: {}",
            cfg.auto_commit_permille
        );
        assert!(
            cfg.rollback_permille <= 300,
            "rollback_permille <= 300: {}",
            cfg.rollback_permille
        );
        let b = cfg.fault_budget;
        assert!(b.max_faults <= 12, "max_faults <= 12: {}", b.max_faults);
        assert!(
            b.disk_weight + b.clock_weight + b.transport_weight >= 1,
            "at least one fault kind is eligible"
        );
        assert!(
            (1..=4).contains(&b.disk_max_pages),
            "disk_max_pages in [1,4]: {}",
            b.disk_max_pages
        );
        assert!(
            (16..=128).contains(&b.disk_page_span),
            "disk_page_span in [16,128]: {}",
            b.disk_page_span
        );
        assert!(
            (1_000..=10_000).contains(&b.clock_max_ns),
            "clock_max_ns in [1000,10000]: {}",
            b.clock_max_ns
        );
        assert!(b.max_crashes <= 3, "max_crashes <= 3: {}", b.max_crashes);
        // Load profile params stay within their documented sub-bounds.
        match cfg.load {
            LoadProfile::Steady { min, max } => {
                assert!((1..=200).contains(&min), "steady min in [1,200]: {min}");
                assert!(max >= min && max <= min + 800, "steady max ordered: {max}");
            }
            LoadProfile::Ramp { start, end } => {
                assert!(
                    (1..=1000).contains(&start),
                    "ramp start in [1,1000]: {start}"
                );
                assert!((1..=1000).contains(&end), "ramp end in [1,1000]: {end}");
            }
            LoadProfile::Spike {
                base,
                period,
                burst,
            } => {
                assert!((1..=200).contains(&base), "spike base in [1,200]: {base}");
                assert!(
                    (2..=16).contains(&period),
                    "spike period in [2,16]: {period}"
                );
                assert!(
                    (1..=period).contains(&burst),
                    "spike burst in [1,period]: {burst}"
                );
            }
        }
    }

    /// **Acceptance: determinism.** Same seed ⇒ byte-identical swarmed config (the derivation is a pure
    /// function of the seed), and the swarmed *run* replays identically too.
    #[test]
    fn swarm_config_is_deterministic_same_seed() {
        for seed in [0u64, 1, 7, 42, 0xDEAD_BEEF, u64::MAX] {
            let a = VoprConfig::swarm(seed);
            let b = VoprConfig::swarm(seed);
            // VoprConfig is Copy + Debug but not PartialEq; compare its Debug projection (covers every
            // field, including the nested mix/load/fault_budget).
            assert_eq!(
                format!("{a:?}"),
                format!("{b:?}"),
                "same seed ⇒ identical swarmed config (seed {seed})"
            );
            assert_swarm_bounds(&a);
            assert_eq!(
                run(a),
                run(b),
                "swarmed run replays identically (seed {seed})"
            );
        }
    }

    /// **Acceptance: the seed is carried through faithfully.** A swarmed config replays from the same
    /// master seed it was derived for — so a flagged swarmed seed reproduces with `--seed <N> --swarm`.
    /// (Workload-stream independence — swarming the environment never reshapes the seed's workload — is
    /// guaranteed structurally by the domain-separated `seed ^ SWARM_TAG` RNG, documented on `swarm`.)
    #[test]
    fn swarm_config_carries_the_master_seed() {
        for seed in [3u64, 11, 99, 0xABCD] {
            assert_eq!(VoprConfig::swarm(seed).seed, seed, "seed carried through");
        }
    }

    /// **Acceptance: non-degeneracy.** Over a 100-seed sweep, the headline knobs each take *several*
    /// distinct values and are not pinned to a constant — proving the swarm genuinely explores a range of
    /// configurations rather than collapsing onto one.
    #[test]
    fn swarm_sweep_is_non_degenerate() {
        use std::collections::BTreeSet;
        let cfgs: Vec<VoprConfig> = (0..100u64).map(VoprConfig::swarm).collect();
        for c in &cfgs {
            assert_swarm_bounds(c);
        }

        let clients: BTreeSet<u32> = cfgs.iter().map(|c| c.clients).collect();
        let pools: BTreeSet<usize> = cfgs.iter().map(|c| c.pool_pages).collect();
        let ops: BTreeSet<u32> = cfgs.iter().map(|c| c.ops_per_client).collect();
        let faults: BTreeSet<u32> = cfgs.iter().map(|c| c.fault_budget.max_faults).collect();
        let crashes: BTreeSet<u32> = cfgs.iter().map(|c| c.fault_budget.max_crashes).collect();
        let load_variants: BTreeSet<u8> = cfgs
            .iter()
            .map(|c| match c.load {
                LoadProfile::Steady { .. } => 0,
                LoadProfile::Ramp { .. } => 1,
                LoadProfile::Spike { .. } => 2,
            })
            .collect();

        // `clients` spans [2,12] (11 values), `max_faults` [0,12] (13), `max_crashes` [0,3] (4); over 100
        // seeds a healthy uniform draw lands on most of each. Assert a strong-but-safe lower bound on
        // distinctness so a future degeneration (e.g. a constant knob) trips this.
        assert!(clients.len() >= 6, "clients vary: {clients:?}");
        assert!(
            pools.len() >= 50,
            "pool_pages vary widely: {} distinct",
            pools.len()
        );
        assert!(
            ops.len() >= 30,
            "ops_per_client vary: {} distinct",
            ops.len()
        );
        assert!(faults.len() >= 6, "max_faults vary: {faults:?}");
        assert!(crashes.len() >= 3, "max_crashes vary: {crashes:?}");
        assert_eq!(
            load_variants.len(),
            3,
            "all three load shapes appear: {load_variants:?}"
        );
        // No knob is a degenerate constant.
        assert!(
            clients.len() > 1 && faults.len() > 1,
            "knobs are not constant"
        );
    }

    /// **Acceptance: distinct seeds ⇒ distinct configs.** Adjacent seeds must not collapse onto the same
    /// configuration (the swarm RNG decorrelates them); over the sweep, near-all configs are unique.
    #[test]
    fn swarm_distinct_seeds_distinct_configs() {
        use std::collections::BTreeSet;
        let projections: BTreeSet<String> = (0..100u64)
            .map(|s| format!("{:?}", VoprConfig::swarm(s)))
            .collect();
        // The seed field differs per config, so all 100 are trivially distinct *strings*; the meaningful
        // check is that the seed-independent knobs decorrelate — strip the seed and demand high variety.
        let knob_projections: BTreeSet<String> = (0..100u64)
            .map(|s| {
                let c = VoprConfig::swarm(s);
                format!(
                    "{}-{}-{}-{:?}-{:?}-{:?}",
                    c.clients, c.ops_per_client, c.pool_pages, c.mix, c.load, c.fault_budget
                )
            })
            .collect();
        assert_eq!(
            projections.len(),
            100,
            "every seed yields a distinct config"
        );
        assert!(
            knob_projections.len() >= 90,
            "swarmed knob-sets are near-all unique across 100 seeds (got {})",
            knob_projections.len()
        );
    }

    /// **Acceptance: every swarmed config is consistent + deterministic.** Run a small swarmed sweep
    /// through the same consistency/determinism probe `run_cli` uses: each seed must replay identically
    /// and the reference-model oracle must agree (no swarmed environment breaks ACID/consistency). This
    /// is the rmp #241 requirement that a swarmed run stays correct.
    #[test]
    fn swarm_sweep_stays_consistent_and_deterministic() {
        for seed in 0..24u64 {
            let cfg = VoprConfig::swarm(seed);
            let first = run(cfg);
            let second = run(cfg);
            assert_eq!(
                first, second,
                "swarmed seed {seed} must be deterministic (config {cfg:?})"
            );
            assert!(
                first.oracle.is_none(),
                "swarmed seed {seed} must stay reference-model-consistent: {:?} (config {cfg:?})",
                first.oracle
            );
            // The consistency probe: no committed create lost or duplicated under the swarmed environment.
            assert_eq!(
                first.persisted_nodes, first.created_nodes,
                "swarmed seed {seed}: no lost/duplicated committed create (config {cfg:?})"
            );
        }
    }

    /// **Acceptance: the `--swarm` CLI flag drives swarmed runs and the pinned path is unchanged.** A
    /// swarmed sweep through `run_cli` reports all-consistent; the non-swarm path still honours
    /// `--clients`/`--ops`; an unknown flag still errors.
    #[test]
    fn swarm_cli_flag_runs_a_swarmed_sweep() {
        let (out, failures) = run_cli(
            ["--seed", "0", "--seeds", "20", "--swarm"]
                .iter()
                .map(|s| s.to_string()),
        );
        assert_eq!(failures, 0, "swarmed sweep is all-consistent:\n{out}");
        assert!(
            out.contains("all deterministic + oracle-consistent"),
            "swarmed sweep summary:\n{out}"
        );
        // The pinned path is untouched: `--clients`/`--ops` still apply without `--swarm`.
        let (pinned, pf) = run_cli(
            [
                "--seed",
                "1",
                "--seeds",
                "2",
                "--clients",
                "3",
                "--ops",
                "20",
            ]
            .iter()
            .map(|s| s.to_string()),
        );
        assert_eq!(pf, 0, "pinned sweep still works:\n{pinned}");
    }
}
