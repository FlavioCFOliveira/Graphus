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

use crate::mix::{LoadProfile, MixProfile, WorkloadGen};
use crate::vopr_fault::{FaultBudget, FaultScheduler};

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
#[derive(Debug, Clone, Copy)]
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

    /// The same run forced into **pure auto-commit mode**: every operation is its own one-statement
    /// transaction (the legacy per-op behaviour, with no explicit-transaction overlap). Use this for
    /// scenarios that certify clean per-op liveness rather than the interleaver's contention path.
    #[must_use]
    pub fn auto_commit_only(mut self) -> Self {
        self.auto_commit_permille = 1000;
        self
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
        );

        // Observe overlap *after* this step settled: how many clients hold an open transaction now.
        let open_now = states.iter().filter(|s| s.is_open()).count();
        max_open_txns = max_open_txns.max(open_now);

        if progressed {
            steps += 1;
        }
        dispatched = dispatched.saturating_add(1);

        // Belt-and-braces termination guard: the analytic bound above already makes the queue drain,
        // but if anything ever regresses we stop rather than spin.
        if steps > step_cap {
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
    // Consistency probe: `persisted_nodes` is the number of `:Person` rows present, `created_nodes`
    // the number of distinct ids among them. They must be equal — no committed create lost, none
    // duplicated — even though contention aborted some transactions along the way.
    let (persisted_nodes, created_nodes) = person_stats(&mut eng);
    let end_time = sched.now();
    // Best-effort: harden + consume the engine (it is dropped either way).
    let _ = eng.shutdown();

    let (disk_faults, clock_faults, transport_faults) = faults.tally();

    VoprReport {
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
    }
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
                        let outcome = run_in(eng, ticket, stmt, params);
                        budget[client] = budget[client].saturating_sub(1);
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
                        // idle so the client can retry / terminate.
                        *err_ops += 1;
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
                // Defensive: a `Stmt` should only arrive on an open transaction. Skip gracefully.
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
                (b"ROLLBACK".as_slice(), ok)
            } else {
                match eng.commit(ticket) {
                    Ok(_) => {
                        *committed_txns += 1;
                        (b"COMMIT".as_slice(), true)
                    }
                    Err(_) => {
                        // A failed COMMIT is an SSI serialization conflict the contention exposed —
                        // exactly the outcome the interleaver is meant to reach. The engine still
                        // upholds ACID (the conflicting transaction is aborted, not half-applied).
                        *aborted_txns += 1;
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
/// (the simulator's core invariant), counted and listed for one-line reproduction. This gives the
/// CLI teeth even before the oracles of later sprints land.
///
/// Flags: `--seed <base>` (default 1), `--seeds <count>` (default 1), `--clients <n>`,
/// `--ops <n>`. Unknown flags are reported as an error string in the summary.
#[must_use]
pub fn run_cli<I: IntoIterator<Item = String>>(args: I) -> (String, u32) {
    let mut base_seed: u64 = 1;
    let mut count: u64 = 1;
    let mut clients: u32 = 4;
    let mut ops: u32 = 50;

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
    for seed in base_seed..base_seed.saturating_add(count) {
        // Inherit the interleaver defaults (`max_txn_stmts`, auto-commit / rollback ratios) and
        // override only the CLI-exposed knobs.
        let cfg = VoprConfig {
            clients,
            ops_per_client: ops,
            ..VoprConfig::for_seed(seed)
        };
        let first = run(cfg);
        let second = run(cfg);
        out.push_str(&summarize(&first));
        if first != second {
            failures += 1;
            failed_seeds.push(seed);
        }
    }
    if failures == 0 {
        out.push_str(&format!(
            "vopr: {count} seed(s) checked, all deterministic\n"
        ));
    } else {
        out.push_str(&format!(
            "vopr: {failures} NON-DETERMINISTIC seed(s): {failed_seeds:?} — reproduce with --seed <N> --seeds 1\n"
        ));
    }
    (out, failures)
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
    }
}
