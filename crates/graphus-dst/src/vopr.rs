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

use std::sync::Arc;

use graphus_core::Value;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{LocalEngine, RunReply};
use graphus_sim::{SharedClock, SimScheduler};
use graphus_wal::MemLogSink;

use crate::mix::{MixProfile, WorkloadGen, WorkloadOp};

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
        }
    }

    /// The same run with a specific workload `mix`.
    #[must_use]
    pub fn with_mix(mut self, mix: MixProfile) -> Self {
        self.mix = mix;
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
}

/// One scheduled unit of work: a client issuing its next operation.
#[derive(Debug, Clone, Copy)]
struct Tick {
    client: u32,
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
    let mut eng: SimEngine = LocalEngine::in_memory(Arc::new(clock.clone()), cfg.pool_pages)
        .expect("build simulated in-memory engine");

    // One scheduler owns the master seed; every random choice is drawn from it.
    let mut sched: SimScheduler<Tick> = SimScheduler::new(cfg.seed);
    for _ in 0..cfg.ops_per_client {
        for client in 0..cfg.clients {
            // A seed-drawn delay interleaves clients; ties at the same tick are RNG-ordered too.
            let delay = sched.rng().range_inclusive(1, 1000);
            sched.schedule_after(delay, Tick { client });
        }
    }

    let mut trace = Fnv::new();
    let mut wgen = WorkloadGen::new(cfg.mix);
    let mut steps = 0usize;
    let mut ok_ops = 0usize;
    let mut err_ops = 0usize;

    while let Some((now, tick)) = sched.next() {
        // Keep the engine's clock in lockstep with logical simulation time.
        clock.set(now);

        let op = wgen.next(sched.rng());
        let outcome = exec_op(&mut eng, op);

        // Fold this step into the canonical trace (dispatch order, client, op, outcome).
        trace.u64(steps as u64);
        trace.u64(u64::from(tick.client));
        trace.bytes(op.label().as_bytes());
        outcome.fold_into(&mut trace);

        if outcome.ok {
            ok_ops += 1;
        } else {
            err_ops += 1;
        }
        steps += 1;
    }

    let state_hash = snapshot_hash(&mut eng);
    let end_time = sched.now();
    // Best-effort: harden + consume the engine (it is dropped either way).
    let _ = eng.shutdown();

    VoprReport {
        seed: cfg.seed,
        steps,
        ok_ops,
        err_ops,
        trace_hash: trace.finish(),
        state_hash,
        end_time,
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
            "--clients" => next_u64("--clients").map(|v| clients = v.min(u64::from(u32::MAX)) as u32),
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
        let cfg = VoprConfig {
            seed,
            clients,
            ops_per_client: ops,
            pool_pages: 256,
            mix: MixProfile::mixed(),
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

/// Executes one workload operation through the real engine in its own auto-commit transaction. The
/// statement + parameters come from [`WorkloadOp::to_cypher`], shared with the Bolt/REST drivers.
fn exec_op(eng: &mut SimEngine, op: WorkloadOp) -> Outcome {
    let mode = if op.is_write() {
        AccessMode::Write
    } else {
        AccessMode::Read
    };
    let (stmt, params) = op.to_cypher();
    run_stmt(eng, mode, stmt, params)
}

/// Runs one statement to completion in a fresh auto-commit transaction, draining its rows.
fn run_stmt(
    eng: &mut SimEngine,
    mode: AccessMode,
    stmt: &str,
    params: Vec<(String, Value)>,
) -> Outcome {
    let ticket = match eng.begin_auto_commit(mode) {
        Ok(t) => t,
        Err(e) => return Outcome { ok: false, rows: 0, cells: Vec::new(), error: Some(e.to_string()) },
    };
    match eng.run(ticket, stmt, params, true, None) {
        Ok(mut reply) => drain(&mut reply),
        Err(e) => Outcome { ok: false, rows: 0, cells: Vec::new(), error: Some(e.to_string()) },
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
                return Outcome { ok: false, rows, cells, error: Some(e.to_string()) };
            }
        }
    }
    Outcome { ok: true, rows, cells, error: None }
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
        assert_eq!(a, b, "same seed ⇒ identical VOPR report (trace + state + counts)");
        // The run is non-trivial: it dispatched every scheduled op and actually mutated the graph.
        assert_eq!(a.steps, (cfg.clients * cfg.ops_per_client) as usize);
        assert!(a.ok_ops > 0, "the workload performs real work");
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

    #[test]
    fn summary_is_stable_and_reproducible() {
        let r = run(VoprConfig::for_seed(7));
        let s1 = summarize(&r);
        let s2 = summarize(&run(VoprConfig::for_seed(7)));
        assert_eq!(s1, s2, "the summary line replays identically from the seed");
        assert!(s1.contains("trace_hash="));
    }
}
