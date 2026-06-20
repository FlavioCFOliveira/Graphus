//! Deterministic, seeded **time-series IoT event-stream generator + retention policy** for the
//! `examples/iot-timeseries` demonstration.
//!
//! It models a fleet of IoT **sensors** emitting time-stamped **readings**, and a **sliding-window
//! retention policy** that deletes readings older than a configurable window. The generator emits,
//! per discrete **tick**, the Cypher to INSERT the tick's new readings and DELETE the readings that
//! have aged out of the window — exactly the *delete-old + insert-new churn* the example drives
//! against the real engine to prove the storage engine reaches a steady state (a stable live count)
//! and a **plateaued on-disk footprint** (freed slots reused, not unbounded growth).
//!
//! # The time-series event-graph model
//!
//! A directed Label Property Graph modelling a sensor fleet and its telemetry:
//!
//! | Node label | Key properties | Meaning |
//! | --- | --- | --- |
//! | `(:Sensor {id, kind, site})` | `id` (stable, `s-<n>`) | a physical sensor / device |
//! | `(:Reading {sensor, seq, ts, value})` | `seq` (global monotonic) | one time-stamped sample |
//!
//! One relationship type carries the time-series edge:
//!
//! | Relationship | Direction | Meaning |
//! | --- | --- | --- |
//! | `:EMITTED` | `(:Sensor)->(:Reading)` | the sensor produced this reading |
//!
//! Readings are **nodes** (not relationship-only payloads) so the churn exercises the full record
//! lifecycle the reclamation proof targets: a deleted `Reading` tombstones a **node** record, its
//! property versions, AND its incident `:EMITTED` relationship (a `DETACH DELETE`), so every store
//! kind (node / rel / property / overflow) is recycled under churn.
//!
//! ## Logical time and the global sequence
//!
//! Time is modelled discretely. The generator advances a **global monotonic sequence** `seq`
//! (`0, 1, 2, …`): every reading gets the next `seq`, and its `ts` is `EPOCH_MS + seq * TICK_MS`, so
//! `seq` and `ts` are order-equivalent. The **retention window** is expressed in *number of
//! readings* (`window`): at any tick the policy retains the most-recent `window` readings and aged
//! out everything with `seq < high_water_seq - window`. Because the per-tick insert rate is fixed,
//! a window of `W` readings corresponds to a wall-clock window of `W * TICK_MS` ms — the README
//! documents both framings.
//!
//! # Determinism
//!
//! Generation is a pure function of [`GenConfig`]: the only randomness is an internal
//! [`SplitMix64`] PRNG seeded from `seed` (sensor assignment + reading value jitter). For a given
//! config the emitted per-tick Cypher is **byte-identical** across runs, hosts, and platforms (no
//! floats in the wire text, no `HashMap` iteration, no clock, no thread scheduling). This is
//! asserted by `tests/determinism.rs`.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

/// A tiny, fast, fully-deterministic PRNG (SplitMix64 — Steele, Lea & Flood 2014). Chosen because it
/// is a *pure* integer mixing function: identical output for identical seeds on every platform, with
/// no global state, no float, and no allocation. We never use the standard library's `HashMap`-based
/// randomness or any clock, so the whole generator is reproducible byte-for-byte.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Seeds the generator. Any `u64` seed is valid.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Returns the next pseudo-random `u64`.
    pub fn next_u64(&mut self) -> u64 {
        // SplitMix64 reference constants.
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Returns a value in `[0, n)` (n > 0) with negligible modulo bias for our small ranges.
    pub fn below(&mut self, n: u64) -> u64 {
        debug_assert!(n > 0, "below(0) is undefined");
        self.next_u64() % n
    }
}

/// Epoch (ms) the modelled time-series starts at — a fixed constant so timestamps are reproducible.
/// `2024-01-01T00:00:00Z` in Unix milliseconds.
pub const EPOCH_MS: u64 = 1_704_067_200_000;

/// Milliseconds of modelled time between two consecutive readings (one global `seq` step). Fixed so
/// `ts = EPOCH_MS + seq * TICK_MS` is a pure function of `seq`.
pub const TICK_MS: u64 = 1_000;

/// Configuration for one generation run. A pure value: identical configs yield identical streams.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenConfig {
    /// PRNG seed — the sole source of (reproducible) randomness.
    pub seed: u64,
    /// Number of sensors in the fleet (created once, up front).
    pub sensors: u64,
    /// Readings inserted per tick (the ingest **rate**).
    pub rate: u64,
    /// Retention window, in number of readings: the policy retains the most-recent `window`
    /// readings and deletes everything older. The steady-state live `Reading` count converges to
    /// `window` (± at most one tick's `rate`).
    pub window: u64,
    /// Number of churn ticks to emit.
    pub ticks: u64,
}

impl GenConfig {
    /// The **fast** profile — small, CI-runnable: a few sensors, a short run that still reaches and
    /// holds a steady state long enough for the plateau to be unambiguous (total ingested ≫ window).
    #[must_use]
    pub fn fast() -> Self {
        Self {
            seed: 0xC0FF_EE15_600D_5EED,
            sensors: 8,
            rate: 50,
            window: 200,
            ticks: 60,
        }
    }

    /// The **large** profile — evidence-scale: a bigger sensor fleet and a longer run so the plateau
    /// is demonstrated against a total-ingested that is many times the window (here ~15×, at a window
    /// an order of magnitude larger than the fast profile). Sized to stay tractable for the
    /// single-threaded inline driver — each tick's retention `DETACH DELETE` scans the live window,
    /// so cost grows with `window × ticks`; this profile keeps that within an evidence-run budget
    /// while still exercising a substantially larger steady-state footprint.
    #[must_use]
    pub fn large() -> Self {
        Self {
            seed: 0xC0FF_EE15_600D_5EED,
            sensors: 16,
            rate: 100,
            window: 500,
            ticks: 50,
        }
    }

    /// Resolves a profile name (`"fast"` / `"large"`) to a config; unknown names fall back to
    /// `fast`. The single knob most worth overriding from the CLI — the retention `window` — is left
    /// to the caller to patch after resolving.
    #[must_use]
    pub fn from_profile(name: &str) -> Self {
        match name {
            "large" => Self::large(),
            _ => Self::fast(),
        }
    }

    /// The total number of readings the whole run will ingest (`rate * ticks`). Used by the
    /// reclamation proof to assert the steady-state footprint is bounded *despite* total-ingested ≫
    /// window.
    #[must_use]
    pub fn total_readings(&self) -> u64 {
        self.rate.saturating_mul(self.ticks)
    }
}

/// The Cypher one tick contributes to the churn: an INSERT batch (new readings) and a DELETE batch
/// (the readings that aged out of the window this tick). Either may be empty (the DELETE is empty
/// until the window first fills).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickCypher {
    /// 0-based tick index.
    pub tick: u64,
    /// `CREATE` statements for this tick's new readings (one per reading), each wiring the reading to
    /// its sensor via `:EMITTED`.
    pub inserts: Vec<String>,
    /// A single `DETACH DELETE` statement removing every reading older than the window, or `None`
    /// when nothing has aged out yet.
    pub delete: Option<String>,
    /// `seq` of the first reading inserted this tick (inclusive).
    pub first_seq: u64,
    /// `seq` one past the last reading inserted this tick (exclusive).
    pub next_seq: u64,
    /// The retention cutoff applied this tick: readings with `seq < delete_cutoff` were deleted
    /// (`0` when nothing aged out).
    pub delete_cutoff: u64,
}

/// The deterministic time-series event-stream generator + sliding-window retention policy.
///
/// Construct with [`Generator::new`], then either pull ticks one at a time with [`Generator::tick`]
/// (the workload's streaming path) or materialise the whole run with [`Generator::emit_all`] (the
/// `iot_gen` binary's file output + the determinism test).
#[derive(Debug, Clone)]
pub struct Generator {
    cfg: GenConfig,
    rng: SplitMix64,
    /// The global monotonic reading sequence — the next `seq` to assign.
    seq: u64,
    /// The next tick index to emit.
    tick: u64,
}

impl Generator {
    /// Creates a generator for `cfg`. The sensor fleet is emitted by [`Generator::schema_cypher`];
    /// reading generation starts at `seq = 0`, `tick = 0`.
    #[must_use]
    pub fn new(cfg: GenConfig) -> Self {
        let rng = SplitMix64::new(cfg.seed);
        Self {
            cfg,
            rng,
            seq: 0,
            tick: 0,
        }
    }

    /// The configuration this generator runs.
    #[must_use]
    pub fn config(&self) -> &GenConfig {
        &self.cfg
    }

    /// The stable id of sensor `i` (`s-<i>`).
    #[must_use]
    pub fn sensor_id(i: u64) -> String {
        format!("s-{i}")
    }

    /// The one-time index-DDL bootstrap: a range index on `Reading.seq`, the retention key the
    /// aged-out DELETE seeks on (the realistic shape for a TTL sweep). Returned separately from the
    /// sensor fleet because index DDL is a distinct engine command path (`CREATE INDEX` is routed to
    /// the index catalog, not the row executor): a workload driving the bare statement seam runs
    /// [`Generator::sensor_cypher`] only, while a full server run (`stream.cypher`, `graphus-cli`)
    /// executes this DDL first.
    #[must_use]
    pub fn index_ddl(&self) -> Vec<String> {
        vec!["CREATE INDEX reading_seq IF NOT EXISTS FOR (r:Reading) ON (r.seq)".to_owned()]
    }

    /// The one-time sensor-fleet bootstrap: a `CREATE` per sensor. Returned as a `Vec` of statements
    /// so the workload can run each in its own auto-commit transaction.
    ///
    /// The sensors are created *once* and never churned — only readings churn — so the steady state
    /// is purely about reading records being recycled.
    #[must_use]
    pub fn sensor_cypher(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(self.cfg.sensors as usize);
        for i in 0..self.cfg.sensors {
            let kind = match i % 3 {
                0 => "temperature",
                1 => "humidity",
                _ => "pressure",
            };
            let site = i % 4; // four sites
            out.push(format!(
                "CREATE (:Sensor {{id: '{}', kind: '{kind}', site: {site}}})",
                Self::sensor_id(i),
            ));
        }
        out
    }

    /// Produces the next tick's churn Cypher, or `None` once `ticks` ticks have been emitted.
    ///
    /// Each call inserts `rate` new readings (assigning the next `rate` global `seq` values, each to
    /// a deterministically-chosen sensor with a jittered value) and, once the window has filled,
    /// deletes every reading older than the window.
    pub fn tick(&mut self) -> Option<TickCypher> {
        if self.tick >= self.cfg.ticks {
            return None;
        }
        let tick = self.tick;
        let first_seq = self.seq;

        let mut inserts = Vec::with_capacity(self.cfg.rate as usize);
        for _ in 0..self.cfg.rate {
            let seq = self.seq;
            let sensor = self.rng.below(self.cfg.sensors.max(1));
            // A bounded integer "value" (no floats on the wire — keeps the stream byte-identical
            // and the property fixed-width): a slow ramp plus seeded jitter, in [0, 1000).
            let value = (seq + self.rng.below(50)) % 1000;
            let ts = EPOCH_MS + seq * TICK_MS;
            inserts.push(format!(
                "MATCH (s:Sensor {{id: '{}'}}) \
                 CREATE (s)-[:EMITTED]->(:Reading {{sensor: '{}', seq: {seq}, ts: {ts}, value: {value}}})",
                Self::sensor_id(sensor),
                Self::sensor_id(sensor),
            ));
            self.seq += 1;
        }

        // Retention policy: once more than `window` readings have ever been inserted, delete every
        // reading whose seq is older than the window. `DETACH DELETE` removes the reading node AND
        // its incident `:EMITTED` relationship in one go, so node + rel + property records all churn.
        let (delete, delete_cutoff) = if self.seq > self.cfg.window {
            let cutoff = self.seq - self.cfg.window;
            (
                Some(format!(
                    "MATCH (r:Reading) WHERE r.seq < {cutoff} DETACH DELETE r"
                )),
                cutoff,
            )
        } else {
            (None, 0)
        };

        self.tick += 1;
        Some(TickCypher {
            tick,
            inserts,
            delete,
            first_seq,
            next_seq: self.seq,
            delete_cutoff,
        })
    }

    /// Materialises the **entire** run as a single deterministic text artifact: the schema/sensor
    /// bootstrap, then every tick's INSERT + DELETE statements, each terminated by `;`. This is what
    /// the `iot_gen` binary writes to `stream.cypher` and what the determinism test hashes.
    ///
    /// The streaming workload does NOT consume this text (it pulls [`Generator::tick`] live to keep
    /// memory bounded); it exists for didactic inspection + the byte-identical determinism proof.
    #[must_use]
    pub fn emit_all(&self) -> String {
        // Clone so emit_all is non-consuming and repeatable (the determinism test calls it twice).
        let mut g = self.clone();
        let mut out = String::with_capacity(64 * (g.cfg.total_readings() as usize + 16));
        out.push_str("// graphus-iot-gen — deterministic time-series churn stream\n");
        let _ = writeln!(
            out,
            "// seed={} sensors={} rate={} window={} ticks={} total_readings={}",
            g.cfg.seed,
            g.cfg.sensors,
            g.cfg.rate,
            g.cfg.window,
            g.cfg.ticks,
            g.cfg.total_readings(),
        );
        out.push_str("// --- schema (index DDL) + sensor fleet ---\n");
        for stmt in g.index_ddl() {
            out.push_str(&stmt);
            out.push_str(";\n");
        }
        for stmt in g.sensor_cypher() {
            out.push_str(&stmt);
            out.push_str(";\n");
        }
        while let Some(t) = g.tick() {
            let _ = writeln!(
                out,
                "// --- tick {} : insert seq [{}, {}) , delete seq < {} ---",
                t.tick, t.first_seq, t.next_seq, t.delete_cutoff
            );
            for ins in &t.inserts {
                out.push_str(ins);
                out.push_str(";\n");
            }
            if let Some(del) = &t.delete {
                out.push_str(del);
                out.push_str(";\n");
            }
        }
        out
    }

    /// A machine-readable one-line summary of the run's shape (the `iot_gen` binary prints it; the
    /// `run.sh` parses it for the evidence report's dataset sizing).
    #[must_use]
    pub fn summary_line(&self) -> String {
        format!(
            "seed={} sensors={} rate={} window={} ticks={} total_readings={} steady_state_live={}",
            self.cfg.seed,
            self.cfg.sensors,
            self.cfg.rate,
            self.cfg.window,
            self.cfg.ticks,
            self.cfg.total_readings(),
            self.cfg.window,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> GenConfig {
        GenConfig {
            seed: 42,
            sensors: 4,
            rate: 10,
            window: 25,
            ticks: 8,
        }
    }

    #[test]
    fn emit_all_is_byte_identical_per_config() {
        let g = Generator::new(cfg());
        assert_eq!(g.emit_all(), g.emit_all(), "same config => identical text");
        let g2 = Generator::new(cfg());
        assert_eq!(g.emit_all(), g2.emit_all(), "fresh generator, same config");
    }

    #[test]
    fn a_different_seed_changes_the_stream() {
        let mut c2 = cfg();
        c2.seed = 43;
        assert_ne!(
            Generator::new(cfg()).emit_all(),
            Generator::new(c2).emit_all()
        );
    }

    #[test]
    fn seq_is_monotonic_and_dense_across_ticks() {
        let mut g = Generator::new(cfg());
        let mut expected = 0u64;
        while let Some(t) = g.tick() {
            assert_eq!(t.first_seq, expected, "ticks are seq-contiguous");
            assert_eq!(t.next_seq, expected + g.config().rate);
            assert_eq!(t.inserts.len() as u64, g.config().rate);
            expected = t.next_seq;
        }
        assert_eq!(expected, cfg().total_readings());
    }

    #[test]
    fn retention_holds_back_until_the_window_fills_then_slides() {
        let c = cfg(); // rate=10, window=25
        let mut g = Generator::new(c.clone());
        // tick 0: 10 readings inserted, total 10 <= 25 => no delete.
        let t0 = g.tick().unwrap();
        assert!(t0.delete.is_none(), "window not full after one tick");
        // tick 1: total 20 <= 25 => still no delete.
        let t1 = g.tick().unwrap();
        assert!(t1.delete.is_none());
        // tick 2: total 30 > 25 => delete seq < 30 - 25 = 5.
        let t2 = g.tick().unwrap();
        assert_eq!(t2.delete_cutoff, 5);
        assert!(t2.delete.as_ref().unwrap().contains("r.seq < 5"));
        // tick 3: total 40 > 25 => delete seq < 15.
        let t3 = g.tick().unwrap();
        assert_eq!(t3.delete_cutoff, 15);
    }

    #[test]
    fn steady_state_live_count_equals_window_band() {
        // The number of live readings after applying tick t's insert+delete is
        // next_seq - delete_cutoff, which must stay within [window, window + rate) once the window
        // has filled — the steady-state invariant the workload asserts against the real engine.
        let c = cfg();
        let mut g = Generator::new(c.clone());
        while let Some(t) = g.tick() {
            if t.delete.is_some() {
                let live = t.next_seq - t.delete_cutoff;
                assert!(
                    live >= c.window && live < c.window + c.rate,
                    "live={live} outside [{}, {})",
                    c.window,
                    c.window + c.rate
                );
            }
        }
    }

    #[test]
    fn schema_emits_index_ddl_plus_one_node_per_sensor() {
        let g = Generator::new(cfg());
        let ddl = g.index_ddl();
        assert_eq!(ddl.len(), 1);
        assert!(ddl[0].contains("CREATE INDEX"));
        let sensors = g.sensor_cypher();
        assert_eq!(sensors.len(), cfg().sensors as usize);
        assert!(sensors[0].contains("s-0"));
    }
}
