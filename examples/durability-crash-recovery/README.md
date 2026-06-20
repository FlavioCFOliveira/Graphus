# Durability & crash recovery under load (DST)

This example demonstrates Graphus's two **inviolable durability guarantees** under a concurrent OLTP
workload, a mid-workload crash, and ARIES recovery:

- **Durability** — *every acknowledged commit survives a crash.* If the engine returned `Ok` from a
  `COMMIT`, that transaction's effect is fully present and correct after recovery.
- **Atomicity (committed-or-nothing)** — *no in-flight effect survives a crash.* A transaction still
  open at the crash leaves **no** partial trace after recovery.

Per the project's DST mandate (`CLAUDE.md`: *"any test that can be expressed as a deterministic
scenario MUST be driven through the DST simulator … especially those involving concurrency, faults,
crashes, and recovery"*), this example is **driven entirely by the project's DST (Deterministic
Simulation Testing) simulator** (`crates/graphus-dst`). It **reuses** that battle-tested machinery —
the cooperative transaction interleaver, the crash + ARIES-restart fault, the four-property safety
oracle, and the replay-artifact tooling — rather than reimplementing any of it.

Everything here is **hermetic**: it runs the real storage / WAL / transaction engine **in-process**
under the simulator. No server, no Bolt driver, no Node, no network — so it runs anywhere the
workspace builds and reproduces bit-for-bit from a seed.

This deterministic core is the example's **hermetic proof**. On top of it, the same `run.sh` then runs
a **real-server SIGKILL phase** (`rmp #275`): it boots the actual production `graphus-server` over a
UDS on a real on-disk store, drives a concurrent OLTP workload to build WAL, **hard-kills it
(`SIGKILL`) mid-life**, restarts from the same store, and asserts every committed account + transfer
survived ARIES WAL replay — measuring the **wall-clock recovery time**, the **on-disk WAL footprint**
recovery replayed, and the **peak RSS during replay**. So the example proves the durability contract
**twice**: deterministically in-process (the DST core), and under a real process crash.

## What it demonstrates

| Capability | How it is exercised |
|------------|---------------------|
| **Concurrent OLTP workload** | 6 virtual clients run **overlapping explicit transactions** (a write-heavy create-node / create-edge / property / delete mix, with auto-commit and rollback outcomes), driven by the DST cooperative interleaver — a genuinely concurrent, single-threaded, deterministic schedule. |
| **Shadow LPG reference model** | An independent, committed-only in-memory Label-Property-Graph (`graphus_dst::ShadowGraph`) records **exactly** the acknowledged-committed operations — the ground truth the recovered engine is checked against. |
| **Seeded mid-workload crash** | At a seeded point mid-workload the live engine is dropped (a torn-durable-prefix / `SIGKILL`-equivalent) and **rebuilt from the durable WAL via ARIES** (`crash_restart`), then the workload continues. Each crash is classified into its **acked-vs-in-flight partition** (`CrashSplit`). |
| **ARIES crash recovery** | Redo replays every acknowledged commit from the WAL; undo / no-redo discards every in-flight transaction. |
| **Durability oracle on the recovered engine** | The four ACID-durability properties — **serializability**, **durability**, **atomicity**, **reference-model equivalence** — are asserted on the **recovered** engine, comparing it **cell-by-cell** (node multiset, edge multiset, `count(n)`, per-node neighbours) against the shadow model. |
| **Determinism** | The same seed yields an identical workload, identical crash schedule, and identical recovered state (proven by re-running each seed and comparing). |
| **One-command replay** | A failing run dumps a self-contained `ReplayArtifact` (seed + full config + the expected trace/state hashes) that re-runs to the **identical** failure with a single command. |
| **Real-server SIGKILL durability** | The production `graphus-server` boots over a UDS on a real store; 4 concurrent writers commit a batch of `:Account` nodes + `:TRANSFER` edges (real WAL); the process is **`SIGKILL`-ed mid-life**; it restarts and ARIES replays the WAL. Every committed account + transfer (count, balance sum, and an exact property) is asserted intact, with **no** phantom/in-flight effect — under a real process crash, not a simulated one. |

## How to run

From the repository root:

```bash
examples/durability-crash-recovery/run.sh
```

Reuse pre-built binaries and pick the scale:

```bash
cargo build --release -p graphus-durability-demo -p graphus-dst -p graphus-server -p graphus-cli
GRAPHUS_BIN_DIR=target/release examples/durability-crash-recovery/run.sh   # CI-fast: 30 seeds
DUR_PROFILE=full examples/durability-crash-recovery/run.sh                 # 100 seeds (evidence scale)
DUR_SEEDS=250    examples/durability-crash-recovery/run.sh                 # any seed count
DUR_FOCUS=7      examples/durability-crash-recovery/run.sh                 # which seed's crash partition to detail
DUR_WRITERS=8 DUR_BATCHES=10 examples/durability-crash-recovery/run.sh     # heavier real-server OLTP workload
```

The real-server SIGKILL phase (step 4) additionally needs `graphus-server` + `graphus-cli`; `run.sh`
builds any missing binary on demand. The committed-baseline gate (step 5) runs only at the default
fast/30-seed profile (the profile the baseline was recorded at).

The script is self-contained and doubles as an executable E2E test: it asserts every step and **exits
non-zero the moment any assertion fails**. It runs five steps:

1. **The deterministic durability sweep** (`durability_demo`) — runs the OLTP workload + crash + ARIES
   recovery + four-property oracle for every seed, proves **zero violations** and full determinism,
   and surfaces a focused seed's acked-vs-in-flight crash partition.
2. **A cross-check through the `graphus-dst vopr safety` gate** (the project's PR safety gate) — the
   same scenario, run through the official gate, must agree: all seeds SAFE + deterministic.
3. **The one-command replay round-trip** (`durability_replay`) — captures a reproducer and replays it
   to the **identical** failure byte-for-byte.
4. **The real-server SIGKILL run** (`graphus-server` + `graphus-cli`) — boots the production server
   over a UDS, drives a concurrent OLTP workload, `SIGKILL`s it mid-life, restarts, and asserts every
   committed account + transfer survived, measuring the wall-clock recovery time, the on-disk WAL
   footprint, and the peak replay RSS into a real-server evidence report.
5. **The regression gate vs the committed baseline** (`durability_baseline_cmp`, at the fast/30-seed
   profile) — compares the fresh deterministic report against `baseline.json` and passes only when the
   structural recovery metrics match exactly (see *Baseline & regression gate* below).

> The real-server phase needs only a Unix host (no TLS / Node / network): it uses a UDS-only server
> config bound to your uid, exactly like `examples/social-network-uds`. It is purely additive — a
> metering hiccup is non-fatal, but every **durability assertion** is hard.

### Driving the underlying DST simulator directly

The example is a thin orchestration over `graphus-dst`. The same scenario is reachable directly:

```bash
# the safety sweep (faults + crashes), the project's PR gate — same oracle the example asserts:
cargo run -p graphus-dst --bin graphus-dst -- vopr safety --seed 1 --seeds 100

# reproduce a single seed (a one-line reproducer):
cargo run -p graphus-dst --bin graphus-dst -- vopr safety --seed 7 --seeds 1
```

## The acked-vs-in-flight crash partition (the committed-or-nothing proof)

For each crash the example reports, on the one deterministic timeline, exactly which transactions were
**acked** (committed before the crash → must survive) versus **in-flight** (still open → must not).
For example, the focused seed `7` (defaults):

```
crash #0 @ step  18: acked(durable)=  6  in-flight(discarded)= 2  recovered_state_hash=…
crash #1 @ step  60: acked(durable)= 15  in-flight(discarded)= 3  recovered_state_hash=…
committed-or-nothing: recovered :Person rows=22 == distinct committed ids=22 (HOLDS)
```

The recovered row count equals the distinct committed-id count exactly — every acknowledged create
survived, and no in-flight create persisted. The `recovered_state_hash` is identical on every replay
of the seed, witnessing determinism.

## One-command replay

The real Graphus engine **has no failing seed** — every durability scenario recovers correctly. To
prove the reproducer tooling genuinely round-trips a failure, the example **plants a synthetic
failure** using the DST replay machinery's `FailurePredicate` path (the same mechanism the simulator's
own shrinker tests use to exercise replay without a real engine bug). The planted predicate is a pure
function of the recorded config, so a separate `--replay` invocation reconstructs it and reproduces the
**identical** failure:

```bash
# plant + capture the reproducer (the real run's canonical trace/state hashes are recorded):
cargo run -p graphus-durability-demo --bin durability_replay -- --capture repro.json --seed 7

# replay it — re-runs the recorded config and asserts an IDENTICAL failure byte-for-byte:
cargo run -p graphus-durability-demo --bin durability_replay -- --replay repro.json
# => REPRODUCED (identical) trace_hash=… state_hash=…
```

A genuine failing seed (were one ever found) is captured + replayed the same way through the
simulator's own tool: `cargo run -p graphus-dst --bin graphus-dst -- vopr-repro --replay <file>`.

## The oracle has teeth (mutation tests)

A durability oracle is only as good as its ability to **catch** a regression. The teeth are proven at
two levels:

- **In the simulator** (`crates/graphus-dst`): `evaluate_safety_has_teeth_per_property` (each of the
  four properties is caught when broken), `integrated_oracle_catches_an_injected_divergence`,
  `oracle_catches_an_injected_extra_edge`, `oracle_catches_a_phantom_node`, and
  `serializability_arm_catches_a_fabricated_cycle`.
- **In this example** (`crates/graphus-durability-demo`): `durability_oracle_surfaces_an_injected_violation`
  injects a lost-acked-commit recovery bug into a real run and asserts the example reports it as
  **non-durable** (it would not mask a regression); `planted_replay_detects_a_corrupted_artifact_as_a_mismatch`
  corrupts a recorded hash and asserts the replay catches the byte-identity breach.

Run them with:

```bash
cargo test -p graphus-durability-demo
```

The same deterministic crash/recovery scenario also runs **in the default `cargo test`** as a
hermetic mirror (`crates/graphus-durability-demo/tests/durability_scenario.rs`): a small seed sweep
that asserts the durability oracle on every recovered engine, with **no server, no Node, no network**.
So `cargo test` alone guards the core; the real-server SIGKILL part lives only in `run.sh`.

## Evidence

At run time the example writes **two** standardized, schema-versioned evidence reports to
`examples/durability-crash-recovery/evidence/` (git-ignored):

### `evidence/report.json` + `report.md` — the deterministic DST core

- the **durability verdict** (seeds checked, violations, non-determinism) and the four certified
  properties;
- the **deterministic recovery metrics** (`rmp #274`), as stable workload params:
  `recovery_records_replayed` (acked commits ARIES redo replayed — the in-process analogue of WAL
  redo records), `recovery_inflight_undone` (in-flight transactions undo discarded), and
  `recovery_crashes` (crash + ARIES restarts). These are **byte-stable** for a fixed seed range;
- the **sweep timing** and a deterministic **seed-rate throughput**.

### `evidence/real-server/report.json` + `report.md` — the real-server SIGKILL run

Collected from the **live, recovered `graphus-server` process** via the shared `measure_server`
harness:

- a **`recovery` phase timing** — the wall-clock time from `SIGKILL` to the server re-binding its UDS
  (ARIES WAL replay);
- the **on-disk `storage.wal_bytes` / `store_bytes`** the recovered server holds, plus
  `wal_bytes_before_crash` (the WAL the crash left for recovery to replay);
- the **peak RSS during replay** (`memory.peak_rss_bytes`) and the server's real CPU;
- the **steady-state throughput** of the pre-crash OLTP workload.

#### Reading recovery-time-vs-WAL-size

This is the headline metric, split across the two reports by determinism:

- The **deterministic** side (`report.json`) reports the *recovery work* — `recovery_records_replayed`
  (the redo set) — which is a pure function of the seed range and identical on every host.
- The **real-server** side (`real-server/report.json`) reports the *physical cost of that work* on
  your machine — the `recovery` phase milliseconds against `wal_bytes_before_crash` (and the
  post-crash `storage.wal_bytes`). A note in that report states both numbers explicitly, e.g.
  *"recovery replayed a 246417-byte on-disk WAL in 106 ms wall-clock"*.

So recovery time scales with WAL/redo size: the deterministic redo-record count tells you *how much*
recovery had to do; the real-server timing tells you *how long it took here*.

## Baseline & regression gate

A committed baseline lives at `examples/durability-crash-recovery/baseline.json` (the `evidence/`
directory itself is git-ignored; the baseline is a tracked, fast-profile reference run). The
`run.sh` regression gate (`durability_baseline_cmp`, fast/30-seed profile only) compares a fresh
deterministic `report.json` against it and **passes only when the structural recovery metrics match**.

The threshold choice follows this example's sharp **deterministic-vs-machine-variant split**:

| Metric | Source | Gate |
|--------|--------|------|
| `metadata.dataset.nodes` (recovered `:Person` rows for the focus seed) | DST core | **EXACT** |
| `workload.recovery_records_replayed` (acked commits replayed = WAL redo records) | DST core | **EXACT** |
| `workload.recovery_inflight_undone` (in-flight txns undo discarded) | DST core | **EXACT** |
| `workload.recovery_crashes` (crash + ARIES restarts) | DST core | **EXACT** |
| `workload.seeds` (seed range / profile) | DST core | **EXACT** |
| sweep wall-time / seed-rate throughput | DST core | **ungated** (machine-variant) |
| real-server WAL bytes / recovery time / peak RSS / CPU | real server | **ungated** (machine-variant) |

The structural metrics are gated at **exact equality** because the DST core is a pure function of the
seed range — they are integer-stable across runs and hosts, so a change to any of them means recovery
itself drifted (a lost acked commit, a surviving in-flight effect, a different crash schedule, or a
profile mismatch), which is precisely the regression the example exists to catch. Everything timing-
or host-dependent (the sweep wall-time, the real-server WAL bytes / recovery time / peak RSS) is left
**ungated** so the shared baseline never flakes across developer / CI machines. This is a *sharper*
gate than the sibling examples' footprint band — appropriate to a scenario whose deterministic
quantity is its **recovery work**, not an on-disk footprint.

The regression gate for *this* deterministic core is, ultimately, **determinism itself**: any change
that alters a recovered state, loses an acked commit, lets an in-flight effect survive, or breaks
reproducibility flips a seed's verdict — failing both the run and the baseline gate.
