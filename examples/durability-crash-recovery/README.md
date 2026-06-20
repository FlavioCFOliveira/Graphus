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

> The **sibling real-server run** (`rmp #274`–`#276`) layers a real `graphus-server` process under an
> actual `SIGKILL` on top of this same deterministic scenario, and collects the live CPU / RAM /
> on-disk-storage evidence. This `run.sh` is that demonstration's deterministic core.

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

## How to run

From the repository root:

```bash
examples/durability-crash-recovery/run.sh
```

Reuse pre-built binaries and pick the scale:

```bash
cargo build --release -p graphus-durability-demo -p graphus-dst
GRAPHUS_BIN_DIR=target/release examples/durability-crash-recovery/run.sh   # CI-fast: 30 seeds
DUR_PROFILE=full examples/durability-crash-recovery/run.sh                 # 100 seeds (evidence scale)
DUR_SEEDS=250    examples/durability-crash-recovery/run.sh                 # any seed count
DUR_FOCUS=7      examples/durability-crash-recovery/run.sh                 # which seed's crash partition to detail
```

The script is self-contained and doubles as an executable E2E test: it asserts every step and **exits
non-zero the moment any assertion fails**. It runs three steps:

1. **The deterministic durability sweep** (`durability_demo`) — runs the OLTP workload + crash + ARIES
   recovery + four-property oracle for every seed, proves **zero violations** and full determinism,
   and surfaces a focused seed's acked-vs-in-flight crash partition.
2. **A cross-check through the `graphus-dst vopr safety` gate** (the project's PR safety gate) — the
   same scenario, run through the official gate, must agree: all seeds SAFE + deterministic.
3. **The one-command replay round-trip** (`durability_replay`) — captures a reproducer and replays it
   to the **identical** failure byte-for-byte.

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

## Evidence

At run time the example writes the standardized, schema-versioned evidence to
`examples/durability-crash-recovery/evidence/` (git-ignored). It records:

- the **durability verdict** (seeds checked, violations, non-determinism) and the four certified
  properties;
- the **aggregate crash-recovery figures** — total crash + ARIES restarts, faults injected, acked
  commits proven durable, in-flight transactions discarded by undo, and non-vacuous-run count — as
  report notes;
- the **sweep timing** (the one phase) and a deterministic **seed-rate throughput** (seeds, each a
  full crash-recovery scenario, per second).

Because the engine here runs **in-process** under the simulator (no server process), the report's
server-oriented CPU / RAM / on-disk-storage vectors are exercised by the **sibling real-server run**
(`rmp #274`–`#276`) layered over this same scenario; a note in the report records this honestly.

The regression gate for *this* deterministic core is **determinism itself**: any change that alters a
recovered state, loses an acked commit, lets an in-flight effect survive, or breaks reproducibility
flips a seed's verdict and fails the run.
