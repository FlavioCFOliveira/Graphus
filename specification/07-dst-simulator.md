# 07 — External Deterministic Simulator (VOPR)

This chapter specifies the **external deterministic simulator** for Graphus: a TigerBeetle-VOPR-style
tool that drives the **real** server interfaces and engine under **seeded, fully reproducible**
workloads, faults, and adversarial clients, and certifies behaviour with a set of oracles. It
realizes decision `D-dst-investment` at the *connectivity/protocol* layer (the pre-existing
`graphus-dst` storage harness realizes it at the storage layer).

It is implemented across `graphus-dst` (the simulator + scenarios + oracles wiring), `graphus-sim`
(the deterministic substrate), `graphus-elle` (the isolation checker), and small public seams added to
`graphus-server`/`graphus-bolt`/`graphus-rest`.

## 1. Determinism model — "external" over a simulated transport

The owner ratified **total determinism** (TigerBeetle's principle): a run is a pure function of its
seed. That is reconciled with "connect by every method" as follows:

> **External** means the simulator speaks the **real wire protocols with no backdoor** — the genuine
> Bolt state machine + PackStream codec and the genuine REST request core — but over an **in-memory,
> simulated transport**, against the **real engine** built on a **simulated disk + clock**. It does
> **not** mean real OS sockets, which would reintroduce non-determinism.

Everything random is drawn from one seeded PRNG (`graphus_sim::SimRng`); everything timed advances one
logical clock (`graphus_sim::SharedClock`, set from the scheduler). There is no wall clock and no
thread scheduling in the driven path.

## 2. Architecture

| Component | Crate | Role |
| --- | --- | --- |
| `LocalEngine` | `graphus-server` (`engine::local`) | Drives the **real** `TxnCoordinator`/storage/WAL **inline, single-threaded**, reusing the production command-dispatch path verbatim. Unbounded result egress so a single thread cannot deadlock. Time flows through an injected `Clock`. |
| `SimScheduler<P>` | `graphus-sim` | Deterministic discrete-event scheduler: one logical clock + one `SimRng`; events ordered by `(due, rng-priority, seq)`. |
| `SimNet` / `SimEndpoint` | `graphus-sim` | Deterministic in-memory network; endpoints implement `graphus_bolt::Transport`. Reliable, ordered, delayable, breakable (latency / partition / reset / close). Byte reorder/drop/dup are deliberately **not** modelled (a reliable TCP stream does not exhibit them). |
| `SharedClock` | `graphus-sim` | Atomic clock the simulator sets from scheduler time; read by the engine — logical time in lockstep. |
| VOPR core | `graphus-dst` (`vopr`) | Builds the world, runs the seed-driven loop, records a canonical FNV-1a event trace + state snapshot. CLI: `graphus-dst vopr --seed B --seeds K`. |

## 3. Connection methods (all three, real protocols)

- **Bolt over UDS** and **Bolt over TCP** share one Bolt state machine; only the transport differs, so
  the simulator's `SimNet`-backed `BoltSession` covers both. `dst::wire::run_scripted_bolt_session`
  drives a real handshake + `RUN`/`PULL`/`BEGIN`/`COMMIT`/… via a `LocalBoltExecutor`
  (`graphus_bolt::BoltExecutor` over `LocalEngine`). Result cells are mapped with the **same**
  `graphus_server::engine::bolt_values` mapping the production seam uses (byte-identical PackStream).
- **REST** is driven through the **real** request core: `graphus_rest::router::execute_autocommit`
  runs `run_statements_buffered` (statement binding, tx lifecycle, wire serialization, RFC 9457
  errors) over a `SimRestEngine` (`graphus_rest::RestEngine` over `LocalEngine`), bypassing only the
  generic axum/hyper socket layer. This required relaxing `RestEngine`'s `Send + Sync` supertrait onto
  the `router` function so a single-threaded (`!Send`) engine can implement it.

Because `BoltSession::run` is a blocking loop, clients are **byte-scripted** (a fixed request stream),
which is also the natural shape for misbehaved clients.

## 4. Workloads

`dst::mix` is the single workload source: `WorkloadOp` (`to_cypher` runs the same op over direct
engine / Bolt / REST), `MixProfile` presets (`write_heavy` / `read_heavy` / `oltp_light` / `mixed`),
and `LoadProfile` arrival shapes (`steady` / `ramp` / `spike`). All seed-reproducible.

## 5. Adversarial and environment coverage

- **Misbehaved clients** (`dst::misbehave`, via `wire::drive_raw_bolt`): garbage after handshake,
  truncated/oversized chunk headers, `RUN` before `LOGON`, bad credentials, unsupported version. The
  real Bolt stack must never panic/hang and must return the correct protocol error or close cleanly.
- **Environment faults** (`dst::faults`): network partition/reset/delay; and **crash + restart**
  (`LocalEngine::crash_restart` rebuilds from the durable WAL via ARIES recovery).
- **Load/stress** (`vopr` + `LoadProfile`): high-concurrency runs with liveness (monotone progress, no
  hang) and consistency (`created == persisted`) checks.

## 6. Oracles

1. **Reference model / consistency** — `created == persisted` node counts; canonical state hash.
2. **Isolation / serializability** — `graphus-elle`: an Elle/Adya dependency-graph checker over the
   list-append model (`ww`/`wr`/`rw` edges, cycle detection). `dst::isolation` drives interleaved
   real transactions and feeds the recovered history to it.
3. **Invariants / liveness** — no panic/hang under misbehaved and stress workloads; correct error
   taxonomy.
4. **Durability under crash/restart** — acked commits survive `crash_restart`; uncommitted work does
   not.

## 7. Scenario catalogue

`dst::scenarios` is a named catalogue of known graph-DB usage patterns. Each scenario is a pure
`fn(seed) -> ScenarioOutcome` that drives the **real** engine (inline, deterministic) and checks an
oracle appropriate to it. The workload scenarios reuse the `vopr` runner + `dst::mix`; the structural
ones drive a `LocalEngine` directly. `run_sweep(seeds)` runs every scenario across a seed range and is
the CI-friendly entry point. The in-crate battery is deliberately sized to stay fast in a debug build;
raw scale is delegated to the `vopr` CLI seed-sweep.

The catalogue holds **18 scenarios**, grouped by the production-readiness dimensions a graph database
must satisfy under extreme concurrency and load. Each entry below names the scenario, the production
concern it certifies, and its oracle.

### OLTP / ingest / serving

- `oltp_mixed` — a balanced read/write mix runs cleanly. *Oracle:* `created == persisted`, the run
  replays identically (determinism), and no spurious errors occur.
- `bulk_ingest` — a write-heavy ingest workload. *Oracle:* every acked create persists
  (`created == persisted`, no errors).
- `read_serving` — a read-heavy serving workload. *Oracle:* the run is deterministic and produces no
  spurious errors.

### Traversal / structural

- `deep_traversal` — a variable-length chain is traversed end to end. *Oracle:* the variable-length
  traversal reaches the tail.
- `supernode_fanout` — one hub with a large sequential fan-out. *Oracle:* counting the hub's out-edges
  returns exactly the fan-out.
- `large_result_stream` — a single query streams 200 rows. *Oracle:* exactly 200 rows are returned.
- `cyclic_traversal` — a directed cycle is traversed variable-length. *Oracle:* the traversal
  terminates (no hang) by way of Cypher relationship-uniqueness and reaches every node in the cycle —
  liveness on cyclic graphs.

### Lookup / aggregation

- `point_lookup` — exact property-equality lookups. *Oracle:* each hit returns exactly one row and a
  miss returns zero rows.
- `aggregation_analytics` — a global `count(n)` over the full dataset. *Oracle:* the aggregate is
  exact.

### Isolation / concurrency

- `contended_writes` — two writers update an existing node concurrently. *Oracle:* SSI must not let
  both transactions commit.
- `concurrent_supernode` — two concurrent writers each create an edge on the **same** hub. *Oracle:*
  both commit and both edges persist (`fan-out == committed`). The scenario asserts only the safe
  two-writer boundary; see finding rmp #220 in section 8.
- `snapshot_isolation` — a read transaction's snapshot must stay stable while a concurrent writer
  commits. *Oracle:* the reader observes the same count twice within its transaction (repeatable read),
  and a fresh read afterward then sees the new row.

### Atomicity / churn

- `transaction_rollback` — a write inside a rolled-back transaction. *Oracle:* the rollback leaves no
  trace (atomicity).
- `churn_create_delete` — create N nodes, `DETACH DELETE` all of them, then create N again. *Oracle:*
  the count returns to the baseline at each step (delete is honoured and storage is reused via the
  free-list).

### Durability / crash recovery

- `crash_recovery_durability` — drives `LocalEngine::crash_restart` (ARIES recovery from the durable
  WAL). *Oracle:* an acked commit survives the crash and uncommitted work does not.

### Load shapes

- `spike_load` — a thundering-herd arrival shape (`LoadProfile::Spike`). *Oracle:* the run stays live
  and consistent (deterministic, no spurious errors, `created == persisted`).
- `ramp_load` — an accelerating arrival shape (`LoadProfile::Ramp`). *Oracle:* the run stays live and
  consistent (same checks as `spike_load`).
- `sustained_high_concurrency` — 16 interleaved clients under heavy load. *Oracle:* liveness (every
  scheduled op runs, monotone progress), `created == persisted`, deterministic replay, and no spurious
  errors.

## 8. Findings (engine gaps surfaced by the simulator)

The simulator did its job and surfaced three real serializability/durability gaps (filed in `rmp`,
pinned by tests so they cannot silently regress, to be fixed in the engine):

- **rmp #171 — phantom write-skew / lost-update.** Two transactions that each read a predicate
  returning nothing and then insert a row matching the other's predicate **both commit**
  (non-serializable). SSI lacks predicate/index-range SIREAD tracking. *Measured boundary:* a
  write–write conflict on an **existing** node is correctly aborted; only phantoms slip.
- **rmp #172 — concurrent same-node write–write durability.** The conflict is detected (not both
  commit), but the surviving committed transaction's update can be **lost** (the value reverts to the
  pre-image). A single, non-concurrent increment persists correctly.
- **rmp #220 — supernode high-concurrency lost edges.** With **three or more** concurrently-open write
  transactions each creating an edge on the **same** node, the engine reports exactly two commits as
  `Ok`, yet the final fan-out collapses to **0** — committed edges are lost (an Atomicity + Durability
  violation). At **two** concurrent writers it is correct (fan-out 2). The behaviour is measured,
  reproducible, and deterministic, and it is a sibling of #172. It is pinned by the regression test
  `scenarios::tests::supernode_high_concurrency_loses_edges_pins_220` so it cannot silently regress;
  the `concurrent_supernode` certification scenario therefore asserts only the safe two-writer
  boundary. To be fixed in the engine.

## 9. Features beyond the original brief

Added because they materially improve realistic testing, though not enumerated in the request: the
seed-double-run **determinism gate** (the CLI fails on any non-reproducible seed); the **crash-restart
durability oracle over the wire**; the **Elle isolation checker**; network **partition/reset/delay**
fault injection; the **misbehaved-client catalogue**; and reusable public value-mapping seams
(`engine::bolt_values` / `engine::rest_values`) so the simulator packs results byte-identically to the
server.
