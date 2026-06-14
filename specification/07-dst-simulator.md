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

`dst::scenarios` is a named catalogue of known graph-DB usage patterns driven across a seed sweep
(`run_sweep`): `oltp_mixed`, `bulk_ingest`, `read_serving`, `deep_traversal` (variable-length paths),
`supernode_fanout` (hotspot), `large_result_stream`, `contended_writes`.

## 8. Findings (engine gaps surfaced by the simulator)

The simulator did its job and surfaced two real serializability/durability gaps (filed in `rmp`,
pinned by tests so they cannot silently regress, to be fixed in the engine):

- **rmp #171 — phantom write-skew / lost-update.** Two transactions that each read a predicate
  returning nothing and then insert a row matching the other's predicate **both commit**
  (non-serializable). SSI lacks predicate/index-range SIREAD tracking. *Measured boundary:* a
  write–write conflict on an **existing** node is correctly aborted; only phantoms slip.
- **rmp #172 — concurrent same-node write–write durability.** The conflict is detected (not both
  commit), but the surviving committed transaction's update can be **lost** (the value reverts to the
  pre-image). A single, non-concurrent increment persists correctly.

## 9. Features beyond the original brief

Added because they materially improve realistic testing, though not enumerated in the request: the
seed-double-run **determinism gate** (the CLI fails on any non-reproducible seed); the **crash-restart
durability oracle over the wire**; the **Elle isolation checker**; network **partition/reset/delay**
fault injection; the **misbehaved-client catalogue**; and reusable public value-mapping seams
(`engine::bolt_values` / `engine::rest_values`) so the simulator packs results byte-identically to the
server.
