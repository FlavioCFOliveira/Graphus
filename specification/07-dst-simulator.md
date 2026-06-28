# 07 — External Deterministic Simulator (VOPR)

This chapter specifies the **external deterministic simulator** for Graphus: a TigerBeetle-VOPR-style
tool that drives the **real** server interfaces and engine under **seeded, fully reproducible**
workloads, faults, and adversarial clients, and certifies behaviour with a set of oracles. It
realizes decision `D-dst-investment` at the *connectivity/protocol* layer (the pre-existing
`graphus-dst` storage harness realizes it at the storage layer).

It is implemented across `graphus-dst` (the simulator core, interleaver, fault scheduler, oracles,
repro/shrink and fuzzer), `graphus-sim` (the deterministic substrate, including the clock- and
transport-fault models), `graphus-io` (the simulated disk and its fault model), `graphus-elle` (the
isolation checker), and small public seams added to `graphus-server`/`graphus-bolt`/`graphus-rest`. A
`dst` cargo feature (off by default, zero-cost in production) exposes a live-device fault seam through
`graphus-server`/`graphus-cypher`/`graphus-storage`/`graphus-bufpool` (section 6.2).

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

The fault, workload, and (swarm) environment choices are each drawn from their **own** seeded PRNG,
derived from the one master seed by mixing in a domain-separation tag (the workload uses `seed`, the
fault scheduler `seed ^ FAULT_TAG`, the swarm config `seed ^ SWARM_TAG`). These streams compose
deterministically: a single seed reproduces all of them bit-for-bit, yet adding a fault or swarming the
environment never silently reshapes an existing seed's workload, because no stream consumes another's
draws.

## 2. Architecture

| Component | Crate | Role |
| --- | --- | --- |
| `LocalEngine` | `graphus-server` (`engine::local`) | Drives the **real** `TxnCoordinator`/storage/WAL **inline, single-threaded**, reusing the production command-dispatch path verbatim. Unbounded result egress so a single thread cannot deadlock. Time flows through an injected `Clock`. |
| `SimScheduler<P>` | `graphus-sim` | Deterministic discrete-event scheduler: one logical clock + one `SimRng`; events ordered by `(due, rng-priority, seq)`. |
| `SimNet` / `SimEndpoint` | `graphus-sim` | Deterministic in-memory network; endpoints implement `graphus_bolt::Transport`. Reliable, ordered, delayable, breakable (latency / partition / reset / close). Byte reorder/drop/dup are deliberately **not** modelled (a reliable TCP stream does not exhibit them). |
| `SharedClock` | `graphus-sim` | Atomic clock the simulator sets from scheduler time; read by the engine — logical time in lockstep. |
| `FaultyClock` | `graphus-sim` (`clock_fault`) | Wraps a `Clock` and perturbs it from a seeded `ClockFaultPlan` (skew, forward jumps, regressions) — see section 6. |
| `MemBlockDevice` + `FaultPlan` | `graphus-io` (`mem`) | The simulated disk; a seeded `FaultPlan` arms the full disk-corruption model (bit-rot, misdirected I/O, latent sector error, ENOSPC, write reordering) — see section 6. |
| `SimNet` + `TransportFaultPlan` | `graphus-sim` (`net`) | Deterministic in-memory network with a seeded transport-fault model (mid-message drop, truncate-then-stall, slow consumer) — see section 6. |
| VOPR core | `graphus-dst` (`vopr`) | Builds the world, runs the seed-driven **cooperative interleaver** of overlapping explicit transactions, records a canonical FNV-1a event trace + state hash, and runs the oracles. CLI: `graphus-dst vopr --seed B --seeds K`. |
| Fault scheduler | `graphus-dst` (`vopr_fault`) | Schedules disk/clock/transport/crash faults on the VOPR timeline under a bounded `FaultBudget`, folded into the canonical trace — see section 6. |
| Reference-model oracle | `graphus-dst` (`vopr_oracle`) | A deterministic shadow LPG compared cell-by-cell against the engine on every commit — see section 8. |
| Repro + shrink | `graphus-dst` (`vopr_repro`) | Persisted JSON replay artifacts and a deterministic config shrinker — see section 11. |
| Fuzzer | `graphus-dst` (`vopr_fuzz`) | A continuous, time-budgeted, multi-core seed sweep — see section 12. |

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

## 5. The cooperative interleaver

The VOPR main loop is a **deterministic cooperative interleaver** of **overlapping explicit
transactions** (`vopr.rs`). Each virtual client is a small state machine (`ClientState`) that is either
`Idle` or `Open` — holding an open transaction ticket and the next scripted step. A client's
transaction is scripted as `[BEGIN, stmt, …, COMMIT | ROLLBACK]`, and the single `SimScheduler`
dispatches each client's **next step** as its own event, ordered by the canonical
`(due, rng-priority, seq)` key. Because each step is a separate event, **multiple clients can have a
transaction open at the same scheduler instant** — real overlap, not serialized batches.

The interleaver runs **single-threaded**. All randomness comes from the scheduler's seeded RNG, so the
entire interleaving is a pure function of the seed.

- **`advance_client`** advances exactly one client's state machine by one step, executes it against the
  engine, folds the `(client, step kind, outcome)` into the canonical trace in dispatch order, and
  schedules the client's following step.
- The loop folds three artifacts into one **canonical FNV-1a trace**: the workload steps (in dispatch
  order), every fault decision (section 6), and every crash event (section 6.5). It also computes a
  **state hash** — an ordered snapshot of all `:Person` nodes and `:KNOWS` relationships read back
  through real queries — so a run is fully described by `(trace_hash, state_hash)`.
- **Determinism gate.** Every seed is run **twice** and the two `VoprReport`s compared field-for-field
  (trace, state, counts, oracle). Any mismatch is a determinism failure — the simulator's own core
  invariant — counted and listed for one-line reproduction.

### 5.1 Concurrency-fidelity ceiling — what DST does **not** cover, and who owns it (rmp #460)

The cooperative interleaver's "concurrency" is **overlapping transaction lifetimes on one cooperative
OS thread**, with **each Cypher statement executed atomically to completion** before the next client's
step begins. This is deliberate: true OS-thread parallelism would reintroduce non-determinism and break
the seed-replay gate. The consequence is a precise, named **fidelity ceiling**: an entire class of
**true-parallel races is structurally invisible to DST** and is therefore **owned by other suites, not
DST**. Reviewers must not attribute a parallel-memory property to "DST-proven".

What DST genuinely covers: transaction-overlap / SSI logical races (e.g. `#171`/`#172`/`#220`),
durability and atomicity across ARIES crash-restart, determinism, single-thread disk/clock fault
recovery, the backup/restore/key-rotation crash windows (section 10), and the property-value /
secondary-index oracle (section 8). What DST **cannot** exercise, with its real owner:

| Parallel-race class (invisible to DST) | Owning suite(s) — the authoritative proof |
| --- | --- |
| Off-thread reader pool (`#336`): reads run **inline** under DST (`ReadDispatch::Inline` is hardcoded in `LocalEngine`), never on the pool | `graphus-server/tests/concurrent_read_scaling.rs`, `concurrent_reader_serializability.rs` |
| Intra-query **morsel** fan-out (`#339`): DST never sets `morsel_threads > 1`, so it runs fully serial (degree 1) | `concurrent_read_scaling.rs` (real reader pool + morsel threads) |
| `ConcurrentBufferPool` contended victim sweep / the `#359` fetch livelock; concurrent evictors | `graphus-bufpool/tests/loom_bufpool.rs`, `loom_eviction_storm.rs`, `loom_freeze_vs_reader.rs` |
| Doublewrite-buffer (DWB) eviction ring (`#411`/`#412`) | `graphus-bufpool/tests/loom_dwb_ring.rs`, `graphus-storage/tests/dwb_concurrent_eviction_411.rs` |
| SSI commit-path interleavings at the memory level | `graphus-txn/tests/loom_ssi.rs` |
| Real-OS-thread supernode write contention (the true-parallel pair to the DST `#220` logical guard) | `graphus-dst/tests/real_thread_supernode_stress.rs` |
| Engine-thread panic isolation; blocking-thread budget under load | `graphus-server/tests/panic_isolation.rs`, `blocking_thread_budget.rs`, `connection_stress.rs`, `slow_consumer_no_head_of_line_block.rs` |

These owners fall in two families: **loom** suites (exhaustive interleaving of the atomic-level memory
operations) and **real-OS-thread** tests (genuine parallelism across threads). Both are **non-determin­istic
by nature**, so they are run as a **soak lane** (section 13, `scripts/tsan-soak.sh`) under
ThreadSanitizer — and that lane **must never feed the deterministic seed-replay gate**, whose
byte-identical contract requires single-threaded execution.

A second, narrower caveat (**F-DST-2**): the `#220` "concurrent writers" guard expresses K concurrency
as **K overlapping tickets executed sequentially** (commutative-overlap-at-commit), which is narrower
than the word "concurrent" suggests. Its true-parallel counterpart is the real-OS-thread supernode
stress named above.

## 6. Fault models

Sprints 22–25 added a composable, fully seeded fault library. Every fault is a pure function of its
plan's seed (no wall clock, no OS entropy on any path) and every fault is designed to be **detectable
or survivable** — corrupt data is never silently served as valid, and the chaos stays bounded so the
engine can still recover.

### 6.1 Disk faults — `graphus_io::FaultPlan` on `MemBlockDevice`

A seed-driven `FaultPlan`, armed via `MemBlockDevice::arm_fault_plan`, drives an in-file SplitMix64 PRNG
(no external RNG crate) to model the disk pathologies the storage spine must recover from:

- **Bit-rot** — flips a seeded, bounded set of bytes when a target page is *read*, forcing each flip to
  actually change a byte, so the page no longer matches its checksum.
- **Misdirected read** — reading page `from` returns the bytes of a different page `to` (whose header
  carries the wrong id, so the caller's page-id/checksum check must reject it).
- **Misdirected write** — writing `from` persists to page `to` instead; `from` keeps its old contents
  and `to` is silently overwritten.
- **Latent sector error** — a page is marked unreadable, so a later read hard-fails instead of serving
  bytes.
- **ENOSPC** — `extend` past a seeded capacity cap fails, modelling a full disk (the failure is sticky,
  not one-shot, and a failed extend grows nothing).
- **Write reordering** — a sync persists only a seeded subset (a configured percentage) of the pending
  page cache and leaves the rest cached, so a subsequent crash loses that pre-sync subset, modelling a
  non-atomic, reordered flush. This resolves the formerly deferred `WriteReordering` fault: it is now a
  real injected fault.

An empty (default) plan is inert: arming it changes nothing.

### 6.2 The live-engine fault seam (`dst` cargo feature)

To arm a disk fault on a **running** store mid-workload (rather than only on a device the harness owned
before construction), the engine exposes a fault seam gated behind the `dst` cargo feature:

- `RecordStore::device_mut()` and `LocalEngine::with_device_mut(f)` borrow the engine's live block
  device so the harness can arm a `FaultPlan` (or the one-shot I/O-error / torn-write seams) during
  interleaved transactions. `LocalEngine::with_device_mut` returns `None` on an already-shut-down
  engine, so a caller can never panic on a spent engine.
- The feature forwards down the crate chain (`graphus-server/dst` → `graphus-cypher/dst` →
  `graphus-storage/dst` → `graphus-bufpool/dst`) and is **off by default**, so the production build
  never compiles the seam — the device stays encapsulated and the cost is exactly zero (the method does
  not exist on the production path).

This seam resolved the former `WriteIoErrorFullEngine` deferral: a write I/O error plus a later read
corruption can now be armed through the **full** engine (not just the buffer-pool layer), and the engine
must surface the error and never serve or commit corrupt data.

### 6.3 Clock faults — `graphus_sim::FaultyClock`

`FaultyClock` wraps any `Clock` and perturbs it from a seeded `ClockFaultPlan`:

- **Bounded skew** — a fixed signed offset (drawn once from the seed, within `±bound` ns) added to
  every reading; models a clock that runs a constant amount fast or slow.
- **Forward jumps** — a seeded, bounded forward leap on some reads (an NTP step, a VM resume); each read
  jumps with a per-mille probability.
- **Non-monotonic regressions** — a seeded, bounded step *backward* on some reads (a wrong-way clock
  correction), so two successive reads can go down.

The clock exposes a documented **tolerance contract** with two read paths:

- `now_nanos()` (the tolerant `Clock` read) serves the full hostile reading, including regressions.
  Timestamping and latency paths use it and already compute durations with `saturating_sub`, so a
  backward read yields a clamped (never negative) duration rather than a panic.
- `now_nanos_monotone()` is used where a non-decreasing source is a correctness precondition (lease /
  lock expiry, keep-alive deadlines). It passes readings through a high-water mark so a faulted reading
  below the previous one is saturated up to it and the value never regresses; skew and forward jumps
  still pass through.

The four guarantees the model upholds: every reading is **bounded** (a hostile clock can never reach
infinity or zero), **durations are never negative**, **monotone reads never regress**, and the whole
sequence is **deterministic** for a given seed.

### 6.4 Transport faults — `graphus_sim::TransportFaultPlan` on `SimNet`

A seeded `TransportFaultPlan`, armed on a `SimNet` link direction, models the pathologies a reliable
transport genuinely exhibits, expressed at **byte-offset precision** so they can land *inside* a
`RUN` / `PULL` / `COMMIT` message, not only at a message boundary:

- **Drop in message** — the link is reset the instant cumulative delivery first reaches a seeded byte
  offset; bytes delivered before the offset stay readable, every read/write afterwards errors.
- **Truncate-then-stall** — only the first seeded prefix of bytes is delivered, then the direction
  half-closes (the reader sees the prefix, then EOF) and the rest is discarded; the reader still
  terminates rather than hanging.
- **Slow consumer** — delivery is throttled to a seeded byte budget per network step (backpressure);
  all bytes still arrive in order, only the rate is capped, so the exchange still reaches quiescence.

The faults **preserve the reliable-stream invariant otherwise**: the bytes that *are* delivered stay
ordered and uncorrupted, and every fault drives the reader to a terminal state (a reset error or an
EOF), so a blocking `BoltSession::run` read always returns rather than blocking forever.

### 6.5 Crash + ARIES restart woven into the interleave

A seeded **crash + ARIES restart** fault can fire *during* the interleave (`CrashSplit`, in `vopr.rs`).
At the firing step the simulator snapshots the durable WAL prefix, drops the live engine (the crash),
and rebuilds a fresh engine purely from that WAL via `LocalEngine::crash_restart` (ARIES recovery),
reusing the same swappable faulty clock so time and clock faults stay continuous across the restart.
The workload then continues on the recovered engine.

The crash fires at the most dangerous durability moment: acknowledged commits and still-open
(in-flight) transactions coexist. Each crash records a `CrashSplit` tracking the acked-vs-in-flight
counts and the post-recovery state hash. Every acknowledged commit must survive the restart (ARIES
redo); every transaction still open at the crash must not (ARIES undo / no-redo). After recovery, all
clients are reset to `Idle` so none reuses a ticket from the dead engine; remaining op budget is
untouched, so the run continues.

### 6.6 The unified fault scheduler and seeded budget

`FaultScheduler` (`vopr_fault.rs`) does not reinvent any fault model; it **schedules** the models above
on the interleaver's single timeline. It decides, up front from a **dedicated** fault RNG
(`master_seed ^ FAULT_TAG`) under a bounded `FaultBudget`, which dispatched-step ordinals fire which
fault, and folds every decision into the canonical trace, so the fault schedule is part of the
reproducible run and does not consume draws from the workload stream.

The `FaultBudget` caps both the **rate** (`max_faults` over the run; `max_crashes` separately) and the
**intensity** (`disk_max_pages`, `disk_page_span`, `clock_max_ns`), and weights which kinds are eligible
(`disk_weight`, `clock_weight`, `transport_weight`). Crashes are off by default (`max_crashes == 0`), so
a standard run never crashes and replays bit-for-bit; the caps keep the chaos recoverable, never a
guaranteed wipe.

**Honest transport status.** Disk and clock faults are physically injected: disk via the `dst`-gated
live-device seam (section 6.2), clock by intensifying the engine's `FaultyClock` plan. Transport faults
are **scheduled, budgeted and folded into the trace** so the budget and reproducibility cover them. The
main in-process VOPR loop calls `LocalEngine` directly (no `SimNet` byte stream to reset), but the
scheduled transport plan **is physically applied** through the `SimNet`-backed Bolt driver
(`wire::run_bolt_session_with_scheduled_transport_fault`, rmp #462, closing F-DST-4): it pulls the very
plan the scheduler folded into the trace via `FaultScheduler::take_transport_plan` and arms it on the
real Bolt session's link, so a mid-message-severed `RUN`/`PULL`/`COMMIT` byte stream is exercised against
the genuine Bolt state machine. The recovery oracle asserts the state machine never panics or hangs
(`run()` always returns) and that a severed transaction is atomic (it never half-commits). The same
seeded `TransportFaultPlan` also drives the REST request core
(`wire::run_rest_with_transport_fault`). The simulator never fakes a transport fault it cannot physically
apply.

## 7. Adversarial and environment coverage

- **Misbehaved clients** (`dst::misbehave`, via `wire::drive_raw_bolt`): garbage after handshake,
  truncated/oversized chunk headers, `RUN` before `LOGON`, bad credentials, unsupported version. The
  real Bolt stack must never panic/hang and must return the correct protocol error or close cleanly.
- **Environment faults** (`dst::faults`): network partition/reset/delay; the disk, clock, transport and
  crash fault models of section 6; and **crash + restart** (`LocalEngine::crash_restart` rebuilds from
  the durable WAL via ARIES recovery).
- **Load/stress** (`vopr` + `LoadProfile`): high-concurrency runs with liveness (monotone progress, no
  hang) and consistency (`created == persisted`) checks.

## 8. Oracles

1. **Strong reference model** (`vopr_oracle.rs`) — a deterministic in-memory **shadow LPG**
   (`ShadowGraph`) applies exactly the *committed* workload operations and is compared **cell-by-cell**
   against the engine queried back: the multiset of node ids, the multiset of relationships keyed by
   stable `(src_id, dst_id)` property keys, and the `count(n)` / neighbour read-backs. The comparison
   keys on the workload's own `id` property (the model cannot predict the engine's internal record
   numbers), uses **multiset semantics** (a duplicate id is a second node; an edge is a Cartesian
   product over its endpoint matches), and is applied **only on COMMIT** — rolled-back, SSI-aborted, or
   crash-lost transactions are discarded, never applied, mirroring the durability contract. A divergence
   surfaces as a precise `OracleError` naming the offending id or edge. The oracle's read-backs run in
   their own auto-commit read transactions and are not folded into the trace, so wiring it in does not
   perturb `trace_hash`.
   - **Property values + secondary index (rmp #461).** The model additionally tracks each id's `rank`
     property and, on every commit, the oracle cross-checks three things the structural multisets are
     blind to: (a) each id's `rank` value (catching a wrong property left by a concurrency bug — e.g. an
     SSI rollback restoring a stale pre-image over a committed `SET`); (b) an **indexed** `rank` seek
     (`MATCH (n:Person {rank: $v})`) against the model; and (c) the indexed seek against a **forced full
     scan** (`MATCH (n:Person) WITH n WHERE n.rank = $v`) — a disagreement is a secondary-index-vs-base
     divergence (the surface of #313/#316). This check is driven by the dedicated **`property_index_oracle`**
     scenario (section 10), which exercises `SET`/`DELETE` churn over a declared `(Person, rank)` index;
     it runs **only** when `rank` data is present, so the default workload's `trace_hash` is unchanged. The
     contended workload vocabulary `WorkloadOp` is extended with `SetProperty` and `DeleteNode`, generated
     only by that scenario's driver — never by the default `WorkloadGen`, so the seed-replay gate stays
     byte-identical.
2. **Isolation / serializability** — `graphus-elle`: an Elle/Adya dependency-graph checker over the
   list-append model (`ww`/`wr`/`rw` edges, cycle detection). `dst::isolation` drives interleaved
   real transactions and feeds the recovered history to it.
3. **Invariants / liveness** — no panic/hang under misbehaved and stress workloads; correct error
   taxonomy.
4. **Durability under crash/restart** — acked commits survive `crash_restart`; uncommitted work does
   not.

## 9. Certification modes — safety, liveness, swarm

The VOPR core can run in three certification modes, each a thin wrapper over the same cooperative
interleaver and selected from the CLI (section 13).

### 9.1 Safety mode (`run_safety` → `SafetyReport`)

Safety mode bundles **four** properties that must all hold simultaneously, under fault injection, on a
contended interleave (overlapping explicit transactions under a write-heavy mix, with faults and crashes
firing during concurrent work):

- **Serializability** — the recovered history is acyclic and order-consistent (the `graphus-elle`
  checker).
- **Durability** — every acknowledged commit from before a crash survives the ARIES restart.
- **Atomicity** — no in-flight or rolled-back effect persisted.
- **Reference-model equivalence** — the shadow model (section 8) agrees with the engine cell-by-cell.

The `SafetyReport` records `safe` (true iff no property was violated), the number of checked
transactions, every `SafetyViolation` (each naming the broken `SafetyProperty` and a detail string), and
the underlying deterministic `VoprReport`.

### 9.2 Liveness mode (`run_liveness` → `LivenessReport`)

Liveness mode asserts the engine makes progress and recovers availability, under a bounded, recoverable
fault window:

- **Progress watchdog** — tracks the longest run of consecutive dispatched scheduler steps during which
  no client advanced its state machine. If that run reaches a generous, client-scaled stall threshold
  (`8 * clients + 32`) — or the run trips the hard step cap on a non-empty queue — the engine is judged
  wedged (deadlock / livelock / hang). The watchdog is **bounded by the same hard step cap as the
  workload**, so a real engine hang becomes a returned `LivenessReport { live: false, .. }`, never an
  actual infinite loop or CI hang.
- **Fault-then-heal recovery** — after the workload drains and every fault and crash has healed, a
  fresh deterministic post-heal workload batch must fully commit *and* read back correctly (the
  reference model agrees), proving the engine resumed serving correct results.

The `LivenessReport` records `live`, any `LivenessFailure` (`ProgressStalled` or
`DidNotRecoverAfterHeal`), the worst stall length and where it occurred, a bounded ring of the recent
schedule for debugging, and the post-heal recovery counts.

### 9.3 Swarm testing (`VoprConfig::swarm(seed)`)

Swarm testing derives the **entire** configuration — environment (clients, ops-per-client, pool pages),
workload mix, load profile, transaction shape, and fault budget — deterministically from the master seed
within sane, documented, bounded ranges, using a dedicated swarm RNG (`seed ^ SWARM_TAG`). Because the
swarm stream is domain-separated from the workload (`seed`) and fault (`seed ^ FAULT_TAG`) streams,
swarming the environment chooses the knobs without perturbing the workload or fault draws; the three
streams compose deterministically from the one seed. The bounds keep every swarmed run recoverable: at
least two clients (so transactions overlap), pools small enough to induce eviction but never zero,
faults and crashes capped so no swarmed config can guarantee a wipe.

## 10. Scenario catalogue

`dst::scenarios` is a named catalogue of known graph-DB usage patterns. Each scenario is a pure
`fn(seed) -> ScenarioOutcome` that drives the **real** engine (inline, deterministic) and checks an
oracle appropriate to it. The workload scenarios reuse the `vopr` runner + `dst::mix`; the structural
ones drive a `LocalEngine` directly. `run_sweep(seeds)` runs every scenario across a seed range and is
the CI-friendly entry point. The in-crate battery is deliberately sized to stay fast in a debug build;
raw scale is delegated to the `vopr` CLI seed-sweep.

The catalogue holds **20 scenarios**, grouped by the production-readiness dimensions a graph database
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
  two-writer boundary; see finding rmp #220 in section 14.
- `snapshot_isolation` — a read transaction's snapshot must stay stable while a concurrent writer
  commits. *Oracle:* the reader observes the same count twice within its transaction (repeatable read),
  and a fresh read afterward then sees the new row.

### Property / secondary index

- `property_index_oracle` (rmp #461) — a contended `CREATE`/`SET rank`/`CREATE edge`/`DETACH DELETE`
  workload over a declared `(Person, rank)` secondary index. *Oracle:* on every commit the extended
  reference model (section 8) cross-checks **property values**, the **indexed `rank` seek vs the model**,
  and the **indexed seek vs a forced full scan** (index-vs-base-store). Closes the oracle's former
  blindness to property values, secondary indexes, and delete churn.

### Atomicity / churn

- `transaction_rollback` — a write inside a rolled-back transaction. *Oracle:* the rollback leaves no
  trace (atomicity).
- `churn_create_delete` — create N nodes, `DETACH DELETE` all of them, then create N again. *Oracle:*
  the count returns to the baseline at each step (delete is honoured and storage is reused via the
  free-list).

### Durability / crash recovery

- `crash_recovery_durability` — drives `LocalEngine::crash_restart` (ARIES recovery from the durable
  WAL). *Oracle:* an acked commit survives the crash and uncommitted work does not.
- `backup_restore_crash` (rmp #440) — drives the genuine backup → seal → file → restore /
  key-rotation pipeline on **real temp files** and injects a crash at each of its four atomicity windows
  (after `seal_artifact` / before the backup rename; mid `write_file_atomic`; mid
  `restore_chain_file_atomic` temp write; after the device temp-rename / before the WAL + DWB reset).
  *Oracle:* at every window the database opens to a **committed-only, consistent** state **under exactly
  the expected key** (a wrong key fails closed). Reconstructs the pipeline at the public-API level
  (`LocalEngine::backup`, `graphus_crypto::seal_backup`/`open_backup`, `atomic_replace_file`,
  `restore_chain_file_atomic`, `verify_on_open`), since the server's `dbcatalog` orchestration is
  private.

### Load shapes

- `spike_load` — a thundering-herd arrival shape (`LoadProfile::Spike`). *Oracle:* the run stays live
  and consistent (deterministic, no spurious errors, `created == persisted`).
- `ramp_load` — an accelerating arrival shape (`LoadProfile::Ramp`). *Oracle:* the run stays live and
  consistent (same checks as `spike_load`).
- `sustained_high_concurrency` — 16 interleaved clients under heavy load. *Oracle:* liveness (every
  scheduled op runs, monotone progress), `created == persisted`, deterministic replay, and no spurious
  errors.

## 11. Shrink and replay (`vopr_repro.rs`)

Every failing run can be persisted and reproduced exactly:

- A **`ReplayArtifact`** is a self-contained JSON reproducer holding the run's `mode`, the full
  `VoprConfig`, the expected `trace_hash` and `state_hash`, and a failure summary. Because the run is a
  pure function of its config, loading the artifact and re-running reproduces the **exact** failure.
- **`vopr-repro --replay <file>`** loads an artifact, re-runs the recorded mode and config, and
  certifies a byte-identical reproduction: the reproduced `trace_hash` / `state_hash` must equal the
  recorded hashes (the determinism gate) **and** the run must still be a failure. The `ReplayOutcome`
  distinguishes the three cases — faithfully reproduced, hash mismatch, or no longer failing.
- **`vopr-repro --shrink <seed>`** runs a deterministic, bounded greedy shrinker: it reduces one config
  knob at a time, accepting a candidate only if it still fails, keeping the config monotonically
  smaller. Knobs are tried in a fixed order (most impactful first); the search is reproducible and
  bounded by a candidate cap, and the emitted artifact is always a real, still-failing — and minimal —
  reproducer.

## 12. Hyper-speed fuzzer (`vopr_fuzz.rs`)

The fuzzer turns "a run is a pure function of its config" into a continuous, wall-clock-time-budgeted,
**parallel multi-core** seed sweep:

- It enumerates a contiguous range of seeds (optionally swarming each seed's full environment, section
  9.3) across `jobs` worker threads, each building its own engine. The wall clock is read **only** in
  the orchestrator — to bound the soak (`--secs`) and measure throughput — never inside a per-seed run.
- Each seed's `SeedVerdict` (`failed`, `trace_hash`, `state_hash`, ops, simulated time) is a pure
  function of `(mode, config, predicate)` — independent of which worker ran it or of thread timing — so
  the **parallel sweep's verdict set is provably equal to a serial sweep's** over the same range, sorted
  by seed.
- The `FuzzReport` reports the verdict set plus throughput: seeds-per-second, ops-per-second, total
  simulated time, and elapsed wall-clock. The verdict set is the determinism contract; the throughput
  metrics vary run to run and are explicitly *not* part of it.
- On any failing seed the fuzzer emits its section 11 `ReplayArtifact` (planted-seed artifact emission),
  so a nightly failure ships a self-contained reproducer.

## 13. CLI and CI integration

The `graphus-dst` binary exposes the VOPR modes as subcommands:

- `graphus-dst vopr --seed B --seeds K` — the serial determinism + reference-model sweep.
- `graphus-dst vopr safety --seed B --seeds K` — the safety bundle (section 9.1).
- `graphus-dst vopr liveness --seed B --seeds K` — the liveness checks (section 9.2).
- `graphus-dst vopr fuzz --mode <m> [--swarm] [--secs T] [--max-seeds N] [--jobs N] …` — the
  time-budgeted soak fuzzer (section 12).
- `graphus-dst vopr-repro --replay <file>` / `--shrink <seed>` — replay and shrink (section 11).

A non-zero exit status signals at least one failing seed, listed for one-line reproduction.

**PR CI gate** (`.github/workflows/ci.yml`). On the x86_64 Linux leg, every pull request runs a fast,
bounded VOPR sweep that fails on any violation, non-determinism, or oracle divergence:

- `vopr safety --seed 1 --seeds 256`
- `vopr liveness --seed 1 --seeds 256`
- `vopr --seed 1 --seeds 256` (determinism + reference-model)

The gate is bounded to 256 seeds per mode so it stays a quick check; it runs once on the x86_64 Linux
leg to keep the matrix fast.

**Nightly soak** (`.github/workflows/nightly-fuzz.yml`). A scheduled job runs the swarmed,
time-budgeted fuzzer once per mode (`safety`, `liveness`, `standard`) — `vopr fuzz --mode <m> --swarm
--secs <budget> --keep-going --write-artifacts <dir>` — and, on any failing seed, uploads the emitted
replay artifacts so the exact failure can be reproduced locally via `vopr-repro --replay`.

**Threaded concurrency soak under ThreadSanitizer** (`scripts/tsan-soak.sh`, rmp #460). A separate,
**non-deterministic, soak-only** lane runs the **real-OS-thread** owners of the parallel-race class
(section 5.1) under ThreadSanitizer (`-Z sanitizer=thread`, nightly toolchain): the
`graphus-server/tests` concurrency tests (`concurrent_read_scaling`, `concurrent_reader_serializability`,
`panic_isolation`, `blocking_thread_budget`, `connection_stress`,
`slow_consumer_no_head_of_line_block`), the `graphus-storage` DWB real-thread test
(`dwb_concurrent_eviction_411`), and the `graphus-dst` real-thread supernode stress
(`real_thread_supernode_stress`). This lane is the **named owner** of the true-parallel races DST cannot
see; it asserts the absence of data races that a single-threaded, byte-identical seed-replay run cannot
detect. It is **deliberately excluded from the deterministic seed-replay gate** — its thread interleaving
is OS-scheduled, not seed-driven, so feeding it into the byte-identical gate would be a category error.
The loom suites (`graphus-bufpool/tests/loom_*`, `graphus-txn/tests/loom_ssi`) are the exhaustive-interleaving
complement and run on their own (`RUSTFLAGS=--cfg loom`).

## 14. Findings (engine gaps surfaced by the simulator)

The simulator did its job and surfaced three real serializability/durability gaps (filed in `rmp`,
pinned by tests so they cannot silently regress). Two (**#172** and **#220**) are now **FIXED** in the
storage engine and their pins were flipped into regression **guards**; **#171** remains open:

- **rmp #171 (OPEN) — phantom write-skew / lost-update.** Two transactions that each read a predicate
  returning nothing and then insert a row matching the other's predicate **both commit**
  (non-serializable). SSI lacks predicate/index-range SIREAD tracking. *Measured boundary:* a
  write–write conflict on an **existing** node is correctly aborted; only phantoms slip.
- **rmp #172 (FIXED) — concurrent same-node write–write durability.** The conflict is detected (SSI
  aborts exactly one), and the surviving committed transaction's update now **persists** — the value
  reflects exactly one increment, never reverting to the pre-image. *Root cause:* the SSI loser's
  rollback restored a stale `first_prop` chain-head pre-image over the survivor's committed value.
  *Fix:* the chain-head update logs a **compare-and-set logical undo** (unlink only if still the head)
  and a record creation logs a **header-only undo** (revert the slot to not-in-use while preserving
  its forward chain pointers), so an abort never reverts another transaction's committed structure.
  Guarded by `isolation::tests::write_write_conflict_is_detected`.
- **rmp #220 (FIXED) — supernode high-concurrency lost edges.** With **three or more** concurrently-open
  write transactions each creating an edge on the **same** node, every edge that **commits** now
  survives — `fan-out == committed`, at every concurrency degree (previously it collapsed to **0**, an
  Atomicity + Durability violation). *Root cause:* an SSI loser's rollback clobbered the shared
  `first_rel` chain head, severed the freshly-created records below it, and — at the catalog level —
  lowered the id high-water / token dictionary that concurrently-committed records depended on. *Fix:*
  the same chain-head compare-and-set + header-only creation undo, plus a **monotonic catalog floor on
  rollback** (an aborting transaction never lowers the shared physical-id high-water, token dictionary,
  or `ElementId` allocator below what a concurrent open transaction has already advanced them to).
  Guarded by `scenarios::tests::supernode_high_concurrency_keeps_committed_edges_guards_220`, swept
  across K ∈ {2,3,4,6,8,12,16,24}.

## 15. Features beyond the original brief

Added because they materially improve realistic testing, though not enumerated in the request: the
seed-double-run **determinism gate** (the CLI fails on any non-reproducible seed); the **crash-restart
durability oracle over the wire**; the **Elle isolation checker**; network **partition/reset/delay**
fault injection; the **misbehaved-client catalogue**; and reusable public value-mapping seams
(`engine::bolt_values` / `engine::rest_values`) so the simulator packs results byte-identically to the
server.
