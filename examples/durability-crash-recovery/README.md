# Durability & crash recovery

This example is Graphus's **durability proof**. It demonstrates the two inviolable guarantees under a
concurrent OLTP workload, real faults, and real crashes:

- **Durability** — *every acknowledged commit survives a crash.* If the server returned success for a
  `COMMIT`, that transaction's effect is fully present and correct after recovery.
- **Atomicity (committed-or-nothing)** — *no in-flight effect survives a crash.* A transaction still
  open at the crash leaves **no** trace: not a row, not an edge, not a property.

It proves them **three times over**, from the most controlled to the most brutal:

| # | Layer | What it proves |
|---|-------|----------------|
| 1 | **Deterministic core** (DST) | The engine, in-process, under disk/clock faults + a seeded mid-workload crash: the four ACID-durability properties hold on the **recovered** engine for every seed, reproducibly. |
| 2 | **The full fault catalogue** (DST) | The **same engine** driven through *every* fault the simulator can physically inject — steal/UNDO, torn WAL tail, torn data page, write reordering, write I/O error — each recovering SAFE. |
| 3 | **A real server, killed mid-workload** | The production `graphus-server` on a real on-disk store, `SIGKILL`ed **while writers are committing and one writer sits inside an OPEN, never-committed transaction**. Every acknowledged commit survives; not one uncommitted row does. |

## Local-only, by construction

Unlike every other example, this one **cannot** run against an already-running instance
(`GRAPHUS_TARGET_*` is refused with a clear message). It must **own the server's lifecycle**: it
`SIGKILL`s the server and then reopens its store exclusively. Killing a shared or remote database is not
a demonstration, and durability can only be shown on a store you control. This is the documented
local-only exception in `examples/CLAUDE.md`.

## How to run

```bash
examples/durability-crash-recovery/run.sh            # CI-fast: 30 seeds + 25 seeds/fault + the real-server crash
DUR_PROFILE=full   examples/durability-crash-recovery/run.sh   # 100 seeds
DUR_FAULT_SEEDS=50 examples/durability-crash-recovery/run.sh   # deepen the fault matrix
DUR_WRITERS=8 DUR_BATCH_NODES=10 examples/durability-crash-recovery/run.sh   # heavier real-server OLTP
```

Requirements: a Unix host, `bash`, `curl`, and `openssl` (the real-server step binds REST so its
Prometheus `/metrics` can be scraped, and a network listener requires TLS). The script builds every
binary it needs through the shared `harness_build` seam — it never runs a stale binary — and doubles as
an executable E2E test: it asserts every step and exits non-zero the moment one fails.

---

## 1. The deterministic core

Per `CLAUDE.md`'s DST mandate, the crash scenario is driven through the project's own simulator
(`crates/graphus-dst`), reusing its cooperative transaction interleaver, its crash + ARIES-restart
fault, and its four-property safety oracle rather than reinventing them.

Each seed runs 6 virtual clients in **overlapping explicit transactions** (a write-heavy
create/relate/property/delete mix) under disk and clock faults, crashes the engine mid-workload, rebuilds
it via ARIES, and then asserts **on the recovered engine**:

| Property | How it is checked |
|----------|-------------------|
| **Serializability** | An Elle checker rules on the recovered committed history. |
| **Durability** | The acknowledged-commit set never regresses across a crash. |
| **Atomicity** | Recovered rows == distinct **acknowledged** ids — no partial or duplicated effect. |
| **Reference-model equivalence** | A committed-only shadow LPG, fed **only** by acknowledged commits, is compared to the recovered engine **cell by cell**: the id multiset (with multiplicities), the full edge multiset, `count(n)`, and every per-node neighbour row. |

That last arm is the one with teeth: **a single un-acknowledged row surviving recovery, or a single
acknowledged row lost, fails the run** — whatever the totals happen to be.

## 2. The full fault catalogue

The headline sweep crashes the engine and rebuilds it from the durable WAL prefix onto a *fresh* device.
That is the **easiest** ARIES case: recovery only has to redo. The hard cases are exercised separately,
through the same real `RecordStore` engine:

| Fault | What recovery must do |
|-------|-----------------------|
| `crash(no-force)` | Redo every acknowledged commit from the durable WAL. |
| `crash(steal)` | **UNDO** the uncommitted dirty pages that were flushed home before the crash. |
| `torn-wal-tail` | Stop cleanly at the last intact record — a half-written record is not a commit. |
| `torn-data-page` | Repair the torn home page from the **doublewrite buffer** *before* ARIES redo reads its `page_lsn`. |
| `write-reordering` | Reconstruct every committed page a non-atomic sync failed to persist. |
| `write-io-error` | **Surface** the hard error and the checksum-rejected read — never serve or commit corrupt data. |

Every cell is a pure function of `(seed, fault)` and is re-run once to prove it. The run asserts not only
that each fault is SAFE but that each is **non-vacuous** — the steal crash must really give UNDO work to
do, the torn-tail fault must really leave a truncated tail — because a fault that did nothing would pass
trivially. The one fault that is **not** physically injected is declared with its reason rather than
hidden: `fsync-eio` (the controlled-panic fsyncgate path, covered by a `graphus-wal` unit test).

On the run recorded below (Linux x86_64, 16 cores), 6 fault kinds × 25 seeds = **150 cells in 1.3 s**,
all SAFE, with the steal crash producing 49 undo losers and the torn-tail fault truncating 25 tails.

## 3. The real server, killed mid-workload

This is the part that used to be weakest, and is now the sharpest. The old version spawned writers,
**waited for them all to finish**, and only then killed the server — a *post-quiescence* kill, which can
only prove the easy half of the contract. It now crashes the server with work genuinely in flight:

- **4 committing writers** run auto-commit `CREATE` statements in a loop and record every commit the
  server **acknowledged**;
- **one writer holds an EXPLICIT transaction open** (`BEGIN` … no `COMMIT`), writes `:Phantom` rows into
  it, proves they are visible *inside* the transaction, and then keeps probing inside it until the socket
  dies — so the ledger can state that the transaction was **still open at the instant of the kill**;
- `SIGKILL` lands while all of them are working.

### The crash window is deterministic, not hoped for (`rmp` #712)

A durability example that only *sometimes* injects the crash it claims to inject is worthless as a
regression instrument — and this one used to be exactly that. The kill landed whenever it landed, and
whether the ledger *witnessed* the open transaction was a race the in-flight writer could lose, so the
run's strongest assertion (`a writer really was inside an OPEN, never-committed transaction at SIGKILL`)
failed intermittently on a server that had in fact behaved perfectly. Three things now make it a fact:

1. **The writer holds its transaction until it is killed.** It never sends `COMMIT` on any code path, and
   it is no longer wound down when the server dies: the driver *joins* it and lets it observe its own dead
   socket first-hand. (The old code raced it with a shutdown flag, so it could wake up, see "stop", and
   report `open_at_kill = false` for a transaction that had never closed.)
2. **The kill is sequenced behind fresh, positive proof.** While holding, the writer refreshes a **hold
   beacon** after every in-transaction round-trip the server *answers*. `run.sh` reads it immediately
   before the `SIGKILL` and requires that it has **advanced** since the ready marker — so the transaction
   is provably still being held *now*, not "a moment ago". The server's own
   `graphus_active_transactions` gauge is scraped at the same moment and must report ≥ 1 open
   transaction, corroborating it from the other side.
3. **A weakened proof is refused, never published.** A server *refusal* (the server answering and rolling
   the transaction back) is no longer mistaken for a dead socket — that false positive would have let the
   assertion pass over a transaction the server had already discarded. And if the server dies without a
   writer attesting an open transaction, the driver exits non-zero rather than emitting a ledger whose
   strongest half is vacuous.

The determinism is pinned by unit tests (`a_server_refusal_is_not_a_connection_death`,
`the_verdict_refuses_every_way_the_crash_window_can_be_vacuous`), not by luck.

The post-restart verifier then asserts the **three-way partition** — and it is the honesty of the third
class that makes the first two meaningful:

| Class | Obligation |
|-------|------------|
| **Acknowledged** commits | MUST be present, complete and correct — every row, every edge, every property value re-derived independently. |
| **In-flight** (the open transaction) | MUST NOT be present. Zero `:Phantom` rows. |
| **Undetermined** (a statement in flight when the socket died) | Its ack never arrived, so it may or may not have committed. It is asserted **only** for atomicity (all-or-nothing, never half-applied) and never for presence — claiming otherwise would be a lie, not a proof. |

### Was the redo log actually load-bearing?

A recovery that replays nothing proves nothing. Two checks make sure it is real:

1. The WAL is measured **before** the kill, classified **by path** — the WAL is a *directory* of
   `seg.<lsn>` segments, so any accounting that classifies by leaf file name reports `wal = 0` and hides
   the redo log entirely. The run asserts the crash leaves **≥ 64 KiB** of un-checkpointed redo log.
2. A **negative control**: the crashed store is copied, its WAL segments are deleted, and a server is
   pointed at the copy. If the committed data were already in the data image, the copy would come back
   whole and the "recovery" would be a no-op. It does not — so the recovery being timed is real redo work.

### What durability actually COST (measured, Linux x86_64, 16 cores)

This is the example's headline evidence: it is a durability proof, so the report a reader opens must be
able to answer *"what did durability cost here?"* — and every figure below is measured on the real store
this run crashed and recovered.

| Vector | Value |
|--------|-------|
| **Redo log at the crash** (`storage.wal_bytes`) | **955 098 B** — the WAL bytes that carried the acknowledged commits to durable media |
| **Store image after replay** (`storage.store_bytes`) | **335 872 B** (196 608 B at the crash — replay grew it) |
| **Bytes forced to durable media** (`storage.bytes_fsynced`) | **955 098 B** (the redo log; see the caveat below) |
| WAL residual after recovery | 1 679 942 B — what the log had grown to once recovery and the restarted server had written to it |
| Doublewrite buffer | 8 871 936 B of **fixed** torn-page-repair overhead (does not scale with the graph) |
| Acknowledged at the crash | **160 commits** (800 accounts + 640 transfers) |
| In flight at the crash | 1 open transaction holding **6 uncommitted rows**, held across **12** answered in-transaction probes, + 4 undetermined statements |
| **Recovery** | **362 ms** wall-clock (`SIGKILL` → UDS bound again), peak replay RSS **37 MB** |
| Without the WAL | the store **refuses to open** — the redo log is load-bearing |
| After recovery | **160/160** acknowledged commits intact · **0** phantom rows · 0 partial · 0 fabricated |
| `graphus_engine_recovery_panics_total` | **0** (scraped from `/metrics`) |
| Commit latency | p50 **3.0 ms**, p99 **33.6 ms**, p999 **33.6 ms** (measured per commit) |

Two honesty caveats the report itself states:

- **`storage.wal_bytes` is the redo log AT THE CRASH, not at report time.** Recovery *consumes* it, so it
  exists at exactly one instant — and it is measured then, by path. Re-walking the WAL directory after
  recovery would report the **1 679 942 B residual** instead: a real number describing the wrong thing,
  and nearly **double** the log the crash actually left behind.
- **`storage.bytes_fsynced` is a proxy, not a syscall counter.** The server exposes no fsync-byte metric,
  so the figure reported is the redo log that carried the acknowledged commits — every byte of which was
  forced to durable media before its commit was acknowledged. It is not claimed to be more than that.

A **graceful-restart companion** then closes the loop: the recovered server is stopped with `SIGTERM` and
reopened, and the graph must be unchanged — the clean path must not lose anything either.

## Evidence

Two standardized, schema-versioned reports are written to `evidence/` (git-ignored):

- **`evidence/report.json`** — **the headline**: the REAL server that was crashed and recovered. It
  carries the durability vector above (the redo log the crash left behind, the store image it was
  replayed into, the WAL residual afterwards, the bytes forced to durable media, the wall-clock and peak
  RSS of the replay), the server's CPU, and the measured commit-latency percentiles.
- **`evidence/dst-core/report.json`** — the deterministic core: the durability verdict, the recovered
  dataset (nodes **and** relationships), the deterministic recovery-work counts
  (`recovery_records_replayed`, `recovery_inflight_undone`, `recovery_crashes`), the measured sweep
  wall-time, and this process's real CPU and peak RSS (the hermetic engine *is* this process). This is
  the report the committed baseline gates.

> **Why the headline is the real server (`rmp` #712).** It used to be the DST core's — which runs the
> engine on an in-memory device and an in-memory WAL sink, and therefore *has* no on-disk footprint. So
> the project's durability example proved durability with 54 assertions and then reported, in the very
> report a reader opens, that the crash-recovered store occupied **zero bytes** and fsynced **zero
> bytes**. The reader was being told that the durability cost of durability is nothing. The real
> crash-and-recover has a real store and a real WAL on the local filesystem; that is now what the
> headline measures.

Everything in both reports is **measured or omitted** — since schema v3 (`rmp #711`) an unmeasured metric
is genuinely **ABSENT** from the JSON rather than written as a `0` that reads like a result. The
`storage` section is absent from the **DST-core** report *by construction* (there is no on-disk footprint
to size), and its notes say so; its latency percentiles are absent because that sweep does not measure
per-operation latency. The **headline** report carries the full durable footprint *and* the per-element
durable costs (`storage.bytes_per_node` / `bytes_per_relationship`) — the measured store image amortised
over the node/relationship counts **read back from the recovered store** (`--nodes` / `--rels` are the
survivors ARIES replayed), so the two inputs describe the same graph by construction. And the run asserts
that the headline report carries a real, non-zero durability vector: a gate that *cannot* fire is the
same lie wearing a green tick.

## Baseline & regression gate

`baseline.json` is a committed fast-profile (30-seed) reference run. The gate compares a fresh run against
it and passes only when the **structural** metrics match exactly: the recovered node count, the recovered
relationship count, the redo/undo record counts, the crash count, and the seed range. These are pure
functions of the seed range, so they are integer-stable across runs and hosts. Everything timing- or
host-dependent (wall-times, throughput, CPU, RSS, on-disk bytes, recovery time) is deliberately **not**
gated, so the shared baseline never flakes.

**What a drift in those numbers means.** It means the *recovery work changed* — and that demands an
explanation, not a re-capture. It does **not**, by itself, mean a durability bug: the numbers move
legitimately whenever the engine commits more (or fewer) transactions. The property that must never move
is the ACID one, and that is guarded independently of any recorded number, by the reference-model oracle
above and by the regression test
`every_recovered_row_corresponds_to_an_acknowledged_commit` (`crates/graphus-durability-demo`).

> **Worked example (`rmp` #705).** This baseline was recaptured once, deliberately. The recovered row
> count for the focus seed had gone from 22 to 44, which looks alarming — same seeds, same crash count,
> exactly double the rows. A `git bisect` traced it to `909c484`, the SSI precise-`scan_filter_eq` fix
> (`rmp` #325), which stopped an unindexed label scan from **falsely aborting** disjoint-key writers. Its
> parent commit still reproduces the old baseline exactly (14 checked transactions, 22 rows); the fix
> takes it to 20, and later engine work to 24 transactions / 44 rows. **More transactions commit, so
> there are more committed rows to recover** — the doubling is a coincidence of where the count landed
> (it passed through 34 and 38 on the way). Throughout, `recovered == acknowledged` held cell-by-cell on
> every seed, and the real-server crash independently recovered 0 phantom rows. Stale baseline; not a
> defect.

## Reproducing a failure

Every layer is a one-line reproducer:

```bash
# a single durability seed (the safety oracle):
cargo run -p graphus-dst --bin graphus-dst -- vopr safety --seed 7 --seeds 1

# a single fault-catalogue cell:
cargo run -p graphus-durability-demo --bin durability_faults -- --seed 7 --seeds 1

# capture + replay a reproducer artifact (byte-identical re-run):
cargo run -p graphus-durability-demo --bin durability_replay -- --capture repro.json --seed 7
cargo run -p graphus-durability-demo --bin durability_replay -- --replay repro.json
```

The real engine has **no failing seed**, so the replay round-trip is demonstrated with a *planted*
synthetic failure through the DST replay machinery's `FailurePredicate` path — the same mechanism the
simulator's own shrinker tests use. The example is explicit about this rather than implying it caught a
real bug.

## The oracle has teeth

A durability oracle is only worth what it can catch. The teeth are proven at two levels:

- **In the simulator** (`crates/graphus-dst`): `evaluate_safety_has_teeth_per_property`,
  `oracle_catches_a_phantom_node`, `oracle_catches_an_injected_extra_edge`,
  `serializability_arm_catches_a_fabricated_cycle`.
- **In this example** (`crates/graphus-durability-demo`): `a_phantom_row_surviving_recovery_would_be_caught`
  (an uncommitted row that survives is caught), `durability_oracle_surfaces_an_injected_violation` (a lost
  acknowledged commit is caught), and `the_verify_verdict_catches_every_class_of_violation` (each class of
  real-server violation — phantom, lost commit, fabricated batch, half-applied transaction, wrong value —
  flips the verdict on its own).
- **On the crash window itself** (`rmp` #712): `the_verdict_refuses_every_way_the_crash_window_can_be_vacuous`
  (the run is refused, not published, if the server died without a writer attesting an open transaction)
  and `a_server_refusal_is_not_a_connection_death` (a server that answers and rolls the transaction back
  is never mistaken for a `SIGKILL`) — because an oracle that only *sometimes* gets the crash it claims
  to inject cannot catch anything.

```bash
cargo test -p graphus-durability-demo
```

The deterministic scenario also runs in the default `cargo test` as a hermetic mirror, so `cargo test`
alone guards the core; the real-server crash lives in `run.sh`.
