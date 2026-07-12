# IoT / time-series event graph — ingest, retention churn & what durability actually costs

A realistic, end-to-end demonstration that Graphus sustains a **continuous IoT telemetry workload** — a
fleet of sensors emitting time-stamped readings under a **sliding-window retention policy** that deletes
aged-out readings — and that, under this relentless *delete-old + insert-new churn*, the storage engine
**recycles the freed space** so the durable **store** reaches a stable plateau rather than growing without
bound.

It is driven over a **real Bolt wire** against a **real `graphus-server`**, with a real store file and a
real segmented WAL on disk. It reports two things, and the second one is the interesting one:

> **1. The on-disk STORE plateaus while `graphus_maintenance_versions_reclaimed_total` climbs.**
>
> **2. And since `rmp` #706, the DATABASE on disk very nearly plateaus too.** At its worst this database
> now occupies **14.5 MB of disk to hold a 229 KB graph — 63×** (it was **347×** while #706 was open),
> because WAL segments are now sized to the store, so the WAL sawtooths in a tight, bounded band instead
> of climbing to 64 MiB. It still writes **~753 physical bytes for every logical byte** ingested — that
> figure is the WAL *format* (dual redo/undo), not the reclaim granularity, and #706 deliberately did not
> change it.

Both halves are load-bearing, and the first without the second is a lie of omission. A flat store is a
true statement about a *component*; published on its own, in an example whose headline is "reclamation
holds the footprint flat", it creates a false impression about the *database*. So this example measures
both, **gates** both, and states the finding plainly.

---

## The finding: the store plateaus, and since `rmp` #706 the WAL sawtooths in a *tight* band

Measured on the default `reclaim` profile — 140 ticks, 7 000 readings, 35× the retention window:

```
store data image   229376 B  ────────────────────────────────────────────  FLAT. Every post-warmup tick.

on-disk WAL       5.4 MB ┤ ╱│╱│╱│╱│╱│╱│╱│╱│╱│╱│╱│╱│╱│╱│╱│      plateau ratio 1.000 (store)
                         │╱ ╵ ╵ ╵ ╵ ╵ ╵ ╵ ╵ ╵ ╵ ╵ ╵ ╵ ╵ ╵     plateau ratio 1.55  (DATABASE)
                   1.6 MB┤                                     peak 63× the graph (was 347×)
                         └──────────────────────────────       36 reclaims, ~96 MB of WAL disk returned
                          a small sealed segment freed on nearly every checkpoint
```

**What `rmp` #706 fixed.** WAL disk is reclaimed in whole **segment** units, and the active segment is
never reclaimed — so nothing below the reclaim floor can be freed until a segment **seals**. The seal size
is now **store-proportional**, `clamp(store_bytes, 1 MiB, 64 MiB)`
([`graphus_wal::segment_target_for_store`](../../crates/graphus-wal/src/sink.rs)), applied by the store at
open and on every checkpoint. For a store this size that is the **1 MiB floor**, so the reclaiming
maintenance checkpoint — whose cadence `rmp #556` already made store-proportional — has small sealed
segments below the floor to delete on nearly every pass. Before #706 the seal size was a fixed **64 MiB**,
so a small database's WAL climbed all the way to 64 MiB (hundreds of times its store) before one byte came
back; a large log still keeps 64 MiB segments (the cap), unchanged.

**Write amplification is a separate, largely-unchanged number.** The ~760× cumulative-WAL / logical-bytes
figure is the record **format** — physiological redo + logical undo, dual imaging (`rmp #556`) — not the
reclaim granularity. #706 shrinks the *retained* footprint on disk, not how many bytes each commit writes;
reducing that would be a WAL-format change, out of scope here. So this figure barely moved (it was ~799×),
and that is expected.

**Why the reclamation counters agree.** `graphus_maintenance_versions_reclaimed_total` counts MVCC versions
freed inside the **store** (what keeps the store flat); the on-disk WAL physically **shrinking** is the
separate, direct proof that WAL disk came back. Both climb here — this run reclaimed WAL disk **37 times**,
returning ~96 MB.

> **Guarded on the real device.** The regression guard in
> [`crates/graphus-cypher/tests/wal_amplification.rs`](../../crates/graphus-cypher/tests/wal_amplification.rs)
> now drives a **real segmented `FileLogSink`** and **fails** on a reverted (fixed-64-MiB) segment on a
> small store (`rmp #719`) — the `MemLogSink` guard it replaced had no segments and was structurally blind
> to this. The gate in this example ([`wire_samples.rs`](../../crates/graphus-iot-gen/src/wire_samples.rs))
> holds the peak footprint to **120× the graph**, so a regression back to fixed 64 MiB segments is caught
> here too.

---

## What changed, and why (`rmp` #713)

This example already measured all of the above — and then **buried it**. `evidence/report.json`, the report
a reader actually opens, described the deterministic **in-memory mirror**: no WAL, no fsync, no
amplification, because an in-memory device has none. The real server's report sat in a side directory
(`evidence-wire/`) that nothing gated and nothing surfaced. The headline evidence of Graphus's ingest and
retention example described a *simulator*.

| Before | Now |
| --- | --- |
| `evidence/` = the in-memory **mirror** (no WAL, no fsync, no amplification) | `evidence/` = the **real server, over the wire** — the PRIMARY evidence |
| The real server's report in `evidence-wire/`, ungated, unread | The mirror in `evidence-mirror/` — a genuine instrument, but the **CONTROL** |
| `baseline.json` gated the simulator | `baseline.json` gates the **real server**; `baseline-mirror.json` gates the control |
| WAL amplification: a number in a note | **A first-class, gated signal.** The run FAILS if it regresses |
| `wal_bytes: 0` published for months, gate green | **Impossible now** — a zeroed or under-counted WAL fails the run |
| Default wire run: 3 000 readings — too short to certify reclamation with the then-fixed 64 MiB seal | Default `reclaim` profile: 7 000 readings ≈ 143 MB WAL — seals and frees **dozens** of small store-proportional segments |

The last row was the quiet one: the old default was sized so that — with the then-fixed 64 MiB seal —
the very reclamation the example claims never ran. `rmp #706` later made the seal size store-proportional,
so segments are now small and even short runs reclaim; the `reclaim` profile remains the default because it
sustains the churn long enough to reach a clear, stable steady state.

---

## The gates — and why each one can actually fire

"A gate that cannot fire is the same lie wearing a green tick" (`examples/README.md`). Every rule below is
a pure function of the measured samples ([`WireSamples::storage_gate`](../../crates/graphus-iot-gen/src/wire_samples.rs)),
and every one is **unit-tested to fire on the defect it names**.

| Gate | Fails when | Why it exists |
| --- | --- | --- |
| **Anti-rot** | writes were committed but `wal_bytes` / `bytes_fsynced` is **zero** | The exact rot being fixed: the WAL is a *directory* of `seg.<lsn>` files, a leaf-name classifier scored every one as store, and this example published `wal_bytes: 0` for months while asserting a green plateau. A commit is not durable until its redo record is fsynced — so a file-backed run that committed 7 135 writes and wrote no WAL is a **broken instrument**, not a measurement. |
| **Per-commit WAL floor** | fewer than **64 B of WAL per commit** | The subtle half, and the one a ceiling can *never* supply: an under-counted WAL makes every amplification figure **fall**, so it sails under any ceiling and reads like a triumph. Nor is an *amplification* floor enough — the data image alone is already ~1.2× the logical payload, so a 0.1 %-counted WAL still clears a naive 2× floor by coincidence. This floor encodes the physics instead (ARIES: N commits ⇒ N fsynced redo records; one record header alone is ~53 B) and is independent of store size. |
| **Write-amplification ceiling** (1 000×) | amplification regresses past the bound | A **ceiling, not a target**. The figure is bad today (799×), and an upper bound is the only honest way to gate a known-bad number: it cannot be satisfied by regressing, and it never has to be relaxed to accept a fix. |
| **Total-footprint ceiling** (450×) | peak `(store + WAL)` per byte of graph regresses | Judges the claim against the **database**, not one component of it. This is the check that stops a true statement about the store standing in for a false one about the whole. |
| **WAL reclamation happened** | the run sealed a segment but the WAL **never shrank** | The maintenance counters cannot stand in for this — they count MVCC versions in the *store* and climb happily while zero WAL bytes come back. Only watching the on-disk WAL actually *shrink* proves reclamation. |
| **Store plateau** + **reclamation climbed** | the store grows, or nothing was reclaimed | The original claim. Both halves needed: a flat store alone also describes a workload that wrote nothing. |

The reclamation gate is deliberately **asymmetric**, so it stays correct under a *fix*: the "sealed a
segment" branch demands reclamation; the "too short to seal" branch demands nothing of it. If `rmp` #706
lands and segments become small, short runs start sealing *and* reclaiming — and still pass. A gate that
failed on an improvement would be worse than no gate.

---

## The two instruments

| | `evidence/` — **PRIMARY** | `evidence-mirror/` — **CONTROL** |
| --- | --- | --- |
| What it is | the real `graphus-server`, driven over **Bolt** | the real engine, driven **in-process** |
| Device / WAL | **on disk** (`FileBlockDevice` + segmented WAL) | **in memory** (`MemBlockDevice` / `MemLogSink`) |
| Reclamation trigger | the **real** `CHECKPOINT DATABASE` + the background cadence | an explicit GC pass per tick — a deterministic stand-in |
| Durable bytes / WAL / fsync / amplification | **measured for real** | **structurally unmeasurable** — absent from the report (schema v3 omits what it did not measure), never zero-filled |
| Footprint curve | real, machine-dependent | **byte-reproducible** for a fixed seed |
| Gated by | `baseline.json` — **14 metrics compared, 0 skipped** | `baseline-mirror.json` |

The control is a genuine instrument, not decoration: a plateau you cannot reproduce is not a regression
gate, and its byte-reproducible curve pins the reclamation *logic* itself. But it runs on an in-memory
device, so it has no store file, no WAL file and no fsync — it can say **nothing** about what durability
costs. That is why it is no longer the headline.

---

## Running it

```bash
examples/iot-timeseries/run.sh                        # local self-boot; wire = `reclaim` profile (the default)
IOT_WIRE_PROFILE=soak  examples/iot-timeseries/run.sh # long, SUSTAINED wire run (300 ticks)
IOT_WIRE_PROFILE=fast  examples/iot-timeseries/run.sh # SHORTER wire run — see the warning below
IOT_PROFILE=large      examples/iot-timeseries/run.sh # scale up the in-memory CONTROL mirror
IOT_CHECKPOINT_EVERY=0 examples/iot-timeseries/run.sh # no operator trigger: lean on the background cadence alone
IOT_WIRE_CLIENTS=4     examples/iot-timeseries/run.sh # 4 concurrent sensor-sharded ingest connections
RUN_WIRE=0             examples/iot-timeseries/run.sh # CONTROL mirror only — collects NO durable-byte evidence
```

### Which profile produced which number

Every figure in this README comes from the **`reclaim`** profile unless the table says otherwise. The
profiles are not interchangeable, and the difference is not cosmetic:

| Wire profile | Readings | Cumulative WAL | Reaches a stable steady state? | What it can prove |
| --- | --- | --- | --- | --- |
| **`reclaim`** (default) | 7 000 | ~143 MB | **yes** — dozens of reclaims, a tight WAL sawtooth | the full cycle at steady state: the store plateaus, the WAL sawtooths and comes back |
| `fast` | 3 000 | ~59 MB | shorter — reclaims (store-proportional segments) but ends further from steady state | a quick smoke of the same churn (post-#706 it still reclaims) |
| `soak` | 9 000 | ~180 MB | yes | the plateau held over hundreds of consecutive post-warmup ticks |

`fast` is a legitimate measurement but it ends further from steady state than `reclaim`, so the run says
which of the two it measured rather than inheriting the green tick the store's plateau earned. The default
is `reclaim` precisely so the CI gate (`rmp` #704) exercises the branch that
demands WAL disk actually come back. Its churn loop takes **~9.5 s**.

### Against an already-running instance (attach mode)

```bash
GRAPHUS_TARGET_UDS=/path/to/graphus.sock \
GRAPHUS_TARGET_REST=http://127.0.0.1:7474 \
GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=... \
  examples/iot-timeseries/run.sh

# or, over the network:
GRAPHUS_TARGET_BOLT=bolt+ssc://host:7687 GRAPHUS_TARGET_REST=https://host:7474 \
GRAPHUS_TARGET_TLS_INSECURE=1 GRAPHUS_TARGET_USER=... GRAPHUS_TARGET_PASSWORD=... \
  examples/iot-timeseries/run.sh
```

Attach mode carves out an **isolated database**, runs the churn there, and drops it on exit — the target's
own data is never touched. The store files and `/proc` belong to the target, so the `storage`, `cpu` and
`memory` sections are **absent** from the report (not zero-filled); `measurement_mode: external` says so,
and the server-side evidence is the `/metrics` before → after delta. The storage gate correctly asserts
**nothing** in this mode: a gate must not punish a run for being unable to see a filesystem on another
host. Note the server **mandates TLS on Bolt-TCP**, so an already-running instance on *this* host is
attached over `GRAPHUS_TARGET_UDS`.

---

## What it demonstrates

| Capability | How it is exercised |
| --- | --- |
| **Time-series event-graph modelling** | `(:Sensor {id, kind, site, location})-[:EMITTED]->(:Reading {sensor, seq, ts, value})` |
| **Retention / TTL policy** | a sliding window: each tick `DETACH DELETE`s every reading older than `window` readings |
| **Index-backed retention sweep** | the aged-out `DELETE` **seeks** the `Reading.seq` RANGE index (asserted at the plan level, not assumed) |
| **A production-realistic schema** | `NODE KEY` on `Sensor.id`; existence + property-type constraints on the reading; `POINT` index on `Sensor.location`; composite `RANGE` index on `Reading(sensor, seq)`; `RANGE` index on `Reading.seq` |
| **Schema *enforcement*, over the wire** | a duplicate `Sensor.id`, a float `ts`, and a `value`-less reading are each **rejected** on a live session — and provably create nothing |
| **Concurrent ingest** | N Bolt connections, **sharded by sensor**, so writers never contend for the same node — the realistic "one gateway per group of devices" shape |
| **MVCC delete → tombstone → reclamation** | deleted readings are MVCC-tombstoned; a checkpoint's GC pass physically reclaims their slots into a free list new inserts reuse |
| **The operator trigger** | `CHECKPOINT DATABASE <db>`, issued over the same Bolt connection as everything else |
| **The automatic trigger** | the background maintenance cadence, firing on WAL growth with no operator at all |
| **Bounded store footprint** | the durable **store** plateaus — flat, despite total-ingested ≫ window |
| **Real durable-byte accounting** | store / doublewrite / WAL / catalog, classified **by path**; cumulative WAL volume; WAL segment reclamation events; kernel `write_bytes` cross-check |

---

## Measured evidence

Every figure is a real measurement from the committed baseline run — none is illustrative. Host: Linux
x86_64, 16 cores, release build, **`reclaim` profile** (8 sensors, rate 50/tick, window 200, 140 ticks →
7 000 readings = **35× the retention window**), 2 concurrent ingest connections, `CHECKPOINT DATABASE`
every 5 ticks. Throughput / latency / CPU / RSS are **machine-variant** and are never gated.

### The store plateaus while reclamation climbs

| Metric | Measured |
| --- | --- |
| Store data image, post-warmup band | `[229376, 229376]` B — **plateau ratio 1.000** (28 pages) |
| Total ingested | 7 000 readings (**35×** the window) |
| Steady-state live `:Reading` count | 200 (the window), held for every post-warmup tick |
| `graphus_maintenance_versions_reclaimed_total` | **+13 600** over the workload window |
| `graphus_maintenance_checkpoints_total` | **+45** (28 issued by `CHECKPOINT DATABASE`, 17 by the background cadence) |
| `graphus_maintenance_stamps_frozen_total` | +37 816 |
| Transactions committed / aborted | 7 292 / 3 — and the 3 aborts are exactly the 3 constraint violations the example *deliberately* attempts |
| `statement_panics` / `engine_recovery_panics` / `engine_force_detached` | **0 / 0 / 0** |

**Warmup is derived, not tuned.** The plateau claim starts only after (a) the window has filled and
(b) reclamation has run **twice** — because the store plateaus by *reusing* freed slots, and one
checkpoint's freed slots have not been consumed yet. That is `fill_ticks + 2 × checkpoint_every` = tick 15.

### The no-GC contrast

With the reclamation pass disabled, the same workload's footprint grows **49 152 B → 286 720 B (5.8×)** in
12 ticks. That is the curve reclamation flattens — and the reason the plateau is a *result*, not an
artefact of a workload that simply wrote nothing.

### What durability cost

| Metric | Measured | Note |
| --- | --- | --- |
| Store data image (`graphus.store`) | **229 376 B** | the graph itself — **0.3 %** of the footprint |
| Doublewrite buffer (`graphus.dwb`) | **8 871 936 B** | a **fixed preallocation** per database — not graph data, and deliberately not counted as store |
| WAL, **cumulative** bytes written (= `bytes_fsynced`) | **142 040 524 B** | every WAL byte is fsynced before its commit is acknowledged |
| WAL, on-disk **peak** | **5 426 043 B** | the honest worst case — ~13× smaller than the ~70 MB peak while #706 was open |
| WAL, residual at exit | **1 634 347 B** | never quote this without the peak beside it |
| **WAL segments reclaimed** | **36 events, 96 551 056 B returned** | the on-disk WAL physically *shrank* 36 times — small store-proportional segments come back on nearly every checkpoint (`rmp #706`) |
| **Total durable footprint** (store + WAL) | peak **14 527 355 B**, min **9 369 259 B** | **plateau ratio 1.55** — a tight sawtooth (was 7.12 while #706 was open) |
| **Peak footprint per byte of graph** | **63×** | the disk a deployment must provision — down from 347× |
| Kernel `write_bytes` (`/proc/<server-pid>/io`) | **189 947 904 B** | an independent cross-check from *outside* the engine |
| Logical payload ingested | **189 000 B** | 7 000 readings × 27 B (`sensor` + `seq` + `ts` + `value`) |
| **Write amplification** | **752.8×** | (cumulative WAL + data image) / logical bytes ingested — the WAL *format* (dual redo/undo), which #706 did not change |
| **Space amplification** | **~1 988×** | total on-disk / logical bytes retained at steady state (was ~4 742×); it is now dominated by the fixed 8.9 MB doublewrite preallocation, not the WAL |
| WAL bytes **per commit** | **~21 KB** | for a 27-byte reading. This is the number `rmp` #706 has to move. |

The amplification figures are staggering, and they are **correct**. They are dominated by the WAL (89 % of
the peak footprint) and the fixed doublewrite preallocation (11 %); the graph itself is 0.3 %.

### Throughput, latency, CPU, RAM

| Metric | PRIMARY (real server, Bolt-UDS) | CONTROL (in-process mirror) |
| --- | --- | --- |
| Workload wall-clock | 9.21 s | 0.64 s |
| Ingest throughput | 760 ops/s | 4 795 ops/s |
| Ingest latency p50 / p99 / p99.9 | 1.95 / 5.47 / 9.97 ms | — |
| Retention `DELETE` p50 / p99 | 2.79 / 4.10 ms | — |
| `CHECKPOINT DATABASE` p50 / p99 | 8.55 / 15.34 ms | n/a |
| Server CPU over the window | 2.17 s user + 1.56 s system = **0.40 cores** | n/a |
| Server peak RSS | 889.2 MB | n/a |
| SSI retries / abort rate | **0** / **0.0** | n/a |

The server used **0.40 of one core** to sustain this ingest. That is not a CPU ceiling — it is the
signature of a workload bound by **durability latency** (an `fsync` per commit group), not by compute. The
mirror is ~6× faster for exactly that reason: its WAL is a `Vec` in memory and never touches a disk.

**Process RSS is not a bounded-resource proof, and is never gated.** In the in-process mirror it is a
high-water of *allocator reservations* (glibc retains freed arenas), so it climbs even though the engine's
durable state is fully reclaimed — the deterministic footprint plateau is what proves the engine releases
its records.

---

## How the pieces fit

| Component | Path |
| --- | --- |
| Deterministic generator + retention policy + profiles | [`crates/graphus-iot-gen/src/lib.rs`](../../crates/graphus-iot-gen/src/lib.rs) |
| **File-backed wire driver** (Bolt, real server) — the PRIMARY instrument | [`crates/graphus-iot-gen/src/bin/iot_wire.rs`](../../crates/graphus-iot-gen/src/bin/iot_wire.rs) |
| The samples contract **+ the storage gate** (and its unit tests) | [`crates/graphus-iot-gen/src/wire_samples.rs`](../../crates/graphus-iot-gen/src/wire_samples.rs) |
| PRIMARY evidence emitter + invariant gate | [`crates/graphus-iot-gen/src/bin/iot_wire_evidence.rs`](../../crates/graphus-iot-gen/src/bin/iot_wire_evidence.rs) |
| Path-classified footprint accounting | [`crates/graphus-iot-gen/src/footprint.rs`](../../crates/graphus-iot-gen/src/footprint.rs) |
| In-process churn CONTROL (real engine, in-memory device) | [`crates/graphus-iot-gen/src/churn.rs`](../../crates/graphus-iot-gen/src/churn.rs) |
| CONTROL evidence emitter | [`crates/graphus-iot-gen/src/bin/iot_evidence.rs`](../../crates/graphus-iot-gen/src/bin/iot_evidence.rs) |
| Baseline regression gate (drives both baselines) | [`crates/graphus-iot-gen/src/bin/iot_baseline_cmp.rs`](../../crates/graphus-iot-gen/src/bin/iot_baseline_cmp.rs) |
| Hermetic plateau test (runs in the default `cargo test`) | [`crates/graphus-iot-gen/tests/churn_plateau.rs`](../../crates/graphus-iot-gen/tests/churn_plateau.rs) |
| Schema-parses-to-the-same-thing test | [`crates/graphus-server/tests/iot_timeseries_schema.rs`](../../crates/graphus-server/tests/iot_timeseries_schema.rs) |
| Checkpoint-metrics regression | [`crates/graphus-server/tests/checkpoint_maintenance_metrics_694.rs`](../../crates/graphus-server/tests/checkpoint_maintenance_metrics_694.rs) |

### A note on the WAL being a *directory*

The server's WAL is `databases/<db>/graphus.wal/` — a **directory** of `seg.<lsn>` files whose leaf names
contain no "wal" at all. Any code that classifies store-vs-WAL bytes by the **leaf file name** therefore
counts every WAL byte as store and reports `wal_bytes = 0`. `footprint.rs` classifies **by path**, a unit
test builds the real server layout in a temp dir and fails any implementation that does not — and the
storage gate now **fails the run** if the WAL comes back zero while writes were committed, so the same rot
cannot return silently.

---

## Evidence honesty

This example follows the suite's non-negotiable rules (`examples/README.md` → "Evidence-honesty rules"),
each of which exists because the opposite was previously done *here*:

* **Measure it or omit it.** No zero placeholders. The CONTROL mirror's WAL / fsync / amplification fields
  are **absent** — because they cannot be measured in memory — and the notes say so, rather than letting a
  reader mistake a zero for a result.
* **Report the right subject.** The PRIMARY report describes the **server**, not a simulator. The whole
  point of `rmp` #713: the report a reader opens must be the one that measured the thing being claimed.
* **`total_millis` is the workload's wall-time**, not the report's emission time.
* **Every field carries the quantity its name promises.** `storage.plateau_ratio` is the **store's**
  plateau, exactly as the schema defines it — and because that is a true statement about a *component*, the
  **total** durable footprint (store + WAL) is reported beside it under its own name, gated, and called out
  in the notes. A field that is honest in isolation can still mislead in context.
* **Sample the server, not the driver.** CPU, RSS and `write_bytes` are read from `/proc/<server-pid>`.
* **Never run a stale binary.** `run.sh` builds through the shared `harness_build` seam.
