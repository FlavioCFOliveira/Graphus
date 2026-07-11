# IoT / time-series event graph — ingest, retention churn & storage reclamation

A realistic, end-to-end demonstration that Graphus sustains a **continuous IoT telemetry workload** — a
fleet of sensors emitting time-stamped readings under a **sliding-window retention policy** that deletes
aged-out readings — and that, under this relentless *delete-old + insert-new churn*, the storage engine
**recycles the freed space** so the on-disk footprint reaches a **stable plateau** rather than growing
without bound.

The headline, proven over a **real Bolt wire** against a **real `graphus-server`** with a real store file
and a real segmented WAL on disk:

> **the on-disk store PLATEAUS *while* `graphus_maintenance_versions_reclaimed_total` CLIMBS**

Both halves are load-bearing, and neither is worth anything alone:

* a flat store, on its own, also describes a workload that **wrote nothing**;
* a climbing reclamation counter, on its own, does **not** rule out a footprint growing without bound.

Together they are the claim: under a sustained churn that ingests many times the retention window, the
engine physically reclaims the tombstoned versions and **new inserts reuse the freed space**.

---

## What changed, and why (rmp #694)

An audit rated this example **2.5/5**. It was right, and the problems were not cosmetic:

| Audit finding | What it actually meant | Status |
| --- | --- | --- |
| The central premise — "GC has no wire or automatic trigger" — is **false** | `rmp #305` shipped: `CHECKPOINT DATABASE` is a parsed admin statement, **and** a background cadence reclaims automatically. Five files still asserted the opposite. | **Corrected everywhere.** Both triggers are now exercised. |
| Storage was **in-memory** (`MemBlockDevice`/`MemLogSink`) | `wal_bytes = 0`. WAL volume, fsync volume and amplification were *structurally unmeasurable* — yet the report emitted them as if measured. | **New file-backed wire run** measures all of them for real. |
| UDS-only, self-boot only | Could not be pointed at a running instance. | **Attach mode** (`GRAPHUS_TARGET_*`), over Bolt-UDS or Bolt-TCP+TLS. |
| A few-thousand-record **burst**, not sustained | A *retention* claim means little if the plateau is held for 60 ticks. | **`soak` profile**: 300 ticks, 9 000 readings, 60× the window. |

Three genuine defects were found *while* fixing it, and all three are fixed here:

1. **The in-process driver planned every statement against `IndexCatalog::empty()`.** The schema it so
   carefully declared was invisible to the planner, so the per-tick retention `DELETE` — whose entire
   purpose is to seek the `Reading.seq` RANGE index — **full-scanned every `:Reading` on every tick**.
   Nothing failed: the results were identical and every assertion passed, while the example measured an
   unindexed engine and reported an indexed one.
2. **Worse: the indexes were never even built.** `begin_online_node_property_index_named` starts a
   *non-blocking* build that the server's engine loop pumps with `advance_index_builds`. This driver never
   pumped it, so the `Reading.seq` RANGE index and the `Sensor.location` POINT index sat `Populating`
   **forever** — never promoted, never usable. Both are now driven to completion before any data lands.
   Regression: `churn::tests::the_retention_delete_plans_as_an_index_range_seek_not_a_scan`, which asserts
   the *planned shape* and proves it has teeth by showing the same statement degrade to a scan under an
   empty catalog.
3. **An operator `CHECKPOINT DATABASE` was never counted on `/metrics`.** The maintenance counters
   document themselves as *"operator `CHECKPOINT DATABASE` **+** the background cadence"*, but only the
   cadence ever recorded into them — so an operator-triggered reclamation pass freed slots completely
   invisibly. That is the *only* server-side channel proving a checkpoint did any work on an attached or
   remote instance. Fixed in `graphus-server/src/engine/mod.rs`; regression:
   `graphus-server/tests/checkpoint_maintenance_metrics_694.rs`.

---

## What it demonstrates

| Capability | How it is exercised |
| --- | --- |
| **Time-series event-graph modelling** | `(:Sensor {id, kind, site, location})-[:EMITTED]->(:Reading {sensor, seq, ts, value})`, one reading per discrete tick |
| **Retention / TTL policy** | a sliding window: each tick `DETACH DELETE`s every reading older than `window` readings |
| **Index-backed retention sweep** | the aged-out `DELETE` **seeks** the `Reading.seq` RANGE index (asserted at the plan level, not assumed) |
| **A production-realistic schema** | `NODE KEY` on `Sensor.id`; existence + property-type constraints on the reading; `POINT` index on `Sensor.location`; composite `RANGE` index on `Reading(sensor, seq)`; `RANGE` index on `Reading.seq` |
| **Schema *enforcement*, over the wire** | a duplicate `Sensor.id`, a float `ts`, and a `value`-less reading are each **rejected** on a live session — and provably create nothing |
| **Concurrent ingest** | N Bolt connections, **sharded by sensor**, so writers never contend for the same node — the realistic "one gateway per group of devices" shape |
| **MVCC delete → tombstone → reclamation** | deleted readings are MVCC-tombstoned; a checkpoint's GC pass physically reclaims their slots into a free list new inserts reuse |
| **The operator trigger** | `CHECKPOINT DATABASE <db>`, issued over the same Bolt connection as everything else |
| **The automatic trigger** | the background maintenance cadence, firing on WAL growth with no operator at all |
| **Bounded on-disk footprint** | the durable store **plateaus** — flat, despite total-ingested ≫ window |
| **Real durable-byte accounting** | store / doublewrite / WAL / catalog, classified **by path**; cumulative WAL volume; kernel `write_bytes` cross-check |

---

## The two runs, and why there are two

| | `evidence/` — the **deterministic mirror** | `evidence-wire/` — the **file-backed wire run** |
| --- | --- | --- |
| Engine | real, driven **in-process** | real, driven over **Bolt** |
| Device / WAL | **in memory** (`MemBlockDevice` / `MemLogSink`) | **on disk** (`FileBlockDevice` + segmented WAL) |
| Reclamation trigger | an explicit GC pass per tick — the *deterministic stand-in* | the **real** `CHECKPOINT DATABASE` + the background cadence |
| Footprint curve | **byte-reproducible** for a fixed seed | real, and machine-dependent |
| Gated by `baseline.json` | **yes** — this is what the committed baseline holds | no (host-dependent) |
| Durable bytes / WAL / fsync / amplification | **NOT MEASURABLE** — the WAL/fsync/amplification fields are **ABSENT** from the report (schema v3 omits what it did not measure), and the notes say so out loud. `store_bytes` IS measured: it is the in-memory device's steady-state plateau. | **measured for real** |
| `storage.plateau_ratio` | **measured** — the largest post-warmup footprint over the smallest (`1.0` = a flat plateau). This is the ONE example in the suite with a genuine steady state, so it is the only one that carries the field; everywhere else it is absent, because nowhere else *is* there a plateau. | **measured** |
| `storage.bytes_per_node` / `bytes_per_relationship` | **measured** — the plateau footprint amortised over the steady-state graph it holds (the live readings plus their sensors) | **measured** over the durable image |

The mirror exists because a plateau you cannot reproduce is not a regression gate. The wire run exists
because a storage claim you cannot weigh in bytes is not evidence. Neither substitutes for the other, and
the mirror no longer pretends to storage numbers it cannot have.

---

## Running it

```bash
examples/iot-timeseries/run.sh                       # local self-boot, fast profile
IOT_PROFILE=soak      examples/iot-timeseries/run.sh # long, SUSTAINED run (300 ticks, 60x the window)
IOT_WIRE_PROFILE=soak examples/iot-timeseries/run.sh # soak the WIRE run only
IOT_CHECKPOINT_EVERY=0 examples/iot-timeseries/run.sh# no operator trigger: lean on the background cadence alone
IOT_WIRE_CLIENTS=4    examples/iot-timeseries/run.sh # 4 concurrent sensor-sharded ingest connections
RUN_WIRE=0            examples/iot-timeseries/run.sh # mirror only
```

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
`memory` sections carry **nothing**; `measurement_mode: external` and explicit
`storage_measured=no` / `server_cpu_measured=no` / `server_rss_measured=no` params say so, and the
server-side evidence is the `/metrics` before → after delta. Note the server **mandates TLS on Bolt-TCP**,
so an already-running instance on *this* host is attached over `GRAPHUS_TARGET_UDS`.

---

## Measured evidence

Every figure below is a real measurement from a committed run — none is illustrative. Host: Linux x86_64,
16 cores (`ROG`), release build, `fast` profile (8 sensors, rate 50/tick, window 200, 60 ticks → 3 000
readings = **15× the retention window**), 2 concurrent ingest connections, `CHECKPOINT DATABASE` every 5
ticks. Throughput/latency/CPU/RSS are **machine-variant** and are never gated.

### The headline: the store plateaus while reclamation climbs

```
store data image (bytes), per tick:
  49152 → 73728 → 90112 → 114688 → 139264 → 139264 → 155648 → 180224 → 212992 → 229376
                                                                                    ↑ tick 9
  then FLAT at 229376 for every one of ticks 10…59, while 2 450 more readings are ingested.
```

| Metric | Measured |
| --- | --- |
| Store data image, post-warmup band | `[229376, 229376]` B — **plateau ratio 1.000** (28 pages) |
| Total ingested | 3 000 readings (**15×** the window) |
| Steady-state live `:Reading` count | 200 (the window), held for every post-warmup tick |
| `graphus_maintenance_versions_reclaimed_total` | **+5 600** over the workload window |
| `graphus_maintenance_checkpoints_total` | **+18** (12 issued by `CHECKPOINT DATABASE`, 6 by the background cadence) |
| `graphus_maintenance_stamps_frozen_total` | +15 616 |
| Transactions committed / aborted | 3 132 / 3 — and the 3 aborts are exactly the 3 constraint violations the example *deliberately* attempts |
| `statement_panics` | 0 |

**Warmup is derived, not tuned.** The plateau claim starts only after (a) the window has filled and
(b) reclamation has run **twice** — because the store plateaus by *reusing* freed slots, and one
checkpoint's freed slots have not been consumed yet. That is `fill_ticks + 2 × checkpoint_every` = tick 15
here, comfortably after the curve above has already settled at tick 9.

### The no-GC contrast

With the reclamation pass disabled, the same workload's footprint grows **49 152 B → 286 720 B (5.8×)**
in 12 ticks. That is the curve reclamation flattens — and the reason the plateau is a *result*, not an
artefact of a workload that simply wrote nothing.

### Real durable bytes (the numbers the old in-memory run could not have)

| Metric | Measured | Note |
| --- | --- | --- |
| Store data image (`graphus.store`) | **229 376 B** | the graph itself |
| Doublewrite buffer (`graphus.dwb`) | **8 871 936 B** | a **fixed preallocation** per database — not graph data, and deliberately not counted as store |
| WAL, cumulative bytes written | **59 619 922 B** | every WAL byte is fsynced before its commit is acknowledged |
| WAL, on-disk peak | **59 619 922 B** | |
| Kernel `write_bytes` (`/proc/<server-pid>/io`) | **77 049 856 B** | an independent cross-check from *outside* the engine |
| Logical payload ingested | **81 000 B** | 3 000 readings × (`s-N` + `seq` + `ts` + `value`) |
| **Write amplification** | **739×** | (cumulative WAL + data image) / logical bytes ingested |
| **Space amplification** | **12 726×** | total on-disk / logical bytes retained at steady state |

Those last two are staggering, and they are **correct**. They are dominated by the WAL (87 % of the
footprint) and the fixed doublewrite preallocation (13 %); the graph itself is 0.3 %. Which brings us to
the finding.

### FINDING: the on-disk WAL does **not** plateau — it sawtooths

The store plateaus. The WAL does not. Measured on the `soak` profile (300 ticks, 9 000 readings), the
on-disk WAL climbs to ~67 MB, **drops to 5 MB**, climbs to ~66 MB, drops to 3.3 MB — while the store sits
flat at 172 032 B throughout. **Peak WAL/store ratio: 260× on `fast`, ~390× on `soak`.**

**Root cause** (traced, not guessed): WAL disk is reclaimed in whole **segment** units, and the active
segment is only sealed at `DEFAULT_SEGMENT_TARGET_BYTES = 64 MiB`
([`graphus-wal/src/sink.rs`](../../crates/graphus-wal/src/sink.rs)). The background maintenance cadence,
meanwhile, *is* adaptive — it fires every `clamp(4 × store_bytes, 8 MiB, 256 MiB)`, i.e. every 8 MiB for a
store this size (`rmp #556`). So the reclaim **floor advances promptly and correctly**, but for the first
64 MiB of WAL there is no *sealed* segment below it to delete, and **no disk is freed at all**. When the
segment finally rolls, the whole 64 MiB is released at once — hence the sawtooth. The *cadence* was made
store-proportional; the reclaim **granularity** was not.

**Impact.** A database holding a few hundred rows still carries up to ~64 MiB of WAL on disk,
indefinitely, *per database*. This is **not** a durability defect — nothing is lost and recovery is
unaffected — but it is a real footprint defect, and it bites hardest exactly where it hurts most: a
Raspberry Pi 5 hosting several small databases.

**Suggested direction.** Make the segment target adaptive in the same spirit as the cadence — e.g.
`clamp(k × store_bytes, 1 MiB, 64 MiB)` — so reclaim granularity tracks the store it protects.

The example reports this loudly in `evidence-wire/report.json` and **does not gate on it**: the claim
under test is that the *store* plateaus while reclamation climbs, and it does. Rounding an inconvenient
measurement away would be precisely the dishonesty this example was audited for.

### Throughput, latency, CPU, RAM

| Metric | Wire run (real server, over Bolt-UDS) | Deterministic mirror (in-process) |
| --- | --- | --- |
| Workload wall-clock | 9.13 s | 1.62 s |
| Ingest throughput | 329 ops/s | 1 892 ops/s |
| Ingest latency p50 / p99 / p99.9 | 4.37 / 13.54 / 66.54 ms | 0.36 / 3.59 / 4.53 ms |
| Retention `DELETE` p50 / p99 | 5.26 / 14.91 ms | (see `retention_delete_latency_ms`) |
| `CHECKPOINT DATABASE` p50 / p99 | 15.69 / 32.77 ms | n/a |
| Server CPU over the window | 1.97 s user + 1.52 s system = **0.38 cores** | n/a |
| Server peak RSS | 445.9 MB | n/a |
| SSI retries | **0** (sensor-sharded ingest is conflict-free by construction) | n/a |

The server used **0.38 of one core** to sustain this ingest. That is not a CPU ceiling — it is the
signature of a workload bound by **durability latency** (an `fsync` per commit group), not by compute.
The wire run is ~5.7× slower than the in-process mirror for exactly that reason: the mirror's WAL is a
`Vec` in memory and never touches a disk.

**Process RSS is not a bounded-resource proof, and is never gated.** In the in-process mirror it is a
high-water of *allocator reservations* (glibc retains freed arenas), so it climbs even though the engine's
durable state is fully reclaimed — the deterministic footprint plateau is what proves the engine releases
its records. The mirror's report says exactly this, and no longer claims "RAM stays bounded" while
recording `rss_bounded=false` two fields below.

---

## How the pieces fit

| Component | Path |
| --- | --- |
| Deterministic generator + retention policy | [`crates/graphus-iot-gen/src/lib.rs`](../../crates/graphus-iot-gen/src/lib.rs) |
| In-process churn mirror (real engine, in-memory device) | [`crates/graphus-iot-gen/src/churn.rs`](../../crates/graphus-iot-gen/src/churn.rs) |
| **File-backed wire driver** (Bolt, real server) | [`crates/graphus-iot-gen/src/bin/iot_wire.rs`](../../crates/graphus-iot-gen/src/bin/iot_wire.rs) |
| Wire evidence emitter + invariant gate | [`crates/graphus-iot-gen/src/bin/iot_wire_evidence.rs`](../../crates/graphus-iot-gen/src/bin/iot_wire_evidence.rs) |
| Path-classified footprint accounting | [`crates/graphus-iot-gen/src/footprint.rs`](../../crates/graphus-iot-gen/src/footprint.rs) |
| Mirror evidence emitter | [`crates/graphus-iot-gen/src/bin/iot_evidence.rs`](../../crates/graphus-iot-gen/src/bin/iot_evidence.rs) |
| Baseline regression gate | [`crates/graphus-iot-gen/src/bin/iot_baseline_cmp.rs`](../../crates/graphus-iot-gen/src/bin/iot_baseline_cmp.rs) |
| Hermetic plateau test (runs in the default `cargo test`) | [`crates/graphus-iot-gen/tests/churn_plateau.rs`](../../crates/graphus-iot-gen/tests/churn_plateau.rs) |
| Schema-parses-to-the-same-thing test | [`crates/graphus-server/tests/iot_timeseries_schema.rs`](../../crates/graphus-server/tests/iot_timeseries_schema.rs) |
| Checkpoint-metrics regression | [`crates/graphus-server/tests/checkpoint_maintenance_metrics_694.rs`](../../crates/graphus-server/tests/checkpoint_maintenance_metrics_694.rs) |

### A note on the WAL being a *directory*

The server's WAL is `databases/<db>/graphus.wal/` — a **directory** of `seg.<lsn>` files whose leaf names
contain no "wal" at all. Any code that classifies store-vs-WAL bytes by the **leaf file name** therefore
counts every WAL byte as store and reports `wal_bytes = 0`. `footprint.rs` classifies **by path**, and a
unit test builds the real server layout in a temp dir and fails any implementation that does not.

---

## Evidence honesty

This example follows the suite's non-negotiable rules (`examples/README.md` → "Evidence-honesty rules"),
each of which exists because the opposite was previously done *here*:

* **Measure it or omit it.** No zero placeholders. The mirror's `wal_bytes` / `bytes_fsynced` /
  amplification are `0` **because they cannot be measured in memory**, and the report says so in a note
  rather than letting a reader mistake a zero for a result.
* **`total_millis` is the workload's wall-time.** The previous baseline recorded `0.0247 ms` for a
  6.6-second run — it was timing the report emission.
* **Every field carries the quantity its name promises.** `write_amplification` used to smuggle the
  *plateau ratio* and `space_amplification` the *bytes-per-live-reading*. Both now carry amplification;
  the plateau ratio has its own name.
* **Sample the server, not the driver.** CPU, RSS and `write_bytes` are read from `/proc/<server-pid>`.
* **Never run a stale binary.** `run.sh` builds through the shared `harness_build` seam.
