# IoT / time-series event graph — ingest, churn & storage reclamation

A realistic, end-to-end demonstration that Graphus sustains a **continuous IoT telemetry workload**
— a fleet of sensors emitting time-stamped readings under a **sliding-window retention policy** that
deletes aged-out readings — and that, under this relentless *delete-old + insert-new churn*, the
storage engine **recycles freed space** so the on-disk footprint reaches a **stable plateau** rather
than growing without bound.

It is the suite's storage-reclamation example: it proves the corpse / page / slot reclamation
machinery (`rmp #220`, `#225`) end to end, with real numbers showing the footprint curve flatten.

---

## What it demonstrates

| Capability | How it is exercised |
| --- | --- |
| **Time-series event-graph modelling** | a `(:Sensor)-[:EMITTED]->(:Reading {seq, ts, value})` LPG, one reading per discrete tick |
| **Retention / TTL policy** | a sliding window: each tick `DETACH DELETE`s every reading older than `window` readings |
| **Sustained ingest + deletion to a steady state** | a long churn loop drives the real engine to a steady state where the live reading count stabilises around `window` |
| **MVCC delete + tombstone + GC reclamation** | deleted readings are MVCC-tombstoned; a GC maintenance pass physically reclaims their slots into a free-list new inserts reuse |
| **Bounded on-disk footprint under churn** | the durable footprint **plateaus** — bounded despite total-ingested ≫ window — and the page **high-water mark** is reported |
| **Deterministic, reproducible workload** | a seeded generator emits a byte-identical churn stream; the whole proof is reproducible |

---

## The time-series model

A directed Label Property Graph modelling a sensor fleet and its telemetry:

| Node label | Key properties | Meaning |
| --- | --- | --- |
| `(:Sensor {id, kind, site})` | `id` = `s-<n>` | a physical sensor / device (created once; never churned) |
| `(:Reading {sensor, seq, ts, value})` | `seq` = global monotonic | one time-stamped sample (the churned record) |

One relationship type carries the time-series edge:

| Relationship | Direction | Meaning |
| --- | --- | --- |
| `:EMITTED` | `(:Sensor)->(:Reading)` | the sensor produced this reading |

Readings are modelled as **nodes** (not relationship-only payloads) deliberately: deleting a reading
with `DETACH DELETE` tombstones a **node** record, its **property** versions, *and* its incident
`:EMITTED` **relationship** — so every store kind (node / rel / property / overflow) is recycled
under churn, which is exactly what the reclamation proof targets.

### Logical time and the retention window

Time is discrete. A global monotonic sequence `seq` (`0, 1, 2, …`) is assigned to readings in order;
each reading's `ts = EPOCH_MS + seq * TICK_MS`, so `seq` and `ts` are order-equivalent. The
**retention window** is expressed as a number of readings, `window`: at any tick the policy keeps the
most-recent `window` readings and deletes everything with `seq < high_water_seq − window`. Because
the per-tick insert rate is fixed, a window of `W` readings equals a wall-clock window of
`W × TICK_MS` ms.

The steady-state live `Reading` count therefore converges to `window` (± at most one tick's `rate`,
i.e. the band `[window, window + rate)`).

---

## Layout

```
examples/iot-timeseries/
├── README.md          # this file
├── run.sh             # self-contained E2E: generator determinism + churn proof + (optional) wire demo
├── data/
│   └── churn_cli.sh   # the optional Bolt-over-UDS wire demonstration (graphus-cli) of ingest+retention
├── baseline.json      # committed reference evidence report (structural metrics; written by #297-300)
└── evidence/          # written at run time (git-ignored): report.json + report.md
```

The deterministic generator + the real-engine churn workload live in the dev-only leaf crate
[`crates/graphus-iot-gen`](../../crates/graphus-iot-gen) (depended on by **nothing** in the
production build — in particular **not** `graphus-server`, so it adds zero overhead to the shipped
binary), exposing three binaries:

- **`iot_gen`** — the hermetic, seeded generator: writes `stream.cypher` (schema + per-tick
  INSERT/DELETE churn) for a profile. Output is byte-identical per config (CI-runnable, no engine).
- **`iot_churn`** — the sustained ingest + retention churn workload + the storage-reclamation proof,
  driving the **real engine** (see *Transport* below).
- **`iot_baseline_cmp`** — the structural-metrics regression gate vs the committed `baseline.json`.

---

## Transport — why the reclamation proof runs the engine in-process

> **Honest design note, backed by the code.** Graphus's MVCC garbage collection
> (`RecordStore::gc`) is a **maintenance operation**: it is WAL-logged and crash-safe, but the live
> server exposes **no automatic, scheduled, or wire-reachable trigger** for it — there is no GC
> `EngineCommand`, no `gds`-style Cypher procedure, and no admin statement that runs a GC pass
> (verified against `graphus-server`'s command surface). Reclamation is reachable only through the
> in-process store seam (`TxnCoordinator::with_store_mut` → `RecordStore::gc`), as used by the DST
> harness and the storage test suite.

This has a concrete, *measurable* consequence, which the example shows honestly:

- **Over the wire (Bolt / REST), with no GC pass, the footprint grows linearly** with total-ingested
  — the delete only *tombstones* records; nothing reclaims the slots. This is **not** a bug: the
  reclamation machinery (free-list reuse + `#220` corpse splice) is correct and proven by the storage
  test suite; it is simply that the *trigger* is a deliberate maintenance step, not an automatic one.
- **With the GC maintenance pass interleaved, the footprint plateaus** — freed slots are reused.

So the reclamation proof (`iot_churn`) drives the **production command-dispatch code path**
(`TxnCoordinator::statement` + `execute` — *exactly* what the server's `handle_run` runs for every
`RUN`) **inline and single-threaded**, interleaving the GC maintenance pass. This is the real engine,
real Cypher, real WAL-logged storage — just driven deterministically in one process so the
steady-state and the plateau are reproducible and assertable. It follows the same precedent as the
`fraud-oltp` example's `dst_contention` driver and the `bulk-etl` example's offline real-engine
binaries.

To *also* show the churn over a real **Bolt-over-UDS wire**, `run.sh` optionally runs
[`data/churn_cli.sh`](data/churn_cli.sh): it boots a real `graphus-server`, drives ingest + retention
over a Unix Domain Socket with `graphus-cli`, and asserts the steady-state live count over the wire
(the wire path tombstones; it does not — and by design cannot — run GC).

---

## The proof, with real numbers (fast profile)

The fast profile churns `rate = 50` readings/tick for `ticks = 60` ticks under a `window = 200`
retention window — **3 000 readings ingested in total, 15× the window**.

### Steady-state live count (`rmp #295`)

After the window fills (~tick 5), the live `Reading` count holds flat at **200 = `window`** for the
remaining 55 ticks, with no error:

```
  tick  total_ingested   live   footprint_B   pages   reclaimed
     0              50     50        49152       6          0
     5             300    200       139264      17        100
    30            1550    200       139264      17        100
    59            3000    200       139264      17        100
  ✓ steady-state live count held in [200, 250) for 55 post-warmup ticks
```

### Storage reclamation — the footprint plateau (`rmp #296`)

With the GC maintenance pass interleaved, the durable footprint reaches a **plateau at 17 pages
(139 264 B)** by tick 5 and stays *exactly* there through tick 59 — `plateau_ratio = 1.000` — while
**15× the window** is ingested. Each tick reclaims `100` slots, reused by the next tick's inserts:

```
  storage: page_high_water=17 footprint_high_water=139264B steady_band=[139264, 139264]B
           plateau_ratio=1.000 (≤1.50) total_ingested/window=15.0×
  ✓ footprint PLATEAUED: bounded within 1.50× while ingesting 15.0× the window (reclaimed space reused)
```

### The honest contrast — what happens *without* a GC pass

Run with `--no-gc` and the same churn (here a 12-tick slice for speed), the footprint grows
**6 → 35 pages (5.8×) over just 600 readings** while the live count stays at 200 — the tombstones
accrue without reclamation. This is the curve the GC pass flattens:

```
  (no-GC contrast) footprint grew 49152B -> 286720B (5.8×) over 600 ingested
                   — tombstones accrue without a GC pass; this is the curve GC flattens
```

> **Footprint metric.** The on-disk footprint is the durable device **page high-water × page size**
> (8 KiB pages) — identical to what a real store file's `length / PAGE_SIZE` reports. The workload
> runs on the project's deterministic in-memory device so the page high-water is reproducible
> bit-for-bit; on a file-backed store the same plateau holds, as the storage test suite's
> file-backed reclamation tests confirm.

---

## How to run it

```bash
examples/iot-timeseries/run.sh                       # fast profile; builds binaries if needed
GRAPHUS_BIN_DIR=target/release  examples/iot-timeseries/run.sh
IOT_PROFILE=large               examples/iot-timeseries/run.sh   # evidence-scale churn
RUN_WIRE=0                      examples/iot-timeseries/run.sh   # skip the Bolt-over-UDS wire demo
```

The script:

1. **Generator determinism** — generates `stream.cypher` twice and proves it is **byte-identical**
   per seed (`rmp #294` AC). Hermetic, always runs.
2. **Sustained ingest + churn + reclamation proof** — runs `iot_churn`, asserting the steady-state
   live count (`#295`) **and** the footprint plateau despite total-ingested ≫ window (`#296`), and
   reporting the page high-water mark. Captures machine-readable per-round samples.
3. **No-GC contrast** — a short `--no-gc` slice, showing the linear-growth curve GC flattens
   (informational).
4. *(optional)* **Bolt-over-UDS wire demo** — boots a real server and drives ingest + retention over
   a UDS with `graphus-cli`, asserting the steady-state live count over the real wire.
5. **Evidence** — the standardized `report.json` + `report.md` (storage footprint + high-water +
   throughput) land in the git-ignored `evidence/` dir, gated against `baseline.json` on structural
   metrics. *(Evidence emission + baseline are wired by sibling tasks `#297`–`#300`.)*

`run.sh` exits non-zero the moment any assertion fails — it doubles as an executable E2E test.

---

## Evidence collected

Per the project's *Examples* rule, the example collects explicit evidence across Graphus's
performance vectors:

- **Storage** — the durable footprint curve (footprint vs total-ingested), the **plateau** band, the
  **page high-water mark**, and reclaimed-slots-per-tick. This is the headline evidence: bounded
  growth under unbounded total churn.
- **Throughput** — readings ingested + deleted per second over the run.
- **CPU / memory** — captured by the shared harness for the wire-server phase.

All evidence is written to `evidence/` (git-ignored) as `report.json` (the stable, versioned schema)
and `report.md`.
