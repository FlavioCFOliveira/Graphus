# IoT / time-series event graph — ingest, churn & storage reclamation

A realistic, end-to-end demonstration that Graphus sustains a **continuous IoT telemetry workload**
— a fleet of sensors emitting time-stamped readings under a **sliding-window retention policy** that
deletes aged-out readings — and that, under this relentless *delete-old + insert-new churn*, the
storage engine **recycles freed space** so the on-disk footprint reaches a **stable plateau** rather
than growing without bound.

It is the suite's storage-reclamation example: it proves the corpse / page / slot reclamation
machinery (`rmp #220`, `#225`) end to end, with real numbers showing the footprint curve flatten.

The headline invariant — **the on-disk footprint plateaus under sustained churn** — is regression-
guarded in the **default `cargo test`** by a hermetic in-process mirror
([`tests/churn_plateau.rs`](../../crates/graphus-iot-gen/tests/churn_plateau.rs), `rmp #299`), and the
full E2E run emits a standardized, schema-versioned evidence report gated against a committed baseline
(`rmp #297`–`#300`).

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
├── baseline.json      # committed reference evidence report (gated on structural metrics)
└── evidence/          # written at run time (git-ignored): report.json + report.md
```

The deterministic generator + the real-engine churn workload live in the dev-only leaf crate
[`crates/graphus-iot-gen`](../../crates/graphus-iot-gen) (depended on by **nothing** in the
production build — in particular **not** `graphus-server`, so it adds zero overhead to the shipped
binary), exposing four binaries (the shared churn engine lives in its `churn` library module, reused
by the binaries **and** the hermetic test):

- **`iot_gen`** — the hermetic, seeded generator: writes `stream.cypher` (schema + per-tick
  INSERT/DELETE churn) for a profile. Output is byte-identical per config (CI-runnable, no engine).
- **`iot_churn`** — the sustained ingest + retention churn workload + the storage-reclamation proof,
  driving the **real engine** (see *Transport* below).
- **`iot_evidence`** — drives the *same* in-process churn run, additionally samples process RSS over
  the loop, and folds the footprint time series + page high-water + `plateau_ratio` + RSS series +
  throughput + end-to-end time into the standardized `report.json` + `report.md`.
- **`iot_baseline_cmp`** — the structural-metrics regression gate vs the committed `baseline.json`.

---

## Transport — why the reclamation proof runs the engine in-process

> **Honest design note, backed by the code.** Graphus's MVCC garbage collection
> (`RecordStore::gc`) is a **maintenance operation**: it is WAL-logged and crash-safe, but the live
> server exposes **no automatic, scheduled, or wire-reachable trigger** for it — there is no GC
> `EngineCommand`, no `gds`-style Cypher procedure, and no admin statement that runs a GC pass
> (verified against `graphus-server`'s command surface). Reclamation is reachable only through the
> in-process store seam (`TxnCoordinator::with_store_mut` → `RecordStore::gc`), as used by the DST
> harness and the storage test suite. **An operator-reachable GC trigger (an admin statement /
> EngineCommand) is filed as the improvement `rmp #305`.**

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
examples/iot-timeseries/run.sh                       # fast profile (CI-fast); builds binaries if needed
GRAPHUS_BIN_DIR=target/release  examples/iot-timeseries/run.sh
IOT_PROFILE=large               examples/iot-timeseries/run.sh   # evidence-scale churn
IOT_TICKS=300                   examples/iot-timeseries/run.sh   # long-running steady-state (plateau held for more ticks)
RUN_WIRE=0                      examples/iot-timeseries/run.sh   # skip the Bolt-over-UDS wire demo
```

**Profiles & knobs.** `IOT_PROFILE` (`fast` default / `large` evidence-scale) sizes the fleet, rate,
window and tick count. `IOT_TICKS` is the *long-running steady-state* knob: it overrides only the
**evidence** run's tick count, so the flat footprint is demonstrated for as long as you ask — the
deterministic structural metrics the baseline gates (page high-water, plateau footprint) are
unaffected, only *how long* the plateau is observed. The default (no `IOT_TICKS`, `fast`) is the
short, CI-fast, baseline-comparable run. A custom-`IOT_TICKS` or non-`fast` run skips the baseline
gate (it is not byte-comparable to the committed fast/default baseline).

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
5. **Evidence + baseline gate** — runs `iot_evidence` to emit the standardized `report.json` +
   `report.md` (footprint time series + page high-water + `plateau_ratio` + RSS series + throughput +
   time) into the git-ignored `evidence/` dir, then gates a fresh fast/default run against
   `baseline.json` on the **structural** metrics via `iot_baseline_cmp`. The evidence path is printed
   in the summary.

`run.sh` cleans up after itself (a `trap` removes the private temp workspace on exit; the optional
wire server is owned + torn down by `data/churn_cli.sh`'s own lifecycle, so this script never holds a
background server PID — there is no bare-`wait` hazard), and exits non-zero the moment any assertion
fails — it doubles as an executable E2E test.

### The hermetic default-`cargo test` mirror (`rmp #299`)

The footprint-plateau invariant is *also* guarded in the **default `cargo test`** run with **no
server, no Bolt driver, no network** — [`tests/churn_plateau.rs`](../../crates/graphus-iot-gen/tests/churn_plateau.rs)
drives the same in-process churn engine at a tiny, fast config (total-ingested = 10× the window) and
asserts the footprint is *exactly flat* post-warmup (`plateau_ratio == 1.0`), the steady-state live
count holds in `[window, window+rate)`, **and** that *without* GC the footprint does **not** plateau
(so the plateau is demonstrably caused by reclamation, not a no-op). It runs as part of
`cargo test --all`.

---

## Evidence collected

Per the project's *Examples* rule, the example collects explicit evidence across Graphus's
performance vectors into the standardized, schema-versioned `report.json` + `report.md` (written to
the git-ignored `evidence/` dir by `iot_evidence`). Four aligned series are captured over the *same*
churn loop:

- **Storage footprint time series + plateau (the headline).** A per-tick footprint sample
  (`footprint_series` = `tick:bytes`), the **page high-water mark** (`storage.store_pages`), the
  post-warmup **plateau band** (`plateau_min_bytes` / `plateau_max_bytes`, mapped onto
  `storage.store_bytes`), and the **`plateau_ratio`** (`max / min` of the band — `1.000` means the
  footprint is *exactly* flat / fully reclaimed). This is the bounded-resource proof: growth then a
  flat plateau while total-ingested ≫ window.
- **RSS time series (process RAM).** A per-tick RSS sample (`rss_series` = `tick:bytes`) plus peak /
  final RSS (`memory.*`). **Read this honestly:** in the single-process inline driver, process RSS is
  a *high-water of allocator reservations*, not live engine memory — glibc retains freed arenas, so
  RSS climbs as a high-water even though the engine's durable state is fully reclaimed (the flat
  footprint above proves the engine *does* release its records). RSS is recorded for visibility only;
  the **footprint plateau is the bounded-resource signal**, not RSS.
- **Throughput.** Readings ingested + retention deletes per second over the loop
  (`throughput.ops_per_sec`, `ingest_events_per_sec`).
- **End-to-end time.** The churn-loop wall clock (`churn` phase + the run total).

### How to read the evidence — and the threshold split

The baseline gate (`iot_baseline_cmp`) deliberately splits the metrics by reproducibility:

| Family | Metrics | Gate |
| --- | --- | --- |
| **Structural (deterministic, tight)** | plateau footprint `storage.store_bytes`, page high-water `storage.store_pages`, `plateau_ratio` (carried as `storage.write_amplification`), per-live-reading cost (`storage.space_amplification`) | **gated ±15 %** |
| **Machine-variant (ungated)** | RSS (`memory.*`), throughput (`throughput.*`), CPU, wall-time | **∞ tolerance** |

For a fixed seed + profile the churn stream — and therefore the plateaued store footprint it produces
on the deterministic in-memory device — is byte-reproducible, so a footprint that drifts beyond the
band is a genuine storage-engine (reclamation) regression worth failing. RSS / throughput / time are
machine- and timing-dependent and would be flaky to gate across machines, so they are recorded for
human visibility but given an effectively-infinite tolerance.

### Honest caveat (carried from `rmp #296` / `#305`)

The plateau is proven by interleaving an **explicit GC maintenance pass** per tick through the
in-process store seam, because the live server has **no automatic, scheduled, or over-the-wire GC
trigger** (see *Transport* above) — this is the real engine, real Cypher, real WAL-logged storage,
just driven deterministically in one process. An operator-reachable GC trigger is filed as the
improvement **`rmp #305`**; the report's notes carry this caveat verbatim so the evidence is never
read as claiming an automatic reclamation the server does not yet expose.
