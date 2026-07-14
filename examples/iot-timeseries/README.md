# IoT / time-series event graph — ingest, retention churn & what durability actually costs

A realistic, end-to-end demonstration that Graphus sustains a **continuous IoT telemetry workload** — a
fleet of sensors emitting `DATETIME`-stamped readings under a **sliding-window retention policy** that
deletes aged-out readings, while concurrent clients **read the live window** — and that, under this
relentless *delete-old + insert-new churn*, the storage engine **recycles the freed space** so the durable
**store** reaches a stable plateau rather than growing without bound.

It is driven over a **real Bolt wire** against a **real `graphus-server`**, with a real store file and a
real segmented WAL on disk. It reports three things:

> **1. The on-disk STORE plateaus while `graphus_maintenance_versions_reclaimed_total` climbs.**
>
> **2. And since `rmp` #706, the DATABASE on disk very nearly plateaus too.** At its worst this database
> occupies **14.7 MB of disk to hold a 279 KB graph — 53×** (it was **347×** while #706 was open),
> because WAL segments are now sized to the store, so the WAL sawtooths in a tight, bounded band instead
> of climbing to 64 MiB. ⚠️ **Read that 53× with its decomposition: 60 % of the peak is the FIXED 8.87 MB
> doublewrite preallocation**, which does not scale with the graph and cannot regress. The number that
> actually moves when the engine changes is the **peak WAL per byte of data image — 20×**.
>
> **3. WHAT DURABILITY COSTS, AND WHY — measured, not assumed (`rmp` #745).** The same run ingests the
> same steady state twice — once **batched** (25 readings per commit, what a real gateway does) and once
> at **one commit per 32-byte reading** — and takes a WAL mark at every **phase boundary inside each
> tick**, so the WAL written by *ingest*, by the retention `DELETE` and by the `CHECKPOINT` is measured
> separately. That split is what makes the comparison sound: every tick pays a **fixed cost F** that
> batching cannot touch (**52% of the batched segment's entire WAL bill**), and F sits in *both*
> numerators of `(50·A₁ + F) / (2·A₂₅ + F)`, dragging the ratio toward 1.
>
> | | `batch = 1` | `batch = 25` | **batching is worth** |
> | --- | --- | --- | --- |
> | **Ingest only** (F excluded — *the sound experiment*) | **871×** | **110×** | **7.9×** |
> | Whole segment (retention + checkpoint included) | 974× | 230× | 4.2× |
>
> **4. AND THE INSTRUMENT THAT MEASURES IT IS ITSELF GATED (`rmp` #745).** The cumulative WAL volume
> is *reconstructed* by polling the WAL directory — which **under-counts** if a segment is born, sealed and
> reclaimed between two samples. It did: the old sampler ran once per tick, *after* the checkpoint had
> deleted that tick's segments, and it was short by **5.5% over the run and 17% in the `batch = 1`
> control**. An under-counted WAL makes write amplification *fall*, so it sailed under every ceiling and
> read like a triumph. The reconstruction is now cross-checked against the **engine's own exact counter**
> and agrees to **+0.00%**; a >3% drift fails the run.

All three are load-bearing, and the first without the second is a lie of omission. A flat store is a true
statement about a *component*; published on its own, in an example whose headline is "reclamation holds the
footprint flat", it creates a false impression about the *database*. So this example measures each of
them, **gates** each of them, and states the finding plainly.

**And it reads its own data back.** Every read used to be a `count(…)`, which meant a corrupted payload
passed green. Now **1 371 ground-truth-gated queries** run *during* the churn across three families
(composite-index window, per-sensor aggregation, and a **temporal** `ts ∈ [t0, t1)` window), **51 852 rows**
are compared field by field against the seeded generator's own stream, and after the churn **every one of
the 200 surviving readings** is read back in full and matched exactly — `ts` compared as a real `DATETIME`,
not as an epoch integer the client re-derived. An index that silently answers with an **empty** result set
(`rmp` #738) fails this run; before, nothing here could have seen it.

---

## The finding: the store plateaus, and since `rmp` #706 the WAL sawtooths in a *tight* band

Measured on the default `reclaim` profile — 140 ticks, 7 000 readings, 35× the retention window:

```
store data image   278528 B  ────────────────────────────────────────────  FLAT. Every post-warmup tick.

on-disk WAL       5.6 MB ┤ ╱│╱│╱│╱│╱│╱│╱│╱│╱│╱│╱│╱│╱│╱│╱│      plateau ratio 1.000 (store)
                         │╱ ╵ ╵ ╵ ╵ ╵ ╵ ╵ ╵ ╵ ╵ ╵ ╵ ╵ ╵ ╵     plateau ratio 1.60  (DATABASE)
                   49 kB ┤                                     peak 53× the graph (was 347×)
                         └──────────────────────────────       29 reclaims, ~29 MB of WAL disk returned
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

> The gate's "did a segment seal?" predicate is tested against that **store-proportional** size, not the
> 64 MiB cap (`rmp` #745). Testing the cap was a sound-but-blunt bound while per-reading commits wrote
> ~143 MB of WAL — but batching cut that to ~50 MB, which still seals ~50 of this store's 1 MiB segments
> and reclaims 29 of them, yet falls *under* the cap. The blunt predicate would then have answered "cannot
> certify a seal" and quietly excused the run from proving WAL disk ever comes back: **an efficiency win
> would have switched the gate off.**

### Write amplification has THREE terms, and `rmp` #745 measured them apart

The cumulative-WAL / logical-bytes figure is set by:

1. **how many commits the client makes** (the batch size),
2. a **fixed per-tick cost F** — the retention `DETACH DELETE` and the amortised `CHECKPOINT DATABASE` —
   that batching cannot touch, and
3. **what a commit's records actually cost**.

The example used to recognise only (1) and (3), and — never having measured either — attributed everything
that was not the commit rate to a WAL "page-image format" that **does not exist**. Term (2) was invisible
because nothing measured it, and it is **52% of the batched segment's entire WAL bill**.

**The two segments differ in exactly one variable.** Both are measured **in steady state**, on the same
server, the same database, the same sensor fleet, and the same retention and checkpoint cadence — the
batched segment starts at the end of warmup (tick 15), *not* at tick 0. That boundary is load-bearing:
during the growth ramp the data image is still extending and, until the window first fills, **not one
retention `DELETE` has run**. Charging the batched segment with a ramp the `batch = 1` control never sees
would divide two different workloads into each other and call the result "the cost of batching".

The driver takes a WAL mark at **every phase boundary inside the tick** — before ingest, after ingest,
after the `DELETE`, after the `CHECKPOINT` — so each term is measured on its own:

| Ingest shape | Ticks | Ingest commits | **Ingest-only WAL / reading** | **Ingest-only write amp** | Whole-segment write amp |
| --- | --- | --- | --- | --- | --- |
| `batch = 25` (a real gateway) | `[15, 130)` | 230 | **2 969 B** | **110×** | 230× |
| `batch = 1` (one commit per 32-byte reading) | `[130, 140)` | 500 | **23 507 B** | **871×** | 974× |

**Batching is worth 7.9× on the ingest itself** — the sound comparison, with F excluded from both sides so
the two segments differ only in batch size. Over the **whole segment**, with retention and checkpoint
included, it is worth **4.2×**; that is what a deployment running *this* retention cadence actually pays,
and both figures are published, under names that say which is which.

> **The fixed per-tick cost F: 160 817 B/tick** (3.28 MB of retention `DELETE` + 15.22 MB of `CHECKPOINT`
> over the main segment's 115 ticks). It is neither the WAL format nor the commit rate. It is the number
> that was hiding inside the old "3.7× saving, and the residual is the format" claim.

#### What a commit's WAL is ACTUALLY made of (`rmp` #745 — measured, by decoding the log)

The old claim — *"a commit's redo is dominated by the **page images** of every page it dirtied (~22 kB ≈
three 8 KiB pages: node, relationship, property)… cutting the residual would be a WAL-format change
(row-level redo instead of page imaging)"* — was **false in every clause, and had never been measured.**

The engine emits **byte-range patches**: `paging::encode_patch(offset, bytes)`
(`crates/graphus-storage/src/paging.rs`) writes two bytes of offset plus *only the changed bytes*.
`RecordType::FullPageImage` is emitted **nowhere in the engine**. It already *is* patch-level physiological
redo, so "cutting the residual would require moving to row-level redo" was doubly false.

`crates/graphus-cypher/tests/wal_amplification.rs` now **decodes the durable WAL** of this example's exact
ingest shape and pins what is really there:

| | measured |
| --- | --- |
| Records per `batch = 1` commit | **~20** — ~19 `Update` byte-range deltas + one `Commit` |
| Mean page-changing record | **~197 B** (a redo image, an undo image, and a fixed frame) — against an **8 192 B page** |
| `FullPageImage` records | **0** |
| Distinct pages a one-reading commit touches | **~5.7** (not three) |
| Cost of a whole commit | **less than ONE image of any single page it dirties** |

So the residual is **not the format**. More than half of it is F (above). And the rest turned out to be
something nobody had ever looked for:

#### The dominant term is the per-commit catalog re-image — and RETENTION inflates it

Every commit re-images the durable catalog (`StoreMeta`) **in full**, and `StoreMeta::free_list` holds every
record id that has been **freed but not yet reused**. Each id is 8 B, imaged in *both* the redo and the undo
— so **every commit pays ~16 B for every freed slot still on the free list**, whether or not it touches it.

This example *is* a retention workload: it deletes 50 aged-out readings every tick, forever. So its free
list is permanently populated, and the effect is not subtle. Measured on the identical single-reading
commit, on the identical store, before and after one retention purge:

| | catalog image / commit | **total WAL / commit** |
| --- | --- | --- |
| before the retention purge | 2 202 B | **4 562 B** |
| after it (≈3 621 ids left on the free list) | **60 137 B** | **62 493 B** — a **13.7×** blow-up |

That is the mechanism. It also explains why batching is worth **7.9×** here but only **1.63×** on a store
with no free list: the catalog image is paid **once per commit**, so the more it costs, the more there is
for a batch to amortise. And it is why declaring this example's full schema (four indexes, three
constraints) adds **zero WAL records** — Graphus's secondary indexes are *derived* structures rebuilt from
the record store on open — yet still costs **+526 B on every commit's catalog image**.

> **This is a real, unaddressed engine cost**, surfaced by measuring the thing the example had been merely
> asserting: write amplification in a retention workload **scales with the number of freed-but-unreused
> record slots**, because the free list rides inside a catalog image that every single commit rewrites.
> Nothing amortises it today except batching.

**A mechanism that is asserted rather than measured will always be there to explain a number nobody
checked.** The page-image story survived for months — in this README, in `run.sh`, and in the report the
example printed on every green run — and it was standing exactly where this finding was.

> **The WAL file grows by exactly what its records encode.** Verified file-backed, on a real segmented
> `FileLogSink`: 940 303 B of LSN space == 940 303 B of WAL file on disk. No padding, no alignment, no
> per-flush framing. The in-memory and file-backed devices agree byte for byte (3 839 B/commit), so none of
> the cost above is an artefact of the durable device — it is all real work.

**Why the reclamation counters agree.** `graphus_maintenance_versions_reclaimed_total` counts MVCC versions
freed inside the **store** (what keeps the store flat); the on-disk WAL physically **shrinking** is the
separate, direct proof that WAL disk came back. Both climb here — this run reclaimed WAL disk **29 times**,
returning ~29 MB.

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

## What changed, and why (`rmp` #745) — the example now validates its own subject

The storage claims above were real. Everything *around* them was not being checked at all:

| Before | Now |
| --- | --- |
| **Every read was a `count(…)`.** A corrupted, transposed or truncated payload passed **green** | **51 852 rows** compared field-by-field against the generator's own stream, plus **every one of the 200 surviving readings** read back in full after the churn |
| **~0 % reads.** `rmp` #738 (an index silently answering with an **empty** set instead of declining) could not have been caught here | **1 371 gated queries** run *during* the churn over 2 independent connections, across 3 index families. An empty result where rows provably exist **fails the run** |
| **`ts` was an `INTEGER`**, and the schema *forbade* a temporal (`IS :: INTEGER`) — so the Bolt/PackStream temporal path, the temporal property encoding and the temporal index key were **never exercised** | **`ts` is a `ZONED DATETIME`**, `RANGE`-indexed, carried as a real PackStream `DateTime` in both directions, with a gated `ts ∈ [t0, t1)` window read. An **`INTEGER` `ts` is now rejected** |
| **Ingest was `batch = 1`** — one round-trip and one commit per 32-byte reading — and the 799× headline was attributed wholesale to it | Ingest is **batched** (what a gateway does); the `batch = 1` shape is measured as a **control segment**, and the two write amplifications are published side by side |
| The schema gate checked **name + state** | It checks **name + TYPE + state**: a `RANGE` index silently created as another kind is caught |
| Retention checked only the live **count** | It checks the live **rows**: nothing below the cutoff survives, and `min(seq) ≥ cutoff` |
| Nothing checked the `:EMITTED` edges | A `DETACH DELETE`d reading must leave **no dangling edge**: edges == live readings, each with exactly one |

---

## The gates — and why each one can actually fire

"A gate that cannot fire is the same lie wearing a green tick" (`examples/README.md`). Every rule below is
a pure function of the measured samples ([`wire_samples.rs`](../../crates/graphus-iot-gen/src/wire_samples.rs)),
and every one is **unit-tested to fire on the defect it names** — several were additionally proven to go red
end-to-end by breaking the thing they guard in a real run (see below).

| Gate | Fails when | Why it exists |
| --- | --- | --- |
| **Payload read-back** | a stored `(sensor, seq, ts, value)` differs from the generated one | Every read used to be a `count(…)`. A count cannot see a corrupted value — this can, and it inspects **every** surviving reading, not a sample. (A first cut sampled 64 of 200 on a stride of 3; a planted corruption at `seq` 6900 fell *between* two samples and passed. A gate that finds a planted defect 32 % of the time is not a gate.) |
| **Empty-but-expected** (`rmp` #738) | a query returns **nothing** where rows provably existed | The exact signature of an index answering `Some(empty)` instead of declining: silent, total row loss that every count-shaped check waves through, because `0` is a well-formed count. |
| **Reader floors** | a family ran too few queries, gated too few of them **exactly**, or returned no rows | A read mix that barely ran is not evidence. The floors cannot be satisfied by doing less. |
| **Ingest-shape comparison** | the `batch = 1` control is missing, or batching did **not** pay | The headline claim ("per-reading commits dominate the bill") is only earned if **both** numbers were measured on the same server. |
| **Segment label honesty** | a segment's declared batch ≠ the batch its commits actually carried | Caught a real defect while being written: chunking at `min(cap, rate/clients)` left remainder commits and dragged the true mean to **17.1** while the label said `25`. Every per-commit figure would have inherited the lie. |
| **Schema by name + TYPE + state** | a declared index is absent, not `ONLINE`, or is the **wrong kind** | Name+state alone passed a `RANGE` index silently created as something else — which would turn every seek in the workload into something else while the example reported the performance of an index it never built. |
| **Anti-rot** | writes were committed but `wal_bytes` / `bytes_fsynced` is **zero** | The WAL is a *directory* of `seg.<lsn>` files; a leaf-name classifier scored every one as store, and this example published `wal_bytes: 0` for months while asserting a green plateau. |
| **Per-commit WAL floor** | WAL < `commits × 64 B + logical payload` | The subtle half, and the one a ceiling can *never* supply: an under-counted WAL makes every amplification figure **fall**, so it sails under any ceiling and reads like a triumph. It encodes the physics (ARIES: N commits ⇒ N fsynced redo records; and every logical byte must appear in the redo to be replayable). The payload term was added in `#745` because batching cut the commit count ~50×, which would otherwise have weakened the floor by the same factor. |
| **Write-amplification ceilings** (350× whole run, **300× batched**) | amplification regresses past the bound | **Ceilings, not targets.** They did **not** move in `#745` even though every WAL figure grew, because the growth was a *corrected instrument*, not a regressed engine — and the measurements (**279× / 230×**) still fit the headroom that was already there. Both sit **below the ~974× a regression back to per-reading commits produces** — and that is not hypothetical: the `batch = 1` control segment measures exactly that regression, in the same run, as its own upper witness. |
| **Peak WAL / store ceiling** (40×) | the WAL runs away from the graph it protects | The **graph-scaling** half of the durable footprint, and the half a real regression moves. Measured **20×**; a revert of the store-proportional segment seal (`#706`) puts it at **~241×**. Its lumped sibling (the 120× total-footprint bound) is ~60 % a **fixed** doublewrite preallocation that cannot regress, so it is coarse by construction. |
| **WAL instrument vs the ENGINE'S EXACT COUNTER** (`rmp` #745) | the polled reconstruction drifts >3 % from `graphus_db_wal_bytes_written_total` | **The gate that would have caught this whole task's defect on day one.** Every other rule tests the reconstruction against *itself*; this one tests it against a monotone durable byte offset published by the engine that wrote the bytes. The broken instrument drifts **−5.5 %** and goes red; the fixed one agrees to **+0.00 %**. |
| **WAL attribution reconciles** | the phases do not sum to the run's WAL, byte for byte | The segments used to be published beside a run total they did **not** add up to — **3.62 MB (7.3 %) unattributed**. A remainder is not a rounding artefact; it is where a measurement defect hides. |
| **Ingest-only comparison exists** | the phase marks are missing, so only the **diluted** whole-segment ratio can be reported | Without them the example cannot tell the batch size apart from the retention cadence, and its headline saving is a floor of unknown tightness — which is exactly what it published for months. |
| **Total-footprint ceiling** (120×) | peak `(store + WAL)` per byte of graph regresses | Judges the claim against the **database**, not one component of it. Stops a true statement about the store standing in for a false one about the whole. |
| **WAL reclamation happened** | the run sealed a segment but the WAL **never shrank** | The maintenance counters cannot stand in for this — they count MVCC versions in the *store* and climb happily while zero WAL bytes come back. |
| **Store plateau** + **reclamation climbed** | the store grows, or nothing was reclaimed | The original claim. Both halves needed: a flat store alone also describes a workload that wrote nothing. |

The reclamation gate is deliberately **asymmetric**, so it stays correct under a *fix*: the "sealed a
segment" branch demands reclamation; the "too short to seal" branch demands nothing of it. A run that gets
*more* efficient still seals, still reclaims, and still passes — a gate that failed on an improvement would
be worse than no gate.

### Proven to fire (end-to-end, on a real run)

Each was injected into the driver, the example was run, and the run went **red**; then the injection was
reverted and the run went green again.

| Injection | What went red |
| --- | --- |
| Corrupt **one** stored `value` (of 7 000) in the batched path | the concurrent readers — 28 mismatches across all three families, including the aggregation family (via its `sum`) |
| Corrupt **one** stored `value` in the surviving band | the post-churn payload read-back (`199 of 200 verified … seq 6900: stored value=7, generated value=948`) **and** the temporal window check |
| Make the temporal index return an **empty** set (`rmp` #738) | `465 empty-but-expected` — the reader gate names the defect explicitly |
| Make retention delete the **newest** rows | the steady-state band, `nothing below the cutoff survives`, and `min(seq) ≥ cutoff` |
| Leave one extra `:EMITTED` edge behind | the orphan-edge check (`:EMITTED total=201 … live readings=200`) |

---

## The two instruments

| | `evidence/` — **PRIMARY** | `evidence-mirror/` — **CONTROL** |
| --- | --- | --- |
| What it is | the real `graphus-server`, driven over **Bolt** | the real engine, driven **in-process** |
| Device / WAL | **on disk** (`FileBlockDevice` + segmented WAL) | **in memory** (`MemBlockDevice` / `MemLogSink`) |
| Reclamation trigger | the **real** `CHECKPOINT DATABASE` + the background cadence | an explicit GC pass per tick — a deterministic stand-in |
| Durable bytes / WAL / fsync / amplification | **measured for real** | **structurally unmeasurable** — absent from the report (schema v3 omits what it did not measure), never zero-filled |
| Footprint curve | real, machine-dependent | **byte-reproducible** for a fixed seed |
| Gated by | `baseline.json` — **14 metrics compared, 0 skipped** | `baseline-mirror.json` — 10 compared, 4 skipped (an in-memory device has no WAL to measure) |

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
IOT_BATCH=100          examples/iot-timeseries/run.sh # the ingest flush CAP (a commit still carries ~rate/clients)
IOT_BATCH1_TICKS=20    examples/iot-timeseries/run.sh # a longer batch=1 CONTROL segment (0 disables the comparison)
IOT_READER_CLIENTS=4   examples/iot-timeseries/run.sh # 4 concurrent gated readers during the churn (0 disables — and FAILS the gate)
IOT_PAYLOAD_SAMPLES=64 examples/iot-timeseries/run.sh # read back a strided sample instead of EVERY surviving reading
RUN_WIRE=0             examples/iot-timeseries/run.sh # CONTROL mirror only — collects NO durable-byte evidence
```

`IOT_BATCH` is a **cap**, not the batch. A tick is a barrier (the retention `DELETE` must never race the
ingest it would conflict with) and a tick's readings are sharded across the ingest connections, so a commit
carries about `rate / ingest-clients` readings. The evidence reports the batch it **measured**, never the
one that was requested — and the segment gate fails a label that does not describe the run.

### Which profile produced which number

Every figure in this README comes from the **`reclaim`** profile unless the table says otherwise. The
profiles are not interchangeable, and the difference is not cosmetic:

| Wire profile | Readings | Cumulative WAL | Reaches a stable steady state? | What it can prove |
| --- | --- | --- | --- | --- |
| **`reclaim`** (default) | 7 000 | ~50 MB | **yes** — 29 reclaims, a tight WAL sawtooth | the full cycle at steady state: the store plateaus, the WAL sawtooths and comes back |
| `fast` | 3 000 | ~21 MB | shorter — reclaims (store-proportional segments) but ends further from steady state | a quick smoke of the same churn |
| `soak` | 9 000 | ~64 MB | yes | the plateau held over hundreds of consecutive post-warmup ticks |

`fast` is a legitimate measurement but it ends further from steady state than `reclaim`, so the run says
which of the two it measured rather than inheriting the green tick the store's plateau earned. The default
is `reclaim` precisely so the CI gate (`rmp` #704) exercises the branch that
demands WAL disk actually come back. Its churn loop takes **~2.5 s** (it was ~9.5 s before the ingest
was batched).

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
| **Time-series event-graph modelling** | `(:Sensor {id, kind, site, location})-[:EMITTED]->(:Reading {sensor, seq, ts, value})`, with `ts` a real **`DATETIME`** |
| **Cypher / Bolt / PackStream TEMPORALS** | `ts` is a `Value::ZonedDateTime` — bound as a real PackStream `DateTime` (struct tag `0x49`) on every ingest, stored as a temporal property, **`RANGE`-indexed**, and returned as a temporal that is compared **as a temporal** against ground truth |
| **A temporal window read** | `MATCH (r:Reading) WHERE r.ts >= $t0 AND r.ts < $t1` — the query a time-series database exists to serve — **seeks** the `Reading.ts` RANGE index (asserted at the plan level *and* against ground truth) |
| **Retention / TTL policy** | a sliding window: each tick `DETACH DELETE`s every reading older than `window` readings. Verified by **rows**, not just by count: nothing below the cutoff survives, `min(seq) ≥ cutoff`, and no orphan `:EMITTED` is left behind |
| **Index-backed retention sweep** | the aged-out `DELETE` **seeks** the `Reading.seq` RANGE index (asserted at the plan level, not assumed) |
| **A production-realistic schema** | `NODE KEY` on `Sensor.id`; existence (`value`) + property-type (`ts IS :: ZONED DATETIME`) constraints; `POINT` index on `Sensor.location`; composite `RANGE` index on `Reading(sensor, seq)`; `RANGE` indexes on `Reading.seq` **and the temporal `Reading.ts`** |
| **Schema *enforcement*, over the wire** | a duplicate `Sensor.id`, an **`INTEGER` `ts`**, a **`STRING` `ts`**, and a `value`-less reading are each **rejected** on a live session — and provably create nothing |
| **Batched ingest** (what a gateway does) | `UNWIND $rows AS row … CREATE` — 25 readings per statement and per commit, with a real `DATETIME` per row |
| **Concurrent ingest** | N Bolt connections, **sharded by sensor**, so writers never contend for the same node — the realistic "one gateway per group of devices" shape |
| **Concurrent READS under churn** | N independent connections driving windowed / aggregate / temporal reads **while** the writers churn, every result gated against the generator's own stream |
| **MVCC delete → tombstone → reclamation** | deleted readings are MVCC-tombstoned; a checkpoint's GC pass physically reclaims their slots into a free list new inserts reuse |
| **The operator trigger** | `CHECKPOINT DATABASE <db>`, issued over the same Bolt connection as everything else |
| **The automatic trigger** | the background maintenance cadence, firing on WAL growth with no operator at all |
| **Bounded store footprint** | the durable **store** plateaus — flat, despite total-ingested ≫ window |
| **Real durable-byte accounting** | store / doublewrite / WAL / catalog, classified **by path**; cumulative WAL volume; WAL segment reclamation events; kernel `write_bytes` cross-check; **per-ingest-shape** write amplification |

### How the read mix stays SOUND while retention slides underneath it

An exact-equality gate over a moving window would be flaky by construction — and a flaky gate gets
disabled, which is how the defect returns. So the writers publish two frontiers, and the **order** in which
they publish them is the whole trick:

* `ingested_through` is published **after** each tick's ingest barrier, so a reader that loads it *before*
  its query knows every reading below it was committed **before the query started** — and is therefore in
  the query's snapshot.
* `cutoff_upper` is published **before** each retention `DELETE`, so it is an *upper bound* on what may
  have been deleted at any instant. A reader that loads it *after* its query returned knows nothing at or
  above it can have been deleted while the query was in flight.

Each query is then gated with `returned ⊆ generated` **and** `returned ⊇ provably-still-live`. When the
window is clear of the retention frontier the two coincide and the gate is an **exact set equality** — and
because the window is chosen with two ticks of headroom, **all 1 371 queries of the baseline run achieved
that**. The gate demands a *floor* of exact gates, so a profile that made them impossible would fail loudly
rather than silently weaken.

---

## Measured evidence

Every figure is a real measurement from the committed baseline run — none is illustrative. Host: Linux
x86_64, 16 cores, release build, **`reclaim` profile** (8 sensors, rate 50/tick, window 200, 140 ticks →
7 000 readings = **35× the retention window**), 2 concurrent ingest connections + **2 concurrent reader
connections**, ingest batched at 25 readings/commit with a 10-tick `batch = 1` control, `CHECKPOINT
DATABASE` every 5 ticks. Throughput / latency / CPU / RSS are **machine-variant** and are never gated.

### The store plateaus while reclamation climbs

| Metric | Measured |
| --- | --- |
| Store data image, post-warmup band | `[278528, 278528]` B — **plateau ratio 1.000** (34 pages) |
| Total ingested | 7 000 readings (**35×** the window) |
| Steady-state live `:Reading` count | 200 (the window), held for every post-warmup tick |
| `graphus_maintenance_versions_reclaimed_total` | **+13 600** over the workload window |
| `graphus_maintenance_checkpoints_total` | **+34** (28 issued by `CHECKPOINT DATABASE`, the rest by the background cadence) |
| `graphus_maintenance_stamps_frozen_total` | +34 840 |
| Transactions committed / aborted | 2 629 / 4 — and the 4 aborts are exactly the 4 constraint violations the example *deliberately* attempts |
| `statement_panics` / `engine_recovery_panics` / `engine_force_detached` | **0 / 0 / 0** |

**Warmup is derived, not tuned.** The plateau claim starts only after (a) the window has filled and
(b) reclamation has run **twice** — because the store plateaus by *reusing* freed slots, and one
checkpoint's freed slots have not been consumed yet. That is `fill_ticks + 2 × checkpoint_every` = tick 15.

### The no-GC contrast

With the reclamation pass disabled, the same workload's footprint grows **57 344 B → 335 872 B (5.9×)** in
12 ticks. That is the curve reclamation flattens — and the reason the plateau is a *result*, not an
artefact of a workload that simply wrote nothing.

### The reads — gated against ground truth, not counted

| Read family | Index it exercises | Queries | Exactly gated | Rows verified | p50 / p99 |
| --- | --- | --- | --- | --- | --- |
| `windowed-composite` | composite `Reading(sensor, seq)` (leading eq + `seq` range) | 457 | **457** | 5 745 | 2.23 / 9.93 ms |
| `per-sensor-aggregate` | the same, aggregated (`count`/`min`/`max`/`sum`) | 457 | **457** | 457 | 2.19 / 12.78 ms |
| `temporal-window` | **`Reading.ts`** — a real `DATETIME` RANGE seek | 457 | **457** | 45 650 | 3.13 / 12.24 ms |
| **Total** | | **1 371** (**544 gated queries/s**) | **1 371** | **51 852** | |

**0 mismatches, 0 empty-but-expected, 0 errors** — and after the churn, **200 of 200** surviving readings
read back in full and matched field by field (`sensor`, `seq`, `ts` as a **temporal**, `value`).

### What durability cost

| Metric | Measured | Note |
| --- | --- | --- |
| Store data image (`graphus.store`) | **278 528 B** | the graph itself — **1.9 %** of the peak footprint |
| Doublewrite buffer (`graphus.dwb`) | **8 871 936 B** | a **fixed preallocation** per database — not graph data, and deliberately not counted as store |
| WAL, **cumulative** bytes written (= `bytes_fsynced`) | **52 511 252 B** | a **documented proxy**: it is the WAL volume, and every WAL byte is fsynced before its commit is acknowledged — but it EXCLUDES the store + doublewrite pages a checkpoint also fsyncs, so it is a *lower bound* on bytes fsynced. The kernel figure below is the honest total. |
| **WAL, cumulative — the ENGINE's own EXACT figure** | **52 513 711 B** | `graphus_db_wal_bytes_written_total` (`rmp` #745) — a monotone durable byte offset reclamation never rewinds. The driver's polled reconstruction agrees to **+0.00%**; a >3% drift **fails the run**. |
| WAL, on-disk **peak** | **5 563 554 B** | the honest worst case |
| WAL, residual at exit | **48 717 B** | never quote this without the peak beside it |
| **Peak WAL per byte of data image** | **20×** | *the graph-scaling half of the footprint* — the number a segment-sizing regression actually moves (a `#706` revert puts it at **~241×**). Gated at 40×. |
| **WAL segments reclaimed** | **29 events, 29 005 868 B returned** | the on-disk WAL physically *shrank* 29 times — small store-proportional segments come back on nearly every checkpoint (`rmp #706`) |
| **Total durable footprint** (store + WAL) | peak **14 714 018 B**, min **9 184 748 B** | **plateau ratio 1.60** — a tight sawtooth (was 7.12 while #706 was open) |
| **Peak footprint per byte of graph** | **53×** | ⚠️ a **LUMPED** ratio: **60% of that peak is the FIXED doublewrite preallocation**, which does not scale with the graph and cannot regress. It bounds the disk to provision — a real question — but it is *not* a measure of WAL behaviour. Use the 20× row above for that. |
| **Fixed preallocation** | **8 871 936 B** | a **constant** per database. Kept OUT of `space_amplification` — which used to be **96% this number** divided by the live data, and therefore moved with the size of a constant rather than with anything the engine did. |
| Kernel `write_bytes` (`/proc/<server-pid>/io`) | **62 390 272 B** | an independent cross-check from *outside* the engine — and the honest **total** fsync volume (WAL + store + doublewrite) |
| Logical payload ingested | **189 000 B** | 7 000 readings × 27 B (`sensor` + `seq` + `ts` + `value`) |
| **Fixed per-tick cost F** (retention + checkpoint) | **160 817 B/tick** | **52% of the batched segment's WAL bill.** Paid regardless of batch size — neither the format nor the commit rate. This is the term the old "page image" story was covering for. |
| **INGEST-ONLY write amp — batched (25/commit)** | **110×** | 17 070 242 B of ingest WAL for 5 750 readings (**2 969 B/reading**) |
| **INGEST-ONLY write amp — `batch = 1` (control)** | **871×** | 11 753 666 B of ingest WAL for 500 readings (**23 507 B/reading**) |
| **⇒ BATCHING IS WORTH** | **7.9×** | *on the ingest itself* — F excluded from both sides, so the two segments differ in exactly one variable |
| Whole-segment write amp — batched / `batch = 1` | **230× / 974×** | retention + checkpoint included: what a deployment on *this* cadence pays. Batching saves **4.2×** here — the diluted figure the example used to publish *as* the batching saving. |
| **Write amplification — whole run** | **279×** | the mix of the two segments (ceiling **350×**, unchanged) |
| **Space amplification** | **~61×** | *(data image + WAL) / logical bytes retained* — the bytes that **scale with the graph**. It used to read **1 704×** by lumping in the fixed doublewrite preallocation, which `examples/README.md` evidence-honesty rule 5 explicitly forbids. |

The amplification figures are large, and they are **correct**. They are dominated by the WAL and the fixed
doublewrite preallocation (60 % of the peak footprint); the graph itself is 1.9 %.

### Throughput, latency, CPU, RAM

| Metric | PRIMARY (real server, Bolt-UDS) | CONTROL (in-process mirror) |
| --- | --- | --- |
| Workload wall-clock | 2.52 s | 0.52 s |
| Ingest throughput | **2 776 readings/s** | 5 920 readings/s |
| Ingest statement latency p50 / p99 (batched, 25 readings) | 7.15 / 9.22 ms | — |
| Ingest statement latency p50 / p99 (`batch = 1` control) | 1.83 / 3.27 ms | — |
| Concurrent read throughput | **544 gated queries/s** across 2 connections | n/a |
| Retention `DELETE` p50 / p99 | 2.60 / 8.78 ms | — |
| `CHECKPOINT DATABASE` p50 / p99 | 10.04 / 18.15 ms | n/a |
| Server CPU over the window | 2.00 s user + 0.39 s system = **0.95 cores** | n/a |
| Server peak RSS | 166.4 MB | n/a |
| SSI retries / abort rate | **0** / **0.0** | n/a |

Batching lifted ingest from ~760 readings/s to **2 776 readings/s** on the same hardware: a commit is not
acknowledged until its redo record is fsynced, so amortising the fsync over 25 readings buys throughput and
durable bytes at the same time. The server sits at **~0.95 of one core** — not a CPU ceiling, but the
signature of a workload bound by **durability latency**, with the concurrent readers served off-thread.

**Process RSS is not a bounded-resource proof, and is never gated.**

**Process RSS is not a bounded-resource proof, and is never gated.** In the in-process mirror it is a
high-water of *allocator reservations* (glibc retains freed arenas), so it climbs even though the engine's
durable state is fully reclaimed — the deterministic footprint plateau is what proves the engine releases
its records.

---

## How the pieces fit

| Component | Path |
| --- | --- |
| Deterministic generator + retention policy + profiles + the **ground-truth oracle** (`all_readings` / `expected_window`) | [`crates/graphus-iot-gen/src/lib.rs`](../../crates/graphus-iot-gen/src/lib.rs) |
| **File-backed wire driver** (Bolt, real server) — the PRIMARY instrument | [`crates/graphus-iot-gen/src/bin/iot_wire.rs`](../../crates/graphus-iot-gen/src/bin/iot_wire.rs) |
| The samples contract **+ the storage / reader / ingest-shape gates** (and their unit tests) | [`crates/graphus-iot-gen/src/wire_samples.rs`](../../crates/graphus-iot-gen/src/wire_samples.rs) |
| PRIMARY evidence emitter + invariant gate | [`crates/graphus-iot-gen/src/bin/iot_wire_evidence.rs`](../../crates/graphus-iot-gen/src/bin/iot_wire_evidence.rs) |
| Path-classified footprint accounting | [`crates/graphus-iot-gen/src/footprint.rs`](../../crates/graphus-iot-gen/src/footprint.rs) |
| In-process churn CONTROL (real engine, in-memory device) | [`crates/graphus-iot-gen/src/churn.rs`](../../crates/graphus-iot-gen/src/churn.rs) |
| CONTROL evidence emitter | [`crates/graphus-iot-gen/src/bin/iot_evidence.rs`](../../crates/graphus-iot-gen/src/bin/iot_evidence.rs) |
| Baseline regression gate (drives both baselines) | [`crates/graphus-iot-gen/src/bin/iot_baseline_cmp.rs`](../../crates/graphus-iot-gen/src/bin/iot_baseline_cmp.rs) |
| Hermetic plateau test (runs in the default `cargo test`) | [`crates/graphus-iot-gen/tests/churn_plateau.rs`](../../crates/graphus-iot-gen/tests/churn_plateau.rs) |
| Schema-parses-to-the-same-thing test — **and the empirical proof that a RANGE index over a `DATETIME` property builds, seeks, and returns the right rows** | [`crates/graphus-server/tests/iot_timeseries_schema.rs`](../../crates/graphus-server/tests/iot_timeseries_schema.rs) |
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
