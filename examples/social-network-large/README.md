# social-network-large — do reads scale across cores?

This example evaluates Graphus's read path on a **big social graph** under **real concurrency**. It
builds a social network of **`USER`** nodes befriended by an **undirected multigraph** `FRIEND`
relationship, a corpus of **`ARTICLE`** nodes carrying realistic headlines, and **`LIKE`** edges from
users to articles — loads it into a **running server over the wire**, then drives a **concurrency
ladder of simultaneous Bolt clients** through a Cypher read battery while **sampling the server
process itself**.

The headline question is deliberately narrow: **when C clients read at once, does the server spread
the work across CPU cores, or does it hit a single-thread ceiling?**

It is both a runnable **demonstration** and an executable **E2E test**: every step asserts its
expected result and `run.sh` exits non-zero if any assertion fails.

> **Why the driver had to change.** An earlier version of this example ran the battery **in-process**
> through the engine's coordinator. That measured the *driver*, not the server: it bypassed the
> server's off-thread reader pool entirely, so its "~1 core" figure was an **artifact of the harness**
> and said nothing about how Graphus serves concurrent readers. The battery now runs over the real
> Bolt wire against a real server process, which is the only way this question can be answered
> honestly (`rmp` #691).

## The graph model (a multigraph LPG)

| Element | Shape | Meaning |
|---------|-------|---------|
| `(:USER {id, name, registered})` | `id` = **globally-unique `u64`**, `name` ≤ 64 chars (realistic Portuguese full names, with diacritics), `registered` = **`i64`** unix ts | a person |
| `(:ARTICLE {id, name, registered})` | `id` = **globally-unique `u64`**, `name` = a realistic news-style headline, `registered` = **`i64`** unix ts | a published article |
| `(:USER)-[:FRIEND {since}]-(:USER)` | **undirected multigraph**, `since` = **`i64`** unix ts | a friendship |
| `(:USER)-[:LIKE {date}]->(:ARTICLE)` | directed, `date` = **`i64`** unix ts | a like |

> The `id` is a label-tagged **bijective scramble** of the entity index — distinct entities always get
> distinct ids and no `USER` id can equal an `ARTICLE` id, so a `REQUIRE n.id IS UNIQUE` constraint can
> never spuriously reject the load. Every id stays in `[0, 2^63)`, so it round-trips losslessly as a
> signed 64-bit integer (`Value::Integer(i64)`, a PackStream `Integer`, and the bulk-import CSV `:long`
> column). A `MATCH (:USER {id: <int>})` point-seek is served by the uniqueness constraint's backing
> index (PROFILE-verified: `NodeIndexSeek`, dbHits 1), not a label scan.

### Realistic, deterministic data

The generator (`graphus-social-gen`, a dev-only leaf crate) is **fully deterministic**: the entire
graph is a pure function of `(seed, profile)`, so it is **byte-identical per seed** across runs,
hosts, and platforms (a seeded `SplitMix64` PRNG; no clock, no float in any emitted text, no hash-map
iteration). Names are assembled from European-Portuguese given-name / surname / particle pools
(diacritics preserved, bounded to 64 bytes on a char boundary); article titles are assembled from
realistic headline-fragment pools so they "tend to contain real information".

### Two degree distributions — including supernodes

`FRIEND` is built with the **configuration model** (stub pairing: each user draws a target degree,
stubs are deterministically shuffled and paired, self-loops avoided, multi-edges allowed).
`SOCIAL_DEGREE_DIST` picks how each user's target degree is drawn:

| Mode | Degree law | Realised (fast profile) | What it exercises |
|------|-----------|--------------------------|-------------------|
| `zipf` *(default)* | power law `P(k) ∝ k^-s` | 3,688 edges, degree ∈ **[1, 367]**, log2 histogram `1:1242 2:447 4:180 8:68 16:35 32:10 64:13 128:4 256:1` | a **heavy tail of SUPERNODES** — the realistic social shape, and the adversarial case for traversal |
| `uniform` | uniform in `[friend_min, friend_max]` | 15,047 edges, degree ∈ [6, 24] | an evenly-connected graph — no hubs |

The default is **power-law**, because a real large social graph is scale-free and only that shape lets
the example demonstrate what it is named for — reads that traverse SUPERNODES. The power-law run asserts
a supernode actually grew (max degree ≥ 32), prints the degree histogram, and is gated against the
committed power-law baseline. The `uniform` mode is the simpler contrast; it has no hubs, so its
supernode-anchor proof (I9) is a clearly-labelled N/A and its structural gate is skipped (it is not
baseline-comparable to the power-law baseline).

**Read anchors follow the supernodes (`rmp` #746).** A power-law graph's high-degree users are
**scattered** across the index space — the per-user stub-count draw is independent of the user index —
so a naive "low-index" bias would miss them entirely. In `zipf` mode the driver instead uses the
reconstructed per-user degree to bias its read anchors toward the hub tail: it sorts users by degree
(rank 0 = the top hub) and draws a rank from a **Zipf(`SOCIAL_ANCHOR_SKEW`, default 2)** distribution,
so the supernodes are queried far more often (`SOCIAL_ANCHOR_SKEW=0` restores uniform anchors). The run
then **asserts (invariant I9)** that a read genuinely landed on a hub — the max queried anchor degree
reaches `max(degree_max/2, 32)` — so a mis-wired skew fails the run instead of quietly querying only the
long tail. It is engaged only on a power-law graph with the generator config reconstructed
(`--gen-profile`); on a uniform graph (no hubs) I9 is a clearly-labelled N/A.

## Scale profiles

| Profile | Users | Friends / user | Articles | ≈ FRIEND edges | Use |
|---------|-------|----------------|----------|----------------|-----|
| `fast`  | 2,000 | 6–24 | 200 | ~15k | CI gate — runs in **seconds**; the committed baseline |
| `large` | 50,000 | 20–120 | 3,000 | ~1.75M | bounded **evidence** run |
| `huge`  | **1,000,000** | **200–2000** | **30,000** | **~550M** | the **literal target**; opt-in, heavy (tens of GB, long) |

Select with `SOCIAL_PROFILE=<fast|large|huge>`. Only `fast` is gated against the committed baseline
(the others are different scales and are not baseline-comparable).

## The two run modes

The example auto-detects its mode through the shared external-target seam (`_harness/harness.sh`).

**LOCAL (default)** — self-boots a real `graphus-server` (Bolt-over-UDS for the ladder + a
plaintext-loopback REST listener for the upload path), **network-bulk-imports** the graph via
`POST /admin/db/{db}/bulk-import` (Mode A) into an isolated database, declares the search schema over
the wire, drives the ladder over UDS while sampling the **server's** per-thread CPU / RSS / IO from
`/proc`, and gates the structural counts against the committed baseline.

**EXTERNAL (attach)** — when any `GRAPHUS_TARGET_{BOLT,REST,UDS}` is set, it attaches to an
**already-running instance** (local or remote) over Bolt-TCP + TLS. It carves out a dedicated,
run-scoped database, loads a small graph over Bolt with a **version-tolerant schema** (a capability
preflight drops any battery family the target cannot serve — e.g. FULLTEXT on an older server),
scrapes the target's Prometheus `/metrics` before and after the ladder, drives the **same** battery,
and **drops the isolated database on exit**. `/proc` sampling is off (there is no co-located PID), so
the server-side channel is the `/metrics` delta and the host-independent invariant gate.

```bash
examples/social-network-large/run.sh                                   # local self-boot
SOCIAL_DEGREE_DIST=uniform  examples/social-network-large/run.sh       # simpler uniform graph (default is power-law)
SOCIAL_WRITERS=2 SOCIAL_WRITE_EVERY_MS=20 examples/…/run.sh            # readers contend with live writers
SOCIAL_PROFILE=large     examples/social-network-large/run.sh          # evidence-scale

GRAPHUS_TARGET_BOLT=bolt+ssc://host:7687 GRAPHUS_TARGET_REST=https://host:7474 \
GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=… \
  examples/social-network-large/run.sh                                 # attach to a running instance
```

Knobs: `SOCIAL_PROFILE`, `SOCIAL_DEGREE_DIST` (+ `SOCIAL_ZIPF_EXPONENT`, `SOCIAL_ANCHOR_SKEW`), `SOCIAL_LADDER` +
`SOCIAL_OPS_PER_RUNG` (override the profile's ladder — e.g. `SOCIAL_LADDER=1` to isolate per-family
latency from queueing, or `1,2,4,8,16,32` to chase the knee), `SOCIAL_WRITERS` /
`SOCIAL_WRITE_EVERY_MS`, `SOCIAL_READER_THREADS`, `GRAPHUS_BIN_DIR`.

> The binaries are rebuilt on every run (cargo is incremental, so this is a no-op when nothing
> changed). Building only when a binary is *absent* would silently run a **stale** binary after any
> source edit, and the evidence would then describe code that is no longer the code under test.
> Setting `GRAPHUS_BIN_DIR` explicitly opts out — you are then pointing at binaries you built.

## What it exercises

| # | Capability | How it is shown |
|---|------------|-----------------|
| 1 | **Deterministic large-graph generation** | `social_gen` emits the graph twice and the bytes are diffed identical. |
| 2 | **Network bulk import** | The graph is uploaded to a **running server** over REST (`bulk-import`, Mode A) and every structural count is round-tripped back over Bolt. |
| 3 | **A production search schema** | **UNIQUENESS constraints** on `USER.id` / `ARTICLE.id` (which enforce the unique key AND back the id point-seek), **TEXT** + **FULLTEXT** over `ARTICLE.name`, a **relationship RANGE** on `LIKE.date`, a **composite** node index, the always-on **LOOKUP** token indexes, and an **existence constraint** on `ARTICLE.name` — declared over the wire and asserted `ONLINE`. |
| 4 | **A concurrent read battery** | Eight families — direct friends, **friend-of-friend**, **mutual friends**, **top-liked** (aggregation + `ORDER BY` + `LIMIT`), degree, **TEXT `CONTAINS`**, **`LIKE.date` recent-window range** (a `RelIndexRangeSeek` run in an explicit read transaction — PROFILE-asserted at runtime, see [I8](#the-invariants-it-asserts)), and **FULLTEXT** `queryNodes` — driven by C simultaneous Bolt clients. |
| 5 | **Read scaling across cores** | The **server process** is sampled per-thread from `/proc` at each rung, so the report shows core utilisation and busy-thread count **vs C**. |
| 6 | **A production-shaped read/write MIX, ON BY DEFAULT** | Every rung runs **twice** — writers off (control), then writers on (treatment) — so the **cost of the mix** is measured and nine concurrency **invariants** (I1–I9) are asserted. See [The read/write mix](#the-readwrite-mix). `SOCIAL_WRITERS=0` restores the read-only ladder. |
| 7 | **Supernode traversal** | The `zipf` mode grows a heavy-tailed hub structure, **Zipf-skews the read anchors toward those hubs** (`SOCIAL_ANCHOR_SKEW`), and asserts a read landed on one (I9). |
| 8 | **Explicit evidence** | A schema-versioned `report.json` + `report.md`: the per-rung scaling curve, real p50/p99/p99.9 per family, server CPU/RSS, and the **decomposed** on-disk footprint. |

## The read/write mix

**The default run is a MIX** (`rmp` #714). Before this, the default drove a read-only ladder against a
**frozen** graph — which cannot exercise one single thing Graphus's concurrency design exists for: MVCC
snapshot-isolation reads that neither abort writers nor are aborted by them, the off-thread reader pool,
SSI for writers, or the GC pin a long reader holds. It measured the one workload nobody runs.

Every rung is now driven **twice, back to back, against the same graph**: arm `readonly` (the CONTROL,
writers off) and then arm `mixed` (the TREATMENT, writers on — the default, and the source of every
headline figure). The control runs **first**, warming the buffer pool for the treatment, so the measured
cost of the mix is a conservative **lower bound**.

The writers are a **trickle, not a storm**: 2 writers, one business unit every 20 ms, each driven
through **managed retry** (bounded exponential backoff + jitter — what `session.execute_write` does in
every official driver). 25% of the units read-modify-write one of 4 *trending* articles
(`SET a.hot = coalesce(a.hot,0)+1`); the rest touch a random user's `registered` timestamp. Both shapes
are property `SET`s on existing nodes, so the mix changes property **values** but never the element
**population** — which is why this example can still honestly report `storage.bytes_per_node` (the
dataset counts still describe the graph the store image holds).

### Two layers of truth, never conflated

The read and write vectors are **never** spliced into one number (the defect fixed in `rmp` #715):

- `throughput.*` is **the READ vector** — one coherent population, the reads of the mixed arm's best
  rung. `throughput.abort_rate` is therefore the **read** abort rate: a genuinely *measured* `0.0`,
  because an auto-commit read runs at **Snapshot Isolation** and *cannot* abort (invariant I1).
- The **WRITE vector** lives in `metadata.workload`, split into the **ENGINE** layer
  (`engine_txn_attempts` / `engine_txn_aborts` / `engine_abort_rate`) and the **APPLICATION** layer
  (`write_units` / `write_committed` / `write_commit_rate`). A high engine abort rate *with* a full
  application commit rate is a **healthy** system under contention: the cost is **latency**
  (`write_p99_ms`, retry-inclusive), never lost work.

### The cost of the mix (measured, 16-core idle host, `fast` profile)

| clients | control (writers off) | mixed (writers on) | cost of the mix | writes committed |
|---:|---:|---:|---:|---:|
| 1 | 275.9 ops/s | 289.5 ops/s | +4.9% | 474 |
| 2 | 509.0 ops/s | 529.1 ops/s | +3.9% | 258 |
| 4 | 973.0 ops/s | 975.5 ops/s | +0.3% | 140 |
| 8 | 1647.2 ops/s | 1643.6 ops/s | −0.2% | 82 |

Serving a production-shaped write stream underneath this read ladder is **essentially free** — the
deltas sit inside run-to-run noise — while the writers commit **100%** of their business units
(`write_commit_rate = 1.0`, 0 retry-budget exhaustions). A read-only ladder can produce **none** of this.

### The invariants it asserts

A violation **fails the run**. None is a performance threshold; they are statements that must be **true**.

| | invariant |
|---|---|
| **I1** | **Reads never abort** (auto-commit reads run at Snapshot Isolation). |
| **I2** | **Writers make progress** — commit rate `1.0`, zero retry-budget exhaustions (no livelock). |
| **I3** | **Readers are not starved by writers** — every mixed rung drains its full read budget and stays above a liveness floor vs its own control. |
| **I4** | **A serialization abort stays retryable** — the `rmp` #612 detector. |
| **I5** | **A slow reader does not stall the writers** — the GC pin (`rmp` #551). |
| **I6** | **No read ever fails with an internal server error** (`Neo.DatabaseError.*`). |
| **I7** | **Reads return correct results** — a sampled fraction of `degree` / `friends` / `mutual` replies is checked against ground truth recomputed from the generator (`rmp` #744). |
| **I8** | **`like_recent` genuinely SEEKS the `LIKE.date` rel-RANGE index** — PROFILEd over the wire under load: the recent-window seek reads a **small fraction** of the dbHits an unrestricted full `LIKE` type scan reads. A plan naming the index it then scans **fails** here instead of passing behind a green tick (`rmp` #746). |
| **I9** | **Anchor-skew landed a read on a hub** — on a power-law graph with `--anchor-skew > 0`, the max queried anchor degree reaches a hub floor; N/A (never a false red) when the skew is off, the graph is uniform, or the config could not be reconstructed (`rmp` #746). |

Three honesty notes, because a gate that cannot fire is worse than no gate:

- **I4 is currently armed but idle.** At the production-shaped default the writers rarely collide, so
  the measured engine abort rate is **~0** (0 aborts in 1238 attempts). With no abort to classify it
  **verifies nothing** on a default run — and it says exactly that in its own output instead of printing
  a reassuring pass. Raise `--writers` / lower `--write-every-ms` / lower `--hot-keys` to exercise it.
- **I6 fails intermittently, and it is meant to.** Turning the mix on exposed a real server bug, filed as
  **`rmp` #721**: an off-thread reader intermittently cannot locate a record (`Prop/Rel store page N not
  allocated`) while a writer **grows** the store, because its location oracle is a *snapshot* while the
  record content it navigates is *live*. The writers-off control arm of the same ladder is **clean at
  every rung** — which is exactly why a read-only ladder could never have found it.
- **I8 measures the seek, it does not trust the plan.** The planner can name a `RelIndexRangeSeek` in the
  plan while the engine actually runs a full scan (`rmp` #755) — a green tick over a lie. So I8 PROFILEs
  the recent-window query *under load* and compares its **measured** dbHits (~2.9k) against an
  unrestricted full `LIKE` type scan, which no index serves. Only the number, not the operator name,
  tells a genuine seek from a scan.

  The reference is deliberately a real index-free scan and **not** "the same query auto-committed".
  That earlier contrast was written against `rmp` #755, when the off-thread reader pool declined an
  index seek to a scan — but `rmp` #769 gave the pool relationship-index seek parity, so both paths now
  seek (measured: `seek == scan == 2907` dbHits, both genuine). A gate whose PASS condition depends on a
  known defect still being present reports **FAIL on the improvement that fixes it**, which is how this
  one was caught.

## The evidence it collects

Written to the git-ignored `evidence/` directory (`report.json` for tooling, `report.md` for humans).
Figures below are a `fast`-profile local run on a 16-core x86_64 host — **machine-variant**; yours
will differ.

### Reads scale across cores — the headline

| Clients | Throughput | p50 | p99 | Server cores | Busy threads |
|--------:|-----------:|----:|----:|-------------:|-------------:|
| 1 | 278 ops/s | 2.20 ms | 12.7 ms | 0.66 | 1 |
| 2 | 519 ops/s | 2.19 ms | 13.2 ms | 1.35 | 16 |
| 4 | 981 ops/s | 2.19 ms | 15.6 ms | 2.79 | 17 |
| 8 | **1,684 ops/s** | 2.25 ms | 23.2 ms | **6.08** | 17 |

Throughput rises **6.1× from C=1 to C=8** while p50 stays flat, and at saturation the server burns
**6.08 cores across 17 busy threads with the busiest single thread at only 0.45 of a core**. That
spread is the proof: no single thread is the bottleneck — the off-thread reader pool (`rmp`
#336/#543) is genuinely engaged. The ladder's top rung is still its best, so the plateau lies beyond
C=8; extend `SOCIAL_LADDER` to find the knee.

### Per-family latency — where the tail comes from

Two families cost far more than the rest. To separate a genuinely **slow query** from a merely
**contended** one, measure both uncontended (`SOCIAL_LADDER=1`, same op budget) and at saturation:

| Family | p50 @ C=1 (uncontended) | p50 @ C=8 (saturated) | Why |
|--------|------------------------:|----------------------:|-----|
| friends, degree, mutual, friend-of-friend, `CONTAINS`, FULLTEXT | ~2.2 ms | ~2.2–2.8 ms | index-backed seeks + bounded traversal |
| **`like_recent`** (`LIKE.date >= X`, the recent ~10% window) | **6.3 ms** | 11.6 ms | a `RelIndexRangeSeek` on the `LIKE.date` rel-RANGE index (`rmp` #680), run in an **explicit read transaction** (`BEGIN`/`RUN`/`COMMIT` = 3 round-trips). PROFILE-measured (I8): **2907 dbHits over the narrow recent window vs 22595 for an unrestricted full `LIKE` type scan**, a **7.8× reduction in reads-touched**. Wall latency is dominated by the round-trips at this small scale, not the dbHits, so it stays a few ms above the point reads — the win is in reads-touched, provable at any size |
| **`top_liked`** (aggregation + `ORDER BY` + `LIMIT`) | **12.6 ms** | 20.5 ms | a full aggregation scan over every `LIKE` edge |

The cost is **intrinsic to the query, not to the contention**: even alone on an idle server these two
run 5–6× every other family. That is the example doing its job — it names the two read-path costs
worth attacking.

> **A trap worth knowing.** Run the same isolation with a *smaller* op budget and `top_liked` reads
> ~58 ms — nearly 5× worse. That is a cold buffer pool, not a slow query: too few iterations for the
> scan's pages to be resident. Always hold the op budget constant when comparing rungs, or the
> warm-up will masquerade as a result.

### Resources

| Vector | `fast`-profile evidence |
|--------|--------------------------|
| **Graph** | 2,000 USER + 200 ARTICLE nodes; 15,047 FRIEND + 10,020 LIKE edges |
| **RAM** | server peak RSS **430 MiB** at C=8 (317 MiB at C=1 — it grows with connection count) |
| **Storage — data image** | `graphus.store` **4.4 MiB** = **2.46× the 1.8 MiB logical graph**. This is the ratio that scales with the graph, and it is healthy. |
| **Storage — doublewrite** | `graphus.dwb` **16.9 MiB** — a **fixed preallocation, one per database**, independent of graph size. It dominates a small graph's footprint and amortises to nothing on a large one. |
| **Storage — redo log** | `graphus.wal` **retains ~19 MiB on disk = ~4.3× the data image** after WRITING **~48 MiB of cumulative redo** over the run — so **~60% was RECYCLED, not accumulated** (the highest `seg.<lsn>` frontier proves it from the evidence itself). The Mode A bulk-load's redo is reclaimed at load end (`rmp` **#579**) and the WAL segment target is sized to the store (`rmp` **#706**), so sealed segments below the checkpoint floor are freed rather than retained; what remains is the recent redo tail. A pure bulk-load (`SOCIAL_WRITERS=0`, no post-load writes) reclaims to **~0.5× the data image**. This **resolves `rmp` #702** — before those fixes the same workload held **~9.3×** and grew monotonically. |

> **On reading the storage numbers.** A single lumped "durable bytes ÷ logical bytes" ratio would
> read as **~23×** here — and it would be *misleading*, because it blends the graph's data image with a
> constant-cost doublewrite buffer and a redo log that is **continuously recycled** (its retained bytes
> are far below the redo it has written). The report therefore **decomposes** the footprint, states
> which bytes scale with the graph and which do not, and reports the redo log's **cumulative-written vs.
> retained** bytes so recycling is provable from the evidence itself. (The WAL is a *directory* of
> `seg.<lsn>` files; a classifier that tests only the leaf file name counts every WAL byte as store and
> reports `wal = 0`, hiding the redo log entirely — that bug is now pinned by a regression test.)

### The baseline regression gate

The `fast` profile is compared against the committed `baseline.json` by `social_baseline_cmp`, which
gates **only the stable, deterministic structural metrics** (node / relationship / USER / ARTICLE /
FRIEND / LIKE counts). The machine-variant families (RSS, throughput, CPU, wall-time, WAL) are given
an effectively-infinite tolerance, so the gate flags a genuine storage-engine or generator regression
without flaking on hardware differences. It is skipped for the `zipf` graph and in attach mode (where
`measure_target --assert` applies the host-independent invariant gate instead: zero statement panics,
zero recovery panics, zero force-detaches).

## CI coverage

`graphus-social-gen`'s own tests exercise the `fast`-profile load, the read-query battery, the shape
invariants, the search schema, and the generator's byte-identical determinism + degree-band + id/name
invariants — including the power-law degree law and the on-disk footprint decomposition.

The search schema is additionally pinned by a **hermetic schema mirror**,
`graphus-server/tests/social_network_large_schema.rs`, which drives the equivalent `CREATE … INDEX` /
`CREATE CONSTRAINT` **strings** through the REAL admin-DDL + `LocalEngine` seam (the exact seam the
Bolt/REST admin surfaces use) and asserts the full `SHOW INDEXES` / `SHOW CONSTRAINTS` column set, the
honest relationship-RANGE planner utilisation (`RelIndexSeek` for equality, `RelIndexRangeSeek` for a
range — `rmp` #680), the TEXT/FULLTEXT known-set search, and the existence-constraint enforcement.
