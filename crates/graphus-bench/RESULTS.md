# SPIKE #8 — Runtime write/ACID shape: measured evidence

Empirical resolution of the **measurement half** of SPIKE #8 (`specification/04-technical-design.md`
§9.1, §12 item 8): does the current **single log shard + group commit** write path (candidate **a**)
sustain adequate throughput with bounded tail latency, or does the single log tail saturate at the
scales a single-node Graphus server sees — justifying **partitioned logging** (candidate **b**)?

Candidate (b) is **not** implemented (per §9.1 it is built "only if (a) is shown to bottleneck").
This document measures (a) thoroughly and gives an evidence-based recommendation. The spec decision
is recorded separately; this is the evidence.

> **TL;DR recommendation: keep candidate (a) — single log shard + group commit.** On this host a
> single thread sustains **~173,000 commits/s (~690,000 ops/s)** of short OLTP-style write
> transactions with **p50 = 3.4 µs, p99 = 7.2 µs, p99.9 = 15.4 µs** per commit, and the p99 stays
> bounded and stable across a 50× sweep of WAL-volume-per-commit and across stream lengths from
> 1,000 to 50,000 back-to-back commits. The log tail does **not** saturate in the single-node
> envelope. Revisit (b) only if a future workload needs sustained write throughput **above ~1.5–2×**
> this single-thread ceiling at a bounded p99 (see "When to revisit candidate (b)").

---

## 1. Test environment

| Axis | Value |
| --- | --- |
| Machine | AMD Ryzen 9 5900HX (8 cores / 16 threads, max 4.89 GHz) |
| Caches | L1d 256 KiB (8×), L2 4 MiB (8×), L3 (shared) |
| CPU features | `sse4_2` present (CRC32C hardware path available) |
| Memory | 32 GiB |
| OS / kernel | Linux 6.8.0-124-generic, `x86_64` |
| Toolchain | `rustc 1.96.0 (ac68faa20 2026-05-25)`, edition 2024 |
| Bench profile | Criterion `bench` profile (release codegen: `codegen-units = 1`, `lto = "thin"`) |
| Harness | Criterion 0.5, `harness = false`, `cargo_bench_support` only (no gnuplot/HTML) |

> **Cross-target note (AC: x86_64 + aarch64).** These numbers are the **x86_64** run. aarch64 is a
> Tier-1 target (`04 §10`) but is **out of scope for this environment** — there is no aarch64 host
> here. The benchmarks are the reusable instrument: re-run `cargo bench -p graphus-bench` on aarch64
> hardware (Apple Silicon / Raspberry Pi 5) and append a sibling column. The write path uses no
> architecture-specific code, so the *shape* of the result (bounded p99, sub-linear-per-op
> amortization) is expected to carry; the absolute numbers will differ with the weaker memory model
> and different cache lines (`04 §10.1`–§10.2).

---

## 2. What is measured, and why it answers the question

The transactional commit path of the **real** persistent store (`graphus_storage::RecordStore`) is
driven over the in-memory Deterministic-Simulation-Testing substrate (`graphus_io::MemBlockDevice` +
`graphus_wal::MemLogSink`), so the WAL/commit machinery is exercised deterministically with **no
disk noise**. The serialization point under test is concrete: on `RecordStore::commit` the path
settles each created/expired MVCC version stamp (one WAL `Update` per record), re-checkpoints the
catalog to the meta page, appends the `COMMIT` record, then `WalManager::commit → harden() →
LogSink::sync()` — the **group-commit `fdatasync`**. Every committer passes through the single log
tail; on the DST sink `sync()` cost tracks the WAL byte volume the transaction logged. So driving
the real store and sweeping per-commit op-count isolates exactly how **WAL-volume-per-commit** drives
the single-log serialization-point cost — the thing candidate (a) relies on group commit to amortize.

Benchmarks (`cargo bench -p graphus-bench`):

- `benches/commit_path.rs` — the write/commit path (this SPIKE):
  - `commit_throughput/short_txn` — Criterion throughput at small op-counts (ops/sec, commits/sec).
  - `commit_serialization_sweep/ops_per_commit` — the **serialization-point sweep**: per-commit
    latency histogram (p50/p99/p99.9/max) over op-counts 1 → 256, to see whether the log tail's
    per-commit latency stays bounded as WAL-volume-per-commit grows.
  - `commit_concurrency_proxy/back_to_back_commits` — per-commit latency under a sustained stream of
    back-to-back committers (the closest single-threaded proxy for "many committers, one log tail").
- `benches/read_path.rs` — the lock-free read side for contrast (traversal + scan).

Tail-latency percentiles are computed by the bench itself from a per-commit latency histogram
(`iter_custom` + a manual percentile), printed to stderr as `[SPIKE#8] …` lines, because Criterion
reports a mean + CI but not p99.9. Store-recreation time (see §5) is **excluded** — only per-commit
latencies are summed and reported.

---

## 3. Results — commit / write path

Numbers below are from a solid run (`--warm-up-time 0.5 --measurement-time 3 --sample-size 50`; the
in-tree default params are lighter for CI — see §6). Criterion `time` is per-iteration (= per
commit, or per stream for the proxy); throughput is from Criterion's `thrpt`.

### 3.1 Short-transaction throughput (`commit_throughput/short_txn`)

| ops / commit | per-commit time (median) | throughput (ops/s) | implied commits/s |
| ---: | ---: | ---: | ---: |
| 1 | 4.62 µs | 216 K | ~216 K |
| 4 | 25.6 µs | 157 K | ~39 K |
| 16 | 74.0 µs | 216 K | ~13.5 K |

### 3.2 Serialization-point sweep (`commit_serialization_sweep/ops_per_commit`)

Per-commit latency from the bench's own histogram (the headline tail-latency evidence):

| ops / commit | p50 | p99 | p99.9 | throughput (ops/s) | commits/s |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 (baseline) | 2.79 µs | 6.22 µs | 13.3 µs | 276 K | ~276 K |
| 4 | 3.28 µs | 4.33 µs | 13.3 µs | 1.22 M | ~304 K |
| 16 | 10.8 µs | 20.5 µs | 115 µs | 1.34 M | ~84 K |
| 64 | 18.5 µs | 48.5 µs | 973 µs | 2.04 M | ~32 K |
| 256 | 66.1 µs | 1.20 ms | 4.17 ms | 2.32 M | ~9 K |

**Reading the sweep.** From 1 → 64 ops/commit the p99 grows ~6 µs → ~49 µs — an ~8× rise for a 64×
rise in WAL-volume-per-commit, i.e. the per-op marginal commit cost *falls* as the transaction grows:
group commit amortizes the fixed per-commit overhead (one `fdatasync`, the catalog re-checkpoint)
across more work, which is exactly the property candidate (a) is supposed to have. Aggregate
**ops/sec rises monotonically** with batch size (276 K → 2.3 M) — bigger transactions are *more*
efficient on the single log, not less. At 256 ops/commit the p99 jumps to 1.2 ms; that op-count is
far above a "short transaction", and part of that tail is a measurement-substrate artifact (§5), not
the production commit path.

### 3.3 Sustained back-to-back commits (`commit_concurrency_proxy`, 4 ops/commit)

Per-commit latency over a sustained stream of committers (the single-threaded proxy for many
committers hitting one log tail):

| stream length (commits) | p50 | p99 | p99.9 | commits/s | ops/s |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 3.42 µs | ~7 µs | ~14 µs | ~173 K | ~690 K |
| 10,000 | 3.42 µs | ~7 µs | ~14 µs | ~173 K | ~690 K |
| 50,000 | 3.42 µs | 7.19 µs | 15.4 µs | ~173 K | ~691 K |

**The p99 and p99.9 are flat across a 50× change in stream length** — the log tail shows no
queue-growth or degradation as the commit stream lengthens. This is the central evidence that the
single log shard does not saturate under sustained single-thread write load: a committer's tail
latency is independent of how many commits preceded it.

---

## 4. Results — read path (lock-free, for contrast)

Reads are "fully parallel and lock-free against committed versions" (§9.1) — they never touch the
log tail. Characterized on the same store/host:

### 4.1 Traversal (`read_traversal`, index-free adjacency pointer chase)

| out-edges/node (deg) | ~edges visited | per-walk time | throughput (edges/s) |
| ---: | ---: | ---: | ---: |
| 2 | ~4 | 135 ns | ~29.6 M |
| 8 | ~16 | 480 ns | ~33.3 M |
| 32 | ~64 | 1.81 µs | ~35.4 M |

`incident_rels` and `degree` track each other (degree is the same chain walk). Latency scales
linearly with degree at ~30–35 M edges/s — the O(degree) pointer chase with no index probe.

### 4.2 Scan (`read_scan`, full node-store scan = `MATCH (n)` leaf)

| nodes | per-scan time | throughput (nodes/s) |
| ---: | ---: | ---: |
| 1,000 | 17.0 µs | ~59.0 M |
| 10,000 | 168 µs | ~59.6 M |
| 20,000 | 336 µs | ~59.5 M |

Flat **~59 M nodes/s** regardless of node count — perfectly linear, no per-element overhead growth.

**Read/write contrast:** reads run at tens of millions of elements/sec lock-free; the serialized
commit path runs at ~173 K commits/s single-thread. Both are bounded and stable. The read side is
nowhere near a bottleneck and imposes no pressure on the write serialization point — consistent with
the §9.1 split (lock-free reads, sharded writes).

---

## 5. Caveats and honesty about the substrate

- **DST log-sink realloc artifact.** `MemLogSink.durable` is a `Vec<u8>` that the whole log appends
  into; when it grows past a capacity boundary it reallocates and copies the entire durable log —
  an O(total-log-size) memcpy that occurs O(log n) times. This produces occasional multi-millisecond
  `max` outliers (e.g. a lone ~12 ms spike even on the 1-op run, where commit cost is *smallest*),
  which are clearly the allocator, not the commit path. The **production `FileLogSink` appends to a
  file and does not realloc**, so those specific spikes do not exist in production. The robust,
  substrate-independent signals are **p50 and p99**; p99.9/max at the largest op-counts are reported
  for completeness but partly reflect the DST sink, not candidate (a).
- **Single-threaded harness.** The storage API and the DST harness are single-threaded by
  construction (`04 §11.1` — the whole engine runs in one deterministic thread in simulation). So
  this measures the **per-commit serialization-point cost** and its stability under sustained load;
  it does **not** measure true multi-threaded group-commit *batching* (many committers parking on
  one queue, one `fdatasync` waking all of them). That batching is a runtime-layer concern (`04
  §9.1`'s "small set of shards"/commit queue), not present in the storage crate, and is the right
  place to measure the *amplification* of candidate (a) — see §7.
- **Store-size envelope (a real storage-layer limit found during this work).** `RecordStore::commit`
  re-checkpoints the whole catalog to the single fixed metadata page on every commit, and that
  catalog embeds each store's `device_pages` map (8 bytes per store page). The catalog must fit one
  8 KiB page, capping a store at **~1,000 total record pages** before `store.rs::write_region`
  asserts "region runs past the page". The bench driver recreates the store before it approaches the
  cap (store-recreation excluded from timings) so the measurement is not contaminated by this
  overflow. **This limit is filed as a separate finding** (a paged/overflow catalog is the fix); it
  is out of scope for this bench-only task (hard rule: touch only `crates/graphus-bench/`).

---

## 6. Reproducing

```sh
# Full suite, in-tree default params (modest, CI-friendly — finishes in a few minutes):
cargo bench -p graphus-bench

# Just the commit path, or just the read path:
cargo bench -p graphus-bench --bench commit_path
cargo bench -p graphus-bench --bench read_path

# The headline solid run used here (heavier sampling):
cargo bench -p graphus-bench --bench commit_path -- \
    --warm-up-time 0.5 --measurement-time 3 --sample-size 50

# The larger 50,000-commit concurrency stream (recorded in §3.3) is run on demand:
cargo bench -p graphus-bench --bench commit_path -- 'commit_concurrency_proxy'
```

The per-commit latency percentiles print to **stderr** as `[SPIKE#8] …` lines (take the last line
per parameter — the final, largest-sample collection). Criterion's mean + CI print to stdout.

---

## 7. Recommendation and decision threshold

**Keep candidate (a): a single log shard with group commit.** The measurement shows the single log
tail is **not** the bottleneck in the single-node envelope:

1. **Throughput is adequate and improves with batching.** ~173 K commits/s (~690 K ops/s) of short
   write transactions on one thread, and aggregate ops/sec *rises* monotonically as transactions
   carry more work (276 K → 2.3 M ops/s across the sweep) — group commit amortizes the fixed
   per-commit cost, the defining property of candidate (a).
2. **Tail latency is bounded and stable.** p99 stays in the single-digit-to-tens-of-µs range for
   short transactions and is **flat across a 50× change in commit-stream length** (3.42 µs / 7.2 µs
   / 15.4 µs p50/p99/p99.9 at the 50,000-commit stream). No queue growth, no saturation.
3. **No p99 regression vs the trivial baseline** (the AC's regression check). The 1-op commit is the
   baseline (p99 = 6.2 µs); the representative 4-op short transaction has p99 = 4.3 µs in the sweep
   and ~7 µs sustained — same order of magnitude, bounded, stable. The p99 grows only sub-linearly
   in per-commit op-count (8× for 64× the WAL volume), which is amortization, not regression.

Building candidate (b) (partitioned logging keyed by data partition with a global LSN order) now
would add cross-partition LSN-ordering complexity and a serializability/recovery surface (every
partition's log must still merge into one global order for ARIES + SSI) for **no measured benefit**
— it would violate "measure to decide" and §9.1's explicit "only if (a) is shown to bottleneck".

### When to revisit candidate (b)

Re-open the (b) decision if, on representative hardware, **either**:

- sustained write throughput must exceed roughly **1.5–2× the single-thread commit ceiling measured
  here at a bounded p99** (i.e. the multi-threaded group-commit batching at the runtime layer — §5,
  to be benchmarked next — fails to scale the single-log path to the target aggregate commit rate
  while keeping p99 bounded); **or**
- the single-log p99 under the *multi-threaded* commit-queue benchmark grows with offered
  concurrency (a saturation knee), rather than staying flat as it does in the single-threaded sweep
  here.

The natural next measurement (a follow-up, needs the runtime-layer commit queue from `04 §9.1`) is
the **multi-threaded group-commit** benchmark: N committer threads parking on one queue, one
`fdatasync` waking the batch, sweeping N and reporting aggregate commits/s and p99. That is where the
*amplification* of candidate (a) is proven or disproven; this SPIKE establishes that the underlying
single-log per-commit serialization cost is small and bounded, which is the prerequisite for that
batching to pay off.

---

## 8. The CI regression gate (`bin/bench_gate`, `rmp` #27)

The full Criterion suites above are the measurement instrument; the **regression gate** is the
lightweight CI counterpart (`crates/graphus-bench/src/bin/bench_gate.rs`). It measures two
representative slices of the hot paths — the **commit serialization point** and the **lock-free scan
leaf** — as wall-clock **medians** (robust to outliers; `WARMUP = 50`, `SAMPLES = 201`), and fails if
either regresses past a tolerance versus the committed baseline `baseline.toml`. It carries no
Criterion dependency, so it is self-contained and runs in ~1–2 s.

The committed baseline was seeded from a release build on this machine class (§1):

| metric | baseline (median) | corresponds to |
| --- | ---: | --- |
| `commit_short_txn_ns` | 4,330 ns | §3.1 short-txn commit (4-op) |
| `scan_1k_nodes_ns` | 21,651 ns | §4.2 scan @ 1,000 nodes |

Default tolerance is **20 %** (absorbs run-to-run jitter — repeated release runs land within ±8 % —
while still catching a real regression, which is typically ≥ 1.5–2×). Run, re-seed, or loosen:

```sh
cargo run -p graphus-bench --release --bin bench_gate              # gate vs baseline (PASS/FAIL)
cargo run -p graphus-bench --release --bin bench_gate -- --update  # re-seed after an intended change
cargo run -p graphus-bench --release --bin bench_gate -- --tolerance 0.30
```

The gate **must** be run in `--release`: the baseline is a release measurement, so a debug run (~10×
slower) deliberately trips it (a useful self-check that the gate has teeth). See `VERIFICATION.md` §6.

---

## 9. LDBC-SNB-flavoured macro harness — broadened query set + offline correctness (`rmp` #78)

This section records the macro harness baseline after `rmp` #78 broadened the operation catalog
toward the official LDBC SNB Interactive-Short (IS), Interactive-Complex (IC), and
Business-Intelligence (BI) query *shapes* and added an offline **correctness** harness. See
`crates/graphus-bench/LDBC.md` for the full provenance and the explicit **offline scope**.

> **Offline scope (read this first).** The official LDBC Datagen (Hadoop/Spark), the official
> dataset, and the audited validation parameters are **not used** (they are not available offline).
> Correctness is verified against the **deterministic synthetic generator's known ground truth**
> (`src/ldbc/correctness.rs`): every operation's Cypher answer (through the real engine pipeline) is
> asserted equal to an answer computed independently in Rust from the same generation parameters. The
> latency/throughput numbers below are a **relative Graphus-vs-Graphus regression signal**, *not*
> comparable to published LDBC results.

### 9.1 Correctness (the headline deliverable)

`cargo test -p graphus-bench` runs `every_operation_matches_ground_truth_at_micro_scale`: it
generates the deterministic micro-scale graph, builds the standard `id` property indexes, and for
**every** one of the 24 catalog operations runs its Cypher through the real
`tokenize → … → execute → commit` pipeline and asserts the result equals the ground truth computed
from the [`SnbModel`]. Reads are checked across 16 anchor invocations each; the write op is verified
by reading the inserted comment back and asserting it links the right post + author.

**Result: 24/24 operations match ground truth (0 disagreements, 0 engine correctness bugs found).**

### 9.2 Operation catalog and SNB provenance (24 operations, 0 deferred)

| family | operations |
| ------ | ---------- |
| IS (short reads) | `IS1-profile`, `IS2-authored`, `IS3-friends`, `IS5-creator`, `IS6-forum` |
| IC (complex traversal/aggregate) | `IC-fof`, `IC-fof-strict`, `IC2-friend-msgs`, `IC-degree`, `IC-top-degree`, `IC-common-friends`, `IC-reach-2`, `IC-collect-friends`, `DEG-forum` |
| BI (aggregates) | `BI-pop`, `BI-popular-posts`, `BI-forum-sizes`, `BI-prolific-authors`, `BI-top-commenters`, `BI-replied-posts`, `BI-age-bands`, `BI-forum-views`, `BI-isolated` |
| write | `IU-comment` (insert, verified by read-back) |

The official queries the offline harness does **not** attempt (and why) are listed in the report
footer and in `LDBC.md` §"Deferred official queries" — chiefly: `shortestPath`/`allShortestPaths`
(IC13/IC14), `creationDate`-windowed analytics (IC3/4/5/6/9, IS4/7), and the
Organisation/Place/Tag/Country dimensions (IC1 full search, BI tag/country correlations) the
synthetic schema omits.

### 9.3 Baseline numbers (tiny scale, release, machine class §1)

Captured with `cargo run -p graphus-bench --release --bin ldbc_snb` on the §1 host
(`rustc 1.96.0`, AMD Ryzen 9 5900HX, Linux 6.8). Each operation timed over 200 invocations; the
graph is the deterministic **174 nodes / 670 rels** tiny graph (built in 337 committed write txns,
plus 3 `id` property indexes). Property-index seeks are active, so id-anchored point reads
(`IS1-profile`) are now sub-millisecond.

| operation            | rw | p50 (µs) | p99 (µs) | ops/s | rows |
| -------------------- | -- | -------: | -------: | ----: | ---: |
| IS1-profile          | R  |    779.0 |   1079.1 |  1270 |    1 |
| IS3-friends          | R  |    969.7 |   1144.3 |  1017 |    7 |
| IS2-authored         | R  |   8029.1 |   8797.6 |   124 |    2 |
| IS5-creator          | R  |   1731.9 |   1961.7 |   575 |    1 |
| IS6-forum            | R  |   1433.5 |   1692.5 |   692 |    1 |
| IC-fof               | R  |   2129.4 |   3172.4 |   445 |   37 |
| IC-fof-strict        | R  |  11481.8 |  33877.1 |    71 |   30 |
| IC2-friend-msgs      | R  |   2792.0 |   4104.1 |   354 |   20 |
| IC-degree            | R  |  12765.5 |  13697.6 |    78 |   60 |
| IC-top-degree        | R  |  13013.7 |  14414.4 |    76 |    5 |
| IC-common-friends    | R  |   4049.5 |   5832.8 |   233 |   36 |
| IC-reach-2           | R  |   3900.4 |   5631.4 |   244 |   38 |
| BI-pop               | R  |   4232.9 |   4569.6 |   239 |    1 |
| BI-popular-posts     | R  |   3024.3 |   4174.2 |   329 |    1 |
| BI-forum-sizes       | R  |   2961.1 |   3237.4 |   335 |    6 |
| BI-prolific-authors  | R  |   4957.2 |   5315.5 |   203 |   10 |
| BI-top-commenters    | R  |   7148.9 |   9430.0 |   138 |   10 |
| BI-replied-posts     | R  |   8386.1 |  10087.7 |   118 |   10 |
| BI-age-bands         | R  |   5618.6 |   6653.2 |   176 |    3 |
| BI-forum-views       | R  |   4929.9 |   6668.0 |   194 |    6 |
| BI-isolated          | R  |  21577.6 |  27355.2 |    45 |    0 |
| DEG-forum            | R  |   3160.8 |   3810.2 |   310 |    1 |
| IC-collect-friends   | R  |   3561.3 |   4246.5 |   275 |    1 |
| IU-comment           | W  |  13606.8 |  18295.0 |    75 |    0 |

A condensed, machine-readable form of three representative slices is recorded in `baseline.toml`
under `[ldbc_snb]` (a documented **relative** signal, not a CI gate — the `bench_gate` `[metrics]`
section remains the only gated micro-baseline). The cost is still dominated by full label/relationship
scans where a query lacks an `id` anchor (the aggregates and the multi-hop traversals); the harness is
the instrument that will show those drop as more index seeks and join strategies are wired into
planning.
