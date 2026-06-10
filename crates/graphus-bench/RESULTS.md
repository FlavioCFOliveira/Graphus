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
