# Design Decision: Multi-core writes (rmp #567 / epic #557)

Status: **DRAFT — design spike, awaiting maintainer ratification (#566).**
This is a decision document, not shipped behaviour. It records the empirical evidence and a ranked
recommendation for unblocking write parallelism in Graphus. Numbers marked `[PROFILE]` come from the
in-process writer profiler committed for this spike (`d3f3599`); `[BENCH]` from the committed
`graphus-bench` commit-path benchmark; `[S0]` from the shard-ceiling probe; everything else is derived
from the source. Host: 16-core Ryzen, NVMe, `perf` blocked (CPU from `/proc/.../stat`, CLK_TCK=100).

---

## 0.0 SUPERSEDED IN PART — read this before the numbers below (2026-08-05, `rmp` #975)

**The headline measurement in §0 and §3 is pre-fix and no longer describes the tree.** This document
was committed in `4359f4a` on 2026-07-03; the fix for the root cause it identifies in §3.3 —
autocommit bypassing group commit — landed in `7957579` **the same day**, and the pipeline was
deepened by `rmp` #570 after it. `finish_autocommit` now takes a `commit_batch` and goes through
`commit_prepare` (`crates/graphus-server/src/engine/exec.rs`), so §3.3's "zero fsync coalescing on the
most common OLTP shape" is fixed.

Re-measured on the same class of host with the committed harness
(`cargo test -p graphus-server --release --test pipeline_scaling -- --ignored --nocapture`, 4000
disjoint auto-commit writes per thread, real `FileBlockDevice` + `FileLogSink`):

| W | commits/s | engine cores | walsync cores | real `fdatasync`/commit |
|--:|----------:|-------------:|--------------:|------------------------:|
| 1 | 688.9 | 0.13 | 0.04 | 1.008 |
| 2 | 780.3 | 0.21 | 0.06 | 0.801 |
| 4 | 1216.0 | 0.33 | 0.08 | 0.391 |
| 8 | 1784.3 | 0.45 | 0.08 | 0.155 |
| 16 | **2092.1** | **0.51** | 0.10 | **0.082** |

Three things changed, and each one moves a conclusion below:

1. **Throughput is no longer flat.** It scales **3.04×** from W=1 to W=16. The "flat ~650–713 across
   W=1→16" line in §0 and the `file` rows in §3.1 describe the pre-`7957579` tree.
2. **Durability latency is no longer the ceiling.** Coalescing is working — the real `fdatasync` count
   falls **12×** per commit, from 1.008 to 0.082 — and the `graphus-walsync` thread sits at 0.10
   cores. Rank 1 of §5 has been delivered.
3. **The engine thread is at 0.51 cores at W=16, not 0.21 and not 1.0.** So the remaining ceiling is
   neither `fdatasync` nor CPU saturation. The residual serialisation is the one §3.3 already named as
   the next opportunity: a depth-1 commit pipeline against closed-loop writers, each blocking on its
   own commit round-trip. That is what the single engine thread now costs, and it is what `rmp` #975
   removes.

**What still stands** is the reasoning, the architecture comparison in §4, and the ranking's *shape*:
coalescing before cores, and cores before sharding. What does not stand is the claim that adding cores
cannot lift the number — it could not lift it *while the fsync barrier stood*, and that barrier is
gone. Treat every `[PROFILE]` figure below as the pre-`7957579` baseline it is, and this table as the
current one.

---

## 0. TL;DR

> The bullets in this section are the **2026-07-03 pre-fix** reading. See §0.0 above for the
> re-measured numbers and which conclusions they change.

- **The common write ceiling is NOT CPU — it is durability latency.** For indexed autocommit OLTP
  writes the single engine thread sits at **0.21 cores (79% idle, blocked in `fdatasync`)** and
  throughput is **flat ~650–713 commits/s across W=1→16** `[PROFILE]`. Adding cores cannot lift this.
- **Root cause is a fixable gap, not a fundamental limit:** *autocommit* commits **bypass** the
  existing group-commit coalescing/pipelining machinery (#528/#532) and do an **inline `fdatasync`
  (~1.2 ms) on the engine thread**. Explicit `BEGIN/COMMIT` writes, which *do* use it, already get
  **2.3× at W=4** `[PROFILE]`.
- **The highest-ROI, lowest-risk, determinism-safe first move is therefore NOT a multi-core
  architecture — it is fsync coalescing** (route autocommit through the batched harden path + deepen
  the pipeline). It can take a single writer from ~650 → toward the measured **~3531 c/s** in-CPU
  ceiling `[PROFILE]` (~5×), with no new cores and no ACID/determinism risk.
- **Multi-core writes matter only *after* that**, when the writer becomes CPU-bound at ~1 core. Then:
  pipelined write execution (determinism-safe, workload-dependent) → and finally sharding.
- **Sharding best case measured `[S0]`: 8 fully-independent engines = 5.8× aggregate** on this box —
  nearly the *same* throughput as free coalescing reaches on ONE writer, but at the cost of the entire
  cross-shard/2PC/determinism epic. Sharding only pays off past the single-core CPU ceiling **and**
  for cleanly-partitionable workloads.

## 1. Problem statement (measured)

Graphus runs **one `!Send` OS thread per database as the single writer** (`dbcatalog.rs:456`). Reads
were already made concurrent (#336/#337/#543) and scale to ~14–16 of 16 cores. A 12-writer Bolt-TCP
OLTP workload (`fraud-oltp`) peaked at **1.34 cores (avg 0.70)**.

Single-writer facts from the current tree:
- `run_engine_loop` (`engine/mod.rs`) owns a `!Send` `TxnCoordinator`; every `EngineCommand` flows
  through a bounded mpsc and is handled **serially**.
- The commit-ts oracle is a **plain `u64`** (`store.rs:235 commit_ts_hw`); WAL `append`/`next_lsn` take
  `&mut self` (`wal/manager.rs:617`). Neither is lock-free — both are single-`&mut`-thread-protected.
- The SSI tracker (`txn/ssi.rs`) is single-writer; the `detect_pivot_abort` victim is a **pure
  function of the transaction set** (deterministic hashing + `sort_unstable` + lowest-id tie-break),
  which the DST "same seed ⇒ identical trace" contract depends on (`ssi.rs:48-52, 479-487, 610-624`).

## 2. The single most important structural fact

**Under Graphus's determinism contract there is exactly ONE serialization point — the *commit
sequencer*: assign commit-ts → assign LSN + append COMMIT in order → run SSI `detect_pivot_abort` →
publish visibility.** Its result (including *which* txn is the SSI abort victim) must be a
deterministic function of the txn set, byte-identical per seed.

Consequence (Amdahl): **every architecture that keeps a single total commit order has the same lower
bound on its serial fraction — the commit sequencer — and the same ceiling `1/serial_fraction`.**
Approaches 2/3/4-with-one-sequencer differ only in how much *pre-commit* work they move off the
sequencer thread; none remove it. **The only way past that ceiling is to PARTITION the total order into
N independent orders (sharding).**

## 3. Where the writer's time goes

### 3.1 Serial commit-tail CPU, isolated `[BENCH]`
`commit_path` bench (real `RecordStore`, in-memory device, **no fsync** — pure commit CPU):

| ops/commit | commit-tail CPU | ≈ commits/s |
|-----------:|----------------:|------------:|
| 1  | 5.0 µs  | ~200 k |
| 4  | 20.4 µs | ~49 k  |
| 16 | 57.0 µs | ~18 k  |

≈ `2–3 µs fixed + 3.3 µs/op`; the per-op term is **WAL record append** — fundamentally serial in a
single log (LSN monotonic). Matches the measured 7–60× WAL amplification.

### 3.2 In-process writer sweep `[PROFILE]` — the authoritative ceiling
Threaded `spawn_engine`, N writer threads, parameterized OLTP edge insert, 5 s windows.
`eng-cores` = the single `graphus-engine` thread. **Cheap-lookup (N=200), the honest OLTP proxy:**

| substrate | W | commits/s | proc-cores | **eng-cores** |
|-----------|--:|----------:|-----------:|--------------:|
| **mem** (no fsync) | 1 | 1171 | 0.73 | 0.70 |
| | 8 | 1427 | 0.89 | 0.83 |
| | 12 | 3045 | 1.07 | **0.99** |
| | 16 | **3531** | 1.09 | **0.99** |
| **file** (real fdatasync) | 1 | 654 | 0.23 | **0.21** |
| | 8 | 678 | 0.22 | **0.20** |
| | 12 | 653 | 0.24 | **0.22** |
| | 16 | **713** | 0.24 | **0.21** |

The file rows are the money shot: **flat ~650–713/s across W=1→16, engine pinned at 0.21 cores (79%
idle in the fsync syscall)**. Remove fsync (mem) and the *same* workload scales to a full core /
3531 c/s. The gap is pure durability latency.

**Stage breakdown (% of engine wall):**

| point | compile_bind | execute | commit_prepare | **wal_sync (fdatasync)** |
|-------|-------------:|--------:|---------------:|-------------------------:|
| N=200 mem W=1  | 1.0% | 85.8% | 12.2% | 1.1% |
| N=200 mem W=12 | 1.3% | 85.9% | 10.4% | 2.4% |
| **N=200 file W=1**  | 0.3% | 15.9% | 1.1% | **82.7%** |
| **N=200 file W=12** | 0.3% | 16.2% | 1.1% | **82.4%** |

The per-commit `fdatasync` is a **fixed ~1.2 ms**, serialized on one writer → caps autocommit at
~1/0.0012 ≈ **830 c/s regardless of cores**. CPU-vs-fsync crossover ≈ 1.2 ms of query CPU/commit:
below it (any indexed point-lookup write) → **fsync-bound**; above it (heavy scan / bulk) → CPU-bound.

### 3.3 Autocommit bypasses group-commit — the fixable root cause `[PROFILE + source-verified]`
`exec.rs:1291 finish_autocommit` → `coordinator.commit` → `store.commit` → **inline `harden_wal()`
(a real `fdatasync`) on the engine thread**. The #528/#532 group-commit + pipelined-offload path
(`commit_prepare_tx` → `commit_batch` → `pipelined_group_commit`) is reached **only** via the explicit
`Cmd::Commit` (`mod.rs:1775`). So the most common OLTP shape gets **zero** fsync coalescing and blocks
the single writer in the syscall. **Explicit `BEGIN/COMMIT`, which does coalesce, is the remedy
evidence:**

| substrate | W | commits/s | avg-batch | walsync-cores |
|-----------|--:|----------:|----------:|--------------:|
| file/explicit | 1 | 656 | 1.00 | 0.03 |
| file/explicit | **4** | **1499** | **2.90** | 0.03 |
| file/explicit | 8 | 808 | 1.55 | 0.03 |
| file/explicit | 12 | 831 | 1.62 | 0.03 |

Coalescing lifts file throughput **2.3× at W=4** and moves the `fdatasync` off the engine thread onto
`graphus-walsync`. It is modest/noisy above W=4 — the depth-1 pipeline + each writer blocking on its
own commit round-trip limits how many commits queue at once (a deeper-pipelining opportunity).

### 3.4 Why the 1.34/0.70-core figure is not a clean ceiling
(1) It was over **Bolt-TCP + TLS** in a closed loop — network+TLS round-trips starve the depth-1 fsync
pipeline, leaving the engine idle. (2) The `fraud-oltp` concurrency workload (`data/concurrency.js`) is
an **explicit managed txn doing read-modify-write on a small HOT set**; its baseline is **262 aborts /
8 commits** — an SSI *stress test*, not throughput. **No architecture parallelizes contention.**

## 4. Candidate architectures — trade-off table

Ceiling = achievable multiple of single-core write **throughput**; "Determinism" = preserves DST
byte-identical trace.

| # | Approach | Ceiling (measured/bounded) | ACID risk | Determinism | WAL / 2PC cost | Effort/risk | Incremental first slice? |
|---|----------|----------------------------|-----------|-------------|----------------|-------------|--------------------------|
| **T** | **Fsync coalescing** — route autocommit through the batched/pipelined harden path; deepen the pipeline; skip `checkpoint_meta` on unchanged catalog | **~650 → ~3531 c/s (≈5×)** toward the 1-core CPU wall `[PROFILE]`; explicit path already 2.3× @W=4 | **Low** | **Preserved** | *reduces* fsync count (N commits/1 sync) | **Low**, self-contained | **Yes** — the recommended #566 slice |
| **2+3** | **Pipelined write execution** — compile+bind+read-resolution off-thread; apply + commit sequencer serial | `1/serial_fraction`. Once fsync-coalesced, execute-CPU is 86% of engine wall @N=200 mem ⇒ moving MATCH/compile off-thread can push past 1 core; workload-dependent | **Low** — one serialization point retained | **Preserved** | none new | **Medium**; reuses Send plans + reader pool (#336/#543) + `ReadOnlyGraph` | **Yes** (after T) |
| **1** | **Key-space sharding** into N single-writer shards | **~5.8× @ 8 shards, zero cross-shard `[S0]`**; **~1×** for hot-node/cross-shard-heavy; eroded by 2PC | **High** — cross-shard SSI; must not reintroduce #220 | **Hard** — per-shard determinism + deterministic cross-shard order/victim | **2PC** (extra fsync) on ~(N-1)/N of edge writes (§6) | **Very high** | **Weakly** — needs 2PC + cross-shard SSI before it is *correct* |
| **4** | **Multi-writer MVCC** | With one sequencer = approach 2 ceiling, far more complexity | **Very high** — page + incidence-chain latch-coupling revive #220 as a *live* hazard | **Very hard** — concurrent commits ⇒ timing-dependent victim unless funnelled through one sequencer (then no gain) | single WAL still serial at sequencer | **Very high** | **No** |

## 5. Ranked recommendation

**Rank 1 — Fsync coalescing (T), do first.** It attacks the *measured* #1 ceiling (82% fdatasync /
0.21 cores) directly, is low-risk, self-contained, determinism-preserving (group commit is already a
proven determinism-safe path), and can take a single writer ~5× (toward the ~3531 c/s CPU wall) with
**no new cores**. The single highest-leverage change: **make autocommit commits use the same
batched/pipelined harden path explicit txns already use** (§3.3), then deepen the depth-1 pipeline so
batches fill under closed-loop clients.

**Rank 2 — Pipelined write execution (2+3).** The first genuine *multi-core* step, needed **after** T
when the writer is CPU-bound at ~1 core (mem shows execute = 86% of engine wall). Move
compile+bind+read-resolution off-thread onto the existing reader-pool/`ReadOnlyGraph` infra; keep
apply + commit sequencer inline. Determinism-safe (single sequencer). Ceiling workload-dependent
(strong for read-heavy/ad-hoc/bulk writes; weak for pure inserts).

**Rank 3 — Key-space sharding (1).** The only path past the single-sequencer *and* single-core CPU
ceiling — measured `[S0]` 5.8× at 8 shards for perfectly-partitioned writes. But a **large epic**, and
for a multigraph most edge writes are cross-shard 2PC (§6), and hot-set OLTP gets zero benefit.
Notably, **its best case (~3582 c/s @ 8 shards) is about the same throughput free coalescing reaches on
one writer (~3531 c/s)** — so sharding only earns its risk when you need >~3500 c/s *and* the workload
partitions cleanly. Gate on a dedicated design + the S0 result below.

**Rank 4 — Multi-writer MVCC (4).** Deprioritize (degenerates to Rank-2 ceiling with far more risk;
revives #220).

## 6. Why sharding a multigraph is hard (risk for Rank 3)

`create_rel(start, end)` pushes the new rel onto the **head of BOTH** endpoints' incidence chains
(`store.rs:2398`+: `write_chain_head` on start **and** end). So a cross-shard edge is an atomic
mutation of two shards → **2PC**. With node-id sharding, ~`(N-1)/N` of edges in a connected graph are
cross-shard → **the majority of edge writes become 2PC** (extra fsync round-trip erasing the gain).
A **supernode/hot set lives on one shard** → zero benefit for the `fraud-oltp` bottleneck, and
concurrent writers to one node's chain is the #220 lost-edge class. Sharding is high-value **only** for
few-cross-shard workloads (bulk import by id-range, disjoint tenants) and must ship a designed answer
to edge placement, cross-shard 2PC, cross-shard SSI, deterministic cross-shard victim, and #220.

## 7. Proposed incremental slicing (for #566, self-contained)

**Phase T (do first — recommended #566 first slice):**
- **T1 (headline)** Route *autocommit* write commits through the existing group-commit
  `commit_prepare` + `pipelined_group_commit` harden path instead of the inline `store.commit →
  harden_wal` (§3.3). Coalesces concurrent autocommit fdatasyncs; moves the sync off the engine thread.
  Measured target: from ~650 toward the ~3531 c/s CPU wall. Determinism-safe.
- **T2** Deepen the commit pipeline beyond depth-1 / improve batch fill under closed-loop clients so
  coalescing keeps scaling past W=4 (§3.3). Complements #556 (WAL amplification).
- **T3 (minor)** Skip `checkpoint_meta` on a write commit when the catalog (tokens/indexes/constraints)
  is unchanged; move per-commit statistics out of the meta-page checkpoint. (Small: commit_prepare is
  only 1–12% of engine wall — do it for CPU-bound/bulk workloads, not as the headline.)

**Phase P (multi-core, after T, determinism-safe):**
- **P1** Off-thread the read-prefix of an auto-commit `ReadWrite` whose write-set is separable
  (MATCH→CREATE/SET) onto the reader pool; apply + commit sequencer inline; inline fallback otherwise.
- **P2** Extend to explicit managed-txn read statements (currently inline) — the modern-driver /
  `fraud-oltp` shape.

**Phase S (sharding — separate epic, gated):**
- **S0 (DONE, this spike)** N-independent-engines aggregate scaling on this hardware = **5.8× at 8
  shards** (each shard 617→448 c/s; disk parallelizes N fdatasyncs sub-linearly). Confirms the
  substrate scales but is device-IO-bounded; establishes the sharding upper bound.
- **S1..** Only if a workload needs >~3500 c/s *and* partitions cleanly: shard routing, single-shard
  fast path, cross-shard 2PC, cross-shard SSI, deterministic cross-shard victim, #220 guarantee.

## 8. Open questions for maintainer ratification (#566)

1. **Confirm the reframing:** the measured #1 write bottleneck is **durability latency (inline
   autocommit fsync), not CPU/core-count.** Do we agree the first slice is **T1 (autocommit
   coalescing)**, not a multi-core architecture? *(Recommendation: yes — biggest measured win, lowest
   risk.)*
2. **Is the ~1-core CPU wall (~3531 c/s here) enough** for the target write throughput once T lands?
   If yes, we can defer Phase P/S entirely and avoid all parallel-write risk.
3. **Do we ever accept PARTITIONED determinism** (N independent per-shard seeds/traces + a deterministic
   cross-shard order)? If "no", sharding is off the table and the ceiling is the single-sequencer /
   1-core CPU wall (Rank 1+2 only).
4. **2PC durability budget:** willing to pay an extra fsync round-trip on ~(N-1)/N of edge writes for
   sharding (§6), or must the data model avoid cross-shard edges (community-aware partitioning)?

## 9. Secondary findings surfaced (file as separate tasks — NOT part of #567's scope)

- **Autocommit-bypasses-group-commit** (§3.3) — the T1 slice; the highest-leverage write fix.
- **Parameterized equality MATCH is not index-accelerated** `[PROFILE]`: with an *online* `:Account(id)`
  index, `MATCH (a:Account {id:$x})` measured **~2.1 ms/lookup at N=5000** (a full label scan; the
  planner's `cost_optimize→cheaper()` appears to revert `NodeIndexSeekEq`→`NodeLabelScanEq`). Not
  root-caused (throwaway spike). **Needs an N-scaling verification probe;** if confirmed, every
  parameterized point-lookup write pays an O(label) scan — a large latent OLTP cost independent of the
  write-parallelism work.

---

### Appendix A — Prototypes and raw numbers
- `[BENCH]` `crates/graphus-bench/benches/commit_path.rs` (pre-existing) — §3.1.
- `[PROFILE]` `crates/graphus-bench/src/bin/writer_profile.rs` + feature-gated `graphus-core/src/profile.rs`
  + engine stage spans. Commit **`d3f3599`** (`bench(writer-profile): single-writer CPU-vs-fsync
  profiling harness (rmp #567)`). Production build with the feature OFF verified byte-clean.
  Reproduce: `cargo build -p graphus-bench --bin writer_profile --release --features writer-profile`
  then `writer_profile --substrate both --mode {auto|explicit} --w 1,4,8,12,16 --n {200|5000} --dur-secs 5 --tempdir <scratch>`.
- `[S0]` shard-ceiling: 8 parallel independent `writer_profile --substrate file --mode auto --w 1 --n 200`
  processes → 8×448 = **3582 c/s aggregate = 5.8×** (solo baseline 617 c/s).
