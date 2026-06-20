# bulk-etl — high-throughput bulk ingest & ETL (offline)

> **Status:** complete. `rmp #264` (dataset + generator), `#265` (import / export / round-trip),
> `#266` (storage footprint + amplification), `#267` (evidence instrumentation), `#268` (`run.sh`),
> `#269` (dev-only cargo mirror), and `#270` (evidence report + committed baseline + this README) are
> all implemented and proven.

This example demonstrates Graphus's **offline bulk data pipeline**: the `graphus-bulk` CLI that
**imports** node/relationship CSV into a fresh store and **dumps** a whole graph back to CSV, with
**no server and no Bolt driver** in the loop. It is the path you use to load a dataset before the
server ever starts, and to export it for backup / migration / interchange.

Unlike `social-network-uds`, `fraud-oltp`, and `gds-analytics` (which boot a real `graphus-server`),
**bulk-etl is fully offline and hermetic** — which makes it the simplest example to run and the
easiest to reason about for storage characterisation.

## What it demonstrates

1. **A deterministic, seeded LDBC-SNB-like social dataset** generated as loader-ready CSV.
2. **Bulk import** of that CSV into a fresh store via the real `graphus-bulk import` binary, loading
   the **full dataset with the correct node / relationship / property counts** (asserted against a
   generated `manifest.json`).
3. A **lossless `import → dump → re-import` round-trip**: the whole graph is dumped back to CSV and
   re-imported into a second fresh store, and the two stores are proven identical by an
   **id-independent content hash** (same labels, relationship types, property values, and
   connectivity — independent of physical id assignment).
4. **Storage footprint + write/space amplification** characterisation of the loaded store
   (bytes-per-node, bytes-per-edge, durable-store vs total-with-WAL space amplification, write
   amplification), emitted as machine-readable JSON for the evidence report.

## The dataset model

A directed Label Property Graph modelling an online social network — a small, honest subset of the
[LDBC Social Network Benchmark](https://ldbcouncil.org/benchmarks/snb/) schema.

### Node labels (one CSV file each)

| Label     | File           | Typed properties |
|-----------|----------------|------------------|
| `Person`  | `persons.csv`  | `firstName:string`, `lastName:string`, `gender:string`, `age:int`, `locationIP:string`, `browserUsed:string`, `tags:string[]` |
| `Forum`   | `forums.csv`   | `title:string`, `createdAt:int` |
| `Post`    | `posts.csv`    | `content:string`, `length:int`, `createdAt:int`, `language:string` |
| `Comment` | `comments.csv` | `content:string`, `length:int`, `createdAt:int` |

Every node carries a **globally-unique** external `:ID` with a per-label prefix (`p…` Person,
`f…` Forum, `po…` Post, `c…` Comment), so `graphus-bulk`'s single shared `:ID → node` map never
collides across labels (which its strict duplicate-`:ID` policy would otherwise reject).

### Relationship types (one CSV file each)

| Type           | File              | Endpoints              | Typed property      |
|----------------|-------------------|------------------------|---------------------|
| `KNOWS`        | `knows.csv`       | `Person → Person`      | `since:int`         |
| `HAS_MEMBER`   | `has_member.csv`  | `Forum → Person`       | `joinedAt:int`      |
| `CONTAINER_OF` | `container_of.csv`| `Forum → Post`         | `addedAt:int`       |
| `HAS_CREATOR`  | `has_creator.csv` | `Post/Comment → Person`| `weight:int`        |
| `REPLY_OF`     | `reply_of.csv`    | `Comment → Post`       | `depth:int`         |
| `LIKES`        | `likes.csv`       | `Person → Post`        | `creationDate:int`  |

### CSV header format (`neo4j-admin import`-flavoured)

Verified empirically against `graphus-bulk` (`crates/graphus-bulk/src/header.rs`):

- **Node file header** — exactly one id column `<name>:ID`, an optional `:LABEL` column (a
  `;`-separated label set per row), and typed property columns `<key>:<type>` where `<type>` is one
  of `string` / `int` / `float` / `boolean` (and `<type>[]` array forms; a bare `<key>` defaults to
  `string`). Example:
  ```
  id:ID,:LABEL,firstName:string,lastName:string,gender:string,age:int,locationIP:string,browserUsed:string,tags:string[]
  p0,Person,Ada,Lovelace,female,36,1.2.3.4,Firefox,graphs;rust
  ```
- **Relationship file header** — `:START_ID`, `:END_ID`, `:TYPE`, then typed property columns. The
  `:START_ID`/`:END_ID` cells match node `:ID` values. Example:
  ```
  :START_ID,:END_ID,:TYPE,since:int
  p0,p1,KNOWS,2014
  ```

### Scale profiles

| Profile | Persons | Forums | Posts | Comments | Total nodes | Total relationships |
|---------|--------:|-------:|------:|---------:|------------:|--------------------:|
| `fast`  | 200     | 24     | 144   | 432      | **800**     | **4,029**           |
| `large` | 4,000   | 400    | 4,000 | 16,000   | **24,400**  | **139,989**         |

The generator is a **pure function of `(seed, scale)`** (an internal SplitMix64 PRNG — no clock, no
float in the graph structure, no `HashMap` iteration), so the CSVs are **byte-identical per
seed/scale** across runs and platforms. All logical counts are **derivable from the config** and
emitted to `manifest.json` (nodes per label, relationships per type, total properties, logical CSV
bytes) — the ground truth every assertion checks against.

## Indexes & constraints — what is (and is not) built offline

The dataset **implies** a `UNIQUE` constraint on each label's `id` plus lookup indexes on it. **Be
honest about what the offline path builds:**

- The `graphus-bulk` importer builds a **fresh store directly** through the low-level record API
  (`create_node` / `set_node_labels` / `set_node_property_value` / `create_rel` / …). It does **not**
  build secondary indexes and does **not** enforce constraints — there is no index/constraint code in
  the crate. (It *does* fail-closed on a duplicate non-empty external `:ID`, a data-integrity guard,
  not a graph constraint.)
- The generator guarantees the dataset **satisfies** the unique-id invariant by construction (every
  `:ID` is distinct), so the implied constraints would validate cleanly.
- Those constraints/indexes would be **declared via DDL on a live server** *after* a bulk load
  (`CREATE CONSTRAINT … REQUIRE n.id IS UNIQUE`, `CREATE INDEX … ON (n.id)`). The exact statements are
  recorded in `manifest.json` under `implied_constraints` for reference. This example, being offline,
  does not start a server and therefore does not create them.

## How it is built — the dev-only generator crate

The dataset generator and the import/round-trip/storage drivers live in
`crates/graphus-bulk-gen` — a **dev-only leaf crate** (`publish = false`), in the same spirit as
`graphus-gds-gen` / `graphus-fraud-gen`. **Nothing in the production build depends on it** (in
particular `graphus-server` does not), so it adds zero overhead to the shipped binary.

It exposes five binaries:

| Binary              | Purpose |
|---------------------|---------|
| `bulk_gen`          | Writes the per-label node CSVs + per-type relationship CSVs + `manifest.json` for a `--profile`. Byte-identical per seed. |
| `bulk_roundtrip`    | Drives the **real `graphus-bulk` binary** through `import → dump → re-import`, asserting counts vs the manifest and proving losslessness by content hash. |
| `bulk_storage`      | Imports the dataset and measures the on-disk footprint + amplification, emitting `storage.json` for the evidence report. |
| `bulk_evidence`     | Runs the **real `graphus-bulk import`** as a metered child, captures ingest throughput (elements/sec + MB/sec), peak RAM, CPU time, and end-to-end time, folds in `storage.json`, and writes the standardized `report.json` + `report.md`. |
| `bulk_baseline_cmp` | Gates a fresh `report.json` against the committed `baseline.json` (structural metrics only); prints `GRAPHUS_BASELINE_OK` and exits `0` on success, else exits `1`. |

The library is covered by unit + integration tests in the DEFAULT `cargo test`:

- `tests/determinism.rs` — byte-identical CSVs per seed, manifest counts == config, globally-unique
  ids, seed sensitivity;
- `tests/hermetic_roundtrip.rs` — the **dev-only cargo mirror** (`rmp #269`): an in-process,
  no-subprocess, no-disk (`MemBlockDevice`) `generate → import → dump → re-import` through the real
  `graphus-bulk` **library** API (`BulkImporter`), asserting the re-imported **counts** and the
  id-independent **content hash** match the original — the same losslessness the core proves, run
  hermetically on every `cargo test`.

## Capabilities exercised

| Capability | How it is exercised | Evidence |
|------------|---------------------|----------|
| **Deterministic dataset generation** | `bulk_gen` (seeded SplitMix64; pure function of profile) | regenerate-and-diff in `run.sh`; `tests/determinism.rs` |
| **Offline bulk import** | the real `graphus-bulk import` binary builds a fresh store | reported counts asserted == `manifest.json` |
| **Whole-graph export** | `graphus-bulk dump` serialises the store back to CSV | non-empty dump asserted; re-import counts asserted |
| **Lossless round-trip** | `import → dump → re-import`, compared by id-independent content hash | `GRAPHUS_BULK_ROUNDTRIP_OK` + content hash equality |
| **Ingest throughput** | metered `graphus-bulk import` child | `report.json` `throughput.ops_per_sec` (elements/sec) + `workload.ingest_mb_per_sec` |
| **Peak RAM / CPU / time** | poll the import child's PID (`/proc` / `ps`) | `report.json` `memory.peak_rss_bytes`, `cpu.*`, `phases[import]` |
| **Storage footprint + amplification** | `bulk_storage` walks the on-disk store + WAL | `report.json` `storage.*` + `storage.json` |
| **Regression gate** | `bulk_baseline_cmp` vs committed `baseline.json` | `GRAPHUS_BASELINE_OK` |

## Running it

The standardized, self-asserting entry point is `run.sh` (fully offline — no server, no driver, no
network). It builds the binaries if needed, then runs the whole pipeline, prints an `N checks run, M
failures` summary + the evidence path, and exits non-zero on any failed assertion. A `trap` removes
the temp workspace on exit (success **or** failure), so it leaves no residue.

```bash
# Fast profile (default): 800 nodes / 4,029 rels — the CI/E2E scale, gated against the baseline.
examples/bulk-etl/run.sh

# Large profile: 24,400 nodes / 139,989 rels — the evidence/volume scale (not baseline-gated).
BULK_PROFILE=large examples/bulk-etl/run.sh

# Point at a pre-built bin dir to skip the build step.
GRAPHUS_BIN_DIR=target/release examples/bulk-etl/run.sh
```

The pieces can also be run directly (what `run.sh` orchestrates):

```bash
cargo build --release -p graphus-bulk --bin graphus-bulk -p graphus-bulk-gen --bins
BD=target/release; WD=$(mktemp -d)
$BD/bulk_gen        --profile fast --out-dir "$WD/data"
$BD/bulk_roundtrip  --bulk-bin "$BD/graphus-bulk" --data-dir "$WD/data"
$BD/bulk_storage    --bulk-bin "$BD/graphus-bulk" --data-dir "$WD/data" --out "$WD/storage.json"
$BD/bulk_evidence   --bulk-bin "$BD/graphus-bulk" --data-dir "$WD/data" --storage "$WD/storage.json" \
                    --evidence-dir examples/bulk-etl/evidence --param profile=fast
rm -rf "$WD"
```

## Evidence

`run.sh` emits a standardized, schema-versioned `report.json` + `report.md` into the git-ignored
`evidence/` directory (the shared `graphus-examples-harness` schema — same shape as every other
example), assembled by `bulk_evidence`. The headline metrics:

| Report field | Meaning |
|--------------|---------|
| `throughput.operations` / `throughput.ops_per_sec` | elements (nodes + rels) loaded / **elements per second** |
| `workload.ingest_mb_per_sec` | input-CSV **MB per second** the loader sustained |
| `memory.peak_rss_bytes` | **peak RAM** of the import process (polled while it ran) |
| `cpu.user_secs` / `cpu.system_secs` / `cpu.mean_core_utilisation` | **CPU time** of the import process |
| `phases[import].millis` / `total_millis` | **end-to-end** import wall time |
| `storage.store_bytes` / `store_pages` | the durable `graph.store` image |
| `storage.wal_bytes` / `wal_pages` | the retained `graph.wal` redo log |
| `storage.space_amplification` | on-disk **store bytes-per-node** (the gated per-element cost) |
| `storage.write_amplification` | on-disk **store bytes-per-edge** (the gated per-element cost) |
| `workload.store_space_amplification` / `total_space_amplification` / `csv_write_amplification` | the CSV-relative amplifications (human visibility, not gated) |
| `workload.content_hash` | the round-trip content hash (lossless evidence) |

`bulk_storage` also writes the lower-level `storage.json` (the footprint source `bulk_evidence`
folds in); its `store_space_amplification` / `space_amplification` / `write_amplification` are the
CSV-relative ratios documented above.

### Reading the evidence honestly

- **The offline import is fully deterministic.** `store_bytes`, `store_pages`, `wal_bytes`, and
  `wal_pages` are **byte-identical across runs and hosts** (the importer batches commits
  deterministically; no clock-driven checkpointing), which is why the baseline gate can hold them to
  a tight band.
- **Amplification.** The durable graph image is ~6–7× the logical CSV size (fixed-record padding,
  free-list slack, token catalogs). The much larger *total* figure (`store + WAL`) is dominated by
  the **retained WAL** the batched bulk-load commits produced; that redo log is transient and is
  truncated/recycled on checkpoint, so it is the peak load-time footprint, not the steady-state cost.
- **Throughput / CPU / RAM / time are machine-variant** and are recorded for human visibility but
  **NOT** gated.

### Measured envelope (release build, this host: linux/x86_64, 16 cores)

| Metric | `fast` (800 nodes / 4,029 rels) | `large` (24,400 nodes / 139,989 rels) |
|--------|--------------------------------:|--------------------------------------:|
| Store image | 991,232 B (121 pages) | 30,801,920 B (3,760 pages) |
| WAL (retained) | 5,420,265 B (662 pages) | 178,519,186 B (21,792 pages) |
| Bytes / node (store) | ~1,239 B | ~1,262 B |
| Bytes / edge (store) | ~246 B | ~220 B |
| Store space amplification | ~7.2× | ~6.1× |
| Total (store+WAL) space amplification | ~46.8× | ~41.8× |
| Ingest throughput (machine-variant) | ~120k–130k elements/sec, ~3.4 MB/sec | scales with volume |
| Peak RAM (machine-variant) | ~8 MB | larger with volume |

Round-trip losslessness is proven by content hash at both scales
(`fast = f09ef9edcd4584631cc07af0116a0d22`, `large = ef61b4b3a9ebb44de27ff88c2c14433e`).

### The committed baseline + regression gate

`baseline.json` (committed, non-git-ignored) is a **fast-profile reference run**. `run.sh` (fast
profile only) gates a fresh run against it with `bulk_baseline_cmp`, which holds only the **stable
structural** metrics:

- **exact equality**: `dataset.nodes` / `dataset.relationships` and `workload.imported_elements`
  (integer-stable for a fixed seed);
- **within 15%**: `storage.store_bytes`, `storage.wal_bytes`, `storage.space_amplification`
  (bytes-per-node), `storage.write_amplification` (bytes-per-edge).

**Why these thresholds.** The footprint is deterministic here, so 15% is comfortably loose enough to
absorb `f64` re-serialization rounding and any future minor record-layout/free-list slack, yet tight
enough to catch a real footprint regression. The structural counts are gated at exact equality
because a change means the generator drifted. Throughput, CPU, peak RAM, and wall-time are
machine-/host-variant and are deliberately **ungated** (held at `∞`) so the shared baseline is never
flaky across the developer/CI machines it travels between — the same gating philosophy as the
`gds-analytics` and `fraud-oltp` examples.

> Note on the round-trip property count: `graphus-bulk dump` unifies every property key across all
> node labels into one CSV file, so a node is written with empty cells for keys other labels carry.
> On re-import, an empty `string`/`string[]` cell becomes a present-but-empty property (graphus-bulk's
> documented value semantics), so the *populated-property count* after a dump is higher than the
> original. This is a property of the importer/dumper pair, not data loss — the content hash
> canonicalises these present-but-empty values away, which is why the round-trip is provably lossless
> while the raw property counts differ.
