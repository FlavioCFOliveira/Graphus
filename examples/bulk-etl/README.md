# bulk-etl — high-throughput bulk ingest & ETL (offline)

> **Status:** core deliverables for `rmp #264` (dataset + generator), `#265` (import / export /
> round-trip), and `#266` (storage footprint + amplification) are implemented and proven. The
> standardized evidence report, `run.sh`, the dev-only cargo mirror, and the written evidence
> narrative are added by `rmp #267`–`#270`. This README documents what exists today; the sibling
> tasks will extend the "Running it" and "Evidence" sections.

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

It exposes three binaries:

| Binary           | Purpose |
|------------------|---------|
| `bulk_gen`       | Writes the per-label node CSVs + per-type relationship CSVs + `manifest.json` for a `--profile`. Byte-identical per seed. |
| `bulk_roundtrip` | Drives the **real `graphus-bulk` binary** through `import → dump → re-import`, asserting counts vs the manifest and proving losslessness by content hash. |
| `bulk_storage`   | Imports the dataset and measures the on-disk footprint + amplification, emitting `storage.json` for the evidence report. |

The library is covered by unit + integration tests (`tests/determinism.rs`): byte-identical CSVs per
seed, manifest counts == config, globally-unique ids, and a content-hash round-trip on a small
fixture.

## Running it (today — pre-`run.sh`)

`run.sh` (the standardized, self-asserting entry point) lands with `rmp #268`. Until then the pieces
run directly:

```bash
# Build the offline importer + the dev-only drivers (release).
cargo build --release -p graphus-bulk --bin graphus-bulk -p graphus-bulk-gen --bins

BD=target/release
WD=$(mktemp -d)

# 1. Generate the dataset (fast | large).
$BD/bulk_gen --profile fast --out-dir "$WD/data"

# 2. Prove the lossless import -> dump -> re-import round-trip on the REAL graphus-bulk binary.
$BD/bulk_roundtrip --bulk-bin "$BD/graphus-bulk" --data-dir "$WD/data"

# 3. Measure the storage footprint + amplification (writes storage.json).
$BD/bulk_storage --bulk-bin "$BD/graphus-bulk" --data-dir "$WD/data" --out "$WD/storage.json"
```

## Evidence

`bulk_storage` emits `storage.json` (consumed by the forthcoming `run.sh` / evidence report,
mirroring how `gds-analytics`' `gds_sweep` emits `sweep.json`). Stable fields:

| Field | Meaning |
|-------|---------|
| `store_bytes` / `store_pages` | The durable `graph.store` image. |
| `wal_bytes` / `wal_pages` | The retained `graph.wal` redo log (transient — truncated/recycled on checkpoint). |
| `bytes_per_node` / `bytes_per_edge` | On-disk **store** bytes per element. |
| `store_space_amplification` | `store_bytes / logical_csv_bytes` — the **steady-state** durable cost. |
| `space_amplification` | `(store + wal) / logical_csv_bytes` — the **peak** footprint right after load (WAL-dominated). |
| `write_amplification` | `(store + wal) / logical_csv_bytes` — an honest **lower bound** on bytes written. |

### Measured envelope (release build, this host)

These are the numbers produced by a real run; they are the documented envelope the evidence report
checks against.

| Metric | `fast` (800 nodes / 4,029 rels) | `large` (24,400 nodes / 139,989 rels) |
|--------|--------------------------------:|--------------------------------------:|
| Store image | 991,232 B (121 pages) | 30,801,920 B (3,760 pages) |
| WAL (retained) | 5,420,265 B (662 pages) | 178,519,186 B (21,792 pages) |
| Bytes / node (store) | ~1,239 B | ~1,262 B |
| Bytes / edge (store) | ~246 B | ~220 B |
| Store space amplification | ~7.2× | ~6.1× |
| Total (store+WAL) space amplification | ~46.8× | ~41.8× |

**Reading the amplification honestly:** the durable graph image is ~6–7× the logical CSV size
(fixed-record padding, free-list slack, token catalogs). The much larger *total* figure is dominated
by the **retained WAL** the batched bulk-load commits produced; that redo log is transient and is
truncated/recycled on checkpoint, so it is the peak load-time footprint, not the steady-state cost.
Round-trip losslessness is proven by content hash at both scales
(`fast = f09ef9edcd4584631cc07af0116a0d22`, `large = ef61b4b3a9ebb44de27ff88c2c14433e`).

> Note on the round-trip property count: `graphus-bulk dump` unifies every property key across all
> node labels into one CSV file, so a node is written with empty cells for keys other labels carry.
> On re-import, an empty `string`/`string[]` cell becomes a present-but-empty property (graphus-bulk's
> documented value semantics), so the *populated-property count* after a dump is higher than the
> original. This is a property of the importer/dumper pair, not data loss — the content hash
> canonicalises these present-but-empty values away, which is why the round-trip is provably lossless
> while the raw property counts differ.
