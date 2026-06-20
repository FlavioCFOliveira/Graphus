# Fraud-detection OLTP over Bolt/TCP — Graphus demonstration

This example demonstrates Graphus as an **OLTP fraud-detection store** driven over **Bolt-over-TCP
secured with TLS**, using the **official `neo4j-driver`** — the exact wire path the Neo4j driver
ecosystem speaks. It plants a **known, enumerable** set of fraud structures into a deterministic,
seeded graph and proves the detection workload finds **exactly** them, then stresses the engine with
**extreme concurrency** to exercise Serializable Snapshot Isolation (SSI) — and collects standardized
**performance evidence** (CPU / RAM / storage / throughput) across the run.

It is both a runnable **demonstration** and an executable **E2E test**: every step asserts its
expected result, the script prints a `N checks run, M failures` summary and the evidence-report path,
and it exits non-zero if any assertion fails.

## What it demonstrates

| # | Capability | How it is shown |
|---|------------|-----------------|
| 1 | **Deterministic, seeded generation** | `graphus-fraud-gen` emits a byte-identical graph + ground truth per profile (fast / large). |
| 2 | **Bolt-over-TCP + TLS** | Boots `graphus-server` with a self-signed cert; the official driver connects with `bolt+ssc://`. |
| 3 | **Schema DDL + bulk load + detection** | Over Bolt via the official `neo4j-driver`; asserts the detection finds **exactly** the planted fraud (0 FP, 0 FN). |
| 4 | **Extreme-concurrency SSI** | Overlapping writer/reader transactions on hot accounts; reports commit/abort tallies; proves **no lost update**. |
| 5 | **Standardized performance evidence** | Meters the live server (CPU/RSS), the on-disk store/WAL footprint, throughput + latency percentiles + abort rate → `report.json` + `report.md`; gates a fresh run against a committed baseline. |
| 6 | **Deterministic SSI repro** | The in-process `dst_contention` binary reproduces the contention byte-identically for a fixed seed (the DST discipline). |

## The data model (Label Property Graph)

| Element | Shape |
|---------|-------|
| `(:Customer {id, name, country})` | the account holder |
| `(:Account {id, holder, balance, risk_score, opened_ts, country})` | a financial account; **`id` is unique** |
| `(:Customer)-[:OWNS]->(:Account)` | ownership |
| `(:Account)-[:TRANSFER {amount, ts, device, ip}]->(:Account)` | a money transfer (the edge detection traverses) |

### Injected ground truth

Two fraud archetypes are planted on top of a benign background of legitimate transfers, and the exact
planted set is emitted as `ground_truth.json`:

- **Transaction rings / cycles** `A → B → C → A`: a closed `TRANSFER` cycle (the layering pattern).
  Every account in a ring is fraudulent.
- **Mule fan-in / fan-out chains**: a central *mule* account that fans **in** from many sources and
  **out** to many destinations (smurfing / structuring). The mule account is fraudulent.

The discriminator that separates planted fraud from benign noise is the **transfer amount**: benign
transfers are `< 900`, ring edges are `≥ 9000`, mule edges are `≥ 2000`. The detection queries apply
these amount floors, so on the seeded dataset they yield **zero false positives and zero false
negatives**.

## Schema / DDL the workload loads

Graphus accepts schema DDL as raw statements over Bolt (intercepted by the server's admin matcher,
**not** the Cypher parser — they must run as auto-commit statements, never inside an explicit
transaction). The verified, supported forms this example uses:

```cypher
CREATE CONSTRAINT account_id_unique  FOR (a:Account)  REQUIRE a.id IS UNIQUE;
CREATE CONSTRAINT customer_id_unique FOR (c:Customer) REQUIRE c.id IS UNIQUE;
CREATE INDEX FOR (a:Account)  ON (a.risk_score);
CREATE INDEX FOR (c:Customer) ON (c.country);
```

> Note: Graphus's **Cypher parser** does not accept `CREATE CONSTRAINT` / `CREATE INDEX` as query
> clauses; the **server's admin path** does, over Bolt. This is the supported, tested surface (see
> `crates/graphus-server/tests/db_admin_surface.rs`). The example uses exactly these forms — no
> invented syntax. The schema is a performance optimisation, not a detection precondition: the
> hermetic cargo mirror (below) loads the data only and still finds the same fraud.

## Detection queries

All three use only Cypher features verified against the real engine (explicit multi-hop cycle
patterns, amount-filtered fan-in/fan-out aggregation, two-stage `WITH`). They are kept **byte-
identical** between the official-driver path (`data/detect.js`) and the hermetic cargo mirror
(`crates/graphus-server/tests/fraud_oltp_detection.rs`), so both front doors assert the same thing:

- **Rings**: explicit 3-hop closed cycle `(a)-[r1]->(b)-[r2]->(c)-[r3]->(a)` with every
  `amount ≥ 9000` and distinct nodes. Returns `DISTINCT a.id`.
- **Mules**: `count(DISTINCT src) ≥ 6` fanning in **and** `count(DISTINCT dst) ≥ 6` fanning out, each
  over transfers `≥ 2000` (two-stage `WITH`).
- **Velocity** (structuring): accounts emitting `≥ 6` large (`≥ 2000`) outgoing transfers, ordered by
  volume — independently re-identifies the mules.

The detector asserts the union of ring + mule findings equals the planted `fraud_accounts` set.

## Running it

```bash
# From the repository root. Builds the binaries if needed, then runs.
examples/fraud-oltp/run.sh

# Use pre-built release binaries from a custom location:
cargo build --release -p graphus-server -p graphus-fraud-gen
GRAPHUS_BIN_DIR=target/release examples/fraud-oltp/run.sh

# Evidence-scale dataset (an order of magnitude larger graph):
FRAUD_PROFILE=large examples/fraud-oltp/run.sh

# Skip the official-driver (Node) steps — the hermetic generator + DST repro still run:
RUN_DRIVER=0 examples/fraud-oltp/run.sh
```

A successful run ends with:

```
10 checks run, 0 failures.
evidence: .../examples/fraud-oltp/evidence {report.json, report.md}
FRAUD-OLTP DEMONSTRATION PASSED — ...
```

The official-driver steps (2–5) require `node`, `npm`, `openssl`, and network access for
`npm install neo4j-driver`; they are opt-in (auto-enabled when `node`/`npm` are present, via
`RUN_DRIVER`). The generator (step 1) and the deterministic SSI repro (step 6) are fully hermetic and
always run. The script is fully self-contained: it works inside a private temp directory (store, TLS
material, generated data, Node project) that a cleanup `trap` removes on exit — a passing or failing
run leaves **no residual server processes and no temp files**.

### Profiles

| Profile | Accounts | Transfers | Purpose |
|---------|----------|-----------|---------|
| `fast` (default) | ~155 | ~430 | CI/E2E assertions + the committed evidence baseline; runs in a few seconds. |
| `large` | ~2 000 | ~12 000 | Evidence collection at volume (storage/CPU/RAM footprint). Plants the same fraud kinds, so the detection queries are identical. The `large` report is for inspection; the committed regression **baseline** is the `fast` profile (the gate runs on `fast` only). |

## Reading the evidence

Each run writes the standardized, schema-versioned evidence into the git-ignored `evidence/`
directory: a machine-readable `report.json` and a human-readable `report.md`. Both follow the shared
`graphus-examples-harness` schema (`SCHEMA_VERSION`), the same one every `examples/*` uses:

| Section | Captures |
|---------|----------|
| `metadata` | scenario id, dataset scale, workload knobs (profile, connection, commit/abort tallies) |
| `host` | os, arch, cpu cores, hostname, rustc version, timestamp |
| `cpu` | server user / system CPU seconds, mean core utilisation |
| `memory` | peak / final server RSS (bytes) |
| `storage` | store / WAL bytes + pages, bytes fsynced, write- & space-amplification |
| `throughput` | operations, ops/sec, p50 / p99 / p999 latency (ms), **abort / conflict rate** |

How the figures are sourced (and their honest caveats):

- **CPU + RSS** are read from the *live* server process (`/proc/<pid>/{stat,statm}` on Linux, a `ps`
  fallback elsewhere) by the dev-only `measure_server` harness binary while the server is still up.
- **Storage** is the real on-disk footprint of `<store>/graphus.store` and the `<store>/graphus.wal/`
  segment directory, measured after the workload. `bytes_fsynced` is the WAL byte count (a faithful
  proxy: every committed WAL byte is fsynced before acknowledgement). `space_amplification` is on-disk
  bytes over a coarse logical-graph estimate (~256 B/node + ~128 B/rel), documented as a
  meaningful-but-honest proxy.
- **Latency percentiles** are measured **client-side** by `detect.js` (per-operation timings over the
  load + detection queries) and emitted as a `GRAPHUS_STATS {…}` line the script feeds into the
  report. **Abort / conflict rate** is measured by `concurrency.js` (SSI write commits vs aborts).
- **ops/sec** uses the detection workload's operation count over the server's uptime — a coarse
  throughput proxy, not a saturating benchmark.

### Variance and the regression baseline

A committed reference run lives at `baseline.json` (a `fast`-profile `report.json`). On a `fast` run
the script compares the fresh report against it with `baseline_cmp`, which gates **only stable
structural metrics** and ignores the machine-variant ones:

| Metric family | Tolerance | Why |
|---------------|-----------|-----|
| storage bytes / pages, amplification | **15%** | deterministic for a fixed seed+profile; a real footprint regression. The benign +4–5% WAL/store drift between runs (variable concurrency commit/abort counts) sits comfortably inside it. |
| abort / conflict rate | **+0.50 band** | concurrency- and timing-dependent, so a generous band, not a hair-trigger. |
| throughput, latency p50/p99/p999, CPU, peak RSS | ignored (∞) | vary with machine speed, allocator, OS, scheduling — flaky to gate across machines. |

This keeps the gate meaningful (it fails a genuine storage-footprint regression) without being flaky
across the developer/CI machines a single committed baseline is shared between. The gate prints
`GRAPHUS_BASELINE_OK` on success.

## CI coverage (hermetic, default `cargo test`)

The official-driver path needs Node; CI's default `cargo test` does not. The npm-free counterpart is
`crates/graphus-server/tests/fraud_oltp_detection.rs`: it generates the **same** fast-profile graph +
ground truth (`graphus-fraud-gen`), loads it into the real engine **in process** via `LocalEngine`
(no Bolt, no Node, no network), runs the **same** detection queries, and asserts the **same** exact
ground-truth match. It is part of the default test run; the official-driver E2E stays feature-gated
(`RUN_DRIVER` for the shell, `neo4j-interop` for the Rust interop test).

## Where the pieces live

- **Generator + ground truth + DST repro + baseline gate**: `crates/graphus-fraud-gen` (a dev-only
  leaf crate; `graphus-server` does **not** depend on it in the production graph, so the shipped
  binary is unaffected).
  - `gen` binary → `graph.cypher` + `ground_truth.json` (hermetic).
  - `dst_contention` binary (feature `dst-repro`) → deterministic in-process SSI contention.
  - `baseline_cmp` binary → the structural regression gate (hermetic; harness only).
  - determinism is guarded by `crates/graphus-fraud-gen/tests/determinism.rs`.
- **Detection + concurrency Node scripts**: `data/detect.js`, `data/concurrency.js` (official driver;
  both emit a machine-readable `GRAPHUS_STATS {…}` line the harness consumes).
- **Hermetic cargo mirror**: `crates/graphus-server/tests/fraud_oltp_detection.rs` (default test run).
- **Evidence harness**: `crates/graphus-examples-harness` (`measure_server`, the report schema, the
  `compare_to_baseline` regression diff).
- **Evidence output**: `report.json` + `report.md` in `evidence/` (git-ignored). The committed
  reference run is `baseline.json`.
