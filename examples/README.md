# Graphus examples

This folder holds Graphus's **demonstrative examples**: realistic, end-to-end demonstrations of how
Graphus is used. They are not toys — each one boots a **real `graphus-server`**, drives it over a
real connection, asserts its results, and **collects explicit evidence** of how it performed.

Per the project's `Examples` rule, every example must fulfil three objectives:

1. **Demonstration** — a didactic walkthrough of a scenario or goal.
2. **Exercise** — exercise the functionality appropriate to the scenario, from the basics to the
   advanced, including combinations of features and the server as a whole.
3. **Evidence** — collect explicit, objective evidence across **all** of Graphus's performance
   vectors: **memory, CPU, and storage** (plus throughput/latency where relevant).

## Layout — what every example MUST contain

Each example lives in its own **self-contained sub-folder** named for its scenario
(kebab-case, e.g. `social-network-uds`). Sub-folders prefixed with `_` are shared infrastructure,
not examples. Each example folder MUST contain:

```
examples/<scenario-name>/
├── README.md        # what it demonstrates, how to run it, and the evidence it collects
├── run.sh           # self-contained: boots a real server, asserts every step, exits non-zero on failure
├── data/            # OPTIONAL — a data generator and/or fixtures the scenario loads
└── evidence/        # written AT RUN TIME (git-ignored); holds the collected evidence reports
```

Rules:

- **`README.md`** documents (a) what capabilities the example demonstrates, (b) exactly how to run
  it, and (c) which evidence it collects and where it lands.
- **`run.sh`** is fully self-contained: it locates or builds the binaries, creates its own private
  temp store / config / socket, boots the server as a **separate process** (no in-process
  shortcuts), drives it over the public surface (`graphus-cli` / a driver / the REST API), asserts
  each step, cleans up on exit, and **exits non-zero the moment any assertion fails**. It doubles as
  an executable E2E test.
- **`evidence/`** is created at run time and is **git-ignored** (see `examples/.gitignore`); never
  commit generated evidence.
- Prefer driving deterministic scenarios through the project's **DST simulator** so they reproduce
  reliably (especially anything involving concurrency, faults, crashes, and recovery).

## Shared infrastructure

Two reusable pieces let every example collect evidence the same way, instead of reinventing it:

### `examples/_harness/harness.sh` — the shell helper

A sourced bash library (portable to the Tier-1 Linux + macOS targets) providing:

- pretty output + `assert` / `harness_summary` helpers (the house `✓ / ✗` style);
- `evidence_init` / `evidence_metric` / `timed_phase` — create the git-ignored evidence dir and a
  `metrics.txt`, and time phases;
- `evidence_capture_rss` / `evidence_capture_storage` — **stubs today** (peak RSS and storage sizing
  are filled in by `rmp #246` / `#247`), but they already create real metric entries so the seam
  works end to end;
- `harness_locate_binaries` / `harness_start_server` / `harness_stop_server` — boot/teardown a real
  server over UDS (generalized from `social-network-uds/run.sh`).

Source it from a `run.sh` with:

```bash
HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../_harness" && pwd)"
source "$HARNESS_DIR/harness.sh"
```

### `crates/graphus-examples-harness` — the Rust harness crate

A dev-only **leaf** crate (depended upon by nothing in the production build — notably **not**
`graphus-server`, so it adds zero overhead to the shipped binary). It exposes the typed
evidence-collection seams:

- `EvidenceCollector` — `new(metadata)` → `start()` → `phase(name, dur)` / `record_resources` /
  `record_storage` / `record_amplification` / `record_throughput` (or the `*_mut()` accessors) →
  `finish()`;
- `EvidenceReport` — the serializable result (the **stable, versioned schema** documented below),
  with one typed section per performance vector and `write_to(dir)` that emits `report.json` +
  `report.md`. `EvidenceReport::load(path)` reads a committed baseline back, and
  `compare_to_baseline(baseline, thresholds)` flags regressions.

The metering is complete: **`rmp #246`** (CPU + memory), **`rmp #247`** (storage +
throughput/latency), and **`rmp #248`** (the standardized emitter, the versioned schema, host/env
detection, and the baseline-diff regression helper). The seams are stable, so examples are written
directly against them.

The `emit_evidence` binary in that crate is a copy-from template that drives the collector end to
end, writes an evidence directory, and (given a baseline path) diffs against it.

<a name="evidence-schema"></a>
## Evidence schema (`report.json`)

Every example emits `report.json` against this **stable, versioned schema** (`SCHEMA_VERSION = 2`).
Field names are fixed snake_case so external tooling and the baseline-diff helper can rely on them.
Reports deserialize leniently (each field added after v1 carries `#[serde(default)]`), so an
older-but-compatible report still loads — a v1 `report.json` deserializes against the v2 schema, with
`measurement_mode` defaulting to `"local"` and `server_metrics` absent.

Schema history:

- **v1** — metadata, host, CPU, memory, storage, throughput.
- **v2** (`rmp #684`) — adds the top-level `measurement_mode` (`"local"` / `"external"`) and the
  optional `server_metrics` section scraped from the server's Prometheus `/metrics` endpoint.

```jsonc
{
  "version": 2,                       // schema version (integer, bump-aware)
  "metadata": {
    "scenario": "fraud-oltp",         // STABLE scenario key (the baseline-diff join key)
    "description": "…",
    "dataset": {                      // dataset scale exercised
      "nodes": 1000,
      "relationships": 4000,
      "scale_factor": 1.0             // optional; omitted when the scenario is not scaled
    },
    "workload": {                     // run knobs as an ordered key→value map
      "clients": "1",
      "operations": "1000"
    },
    "started_unix_secs": 1781940214
  },
  "host": {                           // auto-detected host/environment (report metadata)
    "os": "linux",                    // std::env::consts::OS
    "arch": "x86_64",                 // std::env::consts::ARCH
    "cpu_cores": 16,                  // std::thread::available_parallelism()
    "hostname": "ROG",                // gethostname(2) on Unix
    "rustc_version": "rustc 1.96.0 …",// baked in at build time
    "timestamp_unix_secs": 1781940214 // SystemTime::now()
  },
  "total_millis": 5.124,
  "phases": [ { "name": "warmup", "millis": 2.061 } ],
  "cpu": {                            // CPU vector
    "user_secs": 0.012,
    "system_secs": 0.004,
    "mean_core_utilisation": 0.32     // total CPU secs / wall secs (1.0 == one core saturated)
  },
  "memory": {                         // memory vector (peak RAM)
    "peak_rss_bytes": 18874368,
    "final_rss_bytes": 12582912
  },
  "storage": {                        // storage footprint + amplification
    "store_bytes": 81920,
    "wal_bytes": 16384,
    "store_pages": 10,                // ceil(store_bytes / PAGE_SIZE)
    "wal_pages": 2,
    "bytes_fsynced": 16384,
    "write_amplification": 1.20,      // physical bytes written / logical bytes written (0.0 = N/A)
    "space_amplification": 1.45       // on-disk bytes / logical graph bytes      (0.0 = N/A)
  },
  "throughput": {                     // throughput + latency vector
    "operations": 1000,
    "ops_per_sec": 200000.0,
    "p50_latency_ms": 0.004,
    "p99_latency_ms": 0.012,
    "p999_latency_ms": 0.031,
    "abort_rate": 0.0                  // fraction of write txns lost to conflict (0.0 = N/A)
  },
  "measurement_mode": "local",        // v2: "local" (this host) | "external" (remote /metrics only)
  "server_metrics": {                 // v2: server-side /metrics deltas over the workload window
    "database": "graphus",            // db the db-scoped deltas are attributed to (null = aggregate)
    "transactions_committed": 190,    // committed_total delta
    "transactions_aborted": 5,        // aborted_total delta
    "abort_rate": 0.0256,             // aborted / (committed + aborted)
    "slow_queries": 0,                // slow_queries_total delta
    "statement_panics": 0,            // statement_panics_total delta — MUST be 0 on a healthy server
    "engine_recovery_panics": 0,      // engine_recovery_panics_total delta — MUST be 0
    "engine_force_detached": 0,       // engine_force_detached_total delta — MUST be 0
    "engine_force_detached_active": 0,// force_detached_active gauge (after) — MUST be 0
    "ssi_tracked_before": 12,         // ssi_tracked_transactions gauge before the workload
    "ssi_tracked_after": 190,         // …and after (residual can signal a GC-watermark pin)
    "query_count": 46,                // query_duration_seconds _count delta
    "query_duration_mean_ms": 0.488,  // _sum delta / _count delta, in ms
    "query_duration_p50_ms": 0.30,    // approx p50 from bucket deltas (histogram_quantile), ms
    "query_duration_p99_ms": 2.10,    // approx p99 from bucket deltas, ms
    "scope_note": ""                  // set when no per-db series existed and figures are aggregate
  },
  "notes": [ "…" ]                    // free-form observations / proxy caveats
}
```

`measurement_mode` distinguishes a **local** run (the example boots the server on this host and can
read `/proc`, `getrusage`, and the store/WAL files directly) from an **external** run (the example
targets a *remote* instance where those are inaccessible, so its only server-side evidence is the
Prometheus `/metrics` endpoint). `server_metrics` is present whenever the example scraped `/metrics`
before and after its workload; it is **omitted** (not `null`) when not collected. The db-scoped
figures are attributed to a target `database` when Graphus exposes the per-database `graphus_db_*`
series (`rmp #463`); otherwise they fall back to the server-wide aggregate and `scope_note` records
the fallback. The panic/force-detach counters and the SSI gauge are always server-global.

`report.md` is the human-readable rendering of the same data: a header (scenario, dataset, host,
toolchain) followed by one table per vector (CPU / memory / storage+amplification /
throughput+latency).

### Baseline-diff regression detection

`EvidenceReport::compare_to_baseline(&baseline, &thresholds)` diffs a run against a committed
baseline `report.json` and flags a **regression** when any key metric degrades beyond its threshold
(default **10%**). The per-metric direction of "worse":

| Metric | Worse when |
|--------|-----------|
| `throughput.ops_per_sec` | **lower** |
| `throughput.p50/p99/p999_latency_ms` | **higher** |
| `memory.peak_rss_bytes` | **higher** |
| `storage.store_bytes` / `wal_bytes` | **higher** |
| `storage.write_amplification` / `space_amplification` | **higher** |
| `cpu.total_secs` (user + system) | **higher** |

The returned `ComparisonReport` lists every metric's `baseline → candidate` delta, its `degradation`,
and a `regressed` flag, plus a `regressed: bool` for the run overall and a `summary()` string. A CI
gate exits non-zero when `regressed` is set.

## Running the examples

From the repository root:

```bash
examples/<scenario-name>/run.sh
```

Reuse pre-built binaries from a custom location with `GRAPHUS_BIN_DIR`:

```bash
cargo build --release -p graphus-server -p graphus-cli
GRAPHUS_BIN_DIR=target/release examples/<scenario-name>/run.sh
```

## Running against an external target (local or remote)

By default every example **boots its own co-located server** and measures it directly (`/proc` CPU
and RSS, on-disk store/WAL bytes) — a `measurement_mode: "local"` run. An example that opts into the
shared **external-target seam** can instead be pointed at an **already-running instance**, local or
remote, and will *skip booting a server*, run its workload against that endpoint, and collect only
the vectors observable over the wire (`measurement_mode: "external"`).

Set any `GRAPHUS_TARGET_*` variable to switch a seam-aware example into external mode:

| Variable | Meaning | Default |
|----------|---------|---------|
| `GRAPHUS_TARGET_BOLT` | Bolt URL of the target (`bolt://` / `bolt+s://` / `bolt+ssc://host:port`) | — |
| `GRAPHUS_TARGET_REST` | REST base URL of the target (`https://host:7474`) | — |
| `GRAPHUS_TARGET_UDS` | UDS path of an already-running **local** server | — |
| `GRAPHUS_TARGET_USER` | Principal to authenticate as | `graphus` |
| `GRAPHUS_TARGET_PASSWORD` | Password (prefer `..._PASSWORD` env over a flag) | `graphus-local` |
| `GRAPHUS_TARGET_DB` | Pre-provisioned scratch database to use (operator-owned; not created/dropped) | — |
| `GRAPHUS_TARGET_METRICS` | `/metrics` base URL for server-side evidence | `= GRAPHUS_TARGET_REST` |
| `GRAPHUS_TARGET_METRICS_TOKEN` | Prometheus scrape token | admin Bearer from `/auth/login` |
| `GRAPHUS_TARGET_TLS_INSECURE` | `1` = accept a self-signed cert | inferred from a `+ssc` scheme |
| `GRAPHUS_TARGET_SYSTEM_DB` | Database that `CREATE/STOP/DROP DATABASE` DDL is issued against | `graphus` |

**Isolation — a dedicated database.** To avoid clobbering the target's existing data, an external run
creates a unique run-scoped database (`CREATE DATABASE ex_<scenario>_<epoch>_<pid> IF NOT EXISTS`),
runs its whole workload inside it, and drops it on exit (`STOP DATABASE` then `DROP DATABASE`, since
Graphus requires a database to be offline before it can be dropped). Passing `GRAPHUS_TARGET_DB`
reuses an operator-provisioned database instead and leaves its lifecycle to you. The per-database
`graphus_db_*{database="…"}` metric series let the evidence attribute committed/aborted/slow/latency
figures to *just this run's* database even on a busy shared instance.

**What is (and is not) collectable remotely.** Client-side throughput/latency/abort are always
measured by the driver. Server-side counters come from the target's Prometheus `/metrics`, scraped
before and after the workload and reported as deltas (`server_metrics` section) — including the
health invariants `statement_panics` / `engine_recovery_panics` / `engine_force_detached`, which
`measure_target --assert` gates to `0`. The **process** vectors (CPU, peak RSS) and the **on-disk**
storage vector require a co-located PID and filesystem, so they are **N/A** in external mode and left
zeroed with an explicit note. Consequently, **a committed baseline must always be captured from a
local boot run** — an external run is never a baseline candidate, and `measure_target` replaces the
host-specific baseline diff with the host-independent invariant gate above.

Example — drive a seam-aware example against the live demo instance over TLS:

```bash
GRAPHUS_TARGET_REST=https://100.89.148.30:7474 \
GRAPHUS_TARGET_BOLT=bolt+ssc://100.89.148.30:7687 \
GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=graphus-local \
GRAPHUS_TARGET_TLS_INSECURE=1 \
examples/<scenario-name>/run.sh
```

Durability/crash-recovery examples (`social-network-uds`, `durability-crash-recovery`) are
**local-only by construction** — they own the server lifecycle to inject a crash and prove recovery,
so they cannot target a shared/remote instance.

## The examples

| Example | Demonstrates |
|---------|--------------|
| [`smoke-evidence`](smoke-evidence/) | The scaffold itself: sources the shell helper and invokes the Rust harness to produce an evidence directory. Fast, self-contained — proves the harness works end to end. |
| [`social-network-uds`](social-network-uds/) | **The MVP, over Bolt/UDS** (local-only by construction — it owns the server's lifecycle). Many simultaneous UDS clients build a social graph under real SSI contention (all of them appending to one celebrity supernode), search and mutate it, and it survives a graceful restart **and a SIGKILL taken MID-WRITE**: the last acked commit lives, a large un-acked write leaves no trace, and the ARIES replay is *asserted* to have run (`records_scanned`/`redo_applied` > 0) — a no-op recovery fails the run. |
| [`durability-crash-recovery`](durability-crash-recovery/) | DST-driven durability & crash recovery under load: a concurrent OLTP workload under faults + a seeded mid-workload crash, ARIES recovery, and the four ACID-durability properties asserted on the recovered engine (every acked commit survives, no in-flight effect does), with a one-command replay reproducer. |
| [`fraud-oltp`](fraud-oltp/) | Real-time financial-transaction fraud detection as an OLTP workload over Bolt/TCP. |
| [`gds-analytics`](gds-analytics/) | Graph Data Science analytics over a large network (influence, communities, paths). |
| [`bulk-etl`](bulk-etl/) | Offline high-throughput bulk ingest + export round-trip via `graphus-bulk` (no server, no driver). |
| [`knowledge-graph-rest`](knowledge-graph-rest/) | A semantic knowledge graph served and queried over the Web REST API. |
| [`security-multitenant`](security-multitenant/) | Encryption-at-rest + fine-grained RBAC over a multi-tenant deployment (REST + Bolt). |
| [`iot-timeseries`](iot-timeseries/) | Sustained IoT/time-series ingest + sliding-window retention churn with a storage-reclamation plateau proof. |
| [`social-network-large`](social-network-large/) | Performance under a **LARGE** social graph: ~1,000,000 USERs befriended by an undirected multigraph FRIEND (200–2000 friends each), 30,000 ARTICLEs, and USER→LIKE→ARTICLE edges. Bulk-loads at scale (`graphus-bulk`, O(E)) into an on-disk store, then measures a Cypher traversal battery (friends, friend-of-friend, mutual, top-liked, degree); evidence covers ingest throughput, on-disk footprint/amplification, peak RSS, and per-query latency. |
| [`product-recommendations`](product-recommendations/) | **Read-heavy concurrency** evaluation: a product-recommendation service over a `(:User)-[:FRIEND]-(:User)` + `(:User)-[:PURCHASED]->(:Product)` multigraph. Network-bulk-loads the graph over the wire (Mode A), then drives a **concurrency ladder** of many simultaneous Bolt/UDS clients running recommendation queries (direct-friend, 2nd/3rd-level, and similar-consumption-profile) plus a few concurrent writes, sampling the server's per-thread CPU / RSS / IO to **expose the read-path saturation knee** (single-engine-thread vs off-thread reader pool). |
