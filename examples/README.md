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

Every example emits `report.json` against this **stable, versioned schema** (`SCHEMA_VERSION = 1`).
Field names are fixed snake_case so external tooling and the baseline-diff helper can rely on them.
Reports deserialize leniently (each section added after v1 carries `#[serde(default)]`), so an
older-but-compatible report still loads.

```jsonc
{
  "version": 1,                       // schema version (integer, bump-aware)
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
    "p999_latency_ms": 0.031
  },
  "notes": [ "…" ]                    // free-form observations / proxy caveats
}
```

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

## The examples

| Example | Demonstrates |
|---------|--------------|
| [`smoke-evidence`](smoke-evidence/) | The scaffold itself: sources the shell helper and invokes the Rust harness to produce an evidence directory. Fast, self-contained — proves the harness works end to end. |
| [`social-network-uds`](social-network-uds/) | MVP over Bolt/UDS: a social graph stored, searched, manipulated, and preserved across a graceful restart and a hard crash. |

The forthcoming scenario examples (`rmp #27`–`#33`) MUST follow the layout above and consume the
shared harness.
