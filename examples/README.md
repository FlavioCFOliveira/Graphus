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

Every example emits `report.json` against this **stable, versioned schema** (`SCHEMA_VERSION = 3`).
Field names are fixed snake_case so external tooling and the baseline-diff helper can rely on them.
Reports deserialize leniently (each field added after v1 carries `#[serde(default)]`), so an
older-but-compatible report still loads — a v1 `report.json` deserializes against the v3 schema, with
`measurement_mode` defaulting to `"local"` and `server_metrics` absent.

Schema history:

- **v1** — metadata, host, CPU, memory, storage, throughput.
- **v2** (`rmp #684`) — adds the top-level `measurement_mode` (`"local"` / `"external"`) and the
  optional `server_metrics` section scraped from the server's Prometheus `/metrics` endpoint.
- **v3** (`rmp #711`) — **every metric is optional: a metric an example did not measure is ABSENT
  from the JSON, never a `0` / `0.0` placeholder.** See below.

### Measured, or absent — never a zero placeholder (v3)

Every field in the four vector sections (`cpu`, `memory`, `storage`, `throughput`) is emitted **only
when it was measured**. A vector the run could not measure — the CPU/RSS of a server it is merely
*attached* to, the on-disk footprint of a store it does not own, the per-operation latency of a
one-shot batch import — is simply **not there**.

This is the schema half of the evidence-honesty rule below. Until v3 the schema had no way to say
"not measured", so an unmeasured metric was written as an exact `0.0` that reads exactly like a
result: `storage.bytes_per_node: 0.0` told every reader that a stored node costs *nothing* to keep,
and the baseline gate over it compared `0.0` against `0.0` and reported PASS forever. **The
distinction the type expresses is "was it measured", not "is it zero"** — a genuinely measured zero
(an `abort_rate` of `0.0` in a write workload that hit no conflict) stays a real, present `0.0`.

Consequences you can rely on:

- an absent field means **NOT MEASURED**, and the report's `notes` say why;
- `report.md` renders it as `not measured`, never `0.000`;
- the baseline gate **skips** a metric that either side did not measure, and *names it* as skipped
  (see [Baseline-diff regression detection](#baseline-diff-regression-detection));
- a **pre-v3 baseline** (which carries the old zero placeholders) is normalised on load: those zeros
  become "not measured" again, so a newly-measured figure is never diffed against a number nobody
  ever measured;
- `examples/run-all.sh` **audits every emitted report** and fails the suite if any metric that cannot
  legitimately be zero is emitted as one.

```jsonc
{
  "version": 3,                       // schema version (integer, bump-aware)
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
  // EVERY field below is emitted ONLY IF MEASURED. An absent field = not measured (v3).
  "cpu": {                            // CPU vector — absent entirely for an external target
    "user_secs": 0.012,               // NOTE: the OS reports CPU in USER_HZ clock ticks (10ms), so a
    "system_secs": 0.004,             //   short-lived child can truthfully consume ZERO WHOLE TICKS of
                                      //   user or system time. A 0.0 in ONE of these beside a non-zero
                                      //   OTHER is a MEASURED zero (quantisation), not a placeholder —
                                      //   run-all.sh's audit accepts exactly that case and no other.
    "mean_core_utilisation": 0.32     // total CPU secs / wall secs (1.0 == one core saturated);
                                      //   absent when there was no wall-clock window to divide by
  },
  "memory": {                         // memory vector (peak RAM)
    "peak_rss_bytes": 18874368,
    "final_rss_bytes": 12582912       // absent when the process had already exited (no RSS to read)
  },
  "storage": {                        // storage footprint + amplification + per-element costs
    "store_bytes": 81920,             // everything durable that is NOT the redo log
    "wal_bytes": 16384,               // the redo log — see the WAL-is-a-directory note below;
                                      //   absent for an in-memory mirror, which has no WAL at all
    "store_pages": 10,                // ceil(store_bytes / PAGE_SIZE)
    "wal_pages": 2,
    "bytes_fsynced": 16384,
    "write_amplification": 1.20,      // physical bytes written / logical bytes written
    "space_amplification": 1.45,      // on-disk bytes / logical graph bytes
                                      //   (both absent when no logical figure was supplied)
    "bytes_per_node": 102.4,          // per-element COST, not a ratio: the measured durable STORE
                                      //   IMAGE amortised over the stored node count. Present only
                                      //   when the store AND the dataset scale were measured AND the
                                      //   example can attest they describe the SAME graph.
    "bytes_per_relationship": 24.6,   // …the same image over the relationship count. The two are two
                                      //   VIEWS of one image: they do not sum to store_bytes.
    "plateau_ratio": 1.0              // retention/GC ONLY: the largest post-warmup footprint over the
                                      //   smallest (1.0 = a flat plateau). Present only for a workload
                                      //   with a genuine steady state (iot-timeseries); absent
                                      //   everywhere else, because nowhere else IS there a plateau.
  },
  "throughput": {                     // throughput + latency vector
    "operations": 1000,
    "ops_per_sec": 200000.0,
    "p50_latency_ms": 0.004,          // absent when the run recorded no latency sample — e.g. a
    "p99_latency_ms": 0.012,          //   one-shot offline import has no per-operation request
    "p999_latency_ms": 0.031,         //   boundary to time (a 0.0 would read as "instantaneous")
    "abort_rate": 0.0                 // fraction of write txns lost to conflict. THE ONE METRIC whose
                                      //   zero is a real measurement (a write workload with no
                                      //   conflict): present as 0.0 when observed, absent when the run
                                      //   never observed aborts at all (e.g. a read-only workload).
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
    "query_count": 46,                // query_duration_seconds _count delta (a real counter: 0 = the
                                      //   window recorded no query, which IS a measurement)
    "query_duration_mean_ms": 0.488,  // _sum delta / _count delta, in ms; the three duration figures
    "query_duration_p50_ms": 0.30,    //   are ABSENT when the window recorded no query at all —
    "query_duration_p99_ms": 2.10,    //   there is no mean/percentile of nothing
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
toolchain) followed by one table per vector (CPU / memory / storage+amplification+per-element costs /
throughput+latency). A metric the run did not measure renders as **`not measured`** — never `0.000`.

### Evidence-honesty rules (non-negotiable)

An example exists to tell the truth about the server. Evidence that is subtly wrong is worse than no
evidence, because it is *believed*. These rules are the scar tissue of real defects found in this
suite (`rmp` #699) — do not reintroduce them:

1. **Measure it or omit it.** A metric is either genuinely measured or **absent from the report**.
   Never emit a `0.000` placeholder and never relabel one statement as N operations — a reader cannot
   distinguish a fabricated zero from a real one. Since schema **v3** (`rmp #711`) the type system
   enforces this: every metric is an `Option`, an unmeasured one is omitted from the JSON, and
   `run-all.sh` fails the suite if a report emits a zero for a metric that cannot legitimately be one.
   The rule's scar tissue: `storage.bytes_per_node` was added to the schema, documented to the reader
   as "durable bytes per stored node", gated by the baseline comparator — and then never populated. It
   read `0.0` in all 11 reports, telling every reader that a stored node costs nothing to keep, while
   its gate compared `0.0` to `0.0` and passed forever. **A gate that cannot fire is the same lie
   wearing a green tick.**
2. **`total_millis` is the WORKLOAD's wall-time.** These emitters typically build the report *after*
   the workload has finished, so a naive `start()`/`finish()` bracket times the report's own emission
   (hundredths of a millisecond). Pass the measured duration to
   `EvidenceCollector::record_total_duration`.
3. **Every field carries the quantity its name promises.** The amplification fields carry
   amplification *ratios*. Per-element costs go in `bytes_per_node` / `bytes_per_relationship`; a
   retention plateau goes in `plateau_ratio`. (bulk-etl used to smuggle bytes-per-node into
   `space_amplification`, so its committed baseline read `1239.04` where the real ratio was `46.78`.)
   And a per-element cost is only honest if its two inputs describe the **same graph**: the store the
   example metered must be the store that holds the `nodes`/`relationships` it counted. Where it is
   not — `fraud-oltp` counts the generator's seed while its concurrency phase writes *more* rows into
   the same store; `security-multitenant` meters one tenant's database while counting two tenants'
   graphs — the cost is **omitted**, and the report says why. Real arithmetic over mismatched inputs
   is still a lie; it is just a harder one to see.
4. **Sample the SERVER, not the driver.** When the goal is server evidence, drive the server over the
   wire and sample the *server's* pid (or its `/metrics`). An in-process battery measures the driver:
   that is how social-network-large came to report a "~1 core" ceiling that was purely a harness
   artifact, while the server actually scales to 6+ cores.
5. **The WAL is a DIRECTORY** (`databases/<db>/graphus.wal/seg.<lsn>`). Classifying store-vs-WAL bytes
   by the leaf *file name* counts every WAL byte as store and reports `wal_bytes: 0` — silently hiding
   the entire redo log. Classify by **path**. And decompose the footprint: a lumped total blends the
   data image (which scales with the graph) with a fixed-size doublewrite preallocation (which does
   not), producing ratios that look alarming and mean nothing.
6. **Never run a stale binary.** Build through `harness_build`, which rebuilds unconditionally (cargo
   is incremental, so it is a no-op when nothing changed). A build-only-if-the-file-is-absent guard
   silently runs the *previous* binary after any source edit, so the evidence describes code that is
   no longer the code under test.

### Baseline-diff regression detection

`EvidenceReport::compare_to_baseline(&baseline, &thresholds)` diffs a run against a committed
baseline `report.json` and flags a **regression** when any key metric degrades beyond its threshold
(default **10%**). The per-metric direction of "worse":

| Metric | Worse when |
|--------|-----------|
| `throughput.ops_per_sec` | **lower** |
| `throughput.p50/p99/p999_latency_ms` | **higher** |
| `throughput.abort_rate` | **higher** |
| `memory.peak_rss_bytes` | **higher** |
| `storage.store_bytes` / `wal_bytes` | **higher** |
| `storage.write_amplification` / `space_amplification` | **higher** |
| `storage.bytes_per_node` / `bytes_per_relationship` | **higher** |
| `storage.plateau_ratio` | **higher** |
| `cpu.total_secs` (user + system) | **higher** |

The returned `ComparisonReport` lists every metric's `baseline → candidate` delta, its `degradation`,
and a `regressed` flag, plus a `regressed: bool` for the run overall and a `summary()` string. A CI
gate exits non-zero when `regressed` is set.

**A gate over an unmeasured metric is SKIPPED, not passed** (`rmp #711`). A gate can only compare what
*both* sides measured, so a metric absent on either side goes into `ComparisonReport::skipped` —
named, with the reason (`not measured in the baseline` / `in this run` / `on either side`) — and
`summary()` prints one `~ metric: SKIPPED — …` line for each:

```text
PASS — no regression vs baseline `bulk-etl` (9 metrics compared within threshold, 5 skipped)
  ~ throughput.p50_latency_ms: SKIPPED — not measured on either side (not gated)
  ~ storage.plateau_ratio: SKIPPED — not measured on either side (not gated)
```

The alternative is worse than having no gate: `storage.bytes_per_node` was `0.0` in every report, so
the gate compared `0.0` to `0.0`, found no degradation, and printed PASS — for months. A gate that
cannot fire is a lie of the same family as a zero placeholder. Now the absence is *visible*, and it is
fixed by capturing the missing measurement (a baseline captured before schema v3 has its zero
placeholders normalised back to "not measured" on load, so those gates report as skipped until the
baseline is re-captured from a real run).

## Running the examples

From the repository root — one example, or the whole suite:

```bash
examples/<scenario-name>/run.sh          # one example
examples/run-all.sh                      # the WHOLE suite, one verdict (non-zero if any fails)
examples/run-all.sh fraud-oltp bulk-etl  # …or just the named ones
```

`run-all.sh` also honours the external-target seam below, so the same command sweeps every
attach-capable example against an already-running instance. It skips the two durability examples in
that mode: they must own the server lifecycle to inject a crash, so they are local-only by
construction.

Each `run.sh` **rebuilds the binaries it drives** (via `harness_build`; cargo is incremental, so this
is a no-op when nothing changed). To reuse binaries you built yourself — CI artifacts, or a host with
no cargo — set `GRAPHUS_BIN_DIR`, which opts out of the rebuild:

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
storage vector require a co-located PID and filesystem, so they are **N/A** in external mode: since
schema v3 (`rmp #711`) they are **absent from the report**, with an explicit note — not zero-filled,
which would have told a reader the remote server burned no CPU and stored no bytes. Consequently, **a
committed baseline must always be captured from a
local boot run** — an external run is never a baseline candidate, and `measure_target` replaces the
host-specific baseline diff with the host-independent invariant gate above.

The target is **any** Graphus instance you can reach — there is no privileged or hard-coded host.
Point the `GRAPHUS_TARGET_*` variables at it and the same example runs unchanged:

```bash
# An instance already running on THIS machine (the common case: you booted it yourself):
GRAPHUS_TARGET_REST=https://127.0.0.1:7474 \
GRAPHUS_TARGET_BOLT=bolt+ssc://127.0.0.1:7687 \
GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=… \
GRAPHUS_TARGET_TLS_INSECURE=1 \
examples/<scenario-name>/run.sh

# …or an instance on ANOTHER host — staging, a container, a small ARM box, production:
GRAPHUS_TARGET_REST=https://graphus.example.com:7474 \
GRAPHUS_TARGET_BOLT=bolt+ssc://graphus.example.com:7687 \
GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=… \
examples/<scenario-name>/run.sh
```

`GRAPHUS_TARGET_TLS_INSECURE=1` (and the `bolt+ssc://` scheme) accepts a **self-signed** certificate:
it encrypts, but it does **not** authenticate the peer. That is the right setting for a box you booted
yourself; against anything else, present a certificate your trust store accepts and use `bolt+s://`
without the insecure flag.

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
| [`iot-timeseries`](iot-timeseries/) | **What does durability actually cost?** Sustained IoT ingest + sliding-window retention churn, driven over Bolt against a real server with a real segmented WAL. The durable **store** plateaus flat while the reclamation counters climb — and the same run proves the **database on disk does not**, because WAL disk is freed only in whole 64 MiB segments: **79.6 MB of disk for a 229 KB graph (347×)**, at **799× write amplification** (`rmp` #706). Write amplification is a **gated** signal here: the run fails if the WAL footprint comes back zero, under-counted, or worse than its ceiling. |
| [`social-network-large`](social-network-large/) | **Do reads scale across cores?** A large social graph (up to ~1,000,000 USERs on an undirected multigraph FRIEND, plus ARTICLEs and USER→LIKE→ARTICLE edges, with an optional **power-law degree law that grows real supernodes**) is network-bulk-loaded into a running server, then an 8-family Cypher read battery is driven **over the Bolt wire by a concurrency ladder of simultaneous clients** while the **server process** is sampled per-thread from `/proc`. Evidence: the core-scaling curve vs C, real per-family p50/p99, and a **decomposed** on-disk footprint (data image / doublewrite / redo log). |
| [`clients-go`](clients-go/) | **Third-party driver interoperability** — the only example that drives Graphus through an *external* implementation of its protocols: Bolt-over-TCP through the **official `neo4j-go-driver/v5`**, plus REST and a hand-rolled Bolt-over-UDS client. It is therefore the suite's real conformance check: a PackStream marker or Bolt state-machine drift breaks it. |
| [`product-recommendations`](product-recommendations/) | **Read-heavy concurrency** evaluation: a product-recommendation service over a `(:User)-[:FRIEND]-(:User)` + `(:User)-[:PURCHASED]->(:Product)` multigraph. Network-bulk-loads the graph over the wire (Mode A), then drives a **concurrency ladder** of many simultaneous Bolt/UDS clients running recommendation queries (direct-friend, 2nd/3rd-level, and similar-consumption-profile) plus a few concurrent writes, sampling the server's per-thread CPU / RSS / IO to **expose the read-path saturation knee** (single-engine-thread vs off-thread reader pool). |
