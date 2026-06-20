# Smoke evidence — scaffold validation

This is the trivial example that proves the shared **evidence-harness scaffold** works end to end.
It is the foundation laid by `rmp #245`; every other example (`rmp #27`–`#33`) builds on the same
two pieces it exercises here.

It does **not** boot a server — it is intentionally fast and self-contained. Its only job is to show
that an example can collect evidence through both seams and produce an evidence directory.

## What it demonstrates

| # | Capability | How it is shown |
|---|------------|-----------------|
| 1 | **Shell-side evidence seam** | Sources `examples/_harness/harness.sh`, creates the git-ignored `evidence/` dir, times a phase, and writes `metrics.txt` (with the `rmp #246/#247` metering stubs). |
| 2 | **Rust-side evidence seam** | Runs `graphus-examples-harness`'s `emit_evidence` binary, which drives `EvidenceCollector` and writes a machine-readable `report.json` and a human-readable `report.md`. |
| 3 | **Assertions + non-zero exit** | Asserts each artifact exists and carries the expected metadata; the script exits non-zero if any assertion fails (so it doubles as an E2E smoke test). |

## Running it

```bash
# From the repository root.
examples/smoke-evidence/run.sh
```

A successful run ends with:

```
6 checks run, 0 failures.
SMOKE EXAMPLE PASSED — the evidence-harness produced a report.json + report.md.
```

## The evidence it collects

Written to `examples/smoke-evidence/evidence/` (git-ignored):

- `report.json` — the machine-readable [`EvidenceReport`](../../crates/graphus-examples-harness):
  the schema `version`, run metadata (scenario id, dataset scale, workload params), the auto-detected
  `host` section, per-phase wall-clock timings, and the typed CPU / memory / storage+amplification /
  throughput+latency sections. See the **Evidence schema** section in
  [`examples/README.md`](../README.md#evidence-schema) for the full field reference.
- `report.md` — the human-readable summary of the same report (header + one table per vector).
- `metrics.txt` — the shell helper's metric file (phase timings + the storage/RSS stub entries).

The smoke run injects representative metric **values** (it does not boot a server); the real examples
(`rmp #27`–`#33`) populate the same sections from live meters. The standardized emitter, the stable
versioned schema, host/env detection, and the baseline-diff regression helper were completed by
`rmp #248`.
