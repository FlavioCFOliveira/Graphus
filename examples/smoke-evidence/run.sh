#!/usr/bin/env bash
#
# Graphus smoke example — proves the shared evidence-harness scaffold works end to end.
#
# This is the trivial example that validates the FOUNDATION every other example builds on (rmp #245):
#   1. it sources the shared shell helper (examples/_harness/harness.sh) and uses its evidence +
#      assertion seams, and
#   2. it invokes the Rust harness crate (graphus-examples-harness, via `cargo run`) which writes a
#      machine-readable `report.json` and a human-readable `report.md`.
#
# A successful run leaves a populated `examples/smoke-evidence/evidence/` directory and exits 0.
# It is intentionally fast and self-contained: it does NOT boot a server (the real examples do).
#
# Usage:
#   examples/smoke-evidence/run.sh
#
# Requirements: a Unix host (Linux/macOS), bash, and a checkout that builds.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=../_harness/harness.sh
source "$(cd "$SCRIPT_DIR/../_harness" && pwd)/harness.sh"

EVIDENCE_DIR="$SCRIPT_DIR/evidence"

section "Smoke example — validate the evidence-harness scaffold"

# --- 1. Shell-side seam: create the evidence dir + a metrics file, time a phase --------------------
evidence_init "$EVIDENCE_DIR"
timed_phase "shell-warmup" -- sleep 0.05
evidence_capture_storage "$REPO_ROOT/Cargo.toml" "/nonexistent-wal"
assert "shell metrics file was created" "yes" "$([ -f "$EVIDENCE_DIR/metrics.txt" ] && echo yes || echo no)"

# --- 2. Rust-side seam: drive the harness crate, which writes report.json + report.md --------------
section "Invoke the Rust harness (graphus-examples-harness)"
info "running: cargo run -q -p graphus-examples-harness --bin emit_evidence -- $EVIDENCE_DIR"
( cd "$REPO_ROOT" && cargo run -q -p graphus-examples-harness --bin emit_evidence -- "$EVIDENCE_DIR" )

assert "report.json was produced" "yes" "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
assert "report.md was produced"   "yes" "$([ -f "$EVIDENCE_DIR/report.md" ] && echo yes || echo no)"

# The JSON must carry the stable schema: the scenario id, the schema version, and a populated vector.
assert "report.json names the scenario" "yes" \
  "$(grep -q '"scenario": "smoke-evidence"' "$EVIDENCE_DIR/report.json" && echo yes || echo no)"
assert "report.json carries the schema version" "yes" \
  "$(grep -q '"version": 1' "$EVIDENCE_DIR/report.json" && echo yes || echo no)"
assert "report.json carries the host section" "yes" \
  "$(grep -q '"host"' "$EVIDENCE_DIR/report.json" && echo yes || echo no)"

section "Produced evidence"
ls -1 "$EVIDENCE_DIR"

harness_summary "SMOKE EXAMPLE PASSED — the evidence-harness produced a report.json + report.md." || exit 1
