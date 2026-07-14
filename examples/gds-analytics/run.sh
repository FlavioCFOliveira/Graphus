#!/usr/bin/env bash
#
# Graphus Graph-Data-Science analytics demonstration.
#
# Two ways to run it:
#
#   * LOCAL  (default) — self-boots a `graphus-server` (Bolt-over-TCP + self-signed TLS), loads a
#     seeded influence network over Bolt via the OFFICIAL `neo4j-driver`, runs the full gds.* workload
#     (reference ground-truth, weighted-vs-unweighted, write/mutate/stats), and — separately — a
#     HERMETIC in-process scalability + CSR-footprint + parallelism sweep of the GDS library. Evidence
#     is the standardized report.json/report.md (per-algorithm timings + the live server's CPU/RAM/
#     storage), gated against the committed baseline.json.
#
#   * EXTERNAL (attach) — set GRAPHUS_TARGET_BOLT (+ GRAPHUS_TARGET_REST) and the SAME workload runs
#     against an ALREADY-RUNNING instance (local or remote) over the wire, in a dedicated
#     ISOLATED database the harness carves out and drops again on exit. Evidence is the SERVER's own
#     Prometheus /metrics, scraped before + after the workload and turned into report.json
#     (measurement_mode=external, server_metrics deltas) by the `measure_target` harness binary. The
#     process CPU/RSS and on-disk storage vectors are N/A for a remote server (no /proc, no store path),
#     and the local baseline gate + in-process sweep are skipped — this run measures the SERVER.
#
# The workload itself (data/analyze.js) is idempotent and version-tolerant: it tears down first, uses
# `IF NOT EXISTS` schema DDL, skips DDL/procedures an older instance cannot parse/register, and drops
# what it created — so two consecutive runs against one instance both pass.
#
# Usage:
#   examples/gds-analytics/run.sh                                    # LOCAL: build if needed, then run
#   GRAPHUS_BIN_DIR=target/release  examples/gds-analytics/run.sh    # LOCAL with pre-built binaries
#   GDS_PROFILE=large               examples/gds-analytics/run.sh    # LOCAL, evidence-scale dataset
#   RUN_DRIVER=0                    examples/gds-analytics/run.sh    # LOCAL, skip the official-driver step
#   GDS_SWEEP_SIZES=40,120,360      examples/gds-analytics/run.sh    # LOCAL, custom sweep field sizes
#
#   # EXTERNAL (attach to an already-running instance, local or remote):
#   GRAPHUS_TARGET_BOLT=bolt+ssc://graphus.example.com:7687 \
#   GRAPHUS_TARGET_REST=https://graphus.example.com:7474 \
#   GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=graphus-local \
#   GRAPHUS_TARGET_TLS_INSECURE=1  examples/gds-analytics/run.sh
#
# Requirements: a Unix host (Linux/macOS), bash, node (v18+) + npm (for the official driver). LOCAL
# additionally needs openssl (self-signed cert) and a checkout that builds; EXTERNAL needs curl and a
# reachable target. The generator + sweep + evidence binaries build from `graphus-gds-gen` /
# `graphus-examples-harness` on demand.

set -euo pipefail

# --------------------------------------------------------------------------------------------------
# Shared external-target seam (harness_target_*, harness_scrape_metrics, harness_target_mode).
# Sourced FIRST; this script's own pretty helpers below re-define section/info/assert to use this
# script's CHECKS/FAILURES counters (the later definitions win), so the harness helpers reuse them.
# --------------------------------------------------------------------------------------------------
HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../_harness" && pwd)"
# shellcheck source=/dev/null
source "$HARNESS_DIR/harness.sh"
export HARNESS_SCENARIO="gds-analytics"

# --------------------------------------------------------------------------------------------------
# Pretty output helpers (house style)
# --------------------------------------------------------------------------------------------------
if [ -t 1 ]; then
  BOLD=$'\e[1m'; GREEN=$'\e[32m'; RED=$'\e[31m'; BLUE=$'\e[34m'; DIM=$'\e[2m'; RESET=$'\e[0m'
else
  BOLD=''; GREEN=''; RED=''; BLUE=''; DIM=''; RESET=''
fi

CHECKS=0
FAILURES=0

section() { printf '\n%s== %s ==%s\n' "$BOLD$BLUE" "$1" "$RESET"; }
info()    { printf '%s· %s%s\n' "$DIM" "$1" "$RESET"; }

# assert <description> <expected> <actual>
assert() {
  CHECKS=$((CHECKS + 1))
  if [ "$2" = "$3" ]; then
    printf '  %s✓%s %s %s(= %s)%s\n' "$GREEN" "$RESET" "$1" "$DIM" "$3" "$RESET"
  else
    FAILURES=$((FAILURES + 1))
    printf '  %s✗ %s%s — expected %s[%s]%s, got %s[%s]%s\n' \
      "$RED" "$1" "$RESET" "$BOLD" "$2" "$RESET" "$BOLD" "$3" "$RESET"
  fi
}

# json_field <json-blob> <key> — extract a scalar field from a one-line JSON object without jq.
json_field() {
  printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\\{0,1\\}\\([^,\"}]*\\).*/\\1/p" | head -n1
}

# --------------------------------------------------------------------------------------------------
# Locate (or build) binaries. gds_gen (the deterministic generator) is needed in BOTH modes.
# --------------------------------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${GRAPHUS_BIN_DIR:-$REPO_ROOT/target/release}"
SERVER="$BIN_DIR/graphus-server"
GEN="$BIN_DIR/gds_gen"
SWEEP="$BIN_DIR/gds_sweep"

# The DEFAULT profile is `moderate` (rmp #717): 2 400 authors / ~24 000 citations.
#
# It is sized by MEASUREMENT, not by taste. At the old `fast` default (166 nodes) a
# `gds.betweenness.stream` call returns in well under a millisecond, so bracketing it against the OS's
# 10 ms CPU clock tick measures NOTHING — which is exactly how this project came to carry the
# unmeasured folklore that "GDS uses 2 of 9 cores". At `moderate` the algorithm calls are tens to
# hundreds of milliseconds, the per-algorithm CPU battery below resolves each one to ~1%, and the whole
# example still finishes in well under a minute (the graph goes in through the network bulk-import
# endpoint in ~0.2 s instead of ~8 s of edge-by-edge Cypher).
#
# `GDS_PROFILE=fast` remains available for a quick correctness-only pass.
PROFILE="${GDS_PROFILE:-moderate}"
SWEEP_SIZES="${GDS_SWEEP_SIZES:-40,120,360,1080}"
# Each algorithm in the per-algorithm CPU battery is repeated until its bracket spans at least this
# many seconds, so the OS's 10 ms accounting tick is noise rather than the signal.
CPU_TARGET_SECS="${GDS_CPU_TARGET_SECS:-1.0}"

MODE="$(harness_target_mode)"

harness_build "the deterministic influence-network generator (release)" \
  --release -p graphus-gds-gen --bin gds_gen
[ -x "$GEN" ] || { echo "${RED}fatal: gds_gen binary not found at $GEN${RESET}" >&2; exit 2; }

# --------------------------------------------------------------------------------------------------
# Workspace + evidence dir (removed on exit). In external mode the WORKDIR only holds the generated
# dataset + the Node project + the /metrics snapshots; in local mode it also holds the temp store/TLS.
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-gds-XXXXXX")"
DATA_DIR="$WORKDIR/dataset"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
mkdir -p "$EVIDENCE_DIR"

SERVER_PID=""
cleanup() {
  # External mode: drop the isolated database the harness created (no-op if it created none).
  if [ "$MODE" = external ]; then
    harness_target_drop_db || true
  fi
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

# --------------------------------------------------------------------------------------------------
# Step 1 — generate the deterministic influence network + reference subgraph (both modes).
# --------------------------------------------------------------------------------------------------
section "Step 1 — generate the deterministic influence network ($PROFILE profile)"
mkdir -p "$DATA_DIR"
GEN_OUT="$("$GEN" --profile "$PROFILE" --out-dir "$DATA_DIR")"
info "$GEN_OUT"
GRAPH_CYPHER="$DATA_DIR/graph.cypher"
REFERENCE="$DATA_DIR/reference.json"

kv() { printf '%s' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n1; }
NODE_COUNT="$(kv "$GEN_OUT" nodes)"
REL_COUNT="$(kv "$GEN_OUT" rels)"
assert "graph.cypher generated"   "yes" "$([ -s "$GRAPH_CYPHER" ] && echo yes || echo no)"
assert "reference.json generated" "yes" "$([ -s "$REFERENCE" ] && echo yes || echo no)"

# Determinism check: regenerate and diff (byte-identical per seed/scale).
"$GEN" --profile "$PROFILE" --out-dir "$WORKDIR/dataset2" > /dev/null
if diff -q "$GRAPH_CYPHER" "$WORKDIR/dataset2/graph.cypher" > /dev/null \
   && diff -q "$REFERENCE" "$WORKDIR/dataset2/reference.json" > /dev/null; then
  assert "generator is byte-identical per seed" "yes" "yes"
else
  assert "generator is byte-identical per seed" "yes" "no"
fi

# --------------------------------------------------------------------------------------------------
# install_driver <node-project-dir> — set up a private Node project with the OFFICIAL neo4j-driver.
# --------------------------------------------------------------------------------------------------
install_driver() {
  local proj="$1"
  mkdir -p "$proj"
  cat > "$proj/package.json" <<'EOF'
{
  "name": "graphus-gds-analytics",
  "version": "1.0.0",
  "private": true,
  "description": "Drives Graphus GDS analytics over Bolt with the official Neo4j driver.",
  "dependencies": { "neo4j-driver": "^6.1.0" }
}
EOF
  cp "$SCRIPT_DIR/data/analyze.js" "$proj/analyze.js"
  info "installing neo4j-driver (npm)…"
  ( cd "$proj" && npm install --no-audit --no-fund --loglevel=error ) >/dev/null 2>&1 \
    || { echo "${RED}npm install neo4j-driver failed${RESET}" >&2; return 1; }
}

# parse_stats <analyze-output> — pull the GRAPHUS_STATS blob out of analyze.js's output into globals.
ANALYZE_OPS=0; ANALYZE_SECS=0; ANALYZE_P50=0; ANALYZE_P99=0; ANALYZE_P999=0
ANALYZE_MODES=false; ANALYZE_WRITTEN=0
parse_stats() {
  local blob; blob="$(printf '%s' "$1" | sed -n 's/^GRAPHUS_STATS //p' | head -n1)"
  ANALYZE_OPS="$(json_field "$blob" operations)"
  ANALYZE_SECS="$(json_field "$blob" workload_secs)"
  ANALYZE_P50="$(json_field "$blob" p50_ms)"
  ANALYZE_P99="$(json_field "$blob" p99_ms)"
  ANALYZE_P999="$(json_field "$blob" p999_ms)"
  ANALYZE_MODES="$(json_field "$blob" modes_supported)"
  ANALYZE_WRITTEN="$(json_field "$blob" nodes_written)"
}

# ==================================================================================================
# EXTERNAL MODE — attach to a running instance, isolate in a fresh DB, measure via /metrics.
# ==================================================================================================
if [ "$MODE" = external ]; then
  section "Step 2 — attach to the running Graphus instance (external target)"
  command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1 \
    || { echo "${RED}fatal: node + npm are required to drive the official driver over Bolt${RESET}" >&2; exit 2; }
  if [ -z "${GRAPHUS_TARGET_BOLT:-}" ]; then
    echo "${RED}fatal: external mode needs GRAPHUS_TARGET_BOLT (the neo4j-driver speaks Bolt); set it to bolt://… or bolt+ssc://…${RESET}" >&2
    exit 2
  fi
  if [ -z "${GRAPHUS_TARGET_REST:-}${GRAPHUS_TARGET_METRICS:-}" ]; then
    echo "${RED}fatal: external mode needs GRAPHUS_TARGET_REST (for DB DDL, login and /metrics)${RESET}" >&2
    exit 2
  fi
  info "Bolt target:  ${GRAPHUS_TARGET_BOLT}"
  info "REST target:  ${GRAPHUS_TARGET_REST:-$GRAPHUS_TARGET_METRICS}"

  # Locate (or build) the measure_target evidence binary from the shared harness crate.
  MEASURE="$BIN_DIR/measure_target"
  harness_build "the measure_target harness binary (debug)" --release -p graphus-examples-harness --bin measure_target
  MEASURE="$BIN_DIR/measure_target"
  [ -x "$MEASURE" ] || { echo "${RED}fatal: measure_target binary unavailable${RESET}" >&2; exit 2; }

  # Resolve the run's database: an operator-owned GRAPHUS_TARGET_DB (never dropped), else a fresh
  # isolated DB the harness creates and drops on exit.
  DB="$(harness_target_ensure_db)" || { echo "${RED}fatal: could not resolve/create the target database${RESET}" >&2; exit 1; }
  assert "isolated target database resolved" "yes" "$([ -n "$DB" ] && echo yes || echo no)"
  info "target database: $DB"

  install_driver "$WORKDIR/node" || exit 1

  # Scrape /metrics BEFORE the workload (the server-side evidence window opens here).
  METRICS_BEFORE="$WORKDIR/metrics-before.txt"
  METRICS_AFTER="$WORKDIR/metrics-after.txt"
  if harness_scrape_metrics "$METRICS_BEFORE"; then
    assert "scraped /metrics before the workload" "yes" "yes"
  else
    assert "scraped /metrics before the workload" "yes" "no"
    echo "${RED}fatal: could not scrape /metrics from the target — cannot produce server-side evidence${RESET}" >&2
    exit 1
  fi

  section "Step 3 — run the GDS workload against the instance (OFFICIAL neo4j-driver, isolated DB)"
  # Bracket the workload so total_millis is the RUN's wall-time (rmp #699) — the evidence binary runs
  # after the workload and cannot time it itself.
  WORKLOAD_START_MS="$(_harness_now_ms)"
  # Signal DB ownership to analyze.js: we OWN the DB (safe to blanket-teardown its labels) unless the
  # operator pinned their own GRAPHUS_TARGET_DB — then analyze.js refuses to touch a non-empty operator
  # DB and drops only its OWN GDS projections, never the whole catalog (rmp #742).
  if [ -n "${GRAPHUS_TARGET_DB:-}" ]; then GDS_DB_OWNED=0; else GDS_DB_OWNED=1; fi
  ANALYZE_OUT="$(cd "$WORKDIR/node" && GRAPHUS_DB_OWNED="$GDS_DB_OWNED" node analyze.js \
      --uri "$GRAPHUS_TARGET_BOLT" \
      --user "${GRAPHUS_TARGET_USER:-graphus}" \
      --password "${GRAPHUS_TARGET_PASSWORD:-graphus-local}" \
      --database "$DB" \
      --graph "$GRAPH_CYPHER" --reference "$REFERENCE" 2>&1)" || true
  WORKLOAD_MS=$(( $(_harness_now_ms) - WORKLOAD_START_MS ))
  printf '%s\n' "$ANALYZE_OUT" | sed 's/^/  /'
  assert "GDS workload completed against the instance" "yes" \
    "$(grep -q 'GRAPHUS_GDS_OK' <<<"$ANALYZE_OUT" && echo yes || echo no)"
  parse_stats "$ANALYZE_OUT"

  # Scrape /metrics AFTER the workload (window closes before the DB is dropped, so its per-database
  # series are still present for the delta).
  if harness_scrape_metrics "$METRICS_AFTER"; then
    assert "scraped /metrics after the workload" "yes" "yes"
  else
    assert "scraped /metrics after the workload" "yes" "no"
  fi

  section "Step 4 — server-side evidence from /metrics (measurement_mode=external)"
  MEASURE_ARGS=(
    --evidence-dir "$EVIDENCE_DIR"
    --scenario "gds-analytics"
    --description "GDS analytics over Bolt against a running Graphus instance: load a seeded influence network into an isolated database, assert analytically-known reference outputs, compare weighted vs unweighted PageRank/Dijkstra, and (when the server registers them) exercise the write/mutate/stats execution modes. Server-side evidence is the /metrics before/after delta for the run's database."
    --database "$DB"
    --metrics-before "$METRICS_BEFORE"
    --metrics-after "$METRICS_AFTER"
    --nodes "$NODE_COUNT" --rels "$REL_COUNT"
    --param "profile=$PROFILE"
    --param "connection=bolt-external-attach"
    --param "target=$GRAPHUS_TARGET_BOLT"
    --param "driver=official neo4j-driver"
    --param "gds_write_modes=$ANALYZE_MODES"
    --note "Workload: reference-subgraph ground-truth + weighted-vs-unweighted PageRank/Dijkstra + write/mutate/stats (feature-detected). nodes_written(pagerank)=$ANALYZE_WRITTEN."
    --note "PER-ALGORITHM SERVER CPU: NOT MEASURED in attach mode. The figure requires bracketing the SERVER process's cumulative CPU counters (proc_watch --snapshot on a co-located pid); a target reached over the wire exposes no /proc, so the vector is ABSENT rather than zero-filled. Run the example locally (examples/gds-analytics/run.sh with no GRAPHUS_TARGET_*) for the per-algorithm core-utilisation evidence."
    --note "Load path in attach mode is the Cypher replay of graph.cypher (one MATCH…MATCH…CREATE per edge), NOT the network bulk-import endpoint: a target instance may expose no bulk-import endpoint, or grant no admin rights on it. The local run measures both paths and the README quotes the difference."
    --total-millis "$WORKLOAD_MS"
    --assert
  )
  [ -n "${ANALYZE_OPS:-}" ]  && MEASURE_ARGS+=( --workload-ops "$ANALYZE_OPS" )
  [ -n "${ANALYZE_SECS:-}" ] && MEASURE_ARGS+=( --workload-secs "$ANALYZE_SECS" )
  [ -n "${ANALYZE_P50:-}" ]  && MEASURE_ARGS+=( --p50-ms "$ANALYZE_P50" )
  [ -n "${ANALYZE_P99:-}" ]  && MEASURE_ARGS+=( --p99-ms "$ANALYZE_P99" )
  [ -n "${ANALYZE_P999:-}" ] && MEASURE_ARGS+=( --p999-ms "$ANALYZE_P999" )

  rm -f "$EVIDENCE_DIR/report.json" "$EVIDENCE_DIR/report.md"
  if "$MEASURE" "${MEASURE_ARGS[@]}"; then
    assert "measure_target external invariants held" "yes" "yes"
  else
    assert "measure_target external invariants held" "yes" "no"
  fi
  assert "evidence report.json was produced" "yes" \
    "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
  assert "report is tagged measurement_mode=external" "yes" \
    "$(grep -q '"measurement_mode"[[:space:]]*:[[:space:]]*"external"' "$EVIDENCE_DIR/report.json" 2>/dev/null && echo yes || echo no)"
  assert "report carries a server_metrics block" "yes" \
    "$(grep -q '"server_metrics"' "$EVIDENCE_DIR/report.json" 2>/dev/null && echo yes || echo no)"
  info "evidence: $EVIDENCE_DIR/{report.json, report.md}"

  section "Result"
  printf '%s checks run, %s failures.\n' "$CHECKS" "$FAILURES"
  if [ "$FAILURES" -eq 0 ]; then
    printf '%s%sGDS-ANALYTICS ATTACH DEMONSTRATION PASSED%s — the workload ran against the running\n' "$BOLD" "$GREEN" "$RESET"
    printf 'instance in an isolated database, asserted the analytically-known reference outputs, compared\n'
    printf 'weighted vs unweighted PageRank/Dijkstra, exercised the write/mutate/stats modes where the\n'
    printf 'server registers them, captured the server-side /metrics delta into report.json\n'
    printf '(measurement_mode=external), and dropped the isolated database on exit.\n'
    exit 0
  else
    printf '%s%sGDS-ANALYTICS ATTACH DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
    exit 1
  fi
fi

# ==================================================================================================
# LOCAL MODE — self-boot a server; also run the hermetic in-process scalability/parallelism sweep.
# ==================================================================================================
CONFIG="$WORKDIR/graphus.toml"
SERVER_LOG="$WORKDIR/server.log"
CERT="$WORKDIR/cert.pem"
KEY="$WORKDIR/key.pem"
ADMIN_USER="neo4j"
ADMIN_PW="gds-analytics-demo-pw-32bytes-minimum!"
JWT_SECRET="gds-analytics-demo-jwt-secret-32bytes-ok!"
# The store + WAL the evidence meters. A database created at run time (the bulk-import target) does NOT
# live at the store root: it lives under `<store_path>/databases/<db>/`. Metering the root would meter
# the EMPTY default database and report the influence network as costing a few kilobytes — a lie of
# exactly the kind rule 5 exists to prevent. These are therefore rebound to the run's database as soon
# as its name is known (see Step 3b).
STORE_FILE="$WORKDIR/data/graphus.store"
WAL_DIR="$WORKDIR/data/graphus.wal"
SWEEP_JSON="$EVIDENCE_DIR/sweep.json"
BASELINE="$SCRIPT_DIR/baseline.json"
# The profile the committed baseline was captured from (the default). A run at any other profile is a
# different graph, so its figures are not comparable and the gate is skipped — and says so.
BASELINE_PROFILE="moderate"
PEAK_RSS_BYTES=0
SERVER_START_EPOCH=0
SERVER_UPTIME_SECS=0

harness_build "graphus-server (release)" --release -p graphus-server
[ -x "$SERVER" ] || { echo "${RED}fatal: server binary not found at $SERVER${RESET}" >&2; exit 2; }
harness_build "the hermetic GDS scalability sweep (release)" \
  --release -p graphus-gds-gen --bin gds_sweep
[ -x "$SWEEP" ] || { echo "${RED}fatal: gds_sweep binary not found at $SWEEP${RESET}" >&2; exit 2; }
# The server-pid CPU sampler: the seam that lets a Node driver measure the SERVER rather than itself.
PROC_WATCH="$BIN_DIR/proc_watch"
harness_build "the proc_watch server-pid CPU sampler (release)" \
  --release -p graphus-examples-harness --bin proc_watch
[ -x "$PROC_WATCH" ] || { echo "${RED}fatal: proc_watch binary not found at $PROC_WATCH${RESET}" >&2; exit 2; }

# The logical size of the loaded dataset: the bytes the generator actually emitted. The REAL
# denominator for the amplification ratios (rmp #699) — previously they were computed against an
# invented `nodes*256 + rels*128` formula, which made the published ratio a fabrication.
LOGICAL_GRAPH_BYTES="$(wc -c < "$GRAPH_CYPHER" | tr -d ' ')"
info "logical dataset (graph.cypher): ${LOGICAL_GRAPH_BYTES} B"

# server_rss_bytes <pid> — current resident set size in bytes (Linux /proc, macOS ps).
server_rss_bytes() {
  local pid="$1" bytes=0
  if [ -r "/proc/$pid/statm" ]; then
    local pages page_sz
    pages="$(awk '{print $2}' "/proc/$pid/statm" 2>/dev/null || echo 0)"
    page_sz="$(getconf PAGE_SIZE 2>/dev/null || echo 4096)"
    bytes=$(( ${pages:-0} * ${page_sz:-4096} ))
  elif command -v ps >/dev/null 2>&1; then
    local kib
    kib="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || echo 0)"
    bytes=$(( ${kib:-0} * 1024 ))
  fi
  echo "${bytes:-0}"
}
sample_peak_rss() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    local rss; rss="$(server_rss_bytes "$SERVER_PID")"
    if [ "${rss:-0}" -gt "$PEAK_RSS_BYTES" ]; then PEAK_RSS_BYTES="$rss"; fi
  fi
}

# --------------------------------------------------------------------------------------------------
# Step 2 — hermetic multi-threaded scalability + CSR-footprint + parallelism sweep (always runs).
# --------------------------------------------------------------------------------------------------
section "Step 2 — scalability + CSR-footprint + parallelism sweep (multi-threaded, hermetic)"
info "graphus-gds is MULTI-THREADED via a deterministic Execution knob (rmp #342/#559) — the sweep varies GRAPH SIZE *and* CORE COUNT"
# The example's wall-clock starts here: the sweep IS part of the run's work (rmp #699).
RUN_START_MS="$(_harness_now_ms)"
"$SWEEP" --out "$SWEEP_JSON" --sizes "$SWEEP_SIZES" --repeats 3 2>&1 | sed 's/^/  /'
assert "sweep JSON was produced" "yes" "$([ -s "$SWEEP_JSON" ] && echo yes || echo no)"
assert "sweep reports CSR bytes-per-node / bytes-per-edge" "yes" \
  "$(grep -q 'bytes_per_node' "$SWEEP_JSON" && grep -q 'bytes_per_edge' "$SWEEP_JSON" && echo yes || echo no)"
assert "parallelism demo results are deterministic across thread widths" "yes" \
  "$(grep -q '"deterministic_across_widths": true' "$SWEEP_JSON" && echo yes || echo no)"
HOST_CORES="$(json_field "$(cat "$SWEEP_JSON")" host_cores)"
MAX_SPEEDUP="$(json_field "$(cat "$SWEEP_JSON")" max_speedup)"
info "parallelism demo: host_cores=${HOST_CORES:-?}, best measured speedup=${MAX_SPEEDUP:-?}x"
# Gate on the MEASURED speedup, not a constant string. The old gate grepped for the literal
# '"engine_parallelism": "multi-threaded"' that gds_sweep ALWAYS prints — a green tick that could
# never go red (README's own anti-pattern). A real regression to a serial engine collapses max_speedup
# to ~1.0, so on a multi-core host we require a genuine parallel speedup; a 1-core host cannot speed up,
# so the claim is skipped there rather than asserted vacuously (rmp #743).
PARALLEL_MIN=1.5
if [ -n "${HOST_CORES:-}" ] && [ "${HOST_CORES%%.*}" -gt 1 ] 2>/dev/null; then
  assert "engine is genuinely multi-threaded: measured max_speedup > ${PARALLEL_MIN}x on ${HOST_CORES} cores" "yes" \
    "$(awk -v s="${MAX_SPEEDUP:-0}" -v m="$PARALLEL_MIN" 'BEGIN{print (s+0 > m+0) ? "yes" : "no"}')"
else
  info "single-core host (host_cores=${HOST_CORES:-?}) — parallel-speedup claim not asserted (cannot speed up)"
fi

# --------------------------------------------------------------------------------------------------
# Step 3 — decide whether to run the official-driver step
# --------------------------------------------------------------------------------------------------
RUN_DRIVER="${RUN_DRIVER:-auto}"
if [ "$RUN_DRIVER" = "auto" ]; then
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then RUN_DRIVER=1; else RUN_DRIVER=0; fi
fi

# emit_evidence — build (if needed) and run the dev-only `gds_evidence` binary, turning the sweep JSON
# (+ optional live-server CPU/RAM/storage) into report.json + report.md, then gate against baseline.json.
EVIDENCE_BIN="$BIN_DIR/gds_evidence"
CMP_BIN="$BIN_DIR/gds_baseline_cmp"
emit_evidence() {
  local pid="$1" uptime="$2" store="$3" wal="$4" peak="$5"
  # Wrapping harness_build in an `[ ! -x ]` guard would defeat its entire purpose: a stale
  # target/release/gds_evidence left over from an earlier build would be preferred over the current
  # sources, and the report would describe code that no longer exists. Build unconditionally (cargo is
  # incremental) and use exactly what we just built.
  harness_build "the dev-only gds_evidence harness binary (release)" \
    --release -p graphus-gds-gen --bin gds_evidence
  [ -x "$EVIDENCE_BIN" ] || { echo "${RED}fatal: gds_evidence not found at $EVIDENCE_BIN${RESET}" >&2; return 1; }

  # The run's wall-time: sweep + (when it ran) the official-driver load/analyze. The evidence binary
  # runs after both, so it cannot time them — it must be told (rmp #699).
  local total_ms=$(( $(_harness_now_ms) - RUN_START_MS ))

  local args=(
    --evidence-dir "$EVIDENCE_DIR"
    --sweep "$SWEEP_JSON"
    --scenario "gds-analytics"
    --description "GDS analytics over Bolt/TCP+TLS via the official Neo4j driver: load a seeded influence network, assert the analytically-known reference outputs, compare weighted vs unweighted rankings, exercise write/mutate/stats, and characterise multi-threaded per-algorithm scaling + CSR footprint."
    --total-millis "$total_ms"
    --param "profile=$PROFILE"
    --param "connection=bolt-tcp-tls"
  )
  if [ -n "$pid" ]; then
    args+=( --pid "$pid" --uptime-secs "$uptime" --store "$store" --wal "$wal" --peak-rss-bytes "$peak" )
    args+=( --nodes "$NODE_COUNT" --rels "$REL_COUNT" --param "driver=official neo4j-driver" )
    args+=( --logical-graph-bytes "$LOGICAL_GRAPH_BYTES" )
    # write_amplification must divide by what the client actually WROTE. The local run uploads CSV to
    # the bulk-import endpoint and never sends graph.cypher at all, so the Cypher size is the wrong
    # denominator for it (it remains the right one for space_amplification, which asks how big the
    # GRAPH is, not how it happened to be shipped).
    [ -n "${LOGICAL_WRITTEN_BYTES:-}" ] && args+=( --logical-written-bytes "$LOGICAL_WRITTEN_BYTES" )
    args+=( --param "load_path=network bulk-import (Mode A)" )
    [ -n "${BULK_SECS:-}" ] && args+=( --param "bulk_load_secs=$BULK_SECS" )
    [ -n "${BULK_RELS_PER_SEC:-}" ] && args+=( --param "bulk_load_rels_per_sec=$BULK_RELS_PER_SEC" )
    # The per-algorithm SERVER CPU battery — the vector this example exists to expose (rmp #717).
    if [ -s "${ALGO_CPU_JSON:-}" ]; then
      args+=( --algo-cpu "$ALGO_CPU_JSON" )
      [ -n "${TOP_ALGO:-}" ] && args+=( --param "busiest_algorithm=$TOP_ALGO" )
      [ -n "${TOP_CORES:-}" ] && args+=( --param "busiest_algorithm_cores=$TOP_CORES" )
      [ -n "${SERIAL_ALGOS:-}" ] && args+=( --param "serial_algorithms=$SERIAL_ALGOS of $MEASURED_ALGOS measured (<1.5 cores)" )
    fi
    [ -n "${ANALYZE_OPS:-}" ]  && args+=( --workload-ops "$ANALYZE_OPS" )
    [ -n "${ANALYZE_SECS:-}" ] && args+=( --workload-secs "$ANALYZE_SECS" )
    [ -n "${ANALYZE_P50:-}" ]  && args+=( --p50-ms "$ANALYZE_P50" )
    [ -n "${ANALYZE_P99:-}" ]  && args+=( --p99-ms "$ANALYZE_P99" )
    [ -n "${ANALYZE_P999:-}" ] && args+=( --p999-ms "$ANALYZE_P999" )
  else
    args+=( --param "driver=none (hermetic sweep only)" )
  fi

  rm -f "$EVIDENCE_DIR/report.json" "$EVIDENCE_DIR/report.md"
  # Do NOT swallow the emitter's diagnostics: when it fails, its stderr IS the explanation, and a
  # message pointing at "the output above" while /dev/null eats that output helps nobody.
  if "$EVIDENCE_BIN" "${args[@]}" > "$WORKDIR/evidence.log" 2>&1; then
    info "evidence written to $EVIDENCE_DIR"
  else
    printf '%s' "$RED" >&2
    echo "evidence collection FAILED — emitter output:" >&2
    sed 's/^/    /' "$WORKDIR/evidence.log" >&2
    printf '%s' "$RESET" >&2
  fi
  assert "evidence report.json was produced" "yes" \
    "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
  # total_millis must be the WORKLOAD's wall-time, never the report emitter's own (rmp #699).
  assert "report total_millis is the workload wall-time (not the emitter's)" "yes" \
    "$(python3 -c "
import json,sys
try:
    t = json.load(open('$EVIDENCE_DIR/report.json'))['total_millis']
except Exception:
    print('no'); sys.exit()
print('yes' if t >= 1.0 else 'no')
" 2>/dev/null || echo no)"

  # The committed baseline is captured from the DEFAULT profile, so the gate runs on the default run.
  # (It used to be pinned to `fast` — which, once the default moved, would have been a gate that never
  # fires: the same failure mode as a zero placeholder, wearing a green tick.)
  if [ "$PROFILE" = "$BASELINE_PROFILE" ] && [ -f "$BASELINE" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
    section "regression gate vs committed baseline"
    harness_build "the gds_baseline_cmp gate (debug)" --release -p graphus-gds-gen --bin gds_baseline_cmp
    CMP_BIN="$BIN_DIR/gds_baseline_cmp"
    local cmp_out; cmp_out="$("$CMP_BIN" "$BASELINE" "$EVIDENCE_DIR/report.json" 2>&1)" || true
    printf '%s\n' "$cmp_out" | sed 's/^/  /'
    assert "fresh run is within baseline thresholds (structural metrics)" "yes" \
      "$(grep -q 'GRAPHUS_BASELINE_OK' <<<"$cmp_out" && echo yes || echo no)"
  fi
}

if [ "$RUN_DRIVER" = "1" ]; then
  command -v openssl >/dev/null 2>&1 || { echo "${RED}fatal: openssl required for the TLS cert${RESET}" >&2; exit 2; }

  section "Step 3a — boot graphus-server (Bolt-over-TCP + TLS)"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" \
    -days 2 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

  BOLT_PORT="$(( (RANDOM % 20000) + 40000 ))"
  REST_PORT="$(( BOLT_PORT + 1 ))"
  # REST is enabled for ONE reason: the network bulk-import (Mode A) endpoint the default profile's
  # graph goes in through (`data/bulk_load.py`). It runs over the SAME self-signed TLS as Bolt — no
  # plaintext listener is opened. The analytics themselves are driven over Bolt, as before.
  cat > "$CONFIG" <<EOF
# Generated by examples/gds-analytics/run.sh — a Bolt-TCP+TLS demo configuration.
store_path = "$WORKDIR/data"
buffer_pool_pages = 8192
bolt_tcp_addr = "127.0.0.1:$BOLT_PORT"
rest_addr = "127.0.0.1:$REST_PORT"
uds_path = ""
jwt_secret = "$JWT_SECRET"

[tls]
cert_path = "$CERT"
key_path = "$KEY"

[auth]
admin_user = "$ADMIN_USER"
admin_password = "$ADMIN_PW"
EOF

  "$SERVER" "$CONFIG" >>"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  SERVER_START_EPOCH="$(date +%s)"
  ready=0
  for _ in $(seq 1 100); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      echo "${RED}server exited during startup; last log lines:${RESET}" >&2
      tail -n 20 "$SERVER_LOG" >&2
      exit 1
    fi
    if (exec 3<>"/dev/tcp/127.0.0.1/$BOLT_PORT") 2>/dev/null; then
      exec 3>&- 3<&- 2>/dev/null || true
      ready=1; break
    fi
    sleep 0.1
  done
  [ "$ready" = "1" ] || { echo "${RED}server did not open Bolt-TCP port $BOLT_PORT${RESET}" >&2; tail -n 20 "$SERVER_LOG" >&2; exit 1; }
  info "server pid $SERVER_PID listening on bolt+ssc://127.0.0.1:$BOLT_PORT"

  install_driver "$WORKDIR/node" || exit 1

  # ------------------------------------------------------------------------------------------------
  # Step 3b — get the graph IN, through the network bulk-import endpoint (Mode A).
  #
  # The default profile is 2 400 authors / ~24 000 citations, and how it is loaded is the difference
  # between an example that can afford to measure per-algorithm CPU and one that cannot: replaying
  # graph.cypher edge by edge takes ~8 s (the planner index-seeks only the FIRST anchor of a two-anchor
  # CREATE), where the ratified bulk-import path (specification/08-network-bulk-import.md) ingests the
  # identical graph in ~0.2 s. The ATTACH path below keeps the Cypher loader, because a target instance
  # may expose no bulk-import endpoint (or no admin rights on it).
  # ------------------------------------------------------------------------------------------------
  section "Step 3b — load the influence network (network bulk-import, Mode A)"
  BULK_DB="gds_$(date +%s)_$$"
  BULK_OUT="$(python3 "$SCRIPT_DIR/data/bulk_load.py" \
      --base-url "https://127.0.0.1:$REST_PORT" \
      --user "$ADMIN_USER" --password "$ADMIN_PW" \
      --db "$BULK_DB" --data-dir "$DATA_DIR" --insecure \
      --expect-nodes "$NODE_COUNT" --expect-rels "$REL_COUNT" 2>&1)" || true
  printf '%s\n' "$BULK_OUT" | sed 's/^/  /'
  assert "network bulk-import (Mode A) ingested the graph" "yes" \
    "$(grep -q 'GRAPHUS_BULK_OK' <<<"$BULK_OUT" && echo yes || echo no)"
  BULK_BLOB="$(printf '%s' "$BULK_OUT" | sed -n 's/^GRAPHUS_BULK_OK //p' | head -n1)"
  BULK_SECS="$(json_field "$BULK_BLOB" load_secs)"
  BULK_RELS_PER_SEC="$(json_field "$BULK_BLOB" rels_per_sec)"
  if [ -z "$BULK_BLOB" ]; then
    echo "${RED}fatal: the bulk import did not complete — there is no graph to analyse${RESET}" >&2
    exit 1
  fi
  info "bulk-imported ${NODE_COUNT} nodes + ${REL_COUNT} relationships in ${BULK_SECS}s (${BULK_RELS_PER_SEC} rels/s) into database '$BULK_DB'"
  # What the client actually WROTE to the server on this path: the two CSV files it uploaded.
  LOGICAL_WRITTEN_BYTES=$(( $(wc -c < "$DATA_DIR/nodes.csv") + $(wc -c < "$DATA_DIR/relationships.csv") ))
  info "logical bytes uploaded (nodes.csv + relationships.csv): ${LOGICAL_WRITTEN_BYTES} B"
  # Meter the store/WAL of the database that actually HOLDS the graph (see the note at their defaults).
  STORE_FILE="$WORKDIR/data/databases/$BULK_DB/graphus.store"
  WAL_DIR="$WORKDIR/data/databases/$BULK_DB/graphus.wal"
  assert "the run's database has a store image on disk" "yes" \
    "$([ -s "$STORE_FILE" ] && echo yes || echo no)"
  assert "the run's database has a WAL directory on disk" "yes" \
    "$([ -d "$WAL_DIR" ] && echo yes || echo no)"
  sample_peak_rss

  section "Step 3c — analyze over Bolt (OFFICIAL neo4j-driver) + per-algorithm SERVER CPU"
  ALGO_CPU_JSON="$EVIDENCE_DIR/algo_cpu.json"
  rm -f "$ALGO_CPU_JSON"
  ANALYZE_OUT="$(cd "$WORKDIR/node" && node analyze.js \
      --uri "bolt+ssc://127.0.0.1:$BOLT_PORT" \
      --user "$ADMIN_USER" --password "$ADMIN_PW" \
      --database "$BULK_DB" --skip-load \
      --server-pid "$SERVER_PID" --proc-watch "$PROC_WATCH" \
      --algo-cpu-out "$ALGO_CPU_JSON" --cpu-target-secs "$CPU_TARGET_SECS" \
      --graph "$GRAPH_CYPHER" --reference "$REFERENCE" 2>&1)" || true
  printf '%s\n' "$ANALYZE_OUT" | sed 's/^/  /'
  assert "GDS analytics matched the reference ground truth" "yes" \
    "$(grep -q 'GRAPHUS_GDS_OK' <<<"$ANALYZE_OUT" && echo yes || echo no)"
  sample_peak_rss
  parse_stats "$ANALYZE_OUT"
  sample_peak_rss

  # ------------------------------------------------------------------------------------------------
  # The per-algorithm CPU gate. It exists to make the "GDS uses 2 of 9 cores" folklore FALSIFIABLE, so
  # it must be a gate that can genuinely fail: it fires if the battery measured nothing, and it fires
  # if NO algorithm exceeded one core (i.e. the server really did run the whole GDS surface serially).
  # ------------------------------------------------------------------------------------------------
  assert "per-algorithm SERVER CPU battery produced evidence" "yes" \
    "$([ -s "$ALGO_CPU_JSON" ] && echo yes || echo no)"
  BATTERY_VERDICT="$(python3 - "$ALGO_CPU_JSON" <<'PY' 2>/dev/null || echo "error"
import json, sys
try:
    b = json.load(open(sys.argv[1]))
except Exception as e:  # noqa: BLE001
    print("error"); sys.exit()
algos = [a for a in b["algorithms"] if a.get("mean_core_utilisation") is not None]
if not algos:
    print("none-measured"); sys.exit()
top = max(algos, key=lambda a: a["mean_core_utilisation"])
serial = [a for a in algos if a["mean_core_utilisation"] < 1.5]
print(f'{top["algorithm"]}|{top["mean_core_utilisation"]:.2f}|{len(algos)}|{len(serial)}|{b["host_cores"]}')
PY
)"
  TOP_ALGO="$(printf '%s' "$BATTERY_VERDICT" | cut -d'|' -f1)"
  TOP_CORES="$(printf '%s' "$BATTERY_VERDICT" | cut -d'|' -f2)"
  MEASURED_ALGOS="$(printf '%s' "$BATTERY_VERDICT" | cut -d'|' -f3)"
  SERIAL_ALGOS="$(printf '%s' "$BATTERY_VERDICT" | cut -d'|' -f4)"
  HOST_CORES_BATTERY="$(printf '%s' "$BATTERY_VERDICT" | cut -d'|' -f5)"
  assert "the battery resolved at least one algorithm's server CPU" "yes" \
    "$([ "$MEASURED_ALGOS" -ge 1 ] 2>/dev/null && echo yes || echo no)"
  # THE gate: at this scale at least one GDS algorithm must keep MORE THAN ONE core busy on the
  # server. If every algorithm came back under 1.5 cores, GDS is running serially and this run says so
  # (loudly) instead of passing quietly.
  assert "at least one GDS algorithm keeps >1 core busy on the SERVER" "yes" \
    "$(python3 -c "import sys; print('yes' if float('${TOP_CORES:-0}') > 1.5 else 'no')" 2>/dev/null || echo no)"
  info "busiest algorithm: ${TOP_ALGO:-?} at ${TOP_CORES:-?} of ${HOST_CORES_BATTERY:-?} cores; ${SERIAL_ALGOS:-?}/${MEASURED_ALGOS:-?} measured algorithms are effectively serial (<1.5 cores)"

  section "Step 4 — collect performance evidence (per-algorithm + CPU / RAM / storage)"
  SERVER_UPTIME_SECS=$(( $(date +%s) - SERVER_START_EPOCH ))
  [ "$SERVER_UPTIME_SECS" -lt 1 ] && SERVER_UPTIME_SECS=1
  emit_evidence "$SERVER_PID" "$SERVER_UPTIME_SECS" "$STORE_FILE" "$WAL_DIR" "$PEAK_RSS_BYTES"

  stop_pid="$SERVER_PID"
  kill -TERM "$stop_pid" 2>/dev/null || true
  wait "$stop_pid" 2>/dev/null || true
  SERVER_PID=""
else
  section "Step 3 — official-driver path SKIPPED (RUN_DRIVER=0 or node/npm absent)"
  info "the hermetic generator + scalability sweep still ran; emitting hermetic evidence below"
  section "Step 4 — collect performance evidence (per-algorithm + CSR footprint, hermetic)"
  emit_evidence "" "" "" "" ""
fi

# --------------------------------------------------------------------------------------------------
# Summary (local mode)
# --------------------------------------------------------------------------------------------------
section "Result"
printf '%s checks run, %s failures.\n' "$CHECKS" "$FAILURES"
info "sweep evidence: $SWEEP_JSON"
[ -f "$EVIDENCE_DIR/report.json" ] && info "standardized evidence: $EVIDENCE_DIR/{report.json, report.md}"
if [ "$FAILURES" -eq 0 ]; then
  if [ "$RUN_DRIVER" = "1" ]; then
    printf '%s%sGDS-ANALYTICS DEMONSTRATION PASSED%s — Graphus loaded a seeded influence network over\n' "$BOLD" "$GREEN" "$RESET"
    printf 'Bolt/TLS via the official Neo4j driver, asserted the analytically-known reference outputs,\n'
    printf 'compared weighted vs unweighted rankings, exercised write/mutate/stats, released the\n'
    printf 'projections cleanly, and produced a multi-threaded scalability + CSR-footprint sweep.\n'
  else
    printf '%s%sGDS-ANALYTICS DEMONSTRATION PASSED%s — the hermetic generator produced a byte-identical\n' "$BOLD" "$GREEN" "$RESET"
    printf 'seeded influence network + reference subgraph and the multi-threaded scalability sweep held\n'
    printf 'its invariants. (Official-driver load/analyze was skipped: RUN_DRIVER=0 or node/npm absent.)\n'
  fi
  exit 0
else
  printf '%s%sGDS-ANALYTICS DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
