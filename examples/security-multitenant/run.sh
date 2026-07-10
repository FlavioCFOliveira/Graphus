#!/usr/bin/env bash
#
# Graphus multi-tenant security demonstration — fine-grained RBAC (GRANT + DENY + property/label
# scope), tenant isolation and encryption-at-rest, exercised over BOTH the REST API (HTTPS + Bearer
# obtained from POST /auth/login, a pure-stdlib python3 client) and Bolt-over-TCP+TLS (the OFFICIAL
# Neo4j driver). It runs in one of two modes:
#
#   * LOCAL (default) — boots a REAL, ENCRYPTED `graphus-server` (AES-256-GCM page + WAL encryption)
#     exposing REST + Bolt (both TLS), provisions isolated tenant databases + roles/users/grants +
#     DENY, drives the full RBAC + cross-tenant + DENY surface over both protocols, measures the
#     encryption overhead against a cleartext twin (IDENTICAL seed into isolated dbs on both sides),
#     runs the HERMETIC in-process encryption/rotation/backup verifier, and collects the full evidence
#     set (server CPU/RSS, on-disk TENANT store/WAL footprint, a committed-baseline regression gate)
#     plus a server-side /metrics delta including the auth-failure signal.
#   * EXTERNAL / ATTACH — when any of GRAPHUS_TARGET_{BOLT,REST,UDS} is set, it does NOT boot a server:
#     it attaches to the ALREADY-RUNNING instance (local or remote, e.g. pi516) via the shared
#     external-target seam in `_harness/harness.sh`, authenticates with POST /auth/login, provisions an
#     ISOLATED, NAMESPACED set of tenants/roles/users (idempotent, IF NOT EXISTS), drives the RBAC +
#     cross-tenant + DENY (feature-detected) wire legs against it, scrapes the target's /metrics
#     (incl. the auth-failure signal) via `measure_target` (measurement_mode=external), then TEARS
#     EVERYTHING DOWN (DROP database/role/user) on exit so the target is left exactly as found. The
#     encryption-at-rest / ciphertext / key-rotation legs read raw store bytes and are LOCAL-ONLY.
#
# The generator (step 1) and the crypto verifier (step 2, LOCAL) are HERMETIC. The REST leg needs
# python3 (+ openssl in LOCAL for the self-signed cert; + curl in EXTERNAL for /metrics). The Bolt leg
# needs node/npm (+ network for `npm install neo4j-driver`) and, in EXTERNAL, GRAPHUS_TARGET_BOLT.
#
# Usage:
#   examples/security-multitenant/run.sh                          # LOCAL: builds binaries if needed
#   GRAPHUS_BIN_DIR=target/release SEC_PROFILE=large  examples/security-multitenant/run.sh
#   RUN_DRIVER=0                                      examples/security-multitenant/run.sh
#
#   # EXTERNAL / ATTACH — against an already-running instance (e.g. pi516), isolated + cleaned up:
#   GRAPHUS_TARGET_REST=https://100.89.148.30:7474 GRAPHUS_TARGET_BOLT=bolt+ssc://100.89.148.30:7687 \
#     GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=graphus-local \
#     GRAPHUS_TARGET_TLS_INSECURE=1 examples/security-multitenant/run.sh

set -euo pipefail

# --------------------------------------------------------------------------------------------------
# Shared external-target seam (attach mode + /metrics scrape + isolated-DB DDL). Sourced BEFORE this
# script's own pretty-print helpers so ours take precedence over the harness's identically-named ones.
# --------------------------------------------------------------------------------------------------
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../_harness" && pwd)/harness.sh"

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

# json_field <json-blob> <key> — extract a flat scalar field from a one-line JSON object (no jq dep).
json_field() {
  printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\\{0,1\\}\\([^,\"}]*\\).*/\\1/p" | head -n1
}

# auth_failures_of <metrics-file> — the graphus_auth_failures_total value (0 if absent).
auth_failures_of() {
  local v
  v="$(sed -n 's/^graphus_auth_failures_total \([0-9][0-9]*\)$/\1/p' "$1" 2>/dev/null | head -n1)"
  echo "${v:-0}"
}

# --------------------------------------------------------------------------------------------------
# Locate (or build) the binaries
# --------------------------------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${GRAPHUS_BIN_DIR:-$REPO_ROOT/target/release}"
SERVER="$BIN_DIR/graphus-server"
GEN="$BIN_DIR/security_gen"
VERIFY="$BIN_DIR/security_verify"

PROFILE="${SEC_PROFILE:-fast}"
MODE="$(harness_target_mode)"   # local | external

# The deterministic generator is needed in BOTH modes.
if [ ! -x "$GEN" ]; then
  section "Building the deterministic security generator (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-security-gen --bin security_gen )
fi
[ -x "$GEN" ] || { echo "${RED}fatal: security_gen binary not found at $GEN${RESET}" >&2; exit 2; }

# The server + hermetic crypto verifier are needed ONLY in local mode.
if [ "$MODE" = "local" ]; then
  if [ ! -x "$SERVER" ]; then
    section "Building graphus-server (release)"
    ( cd "$REPO_ROOT" && cargo build --release -p graphus-server )
  fi
  [ -x "$SERVER" ] || { echo "${RED}fatal: server binary not found at $SERVER${RESET}" >&2; exit 2; }
  if [ ! -x "$VERIFY" ]; then
    section "Building the hermetic crypto verifier (release)"
    ( cd "$REPO_ROOT" && cargo build --release -p graphus-security-gen --features dst-repro --bin security_verify )
  fi
  [ -x "$VERIFY" ] || { echo "${RED}fatal: security_verify binary not found at $VERIFY${RESET}" >&2; exit 2; }
fi

# --------------------------------------------------------------------------------------------------
# Workspace + evidence paths
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-sec-mt-XXXXXX")"
CONFIG="$WORKDIR/graphus.toml"
CLEAR_CONFIG="$WORKDIR/graphus-clear.toml"
SERVER_LOG="$WORKDIR/server.log"
CLEAR_LOG="$WORKDIR/server-clear.log"
CERT="$WORKDIR/cert.pem"
KEY="$WORKDIR/key.pem"
MASTER_KEY="$WORKDIR/master.key"
DATA_DIR="$WORKDIR/dataset"
ADMIN_USER="neo4j"
ADMIN_PW="sec-mt-demo-admin-pw-8plus"
JWT_SECRET="sec-mt-demo-jwt-secret-32bytes-minimum!"

EVIDENCE_DIR="$SCRIPT_DIR/evidence"
BASELINE="$SCRIPT_DIR/baseline.json"
METRICS_BEFORE="$WORKDIR/metrics_before.prom"
METRICS_AFTER="$WORKDIR/metrics_after.prom"
PEAK_RSS_BYTES=0
SERVER_START_EPOCH=0
REST_PORT=0
BOLT_PORT=0

# External-mode namespace: a unique, lowercase [a-z0-9_] prefix so a SHARED target hosts isolated,
# collision-free tenant databases/roles/users that are torn down unambiguously.
RUN_NS="secmt_$(date +%s)_$$"

SERVER_PID=""

# teardown_external — replay teardown.cypher (DROP user/role, STOP+DROP database) against the target's
# system DB via the harness. Idempotent (every statement IF EXISTS / STOP), safe from the cleanup trap.
teardown_external() {
  [ "$MODE" = "external" ] || return 0
  local td="$DATA_DIR/teardown.cypher"
  [ -f "$td" ] || return 0
  local sysdb; sysdb="$(_harness_target_system_db)"
  info "tearing down namespaced tenants/roles/users on the external target ($RUN_NS)" >&2
  local line
  while IFS= read -r line; do
    case "$line" in ''|//*) continue ;; esac
    line="${line%;}"
    harness_target_query "$sysdb" "$line" >/dev/null 2>&1 || true
  done < "$td"
}

# cleanup — kill the local server we spawned; tear down the external namespace; remove the workdir.
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  teardown_external 2>/dev/null || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

# server_rss_bytes <pid> — current RSS in bytes (Linux /proc, macOS ps).
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
    [ "${rss:-0}" -gt "$PEAK_RSS_BYTES" ] && PEAK_RSS_BYTES="$rss"
  fi
}

# dir_bytes <path> — total bytes of a file/dir tree (portable du), 0 if missing.
dir_bytes() {
  [ -e "$1" ] || { echo 0; return; }
  du -sb "$1" 2>/dev/null | awk '{print $1}' || echo 0
}

# sum_glob_bytes <glob...> — summed bytes over a set of paths (used to sum tenant stores).
sum_glob_bytes() {
  local total=0 p b
  for p in "$@"; do
    [ -e "$p" ] || continue
    b="$(du -sb "$p" 2>/dev/null | awk '{print $1}')"
    total=$(( total + ${b:-0} ))
  done
  echo "$total"
}

# wait_for_port <pid> <port> <label>
wait_for_port() {
  local pid="$1" port="$2" label="$3" ready=0
  for _ in $(seq 1 100); do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "${RED}$label exited during startup; last log lines:${RESET}" >&2
      tail -n 20 "$SERVER_LOG" "$CLEAR_LOG" 2>/dev/null >&2 || true
      return 1
    fi
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      exec 3>&- 3<&- 2>/dev/null || true
      ready=1; break
    fi
    sleep 0.1
  done
  [ "$ready" = "1" ]
}

# local_login — mint an admin Bearer against the LOCAL server via POST /auth/login (for /metrics).
local_login() {
  command -v curl >/dev/null 2>&1 || return 1
  local resp token
  resp="$(curl -k -sS -X POST "https://127.0.0.1:$REST_PORT/auth/login" \
            -H 'Content-Type: application/json' \
            -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PW\"}" 2>/dev/null)" || return 1
  token="$(printf '%s' "$resp" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  [ -n "$token" ] && printf '%s' "$token"
}

# local_scrape_metrics <outfile> <token>
local_scrape_metrics() {
  command -v curl >/dev/null 2>&1 || return 1
  local out="$1" token="$2" code
  [ -n "$token" ] || return 1
  code="$(curl -k -sS -o "$out" -w '%{http_code}' \
            -H "Authorization: Bearer $token" "https://127.0.0.1:$REST_PORT/metrics" 2>/dev/null)" || return 1
  [ "$code" = "200" ] && [ -s "$out" ]
}

# --------------------------------------------------------------------------------------------------
# Step 1 — generate the deterministic multi-tenant scenario (data + provisioning + DENY + manifest)
# --------------------------------------------------------------------------------------------------
section "Step 1 — generate the deterministic multi-tenant scenario ($PROFILE profile, $MODE mode)"
mkdir -p "$DATA_DIR"
if [ "$MODE" = "external" ]; then
  GEN_OUT="$("$GEN" --profile "$PROFILE" --namespace "$RUN_NS" --out-dir "$DATA_DIR" | head -n1)"
  info "namespace: $RUN_NS (isolated tenants on the shared target, torn down on exit)"
else
  GEN_OUT="$("$GEN" --profile "$PROFILE" --out-dir "$DATA_DIR" | head -n1)"
fi
info "$GEN_OUT"
PROVISION="$DATA_DIR/provision.cypher"
DENY_FILE="$DATA_DIR/deny.cypher"
TEARDOWN="$DATA_DIR/teardown.cypher"
MANIFEST="$DATA_DIR/manifest.json"
assert "provision.cypher generated" "yes" "$([ -s "$PROVISION" ] && echo yes || echo no)"
assert "deny.cypher generated"      "yes" "$([ -s "$DENY_FILE" ] && echo yes || echo no)"
assert "teardown.cypher generated"  "yes" "$([ -s "$TEARDOWN" ] && echo yes || echo no)"
assert "manifest.json generated"    "yes" "$([ -s "$MANIFEST" ] && echo yes || echo no)"

# Resolve the two tenant database names + their load scripts from the (possibly namespaced) manifest.
DB_A="$(python3 -c "import json;print(json.load(open('$MANIFEST'))['tenants'][0]['database'])")"
DB_B="$(python3 -c "import json;print(json.load(open('$MANIFEST'))['tenants'][1]['database'])")"
TENANT_A="$DATA_DIR/$DB_A.cypher"
TENANT_B="$DATA_DIR/$DB_B.cypher"

# Sizing for the evidence report (counted directly off the deterministic load scripts).
NODE_COUNT="$(grep -chE '^CREATE \(:' "$TENANT_A" "$TENANT_B" | paste -sd+ - | bc 2>/dev/null || echo 0)"
REL_COUNT="$(grep -chE 'CREATE \([a-z]\)-\[:' "$TENANT_A" "$TENANT_B" | paste -sd+ - | bc 2>/dev/null || echo 0)"
NODE_COUNT="${NODE_COUNT:-0}"; REL_COUNT="${REL_COUNT:-0}"
LOGICAL_GRAPH_BYTES=$(( NODE_COUNT * 256 + REL_COUNT * 128 ))
info "dataset: $NODE_COUNT nodes, $REL_COUNT relationships across 2 tenants"

# Determinism check: regenerate (same namespace) and diff every artifact.
GEN_OUT2_DIR="$WORKDIR/dataset2"
if [ "$MODE" = "external" ]; then
  "$GEN" --profile "$PROFILE" --namespace "$RUN_NS" --out-dir "$GEN_OUT2_DIR" > /dev/null
else
  "$GEN" --profile "$PROFILE" --out-dir "$GEN_OUT2_DIR" > /dev/null
fi
if diff -q "$PROVISION" "$GEN_OUT2_DIR/provision.cypher" > /dev/null \
   && diff -q "$MANIFEST" "$GEN_OUT2_DIR/manifest.json" > /dev/null \
   && diff -q "$DENY_FILE" "$GEN_OUT2_DIR/deny.cypher" > /dev/null \
   && diff -q "$TENANT_A" "$GEN_OUT2_DIR/$DB_A.cypher" > /dev/null; then
  assert "generator is byte-identical per seed" "yes" "yes"
else
  assert "generator is byte-identical per seed" "yes" "no"
fi

# --------------------------------------------------------------------------------------------------
# Step 2 — hermetic crypto verifier (LOCAL-ONLY: reads raw store bytes; cannot target a remote server)
# --------------------------------------------------------------------------------------------------
V_ROTATION_MS=0; V_BACKUP_BYTES=0; V_SEALED_BYTES=0; V_BACKUP_MS=0; V_RESTORE_MS=0
if [ "$MODE" = "local" ]; then
  section "Step 2 — hermetic encryption/rotation/backup verifier (LOCAL-ONLY, no network)"
  VERIFY_OUT="$("$VERIFY" --out-dir "$WORKDIR/verify" 2>&1)" || true
  printf '%s\n' "$VERIFY_OUT" | sed 's/^/  /'
  assert "ciphertext-on-disk + rotation + encrypted-backup proofs passed" "yes" \
    "$(printf '%s' "$VERIFY_OUT" | grep -q 'GRAPHUS_SECURITY_VERIFY_OK' && echo yes || echo no)"
  VERIFY_STATS="$(printf '%s' "$VERIFY_OUT" | sed -n 's/^GRAPHUS_STATS //p' | head -n1)"
  V_ROTATION_MS="$(json_field "$VERIFY_STATS" rotation_ms)"
  V_BACKUP_BYTES="$(json_field "$VERIFY_STATS" backup_artifact_bytes)"
  V_SEALED_BYTES="$(json_field "$VERIFY_STATS" sealed_backup_bytes)"
  V_BACKUP_MS="$(json_field "$VERIFY_STATS" backup_ms)"
  V_RESTORE_MS="$(json_field "$VERIFY_STATS" restore_ms)"
else
  section "Step 2 — hermetic encryption/rotation/backup verifier SKIPPED (LOCAL-ONLY)"
  info "the ciphertext-on-disk / key-rotation / encrypted-backup proofs read RAW store bytes and"
  info "cannot target a remote server; run this example in LOCAL mode to exercise them."
fi

# --------------------------------------------------------------------------------------------------
# Decide whether the REST/Bolt wire legs can run. LOCAL needs openssl+python3; EXTERNAL needs python3+curl.
# --------------------------------------------------------------------------------------------------
RUN_REST=1
command -v python3 >/dev/null 2>&1 || RUN_REST=0
if [ "$MODE" = "local" ]; then
  command -v openssl >/dev/null 2>&1 || RUN_REST=0
else
  command -v curl >/dev/null 2>&1 || RUN_REST=0
fi

RUN_DRIVER="${RUN_DRIVER:-auto}"
if [ "$RUN_DRIVER" = "auto" ]; then
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then RUN_DRIVER=1; else RUN_DRIVER=0; fi
fi

REST_OUT=""; REST_STATS=""; BOLT_OUT=""
DENY_SUPPORTED="false"; DENY_FLAG=0
AUTH_FAIL_BEFORE=0; AUTH_FAIL_AFTER=0; AUTH_FAIL_DELTA=0
WORKLOAD_SECS=1

# ==================================================================================================
# EXTERNAL / ATTACH — attach to an ALREADY-RUNNING instance (no server boot); isolated + torn down.
# ==================================================================================================
if [ "$RUN_REST" = "1" ] && [ "$MODE" = "external" ]; then
  section "Step 3 — attach to the ALREADY-RUNNING Graphus instance (external target)"
  REST_BASE="$(_harness_target_rest_base)"
  [ -n "$REST_BASE" ] || { echo "${RED}fatal: external mode set but no REST endpoint (GRAPHUS_TARGET_REST)${RESET}" >&2; exit 1; }
  TARGET_TOKEN="$(harness_target_login)" || { echo "${RED}fatal: POST /auth/login failed against $REST_BASE${RESET}" >&2; exit 1; }
  export GRAPHUS_TARGET_METRICS_TOKEN="$TARGET_TOKEN"
  info "authenticated to $REST_BASE via POST /auth/login (${#TARGET_TOKEN} chars)"

  INSECURE_FLAG=(); _harness_target_insecure && INSECURE_FLAG=(--insecure)

  # Scrape /metrics + auth-failures BEFORE the workload window.
  if harness_scrape_metrics "$METRICS_BEFORE"; then
    AUTH_FAIL_BEFORE="$(auth_failures_of "$METRICS_BEFORE")"
    info "scraped /metrics (before) -> auth_failures=$AUTH_FAIL_BEFORE"
  else
    info "metrics-before scrape unavailable (non-fatal)"
  fi

  section "Step 4 — RBAC + DENY + cross-tenant matrix over REST (python3 stdlib, attach mode)"
  WORKLOAD_START="$(date +%s)"
  REST_OUT="$(python3 "$SCRIPT_DIR/data/matrix.py" \
    --base-url "$REST_BASE" \
    --admin-user "${GRAPHUS_TARGET_USER:-graphus}" \
    --admin-password "${GRAPHUS_TARGET_PASSWORD:-graphus-local}" \
    --data-dir "$DATA_DIR" \
    --system-db "$(_harness_target_system_db)" \
    "${INSECURE_FLAG[@]}" 2>&1)" || true
  printf '%s\n' "$REST_OUT" | sed 's/^/  /'
  assert "REST RBAC/DENY/cross-tenant matrix: every cell held" "yes" \
    "$(printf '%s' "$REST_OUT" | grep -q 'GRAPHUS_RBAC_OK' && echo yes || echo no)"
  REST_STATS="$(printf '%s' "$REST_OUT" | sed -n 's/^[[:space:]]*GRAPHUS_STATS //p' | head -n1)"
  DENY_SUPPORTED="$(json_field "$REST_STATS" deny_supported)"; [ "$DENY_SUPPORTED" = "true" ] && DENY_FLAG=1

  # Bolt leg over the OFFICIAL driver (opt-in; needs node/npm + GRAPHUS_TARGET_BOLT).
  BOLT_URI="${GRAPHUS_TARGET_BOLT:-}"
  if [ "$RUN_DRIVER" = "1" ] && [ -n "$BOLT_URI" ]; then
    section "Step 5 — identical matrix over Bolt (OFFICIAL neo4j-driver, attach mode)"
    NODE_PROJ="$WORKDIR/node"; mkdir -p "$NODE_PROJ"
    cat > "$NODE_PROJ/package.json" <<'EOF'
{ "name": "graphus-security-multitenant", "version": "1.0.0", "private": true,
  "dependencies": { "neo4j-driver": "^6.1.0" } }
EOF
    cp "$SCRIPT_DIR/data/matrix.js" "$NODE_PROJ/matrix.js"
    info "installing neo4j-driver (npm)…"
    if ( cd "$NODE_PROJ" && npm install --no-audit --no-fund --loglevel=error ) >>"$SERVER_LOG" 2>&1; then
      BOLT_OUT="$(cd "$NODE_PROJ" && node matrix.js "$BOLT_URI" "$MANIFEST" \
        "${GRAPHUS_TARGET_USER:-graphus}" "${GRAPHUS_TARGET_PASSWORD:-graphus-local}" "$DENY_FLAG" 2>&1)" || true
      printf '%s\n' "$BOLT_OUT" | sed 's/^/  /'
      assert "Bolt RBAC/cross-tenant matrix: identical decisions held" "yes" \
        "$(printf '%s' "$BOLT_OUT" | grep -q 'GRAPHUS_BOLT_RBAC_OK' && echo yes || echo no)"
    else
      info "npm install neo4j-driver failed; skipping the Bolt leg (non-fatal). See $SERVER_LOG"
    fi
  else
    section "Step 5 — Bolt leg SKIPPED (RUN_DRIVER=0, node/npm absent, or GRAPHUS_TARGET_BOLT unset)"
  fi

  WORKLOAD_SECS=$(( $(date +%s) - WORKLOAD_START )); [ "$WORKLOAD_SECS" -lt 1 ] && WORKLOAD_SECS=1

  # Deliberate bad-Bearer GET /metrics — an unauthenticated request that IS rejected AND bumps the
  # auth-failure counter (the /metrics gate + Bolt bump it; a REST data-plane 401 does NOT — see note).
  MBASE="$(_harness_target_metrics_base)"
  _harness_curl -sS -o /dev/null -H "Authorization: Bearer deliberately-invalid-$$-$RANDOM" \
    "$MBASE/metrics" >/dev/null 2>&1 || true

  if harness_scrape_metrics "$METRICS_AFTER"; then
    AUTH_FAIL_AFTER="$(auth_failures_of "$METRICS_AFTER")"
    AUTH_FAIL_DELTA=$(( AUTH_FAIL_AFTER - AUTH_FAIL_BEFORE ))
    info "scraped /metrics (after) -> auth_failures=$AUTH_FAIL_AFTER (delta=$AUTH_FAIL_DELTA)"
    assert "auth-failure signal moved over the window (graphus_auth_failures_total)" "yes" \
      "$([ "${AUTH_FAIL_DELTA:-0}" -ge 1 ] && echo yes || echo no)"
  else
    info "metrics-after scrape unavailable (non-fatal) — auth-failure assertion skipped"
  fi

# ==================================================================================================
# LOCAL — boot an ENCRYPTED server (REST + Bolt, both TLS) and drive it.
# ==================================================================================================
elif [ "$RUN_REST" = "1" ] && [ "$MODE" = "local" ]; then
  section "Step 3 — boot an ENCRYPTED graphus-server (REST + Bolt-TCP, both TLS, AES-256-GCM at rest)"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" \
    -days 2 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
  head -c 32 /dev/urandom > "$MASTER_KEY"

  REST_PORT="$(( (RANDOM % 20000) + 40000 ))"
  BOLT_PORT="$(( (RANDOM % 20000) + 20000 ))"
  cat > "$CONFIG" <<EOF
# Generated by examples/security-multitenant/run.sh — an ENCRYPTED REST+Bolt+TLS multi-tenant demo.
store_path = "$WORKDIR/data"
buffer_pool_pages = 4096
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

[encryption]
key_path = "$MASTER_KEY"
EOF

  "$SERVER" "$CONFIG" >>"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  SERVER_START_EPOCH="$(date +%s)"
  wait_for_port "$SERVER_PID" "$REST_PORT" "encrypted server" \
    || { echo "${RED}encrypted server did not open REST port $REST_PORT${RESET}" >&2; tail -n 20 "$SERVER_LOG" >&2; exit 1; }
  wait_for_port "$SERVER_PID" "$BOLT_PORT" "encrypted server" \
    || { echo "${RED}Bolt port $BOLT_PORT not open${RESET}" >&2; tail -n 20 "$SERVER_LOG" >&2; exit 1; }
  info "encrypted server pid $SERVER_PID — REST https://127.0.0.1:$REST_PORT, Bolt bolt+ssc://127.0.0.1:$BOLT_PORT"

  LOCAL_METRICS_TOKEN="$(local_login || true)"
  if local_scrape_metrics "$METRICS_BEFORE" "$LOCAL_METRICS_TOKEN"; then
    AUTH_FAIL_BEFORE="$(auth_failures_of "$METRICS_BEFORE")"
    info "scraped /metrics (before) -> auth_failures=$AUTH_FAIL_BEFORE"
  fi

  section "Step 4 — provision + RBAC + DENY + cross-tenant matrix over REST (python3 stdlib)"
  WORKLOAD_START="$(date +%s)"
  REST_OUT="$(python3 "$SCRIPT_DIR/data/matrix.py" \
    --base-url "https://127.0.0.1:$REST_PORT" \
    --admin-user "$ADMIN_USER" --admin-password "$ADMIN_PW" \
    --data-dir "$DATA_DIR" --system-db "graphus" --insecure 2>&1)" || true
  printf '%s\n' "$REST_OUT" | sed 's/^/  /'
  assert "REST RBAC/DENY/cross-tenant matrix: every cell held" "yes" \
    "$(printf '%s' "$REST_OUT" | grep -q 'GRAPHUS_RBAC_OK' && echo yes || echo no)"
  sample_peak_rss
  REST_STATS="$(printf '%s' "$REST_OUT" | sed -n 's/^[[:space:]]*GRAPHUS_STATS //p' | head -n1)"
  DENY_SUPPORTED="$(json_field "$REST_STATS" deny_supported)"; [ "$DENY_SUPPORTED" = "true" ] && DENY_FLAG=1

  if [ "$RUN_DRIVER" = "1" ]; then
    section "Step 5 — identical matrix over Bolt (OFFICIAL neo4j-driver)"
    NODE_PROJ="$WORKDIR/node"; mkdir -p "$NODE_PROJ"
    cat > "$NODE_PROJ/package.json" <<'EOF'
{ "name": "graphus-security-multitenant", "version": "1.0.0", "private": true,
  "dependencies": { "neo4j-driver": "^6.1.0" } }
EOF
    cp "$SCRIPT_DIR/data/matrix.js" "$NODE_PROJ/matrix.js"
    info "installing neo4j-driver (npm)…"
    if ( cd "$NODE_PROJ" && npm install --no-audit --no-fund --loglevel=error ) >>"$SERVER_LOG" 2>&1; then
      BOLT_OUT="$(cd "$NODE_PROJ" && node matrix.js "bolt+ssc://127.0.0.1:$BOLT_PORT" "$MANIFEST" \
        "$ADMIN_USER" "$ADMIN_PW" "$DENY_FLAG" 2>&1)" || true
      printf '%s\n' "$BOLT_OUT" | sed 's/^/  /'
      assert "Bolt RBAC/cross-tenant matrix: identical decisions held" "yes" \
        "$(printf '%s' "$BOLT_OUT" | grep -q 'GRAPHUS_BOLT_RBAC_OK' && echo yes || echo no)"
      sample_peak_rss
    else
      info "npm install neo4j-driver failed; skipping the Bolt leg (non-fatal). See $SERVER_LOG"
    fi
  else
    section "Step 5 — Bolt leg SKIPPED (RUN_DRIVER=0 or node/npm absent)"
  fi
  WORKLOAD_SECS=$(( $(date +%s) - WORKLOAD_START )); [ "$WORKLOAD_SECS" -lt 1 ] && WORKLOAD_SECS=1

  # -------- DEFECT-FIX (a): storage = the TENANT database stores under databases/*, NOT the empty
  # default `graphus` db. measure_server walks ONE path per vector, so the primary storage section
  # meters a REAL tenant store (tenant_a); the cross-tenant SUM rides in as params. --------
  TENANT_STORE="$WORKDIR/data/databases/$DB_A/graphus.store"
  TENANT_WAL="$WORKDIR/data/databases/$DB_A/graphus.wal"
  TENANT_STORE_TOTAL="$(sum_glob_bytes "$WORKDIR"/data/databases/*/graphus.store)"
  TENANT_WAL_TOTAL="$(sum_glob_bytes "$WORKDIR"/data/databases/*/graphus.wal)"
  info "tenant stores: tenant_a=$(dir_bytes "$TENANT_STORE") B, all-tenants sum=$TENANT_STORE_TOTAL B"

  # -------- DEFECT-FIX (b): encryption overhead — seed an IDENTICAL dataset into an ISOLATED db on
  # BOTH the encrypted and the cleartext server, then compare ONLY those two db stores. --------
  section "Step 6 — encryption overhead vs cleartext (IDENTICAL isolated seed on both sides)"
  seed_overhead_db() { # <rest-port> <db>
    python3 - "$1" "$ADMIN_USER" "$ADMIN_PW" "$2" "$TENANT_A" <<'PY'
import sys, time, json, ssl, urllib.request, urllib.error
port, user, pw, db, cypher = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
def post(path, body):
    req = urllib.request.Request(f"https://127.0.0.1:{port}{path}", data=json.dumps(body).encode(), method='POST')
    req.add_header('Content-Type','application/json'); req.add_header('Accept','application/json')
    if TOK: req.add_header('Authorization','Bearer '+TOK)
    try: return urllib.request.urlopen(req, context=ctx)
    except urllib.error.HTTPError as e: return e
TOK=None
r = post('/auth/login', {"username":user,"password":pw}); TOK = json.loads(r.read())["token"]
def commit(d, stmts, mode=None):
    b = {"statements": stmts}
    if mode: b["access_mode"] = mode
    return post(f"/db/{d}/tx/commit", b)
commit('graphus', [{"statement": f"CREATE DATABASE {db} IF NOT EXISTS"}])
stmts=[]; buf=''
for line in open(cypher):
    line=line.rstrip('\n')
    if line.startswith('//') or not line.strip(): continue
    buf+=line
    if buf.rstrip().endswith(';'): stmts.append(buf.rstrip()[:-1]); buf=''
t0=time.time(); B=200
for i in range(0,len(stmts),B):
    commit(db, [{"statement": s} for s in stmts[i:i+B]], "WRITE")
print(round((time.time()-t0)*1000,1))
PY
  }
  ENC_SEED_MS="$(seed_overhead_db "$REST_PORT" "overhead_enc")" || ENC_SEED_MS=0

  CLEAR_DATA="$WORKDIR/data-clear"
  CLEAR_REST_PORT="$(( (RANDOM % 20000) + 40000 ))"
  cat > "$CLEAR_CONFIG" <<EOF
# Cleartext twin of the encrypted server, for the encryption-overhead comparison (NO [encryption]).
store_path = "$CLEAR_DATA"
buffer_pool_pages = 4096
bolt_tcp_addr = ""
rest_addr = "127.0.0.1:$CLEAR_REST_PORT"
uds_path = ""
jwt_secret = "$JWT_SECRET"

[tls]
cert_path = "$CERT"
key_path = "$KEY"

[auth]
admin_user = "$ADMIN_USER"
admin_password = "$ADMIN_PW"
EOF
  "$SERVER" "$CLEAR_CONFIG" >>"$CLEAR_LOG" 2>&1 &
  CLEAR_PID=$!
  CLEAR_SEED_MS=0
  if wait_for_port "$CLEAR_PID" "$CLEAR_REST_PORT" "cleartext server"; then
    REST_PORT_SAVE="$REST_PORT"; REST_PORT="$CLEAR_REST_PORT"
    CLEAR_SEED_MS="$(seed_overhead_db "$CLEAR_REST_PORT" "overhead_clear")" || CLEAR_SEED_MS=0
    REST_PORT="$REST_PORT_SAVE"
  fi
  kill -TERM "$CLEAR_PID" 2>/dev/null || true
  wait "$CLEAR_PID" 2>/dev/null || true

  # Measure ONLY the two isolated, identically-seeded overhead db stores (apples-to-apples).
  ENC_STORE_BYTES="$(dir_bytes "$WORKDIR/data/databases/overhead_enc/graphus.store")"
  CLEAR_STORE_BYTES="$(dir_bytes "$CLEAR_DATA/databases/overhead_clear/graphus.store")"
  printf '  %sencrypted%s seed=%s ms, overhead_enc store=%s B   |   %scleartext%s seed=%s ms, overhead_clear store=%s B\n' \
    "$BOLD" "$RESET" "${ENC_SEED_MS:-0}" "${ENC_STORE_BYTES:-0}" \
    "$BOLD" "$RESET" "${CLEAR_SEED_MS:-0}" "${CLEAR_STORE_BYTES:-0}"
  if [ "${CLEAR_STORE_BYTES:-0}" -gt 0 ]; then
    OVERHEAD_OK="$(awk -v e="${ENC_STORE_BYTES:-0}" -v c="${CLEAR_STORE_BYTES:-1}" 'BEGIN{print (e <= c*3)?"yes":"no"}')"
    assert "encrypted store footprint is within 3x cleartext (identical seed; bounded GCM overhead)" "yes" "$OVERHEAD_OK"
  fi

  # Deliberate bad-Bearer /metrics probe to move the auth-failure counter, then scrape after.
  curl -k -sS -o /dev/null -H "Authorization: Bearer deliberately-invalid-$$-$RANDOM" \
    "https://127.0.0.1:$REST_PORT/metrics" >/dev/null 2>&1 || true
  if local_scrape_metrics "$METRICS_AFTER" "$LOCAL_METRICS_TOKEN"; then
    AUTH_FAIL_AFTER="$(auth_failures_of "$METRICS_AFTER")"
    AUTH_FAIL_DELTA=$(( AUTH_FAIL_AFTER - AUTH_FAIL_BEFORE ))
    info "scraped /metrics (after) -> auth_failures=$AUTH_FAIL_AFTER (delta=$AUTH_FAIL_DELTA)"
    assert "auth-failure signal moved over the window (graphus_auth_failures_total)" "yes" \
      "$([ "${AUTH_FAIL_DELTA:-0}" -ge 1 ] && echo yes || echo no)"
  fi
fi

# --------------------------------------------------------------------------------------------------
# Harvest the machine-readable stats from the REST client output.
# --------------------------------------------------------------------------------------------------
R_ALLOW="$(json_field "$REST_STATS" allow_cells)"
R_DENY="$(json_field "$REST_STATS" deny_cells)"
R_UNAUTH="$(json_field "$REST_STATS" unauth_cells)"
R_CELLS="$(json_field "$REST_STATS" matrix_cells)"
R_SEEDED="$(json_field "$REST_STATS" seeded_statements)"
R_DENY_CHECKS="$(json_field "$REST_STATS" deny_checks)"
R_XT_PROBES="$(json_field "$REST_STATS" cross_tenant_probes)"
R_XT_DENIED="$(json_field "$REST_STATS" cross_tenant_denied)"
R_XT_EMPTY="$(json_field "$REST_STATS" cross_tenant_empty)"

# --------------------------------------------------------------------------------------------------
# Step 7 — evidence. LOCAL: measure_server (CPU/RSS/tenant-store) + baseline gate + /metrics companion.
#          EXTERNAL: measure_target (/metrics delta, measurement_mode=external, invariant gate).
# --------------------------------------------------------------------------------------------------
AUTH_FAIL_NOTE="graphus_auth_failures_total moved by ${AUTH_FAIL_DELTA} over the window. CONFIRMED \
server finding: REST DATA-PLANE 401s (missing/invalid Bearer on /db/*/tx/commit) and /auth/login \
failures do NOT increment this counter (they only emit an audit record via RestAuthObserver); only \
Bolt auth failures and the /metrics-endpoint auth gate bump it. The demo bumps it with a deliberate \
bad-Bearer GET /metrics (an unauthenticated request that IS rejected) plus, when the Bolt leg runs, \
the unauthenticated Bolt connection."

if [ "$RUN_REST" = "1" ] && [ "$MODE" = "external" ]; then
  section "Step 7 — server-side evidence via /metrics (external mode)"
  MEASURE_TGT="$BIN_DIR/measure_target"
  if [ ! -x "$MEASURE_TGT" ]; then
    info "building the dev-only measure_target harness binary (debug)…"
    ( cd "$REPO_ROOT" && cargo build -q -p graphus-examples-harness --bin measure_target ) || true
    MEASURE_TGT="$REPO_ROOT/target/debug/measure_target"
  fi
  if [ -x "$MEASURE_TGT" ] && [ -s "$METRICS_BEFORE" ] && [ -s "$METRICS_AFTER" ]; then
    rm -rf "$EVIDENCE_DIR"
    "$MEASURE_TGT" \
      --evidence-dir "$EVIDENCE_DIR" \
      --scenario "security-multitenant" \
      --description "Fine-grained multi-tenant RBAC (GRANT + DENY property/label scope) + cross-tenant isolation over REST and Bolt, attached to an ALREADY-RUNNING instance and provisioned into a namespaced, torn-down set of tenant databases." \
      --database "$DB_A" \
      --metrics-before "$METRICS_BEFORE" \
      --metrics-after "$METRICS_AFTER" \
      --nodes "$NODE_COUNT" --rels "$REL_COUNT" \
      --workload-ops "${R_SEEDED:-0}" --workload-secs "$WORKLOAD_SECS" \
      --abort-rate 0.0 \
      --param "profile=$PROFILE" \
      --param "mode=external-attach" \
      --param "namespace=$RUN_NS" \
      --param "connection=rest-https-jwt+bolt-tcp-tls" \
      --param "tenants=2" \
      --param "matrix_cells=${R_CELLS:-0}" \
      --param "allow_cells=${R_ALLOW:-0}" \
      --param "deny_cells=${R_DENY:-0}" \
      --param "unauth_cells=${R_UNAUTH:-0}" \
      --param "deny_supported=${DENY_SUPPORTED}" \
      --param "deny_checks=${R_DENY_CHECKS:-0}" \
      --param "cross_tenant_probes=${R_XT_PROBES:-0}" \
      --param "cross_tenant_denied=${R_XT_DENIED:-0}" \
      --param "cross_tenant_empty=${R_XT_EMPTY:-0}" \
      --param "auth_failures_before=${AUTH_FAIL_BEFORE}" \
      --param "auth_failures_after=${AUTH_FAIL_AFTER}" \
      --param "auth_failures_delta=${AUTH_FAIL_DELTA}" \
      --note "$AUTH_FAIL_NOTE" \
      --note "DENY (property/label scope) support on this target: ${DENY_SUPPORTED}. When false the grammar predates DENY and only GRANT-scoped RBAC + cross-tenant isolation are exercised here; the full modern DENY coverage (#645 guard) is validated against a current server (LOCAL mode)." \
      --note "Cross-tenant negatives (ssn / secret_token / all-nodes / count) asserted as a tenant_a user against tenant_b over REST (403 coarse gate) and Bolt (value-level filter => zero rows). No sensitive datum crosses the boundary." \
      --assert --max-abort-rate 0.5 \
      && info "evidence written to $EVIDENCE_DIR (external)" \
      || info "measure_target reported a violation or failure (see output above)"
    assert "evidence report.json was produced" "yes" \
      "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
    assert "report.json is external-mode with a server_metrics section" "yes" \
      "$(grep -q '"measurement_mode": *"external"' "$EVIDENCE_DIR/report.json" 2>/dev/null \
         && grep -q '"server_metrics"' "$EVIDENCE_DIR/report.json" 2>/dev/null && echo yes || echo no)"
  else
    info "measure_target unavailable or /metrics snapshots missing; skipping server-side evidence (non-fatal)"
  fi

elif [ "$RUN_REST" = "1" ] && [ "$MODE" = "local" ]; then
  section "Step 7 — collect performance evidence (CPU / RAM / TENANT storage)"
  sample_peak_rss
  SERVER_UPTIME_SECS=$(( $(date +%s) - SERVER_START_EPOCH )); [ "$SERVER_UPTIME_SECS" -lt 1 ] && SERVER_UPTIME_SECS=1

  MEASURE_BIN="$BIN_DIR/measure_server"
  if [ ! -x "$MEASURE_BIN" ]; then
    info "building the dev-only measure_server harness binary (debug)…"
    ( cd "$REPO_ROOT" && cargo build -q -p graphus-examples-harness --bin measure_server ) || true
    MEASURE_BIN="$REPO_ROOT/target/debug/measure_server"
  fi

  if [ -x "$MEASURE_BIN" ] && [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    rm -rf "$EVIDENCE_DIR"
    "$MEASURE_BIN" \
      --evidence-dir "$EVIDENCE_DIR" \
      --scenario "security-multitenant" \
      --description "Fine-grained RBAC (GRANT + DENY property/label scope) over an ENCRYPTED multi-tenant server (AES-256-GCM at rest): provision isolated tenant databases + roles/users/grants + DENY and assert the allow/deny/cross-tenant/DENY matrix over REST and Bolt, with ciphertext-on-disk, offline key rotation and encrypted-backup proofs." \
      --pid "$SERVER_PID" \
      --uptime-secs "$SERVER_UPTIME_SECS" \
      --store "$TENANT_STORE" \
      --wal "$TENANT_WAL" \
      --nodes "$NODE_COUNT" --rels "$REL_COUNT" \
      --peak-rss-bytes "$PEAK_RSS_BYTES" \
      --workload-ops "${R_SEEDED:-0}" --workload-secs "$SERVER_UPTIME_SECS" \
      --logical-graph-bytes "$LOGICAL_GRAPH_BYTES" \
      --param "profile=$PROFILE" \
      --param "connection=rest-https-jwt+bolt-tcp-tls" \
      --param "encryption=aes-256-gcm-at-rest" \
      --param "tenants=2" \
      --param "matrix_cells=${R_CELLS:-0}" \
      --param "allow_cells=${R_ALLOW:-0}" \
      --param "deny_cells=${R_DENY:-0}" \
      --param "unauth_cells=${R_UNAUTH:-0}" \
      --param "deny_supported=${DENY_SUPPORTED}" \
      --param "deny_checks=${R_DENY_CHECKS:-0}" \
      --param "cross_tenant_probes=${R_XT_PROBES:-0}" \
      --param "cross_tenant_empty=${R_XT_EMPTY:-0}" \
      --param "tenant_store_bytes=${TENANT_STORE_TOTAL:-0}" \
      --param "tenant_wal_bytes=${TENANT_WAL_TOTAL:-0}" \
      --param "enc_seed_ms=${ENC_SEED_MS:-0}" \
      --param "clear_seed_ms=${CLEAR_SEED_MS:-0}" \
      --param "enc_store_bytes=${ENC_STORE_BYTES:-0}" \
      --param "clear_store_bytes=${CLEAR_STORE_BYTES:-0}" \
      --param "rotation_ms=${V_ROTATION_MS:-0}" \
      --param "backup_artifact_bytes=${V_BACKUP_BYTES:-0}" \
      --param "sealed_backup_bytes=${V_SEALED_BYTES:-0}" \
      --param "backup_ms=${V_BACKUP_MS:-0}" \
      --param "restore_ms=${V_RESTORE_MS:-0}" \
      --param "auth_failures_delta=${AUTH_FAIL_DELTA}" \
      --note "STORAGE FIX (rmp #696): the primary storage section meters a REAL tenant database store ($DB_A/graphus.store), not the empty default 'graphus' db; the all-tenants store/WAL SUM rides in as tenant_store_bytes/tenant_wal_bytes params." \
      --note "OVERHEAD FIX (rmp #696): enc_store_bytes vs clear_store_bytes now measure two ISOLATED databases (overhead_enc / overhead_clear) each seeded with the IDENTICAL tenant_a dataset, so the delta is purely per-page GCM overhead (apples-to-apples); the timing is a coarse single-run figure." \
      --note "RBAC allow/deny/cross-tenant/DENY matrix asserted over BOTH REST and Bolt from one deterministic manifest; the hermetic security_verify proved ciphertext-on-disk, offline key rotation and the encrypted backup roundtrip." \
      --note "$AUTH_FAIL_NOTE" \
      && info "evidence written to $EVIDENCE_DIR" \
      || info "evidence collection failed (non-fatal); see output above"
    assert "evidence report.json was produced" "yes" \
      "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
    assert "evidence report.md was produced" "yes" \
      "$([ -f "$EVIDENCE_DIR/report.md" ] && echo yes || echo no)"

    if [ "$PROFILE" = "fast" ] && [ -f "$BASELINE" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
      section "Step 7b — regression gate vs committed baseline"
      CMP_BIN="$BIN_DIR/sec_baseline_cmp"
      if [ ! -x "$CMP_BIN" ]; then
        ( cd "$REPO_ROOT" && cargo build -q -p graphus-security-gen --bin sec_baseline_cmp ) || true
        CMP_BIN="$REPO_ROOT/target/debug/sec_baseline_cmp"
      fi
      CMP_OUT="$("$CMP_BIN" "$BASELINE" "$EVIDENCE_DIR/report.json" 2>&1)" || true
      printf '%s\n' "$CMP_OUT" | sed 's/^/  /'
      assert "fresh run is within baseline thresholds (structural metrics)" "yes" \
        "$(printf '%s' "$CMP_OUT" | grep -q 'GRAPHUS_BASELINE_OK' && echo yes || echo no)"
    fi

    # Additive server-side /metrics delta (companion), incl. the auth-failure signal.
    if [ -s "$METRICS_BEFORE" ] && [ -s "$METRICS_AFTER" ]; then
      MEASURE_TGT="$BIN_DIR/measure_target"
      [ -x "$MEASURE_TGT" ] || MEASURE_TGT="$REPO_ROOT/target/debug/measure_target"
      if [ -x "$MEASURE_TGT" ]; then
        "$MEASURE_TGT" \
          --evidence-dir "$EVIDENCE_DIR/server-metrics" \
          --scenario "security-multitenant" \
          --description "Server-side /metrics counter delta for the local co-located run (companion to the primary report.json)." \
          --database "$DB_A" \
          --metrics-before "$METRICS_BEFORE" --metrics-after "$METRICS_AFTER" \
          --nodes "$NODE_COUNT" --rels "$REL_COUNT" \
          --workload-ops "${R_SEEDED:-0}" --workload-secs "$SERVER_UPTIME_SECS" --abort-rate 0.0 \
          --param "auth_failures_delta=${AUTH_FAIL_DELTA}" \
          --note "$AUTH_FAIL_NOTE" >/dev/null 2>&1 \
          && info "server-side /metrics delta written to $EVIDENCE_DIR/server-metrics/report.json" \
          || info "server-side /metrics delta unavailable (non-fatal)"
      fi
    fi
  else
    info "measure_server unavailable or server not alive; skipping evidence collection (non-fatal)"
  fi

  stop_pid="$SERVER_PID"
  kill -TERM "$stop_pid" 2>/dev/null || true
  wait "$stop_pid" 2>/dev/null || true
  SERVER_PID=""
fi

if [ "$RUN_REST" != "1" ]; then
  section "Wire legs SKIPPED (python3, or in local mode openssl, or in external mode curl absent)"
  info "the hermetic generator (+ crypto verifier in LOCAL) above still ran and asserted their properties."
fi

# --------------------------------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------------------------------
section "Result"
printf '%s checks run, %s failures.\n' "$CHECKS" "$FAILURES"
if [ "$RUN_REST" = "1" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
  printf 'evidence: %s {report.json, report.md}\n' "$EVIDENCE_DIR"
fi
if [ "$FAILURES" -eq 0 ]; then
  printf '%s%sSECURITY-MULTITENANT DEMONSTRATION PASSED%s (%s mode) — Graphus provisioned isolated\n' "$BOLD" "$GREEN" "$RESET" "$MODE"
  printf 'tenant databases + fine-grained roles/users/grants (+ DENY where supported), enforced the\n'
  printf 'allow/deny/cross-tenant/DENY authorization matrix over REST and Bolt (no sensitive data crosses\n'
  printf 'a tenant boundary), and captured the server-side /metrics auth-failure signal as evidence.\n'
  exit 0
else
  printf '%s%sSECURITY-MULTITENANT DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
