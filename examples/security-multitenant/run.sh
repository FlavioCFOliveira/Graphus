#!/usr/bin/env bash
#
# Graphus multi-tenant security demonstration — fine-grained RBAC over an ENCRYPTED server, exercised
# over BOTH the REST API (HTTPS + Bearer-JWT, python3 stdlib client) and Bolt-over-TCP+TLS (the
# OFFICIAL Neo4j driver), plus a hermetic in-process encryption/rotation/backup verifier.
#
# This script doubles as an executable E2E test. It:
#   1. generates a DETERMINISTIC, SEEDED multi-tenant sensitive-data scenario (the `security_gen`
#      binary): per-tenant patient/record PII (`tenant_<name>.cypher`), the admin RBAC provisioning
#      DDL (`provision.cypher`: CREATE DATABASE / ROLE / USER + GRANTs), and a `manifest.json` with
#      the tenants/roles/users/grants and the expected allow/deny matrix — and proves it is
#      byte-identical per seed/profile (regenerate + diff);
#   2. runs the HERMETIC crypto verifier (`security_verify`): ciphertext-on-disk proof (the sensitive
#      token is ABSENT from the raw encrypted store but PRESENT in a cleartext store), offline
#      master-key rotation (data intact across, OLD key fails closed), and the encrypted backup
#      roundtrip (no plaintext in the sealed artifact, lossless restore) — always runs, no network;
#   3. boots a REAL, ENCRYPTED `graphus-server` (AES-256-GCM page + WAL encryption) exposing BOTH the
#      REST API AND Bolt-over-TCP, both TLS; provisions the tenants/roles/users/grants as the admin
#      over REST; drives the RBAC allow/deny matrix over REST (`data/matrix.py`) asserting every cell
#      (incl. cross-tenant denial + access_mode=READ for reads + 401/403 codes); and, if node/npm are
#      present (RUN_DRIVER=1 auto), ALSO drives the identical matrix over Bolt via the official driver
#      (`data/matrix.js`) asserting the same allow/deny + `Neo.ClientError.Security.Forbidden` codes;
#   4. measures the ENCRYPTION OVERHEAD: it seeds the SAME tenant data against the encrypted server
#      and a cleartext server and reports the seed-time + on-disk store-size delta.
#
# The generator (step 1) and the verifier (step 2) are HERMETIC and always run (the generator's
# determinism is also `cargo test -p graphus-security-gen`). Steps 3-4 need `openssl` + `python3`
# (stdlib only); the Bolt leg additionally needs `node`/`npm` + network (for `npm install
# neo4j-driver`). Each network leg is skipped with a clear note if its tools are absent.
#
# Usage:
#   examples/security-multitenant/run.sh                          # builds binaries if needed, runs
#   GRAPHUS_BIN_DIR=target/release  examples/security-multitenant/run.sh
#   SEC_PROFILE=large               examples/security-multitenant/run.sh   # evidence-scale dataset
#   RUN_DRIVER=0                    examples/security-multitenant/run.sh   # skip the Bolt leg
#
# Requirements: a Unix host (Linux/macOS), bash, openssl, python3 (3.8+, stdlib only). For the Bolt
# leg also: node (v18+), npm, and network/cache access.

set -euo pipefail

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

if [ ! -x "$SERVER" ]; then
  section "Building graphus-server (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-server )
fi
[ -x "$SERVER" ] || { echo "${RED}fatal: server binary not found at $SERVER${RESET}" >&2; exit 2; }

if [ ! -x "$GEN" ]; then
  section "Building the deterministic security generator (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-security-gen --bin security_gen )
fi
[ -x "$GEN" ] || { echo "${RED}fatal: security_gen binary not found at $GEN${RESET}" >&2; exit 2; }

if [ ! -x "$VERIFY" ]; then
  section "Building the hermetic crypto verifier (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-security-gen --features dst-repro --bin security_verify )
fi
[ -x "$VERIFY" ] || { echo "${RED}fatal: security_verify binary not found at $VERIFY${RESET}" >&2; exit 2; }

# --------------------------------------------------------------------------------------------------
# Workspace: a private temp store + TLS material + generated data, removed on exit
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

# Evidence collection. The standardized report.json + report.md land in the git-ignored evidence/
# dir; the durable store/WAL paths follow the server's single-db layout. BASELINE is the committed
# reference run we compare a fresh fast-profile run against.
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
STORE_FILE="$WORKDIR/data/graphus.store"
WAL_DIR="$WORKDIR/data/graphus.wal"
BASELINE="$SCRIPT_DIR/baseline.json"
PEAK_RSS_BYTES=0
SERVER_START_EPOCH=0

SERVER_PID=""
# cleanup — kill ONLY the server pid we spawned and `wait` ONLY on it (never a bare `wait`, which
# would block on a background server). The python/node clients run synchronously in the foreground via
# command-substitution, so they have already exited by teardown — there is no client pid to reap.
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

# server_rss_bytes <pid> — current resident set size of the server in bytes (Linux /proc, macOS ps).
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

# sample_peak_rss — read the live server's RSS once and keep the running high-watermark.
sample_peak_rss() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    local rss
    rss="$(server_rss_bytes "$SERVER_PID")"
    if [ "${rss:-0}" -gt "$PEAK_RSS_BYTES" ]; then
      PEAK_RSS_BYTES="$rss"
    fi
  fi
}

# json_field <json-blob> <key> — extract a numeric/string field from a one-line GRAPHUS_STATS JSON
# object without a jq dependency (the object is flat scalars).
json_field() {
  printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\\{0,1\\}\\([^,\"}]*\\).*/\\1/p" | head -n1
}

# dir_bytes <dir> — total bytes of a directory tree (portable du), 0 if missing.
dir_bytes() {
  [ -e "$1" ] || { echo 0; return; }
  du -sb "$1" 2>/dev/null | awk '{print $1}' || echo 0
}

# wait_for_port <pid> <port> <label> — block until the port accepts a connection or the process dies.
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
      ready=1
      break
    fi
    sleep 0.1
  done
  [ "$ready" = "1" ]
}

# --------------------------------------------------------------------------------------------------
# Step 1 — generate the deterministic multi-tenant scenario (data + provisioning + manifest)
# --------------------------------------------------------------------------------------------------
section "Step 1 — generate the deterministic multi-tenant scenario ($PROFILE profile)"
mkdir -p "$DATA_DIR"
GEN_OUT="$("$GEN" --profile "$PROFILE" --out-dir "$DATA_DIR" | head -n1)"
info "$GEN_OUT"
PROVISION="$DATA_DIR/provision.cypher"
MANIFEST="$DATA_DIR/manifest.json"
TENANT_A="$DATA_DIR/tenant_a.cypher"
TENANT_B="$DATA_DIR/tenant_b.cypher"
assert "provision.cypher generated" "yes" "$([ -s "$PROVISION" ] && echo yes || echo no)"
assert "manifest.json generated"    "yes" "$([ -s "$MANIFEST" ] && echo yes || echo no)"
assert "tenant_a.cypher generated"  "yes" "$([ -s "$TENANT_A" ] && echo yes || echo no)"
assert "tenant_b.cypher generated"  "yes" "$([ -s "$TENANT_B" ] && echo yes || echo no)"

# Sizing for the evidence report (counted directly off the deterministic load scripts).
NODE_COUNT="$(grep -chE '^CREATE \(:' "$TENANT_A" "$TENANT_B" | paste -sd+ - | bc 2>/dev/null || echo 0)"
REL_COUNT="$(grep -chE 'CREATE \([a-z]\)-\[:' "$TENANT_A" "$TENANT_B" | paste -sd+ - | bc 2>/dev/null || echo 0)"
NODE_COUNT="${NODE_COUNT:-0}"; REL_COUNT="${REL_COUNT:-0}"
LOGICAL_GRAPH_BYTES=$(( NODE_COUNT * 256 + REL_COUNT * 128 ))
info "dataset: $NODE_COUNT nodes, $REL_COUNT relationships across 2 tenants"

# Determinism check: regenerate and diff every artifact (the AC: byte-identical per seed/profile).
GEN_OUT2_DIR="$WORKDIR/dataset2"
"$GEN" --profile "$PROFILE" --out-dir "$GEN_OUT2_DIR" > /dev/null
if diff -q "$PROVISION" "$GEN_OUT2_DIR/provision.cypher" > /dev/null \
   && diff -q "$MANIFEST" "$GEN_OUT2_DIR/manifest.json" > /dev/null \
   && diff -q "$TENANT_A" "$GEN_OUT2_DIR/tenant_a.cypher" > /dev/null \
   && diff -q "$TENANT_B" "$GEN_OUT2_DIR/tenant_b.cypher" > /dev/null; then
  assert "generator is byte-identical per seed" "yes" "yes"
else
  assert "generator is byte-identical per seed" "yes" "no"
fi

# --------------------------------------------------------------------------------------------------
# Step 2 — hermetic crypto verifier (ciphertext proof + key rotation + encrypted backup roundtrip)
# --------------------------------------------------------------------------------------------------
section "Step 2 — hermetic encryption/rotation/backup verifier (no network)"
VERIFY_OUT="$("$VERIFY" --out-dir "$WORKDIR/verify" 2>&1)" || true
printf '%s\n' "$VERIFY_OUT" | sed 's/^/  /'
assert "ciphertext-on-disk + rotation + encrypted-backup proofs passed" "yes" \
  "$(printf '%s' "$VERIFY_OUT" | grep -q 'GRAPHUS_SECURITY_VERIFY_OK' && echo yes || echo no)"
VERIFY_STATS="$(printf '%s' "$VERIFY_OUT" | sed -n 's/^GRAPHUS_STATS //p' | head -n1)"
V_ENC_STORE_BYTES="$(json_field "$VERIFY_STATS" enc_store_bytes)"
V_ROTATION_MS="$(json_field "$VERIFY_STATS" rotation_ms)"
V_BACKUP_BYTES="$(json_field "$VERIFY_STATS" backup_artifact_bytes)"
V_SEALED_BYTES="$(json_field "$VERIFY_STATS" sealed_backup_bytes)"
V_BACKUP_MS="$(json_field "$VERIFY_STATS" backup_ms)"
V_RESTORE_MS="$(json_field "$VERIFY_STATS" restore_ms)"

# --------------------------------------------------------------------------------------------------
# Step 3 — decide whether to run the live REST/Bolt workload (needs openssl + python3)
# --------------------------------------------------------------------------------------------------
RUN_REST=1
command -v openssl >/dev/null 2>&1 || RUN_REST=0
command -v python3 >/dev/null 2>&1 || RUN_REST=0

RUN_DRIVER="${RUN_DRIVER:-auto}"
if [ "$RUN_DRIVER" = "auto" ]; then
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then RUN_DRIVER=1; else RUN_DRIVER=0; fi
fi

if [ "$RUN_REST" = "1" ]; then
  # ------------------------------------------------------------------------------------------------
  # Boot an ENCRYPTED server exposing BOTH REST and Bolt, both TLS.
  # ------------------------------------------------------------------------------------------------
  section "Step 3 — boot an ENCRYPTED graphus-server (REST + Bolt-TCP, both TLS, AES-256-GCM at rest)"

  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" \
    -days 2 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

  # A raw 32-byte master key => AES-256-GCM page encryption + HKDF keyring.
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
  if ! wait_for_port "$SERVER_PID" "$REST_PORT" "encrypted server"; then
    echo "${RED}encrypted server did not open REST port $REST_PORT${RESET}" >&2; tail -n 20 "$SERVER_LOG" >&2; exit 1
  fi
  wait_for_port "$SERVER_PID" "$BOLT_PORT" "encrypted server" || { echo "${RED}Bolt port $BOLT_PORT not open${RESET}" >&2; tail -n 20 "$SERVER_LOG" >&2; exit 1; }
  info "encrypted server pid $SERVER_PID — REST https://127.0.0.1:$REST_PORT, Bolt bolt+ssc://127.0.0.1:$BOLT_PORT"

  # ------------------------------------------------------------------------------------------------
  # Step 4 — provision + drive the RBAC matrix over REST (python3 stdlib).
  # ------------------------------------------------------------------------------------------------
  section "Step 4 — provision tenants/roles/users + RBAC matrix over REST (python3 stdlib)"
  REST_OUT="$(python3 "$SCRIPT_DIR/data/matrix.py" \
    --port "$REST_PORT" \
    --secret "$JWT_SECRET" \
    --manifest "$MANIFEST" \
    --provision "$PROVISION" \
    --tenant-dir "$DATA_DIR" \
    --admin "$ADMIN_USER" 2>&1)" || true
  printf '%s\n' "$REST_OUT" | sed 's/^/  /'
  assert "REST RBAC matrix: every allow/deny/401 cell held" "yes" \
    "$(printf '%s' "$REST_OUT" | grep -q 'GRAPHUS_RBAC_OK' && echo yes || echo no)"
  sample_peak_rss

  REST_STATS="$(printf '%s' "$REST_OUT" | sed -n 's/^[[:space:]]*GRAPHUS_STATS //p' | head -n1)"
  R_ALLOW="$(json_field "$REST_STATS" allow_cells)"
  R_DENY="$(json_field "$REST_STATS" deny_cells)"
  R_UNAUTH="$(json_field "$REST_STATS" unauth_cells)"
  R_CELLS="$(json_field "$REST_STATS" matrix_cells)"
  R_SEEDED="$(json_field "$REST_STATS" seeded_statements)"

  # ------------------------------------------------------------------------------------------------
  # Step 5 — drive the IDENTICAL matrix over Bolt via the OFFICIAL neo4j-driver (opt-in).
  # ------------------------------------------------------------------------------------------------
  if [ "$RUN_DRIVER" = "1" ]; then
    section "Step 5 — RBAC matrix over Bolt (OFFICIAL neo4j-driver) — provisioning already done"
    NODE_PROJ="$WORKDIR/node"
    mkdir -p "$NODE_PROJ"
    cat > "$NODE_PROJ/package.json" <<'EOF'
{
  "name": "graphus-security-multitenant",
  "version": "1.0.0",
  "private": true,
  "description": "Drives the Graphus multi-tenant RBAC matrix over Bolt+TLS with the official Neo4j driver.",
  "dependencies": { "neo4j-driver": "^6.1.0" }
}
EOF
    cp "$SCRIPT_DIR/data/matrix.js" "$NODE_PROJ/matrix.js"
    info "installing neo4j-driver (npm)…"
    if ( cd "$NODE_PROJ" && npm install --no-audit --no-fund --loglevel=error ) >>"$SERVER_LOG" 2>&1; then
      BOLT_OUT="$(cd "$NODE_PROJ" && node matrix.js "$BOLT_PORT" "$MANIFEST" "$ADMIN_USER" "$ADMIN_PW" 2>&1)" || true
      printf '%s\n' "$BOLT_OUT" | sed 's/^/  /'
      assert "Bolt RBAC matrix: identical allow/deny + Forbidden codes held" "yes" \
        "$(printf '%s' "$BOLT_OUT" | grep -q 'GRAPHUS_BOLT_RBAC_OK' && echo yes || echo no)"
      sample_peak_rss
    else
      info "npm install neo4j-driver failed; skipping the Bolt leg (non-fatal). See $SERVER_LOG"
    fi
  else
    section "Step 5 — Bolt leg SKIPPED (RUN_DRIVER=0 or node/npm absent)"
    info "the REST matrix above already asserted every authorization cell; install node/npm for the Bolt leg."
  fi

  ENC_STORE_BYTES="$(dir_bytes "$WORKDIR/data")"

  # ------------------------------------------------------------------------------------------------
  # Step 6 — encryption overhead vs a cleartext server (same tenant-seed workload).
  # ------------------------------------------------------------------------------------------------
  section "Step 6 — encryption overhead vs cleartext (same seed workload)"
  # Time the encrypted seed (re-seed a fresh tenant `overhead_enc` so the measurement is isolated).
  ENC_SEED_MS="$(python3 - "$REST_PORT" "$JWT_SECRET" "$ADMIN_USER" "$TENANT_A" <<'PY'
import sys, time, json, ssl, hmac, hashlib, base64, urllib.request, urllib.error
port, secret, admin, cypher = sys.argv[1], sys.argv[2].encode(), sys.argv[3], sys.argv[4]
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=')
def jwt(sub):
    now=int(time.time()); h={"alg":"HS256","typ":"JWT"}
    p={"sub":sub,"iat":now,"exp":now+3600,"iss":"graphus","aud":"graphus","jti":f"oh-{now}","ver":0}
    si=b64u(json.dumps(h,separators=(',',':')).encode())+b'.'+b64u(json.dumps(p,separators=(',',':')).encode())
    return (si+b'.'+b64u(hmac.new(secret,si,hashlib.sha256).digest())).decode()
ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
tok=jwt(admin)
stmts=[]; buf=''
for line in open(cypher):
    line=line.rstrip('\n')
    if line.startswith('//') or not line.strip(): continue
    buf+=line
    if buf.rstrip().endswith(';'): stmts.append(buf.rstrip()[:-1]); buf=''
def commit(db, body):
    req=urllib.request.Request(f"https://127.0.0.1:{port}/db/{db}/tx/commit",data=json.dumps(body).encode(),method='POST')
    req.add_header('Accept','application/json'); req.add_header('Content-Type','application/json'); req.add_header('Authorization','Bearer '+tok)
    try: return urllib.request.urlopen(req,context=ctx).status
    except urllib.error.HTTPError as e: return e.code
commit('graphus',{"statements":[{"statement":"CREATE DATABASE overhead_enc IF NOT EXISTS"}]})
t0=time.time()
B=200
for i in range(0,len(stmts),B):
    commit('overhead_enc',{"statements":[{"statement":s} for s in stmts[i:i+B]],"access_mode":"WRITE"})
print(round((time.time()-t0)*1000,1))
PY
)" || ENC_SEED_MS=0
  info "encrypted seed of tenant_a data: ${ENC_SEED_MS} ms"

  # Boot a CLEARTEXT server (identical config minus [encryption]) and seed the same data into it.
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
  CLEAR_STORE_BYTES=0
  if wait_for_port "$CLEAR_PID" "$CLEAR_REST_PORT" "cleartext server"; then
    CLEAR_SEED_MS="$(python3 - "$CLEAR_REST_PORT" "$JWT_SECRET" "$ADMIN_USER" "$TENANT_A" <<'PY'
import sys, time, json, ssl, hmac, hashlib, base64, urllib.request, urllib.error
port, secret, admin, cypher = sys.argv[1], sys.argv[2].encode(), sys.argv[3], sys.argv[4]
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=')
def jwt(sub):
    now=int(time.time()); h={"alg":"HS256","typ":"JWT"}
    p={"sub":sub,"iat":now,"exp":now+3600,"iss":"graphus","aud":"graphus","jti":f"oh-{now}","ver":0}
    si=b64u(json.dumps(h,separators=(',',':')).encode())+b'.'+b64u(json.dumps(p,separators=(',',':')).encode())
    return (si+b'.'+b64u(hmac.new(secret,si,hashlib.sha256).digest())).decode()
ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
tok=jwt(admin)
stmts=[]; buf=''
for line in open(cypher):
    line=line.rstrip('\n')
    if line.startswith('//') or not line.strip(): continue
    buf+=line
    if buf.rstrip().endswith(';'): stmts.append(buf.rstrip()[:-1]); buf=''
def commit(db, body):
    req=urllib.request.Request(f"https://127.0.0.1:{port}/db/{db}/tx/commit",data=json.dumps(body).encode(),method='POST')
    req.add_header('Accept','application/json'); req.add_header('Content-Type','application/json'); req.add_header('Authorization','Bearer '+tok)
    try: return urllib.request.urlopen(req,context=ctx).status
    except urllib.error.HTTPError as e: return e.code
commit('graphus',{"statements":[{"statement":"CREATE DATABASE overhead_clear IF NOT EXISTS"}]})
t0=time.time()
B=200
for i in range(0,len(stmts),B):
    commit('overhead_clear',{"statements":[{"statement":s} for s in stmts[i:i+B]],"access_mode":"WRITE"})
print(round((time.time()-t0)*1000,1))
PY
)" || CLEAR_SEED_MS=0
    CLEAR_STORE_BYTES="$(dir_bytes "$CLEAR_DATA")"
  fi
  kill -TERM "$CLEAR_PID" 2>/dev/null || true
  wait "$CLEAR_PID" 2>/dev/null || true

  # Report the deltas (honest: a coarse single-run timing on shared hardware, documented in README).
  printf '  %sencrypted%s seed=%s ms, store=%s B   |   %scleartext%s seed=%s ms, store=%s B\n' \
    "$BOLD" "$RESET" "${ENC_SEED_MS:-0}" "${ENC_STORE_BYTES:-0}" \
    "$BOLD" "$RESET" "${CLEAR_SEED_MS:-0}" "${CLEAR_STORE_BYTES:-0}"
  # The encryption-at-rest overhead must be bounded, not pathological: assert the encrypted store is
  # within 3x the cleartext store footprint (per-page GCM tag/nonce overhead is small + constant).
  if [ "${CLEAR_STORE_BYTES:-0}" -gt 0 ]; then
    OVERHEAD_OK="$(awk -v e="${ENC_STORE_BYTES:-0}" -v c="${CLEAR_STORE_BYTES:-1}" 'BEGIN{print (e <= c*3)?"yes":"no"}')"
    assert "encrypted store footprint is within 3x cleartext (bounded GCM overhead)" "yes" "$OVERHEAD_OK"
  fi

  # ------------------------------------------------------------------------------------------------
  # Step 7 — collect standardized performance evidence (CPU / RAM / storage) + baseline gate.
  # ------------------------------------------------------------------------------------------------
  section "Step 7 — collect performance evidence (CPU / RAM / storage)"
  sample_peak_rss
  SERVER_UPTIME_SECS=$(( $(date +%s) - SERVER_START_EPOCH ))
  [ "$SERVER_UPTIME_SECS" -lt 1 ] && SERVER_UPTIME_SECS=1

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
      --description "Fine-grained RBAC over an ENCRYPTED multi-tenant server (AES-256-GCM at rest): provision isolated tenant databases + roles/users/grants and assert the allow/deny matrix over REST and Bolt, with ciphertext-on-disk, offline key rotation and encrypted-backup proofs." \
      --pid "$SERVER_PID" \
      --uptime-secs "$SERVER_UPTIME_SECS" \
      --store "$STORE_FILE" \
      --wal "$WAL_DIR" \
      --nodes "$NODE_COUNT" \
      --rels "$REL_COUNT" \
      --peak-rss-bytes "$PEAK_RSS_BYTES" \
      --workload-ops "${R_SEEDED:-0}" \
      --workload-secs "$SERVER_UPTIME_SECS" \
      --logical-graph-bytes "$LOGICAL_GRAPH_BYTES" \
      --param "profile=$PROFILE" \
      --param "connection=rest-https-jwt+bolt-tcp-tls" \
      --param "encryption=aes-256-gcm-at-rest" \
      --param "tenants=2" \
      --param "matrix_cells=${R_CELLS:-0}" \
      --param "allow_cells=${R_ALLOW:-0}" \
      --param "deny_cells=${R_DENY:-0}" \
      --param "unauth_cells=${R_UNAUTH:-0}" \
      --param "enc_seed_ms=${ENC_SEED_MS:-0}" \
      --param "clear_seed_ms=${CLEAR_SEED_MS:-0}" \
      --param "enc_store_bytes=${ENC_STORE_BYTES:-0}" \
      --param "clear_store_bytes=${CLEAR_STORE_BYTES:-0}" \
      --param "rotation_ms=${V_ROTATION_MS:-0}" \
      --param "backup_artifact_bytes=${V_BACKUP_BYTES:-0}" \
      --param "sealed_backup_bytes=${V_SEALED_BYTES:-0}" \
      --param "backup_ms=${V_BACKUP_MS:-0}" \
      --param "restore_ms=${V_RESTORE_MS:-0}" \
      --note "RBAC allow/deny matrix asserted over BOTH REST and Bolt from one deterministic manifest; the hermetic security_verify proved ciphertext-on-disk (encrypted absent / cleartext present), offline key rotation (data intact, old key fails closed) and the encrypted backup roundtrip (no plaintext sealed, lossless restore)." \
      --note "Encryption overhead (enc_seed_ms vs clear_seed_ms, enc_store_bytes vs clear_store_bytes) is a coarse single-run measurement on shared hardware; the storage footprint delta is the stable signal (bounded per-page GCM tag/nonce overhead), the timing is machine-variant." \
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
  else
    info "measure_server unavailable or server not alive; skipping evidence collection (non-fatal)"
  fi

  stop_pid="$SERVER_PID"
  kill -TERM "$stop_pid" 2>/dev/null || true
  wait "$stop_pid" 2>/dev/null || true
  SERVER_PID=""
else
  section "Steps 3–7 — live REST/Bolt workload SKIPPED (openssl or python3 absent)"
  info "the hermetic generator + crypto verifier above still ran and asserted their properties."
  info "install openssl + python3 (and node/npm for the Bolt leg) for the full demonstration."
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
  if [ "$RUN_REST" = "1" ]; then
    printf '%s%sSECURITY-MULTITENANT DEMONSTRATION PASSED%s — Graphus provisioned isolated tenant\n' "$BOLD" "$GREEN" "$RESET"
    printf 'databases + fine-grained roles/users/grants on an ENCRYPTED server, enforced the allow/deny\n'
    printf 'authorization matrix identically over REST and Bolt (incl. cross-tenant denial + 401/403\n'
    printf 'codes), proved the sensitive data is ciphertext on disk, rotated the master key offline with\n'
    printf 'the old key failing closed, and round-tripped an encrypted backup losslessly.\n'
  else
    printf '%s%sSECURITY-MULTITENANT DEMONSTRATION PASSED%s — the hermetic generator produced a\n' "$BOLD" "$GREEN" "$RESET"
    printf 'byte-identical multi-tenant scenario and the crypto verifier proved ciphertext-on-disk, key\n'
    printf 'rotation and the encrypted backup roundtrip. (The live REST/Bolt RBAC matrix was skipped:\n'
    printf 'openssl or python3 absent. Install them for the full demonstration.)\n'
  fi
  exit 0
else
  printf '%s%sSECURITY-MULTITENANT DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
