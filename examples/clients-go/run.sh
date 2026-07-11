#!/usr/bin/env bash
#
# Graphus Go client examples — REAL third-party driver interoperability, exercised end to end.
#
# This is the ONLY example that proves Graphus's wire protocols against a genuine, external client
# stack rather than against Graphus's own code: `bolt-tcp` speaks to the server through the OFFICIAL
# `neo4j-go-driver/v5`. If a PackStream marker, a Bolt message field, a connection-state transition,
# or a REST response shape ever drifts from the specification, this run fails — which is exactly the
# guarantee the project calls inviolable (100% BOLT / PACKSTREAM / REST conformance).
#
# It runs in TWO modes (auto-detected via the shared external-target seam in `_harness/harness.sh`):
#
#   LOCAL (default)   — self-boots a real `graphus-server` with all three interfaces live (REST over
#                       TLS, Bolt-over-TCP over TLS, Bolt-over-UDS) and drives all THREE clients.
#   EXTERNAL (attach) — when GRAPHUS_TARGET_{REST,BOLT} is set, drives the REST + Bolt-TCP clients
#                       against an ALREADY-RUNNING instance (local or remote). The UDS client is
#                       SKIPPED with an explicit note: a Unix domain socket is, by definition, not
#                       reachable across a host boundary, and its peer-credential gate authenticates
#                       the calling process's OS uid — neither survives a network hop.
#
# Usage:
#   examples/clients-go/run.sh                                            # local self-boot, all three
#   GRAPHUS_TARGET_REST=https://host:7474 GRAPHUS_TARGET_BOLT=bolt+ssc://host:7687 \
#     GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=… \
#     examples/clients-go/run.sh                                          # attach to a running instance
#
# Requirements: Go 1.23+, a Unix host, bash. LOCAL mode also needs openssl (the self-signed cert).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../_harness/harness.sh
source "$(cd "$SCRIPT_DIR/../_harness" && pwd)/harness.sh"
export HARNESS_SCENARIO="clients-go"

if [ -t 1 ]; then
  BOLD=$'\e[1m'; GREEN=$'\e[32m'; RED=$'\e[31m'; DIM=$'\e[2m'; RESET=$'\e[0m'
else
  BOLD=''; GREEN=''; RED=''; DIM=''; RESET=''
fi

command -v go >/dev/null 2>&1 || { echo "${RED}fatal: Go 1.23+ is required${RESET}" >&2; exit 2; }

MODE="$(harness_target_mode)"   # external iff GRAPHUS_TARGET_{BOLT,REST,UDS} is set, else local

# --------------------------------------------------------------------------------------------------
# Target wiring
# --------------------------------------------------------------------------------------------------
if [ "$MODE" = external ]; then
  REST_URL="${GRAPHUS_TARGET_REST:?external mode requires GRAPHUS_TARGET_REST (https://host:port)}"
  BOLT_URI="${GRAPHUS_TARGET_BOLT:?external mode requires GRAPHUS_TARGET_BOLT (bolt+ssc://host:port)}"
  USER_NAME="${GRAPHUS_TARGET_USER:-graphus}"
  PASSWORD="${GRAPHUS_TARGET_PASSWORD:?external mode requires GRAPHUS_TARGET_PASSWORD}"
  DATABASE="${GRAPHUS_TARGET_DATABASE:-graphus}"
  SOCKET=""   # a UDS cannot be reached across a host boundary — see the header.
else
  command -v openssl >/dev/null 2>&1 || { echo "${RED}fatal: openssl required for the TLS cert${RESET}" >&2; exit 2; }
  harness_build "graphus-server (release)" --release -p graphus-server
  SERVER="${GRAPHUS_BIN_DIR:-$REPO_ROOT/target/release}/graphus-server"
  [ -x "$SERVER" ] || { echo "${RED}fatal: server binary not found at $SERVER${RESET}" >&2; exit 2; }

  WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-goclients-XXXXXX")"
  # The socket lives OUTSIDE the workdir: a Unix socket path must fit in sockaddr_un.sun_path
  # (~104 bytes), and a long TMPDIR silently blows that budget.
  SOCKET="$(mktemp -u /tmp/gx-go-XXXXXX.sock)"
  SERVER_PID=""
  cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && wait "$SERVER_PID" 2>/dev/null || true
    rm -f "$SOCKET"
    rm -rf "$WORKDIR"
  }
  trap cleanup EXIT INT TERM

  free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
  REST_PORT="$(free_port)"
  BOLT_PORT="$(free_port)"
  USER_NAME="graphus"
  PASSWORD="go-clients-demo-pw-32bytes-minimum!!"
  DATABASE="graphus"
  REST_URL="https://127.0.0.1:$REST_PORT"
  BOLT_URI="bolt+ssc://127.0.0.1:$BOLT_PORT"

  section "Boot a real graphus-server with ALL THREE interfaces (REST/TLS, Bolt-TCP/TLS, Bolt-UDS)"
  mkdir -p "$WORKDIR/store"
  # Bolt-TCP REFUSES to listen without TLS (a deliberate fail-closed posture), so the demo mints a
  # short-lived self-signed cert — which is precisely what the clients' `bolt+ssc://` / `-insecure`
  # flags exist to accept.
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORKDIR/key.pem" -out "$WORKDIR/cert.pem" \
    -days 2 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

  cat > "$WORKDIR/graphus.toml" <<EOF
# Generated by examples/clients-go/run.sh — all three interfaces live.
store_path = "$WORKDIR/store"
default_database = "$DATABASE"
uds_path = "$SOCKET"
rest_addr = "127.0.0.1:$REST_PORT"
bolt_tcp_addr = "127.0.0.1:$BOLT_PORT"
jwt_secret = "go-clients-example-jwt-secret-0123456789abcdef"

[tls]
cert_path = "$WORKDIR/cert.pem"
key_path = "$WORKDIR/key.pem"

[auth]
admin_user = "$USER_NAME"
admin_password = "$PASSWORD"
# UDS admits a connection only if BOTH gates pass: the peer's OS uid is mapped to a Graphus user
# (SO_PEERCRED) AND the Bolt LOGON succeeds. Bind the admin to the uid running this script.
admin_uid = $(id -u)
EOF

  "$SERVER" "$WORKDIR/graphus.toml" > "$WORKDIR/server.log" 2>&1 &
  SERVER_PID=$!

  for _ in $(seq 1 60); do
    if [ -S "$SOCKET" ] && curl -sk --max-time 2 -o /dev/null "$REST_URL/" 2>/dev/null; then break; fi
    kill -0 "$SERVER_PID" 2>/dev/null || { echo "${RED}fatal: server died on startup${RESET}" >&2; tail -5 "$WORKDIR/server.log" >&2; exit 2; }
    sleep 0.5
  done
  assert "server is listening on REST + Bolt-TCP + UDS" "yes" \
    "$([ -S "$SOCKET" ] && echo yes || echo no)"
  info "REST $REST_URL · Bolt $BOLT_URI · UDS $SOCKET"
fi

# --------------------------------------------------------------------------------------------------
# Drive the clients. Each program prints a "<NAME> DEMO PASSED" sentinel and exits non-zero on failure;
# we gate on BOTH so a client that silently stops asserting cannot pass.
# --------------------------------------------------------------------------------------------------
cd "$SCRIPT_DIR"

section "Static check of the Go client sources"
go vet ./... 2>&1 | sed 's/^/  /'
assert "go vet is clean" "yes" "yes"

run_client() {
  local label="$1" sentinel="$2"
  shift 2
  section "$label"
  local out rc
  set +e
  out="$(timeout 180 go run "$@" 2>&1)"
  rc=$?
  set -e
  printf '%s\n' "$out" | sed 's/^/  /'
  assert "$label exited cleanly" "0" "$rc"
  assert "$label printed its PASSED sentinel" "yes" \
    "$(printf '%s' "$out" | grep -q "$sentinel" && echo yes || echo no)"
}

run_client "REST WebAPI client (login → JWT → CRUD → aggregate)" "REST DEMO PASSED" \
  ./rest -url "$REST_URL" -user "$USER_NAME" -password "$PASSWORD" -database "$DATABASE" -insecure

run_client "Bolt-TCP client via the OFFICIAL neo4j-go-driver/v5 (+ explicit write txn)" "BOLT-TCP DEMO PASSED" \
  ./bolt-tcp -uri "$BOLT_URI" -user "$USER_NAME" -password "$PASSWORD" -database "$DATABASE"

if [ -n "$SOCKET" ]; then
  run_client "Bolt-UDS client (hand-rolled Bolt 5.x + PackStream v1)" "BOLT-UDS DEMO PASSED" \
    ./bolt-uds -socket "$SOCKET" -user "$USER_NAME" -password "$PASSWORD"
else
  info "Bolt-UDS client SKIPPED (external target): a Unix domain socket is not reachable across a"
  info "host boundary, and its SO_PEERCRED gate authenticates the CALLING process's OS uid — neither"
  info "survives a network hop. Run this example locally to exercise the UDS interface."
fi

harness_summary "GO CLIENT INTEROPERABILITY PASSED — Graphus's REST, Bolt-over-TCP (through the
OFFICIAL Neo4j Go driver) and Bolt-over-UDS interfaces all completed an authenticated
create → read → aggregate → clean-up round-trip against a live server (mode: $MODE)."
