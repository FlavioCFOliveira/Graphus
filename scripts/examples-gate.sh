#!/usr/bin/env bash
# examples-gate.sh — run the WHOLE examples suite in BOTH of its modes, as one gate (`rmp` #704).
#
# Why this exists
# ---------------
# The examples are the project's instrument for exposing regressions, fragilities and resource
# inefficiencies in the server. An example that is never run cannot expose anything — and for a long
# time nothing ran them, so they rotted in place: a failing example sat on `main` unnoticed, reports
# published fabricated zeros, and a baseline gate compared 0.0 against 0.0 and called it a pass. Every
# one of those defects was found the moment the suite was actually executed.
#
# So the suite is a GATE, not a demo, and it is wired into `scripts/verify.sh`.
#
# It runs BOTH modes, because the examples make two distinct promises and each can rot on its own:
#
#   LOCAL   — every example self-boots its own server and measures it directly (/proc CPU + RSS,
#             on-disk store and WAL bytes). This is the only mode that can produce the process and
#             storage vectors, so it is also the only mode a committed baseline may come from.
#
#   ATTACH  — every attach-capable example runs against an ALREADY-RUNNING instance, isolating itself
#             in a run-scoped database. This gate boots that instance here, exactly as the Docker
#             image does (self-signed TLS, Bolt-TCP + REST + UDS, an admin identity), so the
#             "runnable against a local OR remote Graphus" promise is proven on every run rather than
#             asserted in a README. The two durability examples are local-only by construction — they
#             SIGKILL the server to prove crash recovery, so they cannot target a shared instance.
#
# Usage:
#   scripts/examples-gate.sh              # both modes (the gate)
#   scripts/examples-gate.sh --local      # self-boot mode only
#   scripts/examples-gate.sh --attach     # attach mode only (boots the target instance itself)
#
# Exits non-zero if any example fails in either mode.
set -uo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

RUN_LOCAL=1
RUN_ATTACH=1
for arg in "$@"; do
    case "$arg" in
        --local)  RUN_ATTACH=0 ;;
        --attach) RUN_LOCAL=0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [ -t 1 ]; then
    BOLD=$'\e[1m'; GREEN=$'\e[32m'; RED=$'\e[31m'; DIM=$'\e[2m'; RESET=$'\e[0m'
else
    BOLD=''; GREEN=''; RED=''; DIM=''; RESET=''
fi
step() { printf '\n%s==> %s%s\n' "$BOLD" "$1" "$RESET"; }

FAILED=()

# ------------------------------------------------------------------------------------------------
# Mode 1 — LOCAL: every example self-boots the server it measures.
# ------------------------------------------------------------------------------------------------
if [ "$RUN_LOCAL" = "1" ]; then
    step "examples suite — LOCAL mode (each example self-boots and measures its own server)"
    # Unset the external-target contract: a stray GRAPHUS_TARGET_* in the caller's environment would
    # silently turn this into a second attach run, and the local vectors would come back N/A.
    if env -u GRAPHUS_TARGET_BOLT -u GRAPHUS_TARGET_REST -u GRAPHUS_TARGET_UDS \
           examples/run-all.sh; then
        printf '%s✓ local mode: all examples passed%s\n' "$GREEN" "$RESET"
    else
        printf '%s✗ local mode: an example FAILED%s\n' "$RED" "$RESET"
        FAILED+=("local")
    fi
fi

# ------------------------------------------------------------------------------------------------
# Mode 2 — ATTACH: boot ONE real instance and point every attach-capable example at it.
# ------------------------------------------------------------------------------------------------
TARGET_DIR=""
SERVER_PID=""

cleanup_target() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        for _ in $(seq 1 100); do
            kill -0 "$SERVER_PID" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$SERVER_PID" 2>/dev/null || true
    fi
    [ -n "$TARGET_DIR" ] && rm -rf "$TARGET_DIR"
    rm -f "${GATE_UDS:-}"
}
trap cleanup_target EXIT INT TERM

if [ "$RUN_ATTACH" = "1" ]; then
    step "examples suite — ATTACH mode (one already-running instance; each example isolates itself in its own database)"

    cargo build --release -p graphus-server -p graphus-cli || {
        printf '%s✗ could not build the server for the attach target%s\n' "$RED" "$RESET"
        exit 1
    }

    TARGET_DIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-examples-target-XXXXXX")"
    # A UDS path lives in a `sockaddr_un.sun_path`, which is ~104 bytes on macOS and 108 on Linux. A
    # socket under a long mktemp path silently overruns SUN_LEN and the server refuses to boot, so the
    # socket goes at a short, fixed path while the store stays in the temp dir.
    GATE_UDS="/tmp/graphus-examples-gate.sock"
    rm -f "$GATE_UDS"

    mkdir -p "$TARGET_DIR/tls"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$TARGET_DIR/tls/key.pem" -out "$TARGET_DIR/tls/cert.pem" \
        -days 1 -subj "/CN=graphus-examples-gate" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 || {
        printf '%s✗ openssl is required to provision the TLS certificate the attach target needs%s\n' "$RED" "$RESET"
        exit 1
    }

    # Bolt-TCP always requires TLS and REST is served over it too, so the target is provisioned exactly
    # as the container image provisions itself: a self-signed certificate and a random JWT secret. The
    # certificate authenticates nothing — clients attach with bolt+ssc:// and curl -k, which is correct
    # for a box you booted yourself and is NOT correct for anything else.
    GATE_PASSWORD="examples-gate-$$"
    cat > "$TARGET_DIR/graphus.toml" <<EOF
store_path    = "$TARGET_DIR/graphus-data"
uds_path      = "$GATE_UDS"
bolt_tcp_addr = "127.0.0.1:${GRAPHUS_GATE_BOLT_PORT:-7687}"
rest_addr     = "127.0.0.1:${GRAPHUS_GATE_REST_PORT:-7474}"

[auth]
admin_user     = "graphus"
admin_password = "$GATE_PASSWORD"
EOF

    GRAPHUS_TLS_CERT_PATH="$TARGET_DIR/tls/cert.pem" \
    GRAPHUS_TLS_KEY_PATH="$TARGET_DIR/tls/key.pem" \
    GRAPHUS_JWT_SECRET="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')" \
        ./target/release/graphus-server "$TARGET_DIR/graphus.toml" > "$TARGET_DIR/server.log" 2>&1 &
    SERVER_PID=$!

    REST_URL="https://127.0.0.1:${GRAPHUS_GATE_REST_PORT:-7474}"
    READY=no
    for _ in $(seq 1 150); do
        if curl -sk -o /dev/null -X POST "$REST_URL/auth/login" \
               -H 'content-type: application/json' \
               -d "{\"username\":\"graphus\",\"password\":\"$GATE_PASSWORD\"}" 2>/dev/null; then
            READY=yes; break
        fi
        kill -0 "$SERVER_PID" 2>/dev/null || break
        sleep 0.2
    done
    if [ "$READY" != "yes" ]; then
        printf '%s✗ the attach target never became reachable; server log:%s\n' "$RED" "$RESET"
        tail -20 "$TARGET_DIR/server.log" >&2
        exit 1
    fi
    printf '%s· attach target up: %s (pid %s)%s\n' "$DIM" "$REST_URL" "$SERVER_PID" "$RESET"

    if GRAPHUS_TARGET_REST="$REST_URL" \
       GRAPHUS_TARGET_BOLT="bolt+ssc://127.0.0.1:${GRAPHUS_GATE_BOLT_PORT:-7687}" \
       GRAPHUS_TARGET_UDS="$GATE_UDS" \
       GRAPHUS_TARGET_USER=graphus \
       GRAPHUS_TARGET_PASSWORD="$GATE_PASSWORD" \
       GRAPHUS_TARGET_TLS_INSECURE=1 \
       examples/run-all.sh; then
        printf '%s✓ attach mode: all attach-capable examples passed against a running instance%s\n' "$GREEN" "$RESET"
    else
        printf '%s✗ attach mode: an example FAILED against a running instance%s\n' "$RED" "$RESET"
        FAILED+=("attach")
    fi

    # The instance must have survived the whole suite. An example that leaves the target dead, wedged,
    # or panicking is a server finding, not a passing run — and a per-example verdict cannot see it.
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        printf '%s✗ the attach target DIED during the suite — that is a server defect, not a test artefact%s\n' "$RED" "$RESET"
        tail -30 "$TARGET_DIR/server.log" >&2
        FAILED+=("attach target died")
    elif grep -qiE "panicked|force[_-]detach" "$TARGET_DIR/server.log"; then
        printf '%s✗ the attach target logged a panic / force-detach during the suite%s\n' "$RED" "$RESET"
        grep -iE "panicked|force[_-]detach" "$TARGET_DIR/server.log" | head -10 >&2
        FAILED+=("attach target panicked")
    else
        printf '%s✓ the attach target survived the whole suite with no panic and no force-detach%s\n' "$GREEN" "$RESET"
    fi
fi

printf '\n'
if [ "${#FAILED[@]}" -gt 0 ]; then
    printf '%s%sexamples gate FAILED: %s%s\n' "$BOLD" "$RED" "${FAILED[*]}" "$RESET"
    exit 1
fi
printf '%s%sexamples gate passed.%s\n' "$BOLD" "$GREEN" "$RESET"
