#!/usr/bin/env bash
#
# Graphus large-scale social-graph demonstration — a performance evaluation under a LARGE graph.
#
# The model (a multigraph LPG): a social network of (:USER {id, name, registered}) befriended by an
# UNDIRECTED multigraph (:USER)-[:FRIEND {since}]-(:USER) where each USER has between `friend_min`
# and `friend_max` friends, a corpus of (:ARTICLE {id, name, registered}) carrying realistic
# headlines, and (:USER)-[:LIKE {date}]->(:ARTICLE) edges. The literal target this example is built
# around is 1,000,000 USERs (friend 200..=2000), 30,000 ARTICLEs (the `huge` profile) — see README.md.
#
# This script doubles as an executable E2E test. It:
#   1. proves the deterministic, seeded generator (`social_gen`) is BYTE-IDENTICAL per seed by
#      generating `graph.cypher` twice and diffing;
#   2. runs the in-process BULK LOAD + traversal workload (`social_load`) against the REAL engine —
#      ingesting via the production bulk path (graphus-bulk, O(E)) into an on-disk store and then
#      driving a Cypher read battery (direct friends, friend-of-friend, mutual friends, top-liked
#      articles, degree) — asserting the graph shape (|USER|, |ARTICLE|, |FRIEND|, |LIKE|) and that
#      the traversals return well-formed results;
#   3. emits standardized evidence (`social_evidence`: ingest throughput, on-disk footprint +
#      amplification, peak RSS, per-query latency) into report.json + report.md and gates the stable
#      STRUCTURAL metrics against the committed baseline (`social_baseline_cmp`);
#   4. (optional) drives a small slice of the SAME model over a real Bolt-over-UDS WIRE with
#      `graphus-cli` against a booted `graphus-server`, asserting a friend-of-friend traversal over
#      the socket.
#
# Steps 1–3 are HERMETIC (the load driver runs the real engine in-process — see README.md →
# "Transport" for why the bulk-load + GC-free read evidence is driven in-process). Step 4 is OPT-IN
# via RUN_WIRE (default ON; set RUN_WIRE=0 to skip).
#
# Usage:
#   examples/social-network-large/run.sh                       # builds binaries if needed, then runs
#   GRAPHUS_BIN_DIR=target/release  examples/social-network-large/run.sh
#   SOCIAL_PROFILE=large            examples/social-network-large/run.sh   # evidence-scale load
#   RUN_WIRE=0                      examples/social-network-large/run.sh   # skip the Bolt/UDS wire demo
#
# Requirements: a Unix host (Linux/macOS), bash, and a checkout that builds. No network/openssl/node.

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

GEN="$BIN_DIR/social_gen"
LOAD="$BIN_DIR/social_load"
EVIDENCE_BIN="$BIN_DIR/social_evidence"
CMP_BIN="$BIN_DIR/social_baseline_cmp"
SERVER="$BIN_DIR/graphus-server"
CLI="$BIN_DIR/graphus-cli"

PROFILE="${SOCIAL_PROFILE:-fast}"
RUN_WIRE="${RUN_WIRE:-1}"

# The generator + load driver + evidence emitter + baseline gate all live in the one crate; the load
# driver + evidence emitter need the `engine` feature (real engine + bulk importer).
if [ ! -x "$GEN" ] || [ ! -x "$LOAD" ] || [ ! -x "$EVIDENCE_BIN" ] || [ ! -x "$CMP_BIN" ]; then
  section "Building the social-network-large generator + load + evidence binaries (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-social-gen --features engine --bins )
fi
for b in "$GEN" "$LOAD" "$EVIDENCE_BIN" "$CMP_BIN"; do
  [ -x "$b" ] || { echo "${RED}fatal: required binary not found at $b${RESET}" >&2; exit 2; }
done

# --------------------------------------------------------------------------------------------------
# Workspace: a private temp dir for generated artifacts, removed on exit. The evidence/ dir is
# git-ignored; baseline.json lives at a non-ignored path.
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-social-XXXXXX")"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
BASELINE="$SCRIPT_DIR/baseline.json"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT INT TERM
mkdir -p "$EVIDENCE_DIR"

# kv <summary-line> <key> — pull a `key=value` token out of a generator/driver summary line.
kv() { printf '%s' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n1; }

# ==================================================================================================
# Step 1 — deterministic generator (byte-identical per seed)
# ==================================================================================================
section "Step 1 — deterministic social-graph generator ($PROFILE profile)"
GEN_OUT="$("$GEN" --profile "$PROFILE" --out-dir "$WORKDIR/gen1")"
printf '%s\n' "$GEN_OUT" | sed 's/^/  /'
assert "graph.cypher generated" "yes" "$([ -s "$WORKDIR/gen1/graph.cypher" ] && echo yes || echo no)"

"$GEN" --profile "$PROFILE" --out-dir "$WORKDIR/gen2" >/dev/null
if diff -q "$WORKDIR/gen1/graph.cypher" "$WORKDIR/gen2/graph.cypher" >/dev/null; then
  assert "generator is byte-identical per seed" "yes" "yes"
else
  assert "generator is byte-identical per seed" "yes" "no"
fi

GEN_USERS="$(kv "$GEN_OUT" users)"
GEN_ARTICLES="$(kv "$GEN_OUT" articles)"
GEN_FRIENDS="$(kv "$GEN_OUT" friend_edges)"
GEN_LIKES="$(kv "$GEN_OUT" like_edges)"
GEN_DMIN="$(kv "$GEN_OUT" degree_min)"
GEN_DMAX="$(kv "$GEN_OUT" degree_max)"
info "realized degree band: [$GEN_DMIN, $GEN_DMAX]  (configured [$(kv "$GEN_OUT" friend_min), $(kv "$GEN_OUT" friend_max)])"

# ==================================================================================================
# Step 2 — in-process BULK LOAD + traversal + shape asserts (REAL engine)
# ==================================================================================================
section "Step 2 — in-process bulk load + read-query battery (real engine, on-disk store)"
LOAD_OUT="$("$LOAD" --profile "$PROFILE" 2>&1)" || true
printf '%s\n' "$LOAD_OUT" | grep -v '^GRAPHUS_SOCIAL_OK' | sed 's/^/  /'
assert "load reached the expected graph shape AND traversals returned" "yes" \
  "$(printf '%s' "$LOAD_OUT" | grep -q 'GRAPHUS_SOCIAL_OK' && echo yes || echo no)"

# ==================================================================================================
# Step 3 — standardized evidence (throughput + footprint + RSS + latency) + baseline gate
# ==================================================================================================
section "Step 3 — collect performance evidence (throughput + footprint + RSS + latency)"
rm -f "$EVIDENCE_DIR/report.json" "$EVIDENCE_DIR/report.md"
EVIDENCE_OUT="$("$EVIDENCE_BIN" --evidence-dir "$EVIDENCE_DIR" --profile "$PROFILE" 2>&1)" || true
printf '%s\n' "$EVIDENCE_OUT" | sed 's/^/  /'
assert "evidence report.json was produced" "yes" \
  "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
assert "evidence report.md was produced" "yes" \
  "$([ -f "$EVIDENCE_DIR/report.md" ] && echo yes || echo no)"

# Regression gate (fast profile only — the committed baseline is that run). Compares ONLY the stable
# STRUCTURAL metrics (node/rel counts, durable store bytes/pages, store-only space amplification)
# against baseline.json; the machine-variant RSS / throughput / CPU / wall-time / WAL families are
# given an effectively-infinite tolerance (see social_baseline_cmp). A non-fast profile is not
# baseline-comparable (different scale), so the gate is skipped then.
if [ "$PROFILE" = "fast" ] && [ -f "$BASELINE" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
  section "regression gate vs committed baseline"
  CMP_OUT="$("$CMP_BIN" "$BASELINE" "$EVIDENCE_DIR/report.json" 2>&1)" || true
  printf '%s\n' "$CMP_OUT" | sed 's/^/  /'
  assert "fresh run is within baseline thresholds (structural metrics)" "yes" \
    "$(printf '%s' "$CMP_OUT" | grep -q 'GRAPHUS_BASELINE_OK' && echo yes || echo no)"
elif [ ! -f "$BASELINE" ]; then
  info "no committed baseline.json yet — skipping the regression gate."
else
  info "regression gate skipped (non-fast profile: not baseline-comparable)."
fi

# ==================================================================================================
# Step 4 — (optional) Bolt-over-UDS wire demonstration of the same model
# ==================================================================================================
if [ "$RUN_WIRE" = "1" ]; then
  if [ ! -x "$SERVER" ] || [ ! -x "$CLI" ]; then
    section "Building graphus-server and graphus-cli (release) for the wire demo"
    ( cd "$REPO_ROOT" && cargo build --release -p graphus-server -p graphus-cli )
  fi
  if [ -x "$SERVER" ] && [ -x "$CLI" ]; then
    section "Step 4 — Bolt-over-UDS wire demo (the same USER/FRIEND/ARTICLE/LIKE model via graphus-cli)"
    CONFIG="$WORKDIR/graphus.toml"
    SOCKET="$WORKDIR/graphus.sock"
    SERVER_LOG="$WORKDIR/server.log"
    ADMIN_USER="social"
    ADMIN_PW="social-large-demo-pw-1"
    cat > "$CONFIG" <<EOF
# Generated by examples/social-network-large/run.sh — a UDS-only wire-demo configuration.
store_path = "$WORKDIR/data"
buffer_pool_pages = 2048
uds_path = "$SOCKET"
rest_addr = ""
jwt_secret = "graphus-social-large-demo-uds-only-secret-32+"

[auth]
admin_user = "$ADMIN_USER"
admin_password = "$ADMIN_PW"
admin_uid = $(id -u)
EOF
    SERVER_PID=""
    wire_cleanup() {
      if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
      fi
    }
    trap 'wire_cleanup; cleanup' EXIT INT TERM

    "$SERVER" "$CONFIG" >>"$SERVER_LOG" 2>&1 &
    SERVER_PID=$!
    BOUND=no
    for _ in $(seq 1 100); do
      if [ -S "$SOCKET" ]; then BOUND=yes; break; fi
      if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
      sleep 0.1
    done
    assert "server bound the UDS socket" "yes" "$BOUND"

    cypher() { GRAPHUS_PASSWORD="$ADMIN_PW" "$CLI" --uds "$SOCKET" --user "$ADMIN_USER" -c "$1"; }
    scalar() {
      cypher "$1" | awk -F'|' '
        /^\|/ { rows++; if (rows == 2) { v = $2; gsub(/^[ \t"]+|[ \t"]+$/, "", v); print v } }
      '
    }

    if [ "$BOUND" = "yes" ]; then
      # A small, hand-written slice of the SAME model: USERs befriended in a chain (so a
      # friend-of-friend query has a non-empty answer), ARTICLEs, and LIKE edges — created over the
      # wire exactly as an operator would, proving the model round-trips over Bolt/UDS.
      cypher "
CREATE (u0:USER {id:'000000000000000000000000', name:'José António da Silva e Carvalho', registered:1781876640}),
       (u1:USER {id:'000000000000000000000001', name:'Maria Inês Gonçalves',              registered:1781876700}),
       (u2:USER {id:'000000000000000000000002', name:'João Pedro Patrícia Sá',            registered:1781876760}),
       (u3:USER {id:'000000000000000000000003', name:'Ana Rita Fonseca',                  registered:1781876820}),
       (a0:ARTICLE {id:'0000000000000000000000a0', name:'Economia cresce acima do esperado no trimestre', registered:1781870000}),
       (a1:ARTICLE {id:'0000000000000000000000a1', name:'Nova política ambiental aprovada no parlamento',  registered:1781871000}),
       (u0)-[:FRIEND {since:1781876640}]->(u1),
       (u1)-[:FRIEND {since:1781876700}]->(u2),
       (u2)-[:FRIEND {since:1781876760}]->(u3),
       (u0)-[:LIKE {date:1781876900}]->(a0),
       (u1)-[:LIKE {date:1781876901}]->(a0),
       (u2)-[:LIKE {date:1781876902}]->(a1)
RETURN count(*) AS created" > /dev/null

      assert "wire: |USER| created over UDS" "4" "$(scalar "MATCH (u:USER) RETURN count(u) AS c")"
      assert "wire: |ARTICLE| created over UDS" "2" "$(scalar "MATCH (a:ARTICLE) RETURN count(a) AS c")"
      assert "wire: |FRIEND| created over UDS" "3" "$(scalar "MATCH ()-[r:FRIEND]->() RETURN count(r) AS c")"
      assert "wire: |LIKE| created over UDS" "3" "$(scalar "MATCH ()-[r:LIKE]->() RETURN count(r) AS c")"
      # Friend-of-friend of u0 over the undirected FRIEND relation: u0–u1–u2 ⇒ u2 is the 2-hop friend.
      assert "wire: friend-of-friend traversal returns u2" "000000000000000000000002" \
        "$(scalar "MATCH (u:USER {id:'000000000000000000000000'})-[:FRIEND]-(:USER)-[:FRIEND]-(fof:USER) WHERE fof.id <> u.id RETURN fof.id AS id")"
      # Most-liked article (aggregation + ORDER BY + LIMIT): a0 has 2 likes, a1 has 1.
      assert "wire: top-liked article is a0" "0000000000000000000000a0" \
        "$(scalar "MATCH (:USER)-[:LIKE]->(a:ARTICLE) WITH a, count(*) AS likes RETURN a.id AS id ORDER BY likes DESC LIMIT 1")"
    fi

    wire_cleanup
    SERVER_PID=""
    trap cleanup EXIT INT TERM
  else
    section "Step 4 — wire demo SKIPPED (server/cli binaries unavailable)"
  fi
else
  section "Step 4 — Bolt-over-UDS wire demo SKIPPED (RUN_WIRE=0)"
fi

# ==================================================================================================
# Summary
# ==================================================================================================
section "Result"
printf '%s checks run, %s failures.\n' "$CHECKS" "$FAILURES"
if [ -f "$EVIDENCE_DIR/report.json" ]; then
  info "standardized evidence: $EVIDENCE_DIR/{report.json, report.md}"
fi
if [ "$FAILURES" -eq 0 ]; then
  printf '%s%sSOCIAL-NETWORK-LARGE DEMONSTRATION PASSED%s — the seeded generator is byte-identical, the\n' "$BOLD" "$GREEN" "$RESET"
  printf 'bulk load produced a %s-USER / %s-ARTICLE graph (%s FRIEND, %s LIKE) with realized friend\n' "${GEN_USERS:-?}" "${GEN_ARTICLES:-?}" "${GEN_FRIENDS:-?}" "${GEN_LIKES:-?}"
  printf 'degree within [%s, %s], the Cypher read battery traversed it, and the structural evidence\n' "${GEN_DMIN:-?}" "${GEN_DMAX:-?}"
  printf 'matched the committed baseline.\n'
  exit 0
else
  printf '%s%sSOCIAL-NETWORK-LARGE DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
