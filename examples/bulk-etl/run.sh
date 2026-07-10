#!/usr/bin/env bash
#
# Graphus high-throughput bulk ingest & ETL demonstration — fully OFFLINE (no server, no Bolt driver,
# no network).
#
# This script doubles as an executable E2E test. It:
#   1. generates a DETERMINISTIC, SEEDED LDBC-SNB-like social-network dataset as loader-ready CSV
#      (per-label node files + per-type relationship files + manifest.json) via the `bulk_gen` binary,
#      and proves the generator is BYTE-IDENTICAL per seed by regenerating and diffing;
#   2. imports the dataset into a fresh store with the REAL `graphus-bulk import` binary, asserting the
#      reported node/relationship counts equal the manifest;
#   3. proves a LOSSLESS `import -> dump -> re-import` round-trip (`bulk_roundtrip`): the whole graph is
#      dumped back to CSV, re-imported into a second fresh store, and the two stores are proven
#      identical by an id-independent CONTENT HASH (same labels, types, property values, connectivity);
#   4. measures the on-disk STORAGE footprint + write/space amplification (`bulk_storage` -> storage.json);
#   5. emits the standardized, schema-versioned report.json + report.md (ingest THROUGHPUT — elements/sec
#      and MB/sec — peak RAM, CPU time, end-to-end time, plus the store footprint + amplification) via
#      the dev-only `bulk_evidence` harness binary, and gates a fresh fast-profile run against the
#      committed baseline.json (STRUCTURAL metrics only) via `bulk_baseline_cmp`.
#
# Everything is HERMETIC and always runs — there is no server to boot and no opt-in driver path.
#
# Usage:
#   examples/bulk-etl/run.sh                       # builds binaries if needed, then runs
#   GRAPHUS_BIN_DIR=target/release  examples/bulk-etl/run.sh
#   BULK_PROFILE=large              examples/bulk-etl/run.sh   # evidence-scale dataset
#
# Requirements: a Unix host (Linux/macOS), bash, and a checkout that builds. No openssl/node/npm/network.

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

BULK="$BIN_DIR/graphus-bulk"
GEN="$BIN_DIR/bulk_gen"
ROUNDTRIP="$BIN_DIR/bulk_roundtrip"
STORAGE="$BIN_DIR/bulk_storage"
EVIDENCE_BIN="$BIN_DIR/bulk_evidence"
CMP_BIN="$BIN_DIR/bulk_baseline_cmp"
SERVER="$BIN_DIR/graphus-server"
CLI="$BIN_DIR/graphus-cli"

PROFILE="${BULK_PROFILE:-fast}"
# The offline import/round-trip/storage/baseline core is the always-run hermetic body. The online
# schema-hardening demo (Step 5) boots a REAL server over Bolt-over-UDS and is OPT-IN via RUN_WIRE
# (default ON; set RUN_WIRE=0 to skip it on a host without a server/cli build).
RUN_WIRE="${RUN_WIRE:-1}"

# The offline importer is its own release binary; the generator + drivers are the dev-only crate's.
if [ ! -x "$BULK" ]; then
  section "Building the offline graphus-bulk importer (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-bulk --bin graphus-bulk )
fi
[ -x "$BULK" ] || { echo "${RED}fatal: graphus-bulk binary not found at $BULK${RESET}" >&2; exit 2; }

if [ ! -x "$GEN" ] || [ ! -x "$ROUNDTRIP" ] || [ ! -x "$STORAGE" ] || [ ! -x "$EVIDENCE_BIN" ] || [ ! -x "$CMP_BIN" ]; then
  section "Building the dev-only bulk-etl generator + drivers (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p graphus-bulk-gen --bins )
fi
for b in "$GEN" "$ROUNDTRIP" "$STORAGE" "$EVIDENCE_BIN" "$CMP_BIN"; do
  [ -x "$b" ] || { echo "${RED}fatal: required binary not found at $b${RESET}" >&2; exit 2; }
done

# --------------------------------------------------------------------------------------------------
# Workspace + evidence paths. The temp workspace is removed on exit (success or failure). The
# evidence/ dir is git-ignored; baseline.json lives at a non-ignored path.
# --------------------------------------------------------------------------------------------------
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/graphus-bulk-etl-XXXXXX")"
DATA_DIR="$WORKDIR/data"
STORAGE_JSON="$WORKDIR/storage.json"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
BASELINE="$SCRIPT_DIR/baseline.json"

cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT INT TERM

mkdir -p "$EVIDENCE_DIR"

# kv <summary-line> <key> — pull a `key=value` token out of a generator/driver summary line.
kv() { printf '%s' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n1; }

# --------------------------------------------------------------------------------------------------
# Step 1 — generate the deterministic dataset + prove it is byte-identical per seed
# --------------------------------------------------------------------------------------------------
section "Step 1 — generate the deterministic social-network dataset ($PROFILE profile)"
GEN_OUT="$("$GEN" --profile "$PROFILE" --out-dir "$DATA_DIR")"
printf '%s\n' "$GEN_OUT" | sed 's/^/  /'
NODE_COUNT="$(kv "$GEN_OUT" nodes)"
REL_COUNT="$(kv "$GEN_OUT" relationships)"
assert "manifest.json generated" "yes" "$([ -s "$DATA_DIR/manifest.json" ] && echo yes || echo no)"

# Determinism check: regenerate into a second dir and diff every emitted file (the #264 AC).
DATA_DIR2="$WORKDIR/data2"
"$GEN" --profile "$PROFILE" --out-dir "$DATA_DIR2" > /dev/null
if diff -rq "$DATA_DIR" "$DATA_DIR2" > /dev/null; then
  assert "generator is byte-identical per seed" "yes" "yes"
else
  assert "generator is byte-identical per seed" "yes" "no"
fi

# --------------------------------------------------------------------------------------------------
# Step 2 — prove the lossless import -> dump -> re-import round-trip on the REAL graphus-bulk binary
# --------------------------------------------------------------------------------------------------
section "Step 2 — lossless import -> dump -> re-import round-trip (real graphus-bulk)"
ROUNDTRIP_OUT="$("$ROUNDTRIP" --bulk-bin "$BULK" --data-dir "$DATA_DIR" 2>&1)" || true
printf '%s\n' "$ROUNDTRIP_OUT" | sed 's/^/  /'
assert "round-trip is lossless (content hash preserved)" "yes" \
  "$(printf '%s' "$ROUNDTRIP_OUT" | grep -q 'GRAPHUS_BULK_ROUNDTRIP_OK' && echo yes || echo no)"
RT_LINE="$(printf '%s' "$ROUNDTRIP_OUT" | sed -n 's/^GRAPHUS_BULK_ROUNDTRIP_OK //p' | head -n1)"
CONTENT_HASH="$(kv "$RT_LINE" content_hash)"
assert "round-trip reports the original node count" "$NODE_COUNT" "$(kv "$RT_LINE" nodes)"
assert "round-trip reports the original relationship count" "$REL_COUNT" "$(kv "$RT_LINE" relationships)"

# --------------------------------------------------------------------------------------------------
# Step 3 — measure the on-disk storage footprint + amplification
# --------------------------------------------------------------------------------------------------
section "Step 3 — on-disk storage footprint + write/space amplification"
STORAGE_OUT="$("$STORAGE" --bulk-bin "$BULK" --data-dir "$DATA_DIR" --out "$STORAGE_JSON" 2>&1)" || true
printf '%s\n' "$STORAGE_OUT" | sed 's/^/  /'
assert "storage.json was produced" "yes" "$([ -s "$STORAGE_JSON" ] && echo yes || echo no)"

# --------------------------------------------------------------------------------------------------
# Step 4 — emit the standardized evidence (throughput + RAM + CPU + time + storage) and gate it
# --------------------------------------------------------------------------------------------------
section "Step 4 — collect performance evidence (ingest throughput + RAM / CPU / time + storage)"
# Refresh only the report files (NOT storage.json — that lives under WORKDIR; the dir is git-ignored).
rm -f "$EVIDENCE_DIR/report.json" "$EVIDENCE_DIR/report.md"
EVIDENCE_ARGS=(
  --evidence-dir "$EVIDENCE_DIR"
  --data-dir "$DATA_DIR"
  --storage "$STORAGE_JSON"
  --bulk-bin "$BULK"
  --scenario "bulk-etl"
  --param "profile=$PROFILE"
  --param "connection=offline"
)
[ -n "${CONTENT_HASH:-}" ] && EVIDENCE_ARGS+=( --content-hash "$CONTENT_HASH" )
EVIDENCE_OUT="$("$EVIDENCE_BIN" "${EVIDENCE_ARGS[@]}" 2>&1)" || true
printf '%s\n' "$EVIDENCE_OUT" | sed 's/^/  /'
assert "evidence report.json was produced" "yes" \
  "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
assert "evidence report.md was produced" "yes" \
  "$([ -f "$EVIDENCE_DIR/report.md" ] && echo yes || echo no)"

# Regression gate (fast profile only — the committed baseline is a fast-profile run). Compares only
# the STABLE STRUCTURAL metrics (dataset size, imported_elements, store footprint within 15%) against
# the committed baseline; ingest throughput / CPU / RAM / wall-time are machine-variant and NOT gated.
if [ "$PROFILE" = "fast" ] && [ -f "$BASELINE" ] && [ -f "$EVIDENCE_DIR/report.json" ]; then
  section "regression gate vs committed baseline"
  CMP_OUT="$("$CMP_BIN" "$BASELINE" "$EVIDENCE_DIR/report.json" 2>&1)" || true
  printf '%s\n' "$CMP_OUT" | sed 's/^/  /'
  assert "fresh run is within baseline thresholds (structural metrics)" "yes" \
    "$(printf '%s' "$CMP_OUT" | grep -q 'GRAPHUS_BASELINE_OK' && echo yes || echo no)"
fi

# --------------------------------------------------------------------------------------------------
# Step 5 — (optional) online schema-hardening over a REAL Bolt-over-UDS server
#
# The realistic offline→online workflow: after the OFFLINE bulk load above, an operator brings the
# data online and DECLARES the production schema on the live server. We boot a real `graphus-server`
# and, over Bolt-over-UDS, load a small representative slice of the SAME LDBC-SNB-like model, then
# apply the FULL schema-hardening palette this example documents (a NODE KEY + composite UNIQUE +
# UNIQUEs, a node + a relationship property-type, a relationship existence, and TEXT + FULLTEXT +
# composite RANGE indexes), prove one enforcement rejection, and capture SHOW CONSTRAINTS / SHOW
# INDEXES into the evidence dir.
#
# Why a fresh server store and not the bulk-imported one (verified empirically, `rmp` #678): the
# offline importer writes a flat `<dir>/graph.store` + `graph.wal` pair and does NOT persist the CSV
# `:ID` column as a queryable node property (it is consumed only as the physical-id join key), whereas
# the server resolves its store as `<store_path>/databases/<name>/graphus.store` (+ catalog) and the
# id-anchored schema needs an `id` property. So the online schema-hardening is demonstrated over the
# server's own store with `id` carried as a property — exactly as an online client does after a load —
# while the hermetic `graphus-server/tests/bulk_etl_schema.rs` mirror is the rigorous proof over the
# generator's exact dataset.
# --------------------------------------------------------------------------------------------------
if [ "$RUN_WIRE" = "1" ]; then
  if [ ! -x "$SERVER" ] || [ ! -x "$CLI" ]; then
    section "Building graphus-server and graphus-cli (release) for the online schema-hardening demo"
    ( cd "$REPO_ROOT" && cargo build --release -p graphus-server -p graphus-cli )
  fi
  if [ -x "$SERVER" ] && [ -x "$CLI" ]; then
    section "Step 5 — online schema-hardening over Bolt-over-UDS (the same Person/Post/… model live)"
    CONFIG="$WORKDIR/graphus.toml"
    SOCKET="$WORKDIR/graphus.sock"
    SERVER_LOG="$WORKDIR/server.log"
    ADMIN_USER="etl"
    ADMIN_PW="bulk-etl-demo-pw-1"
    cat > "$CONFIG" <<EOF
# Generated by examples/bulk-etl/run.sh — a UDS-only online schema-hardening configuration.
store_path = "$WORKDIR/server-data"
buffer_pool_pages = 1024
uds_path = "$SOCKET"
rest_addr = ""
jwt_secret = "graphus-bulk-etl-demo-uds-only-secret-32chars+"

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
      # 1. Load a small slice of the SAME model over the wire — the "data is already loaded" state a
      #    bulk load leaves behind — with `id` carried as a property (as an online client does).
      cypher "
CREATE (p0:Person {id:'p0', firstName:'Ada',   lastName:'Lovelace',   gender:'female', age:36, locationIP:'10.0.0.1', browserUsed:'Firefox', tags:['graphs','rust']}),
       (p1:Person {id:'p1', firstName:'Grace', lastName:'Hopper',     gender:'female', age:42, locationIP:'10.0.0.2', browserUsed:'Chrome',  tags:['systems']}),
       (p2:Person {id:'p2', firstName:'Edsger',lastName:'Dijkstra',   gender:'male',   age:51, locationIP:'10.0.0.3', browserUsed:'Safari',  tags:['distributed','graphs']}),
       (f0:Forum  {id:'f0', title:'forum-0', createdAt:1500000000}),
       (po0:Post  {id:'po0', content:'post-content-0', length:120, createdAt:1500000100, language:'en'}),
       (po1:Post  {id:'po1', content:'post-content-1', length:220, createdAt:1500000200, language:'pt'}),
       (c0:Comment{id:'c0', content:'comment-content-0', length:40, createdAt:1500000300}),
       (p0)-[:KNOWS {since:2015}]->(p1),
       (f0)-[:HAS_MEMBER {joinedAt:1500000400}]->(p0),
       (f0)-[:CONTAINER_OF {addedAt:1500000500}]->(po0),
       (po0)-[:HAS_CREATOR {weight:7}]->(p0),
       (c0)-[:REPLY_OF {depth:1}]->(po0),
       (p0)-[:LIKES {creationDate:1500000600}]->(po0)
RETURN count(*) AS created" > /dev/null

      assert "wire: |Person| loaded over UDS" "3" "$(scalar "MATCH (n:Person) RETURN count(n) AS c")"
      assert "wire: |Post| loaded over UDS" "2" "$(scalar "MATCH (n:Post) RETURN count(n) AS c")"

      # 2. Online schema-hardening: declare the FULL production palette over the now-loaded data. Each
      #    creation-time validation passes because the seeded slice conforms by construction.
      cypher "CREATE CONSTRAINT person_id_key FOR (n:Person) REQUIRE n.id IS NODE KEY" > /dev/null
      cypher "CREATE CONSTRAINT forum_id_unique FOR (n:Forum) REQUIRE n.id IS UNIQUE" > /dev/null
      cypher "CREATE CONSTRAINT comment_id_unique FOR (n:Comment) REQUIRE n.id IS UNIQUE" > /dev/null
      cypher "CREATE CONSTRAINT post_id_created_unique FOR (n:Post) REQUIRE (n.id, n.createdAt) IS UNIQUE" > /dev/null
      cypher "CREATE CONSTRAINT post_length_integer FOR (n:Post) REQUIRE n.length IS :: INTEGER" > /dev/null
      cypher "CREATE CONSTRAINT likes_created_exists FOR ()-[r:LIKES]-() REQUIRE r.creationDate IS NOT NULL" > /dev/null
      cypher "CREATE CONSTRAINT has_creator_weight_integer FOR ()-[r:HAS_CREATOR]-() REQUIRE r.weight IS :: INTEGER" > /dev/null
      cypher "CREATE TEXT INDEX post_content_text FOR (n:Post) ON (n.content)" > /dev/null
      cypher "CREATE FULLTEXT INDEX post_content_fulltext FOR (n:Post) ON EACH [n.content]" > /dev/null
      cypher "CREATE INDEX post_catalog_composite FOR (n:Post) ON (n.createdAt, n.id)" > /dev/null

      # 3. Capture the hardened schema (full columns) into the evidence dir for inspection.
      cypher "SHOW CONSTRAINTS" > "$EVIDENCE_DIR/schema_constraints.txt" 2>&1 || true
      cypher "SHOW INDEXES"     > "$EVIDENCE_DIR/schema_indexes.txt"     2>&1 || true
      assert "evidence: SHOW CONSTRAINTS captured" "yes" \
        "$([ -s "$EVIDENCE_DIR/schema_constraints.txt" ] && echo yes || echo no)"
      assert "evidence: SHOW INDEXES captured" "yes" \
        "$([ -s "$EVIDENCE_DIR/schema_indexes.txt" ] && echo yes || echo no)"

      SHOW_CONS="$(cat "$EVIDENCE_DIR/schema_constraints.txt")"
      SHOW_IDX="$(cat "$EVIDENCE_DIR/schema_indexes.txt")"
      assert "wire: SHOW CONSTRAINTS lists the NODE KEY" "yes" \
        "$(printf '%s' "$SHOW_CONS" | grep -q 'person_id_key' && echo yes || echo no)"
      assert "wire: SHOW CONSTRAINTS lists the composite UNIQUE" "yes" \
        "$(printf '%s' "$SHOW_CONS" | grep -q 'post_id_created_unique' && echo yes || echo no)"
      assert "wire: SHOW CONSTRAINTS lists the relationship existence" "yes" \
        "$(printf '%s' "$SHOW_CONS" | grep -q 'likes_created_exists' && echo yes || echo no)"
      assert "wire: SHOW INDEXES lists the TEXT index" "yes" \
        "$(printf '%s' "$SHOW_IDX" | grep -q 'post_content_text' && echo yes || echo no)"
      assert "wire: SHOW INDEXES lists the FULLTEXT index" "yes" \
        "$(printf '%s' "$SHOW_IDX" | grep -q 'post_content_fulltext' && echo yes || echo no)"
      assert "wire: SHOW INDEXES lists the composite RANGE index" "yes" \
        "$(printf '%s' "$SHOW_IDX" | grep -q 'post_catalog_composite' && echo yes || echo no)"
      assert "wire: SHOW INDEXES surfaces the always-on node LOOKUP index" "yes" \
        "$(printf '%s' "$SHOW_IDX" | grep -q 'node_label_lookup_index' && echo yes || echo no)"

      # 4. Prove one ENFORCEMENT rejection: a duplicate Person.id (NODE KEY) is refused and rolls back.
      REJECT_OUT="$(cypher "CREATE (:Person {id:'p0', firstName:'Dup', lastName:'Dup', gender:'female', age:20, locationIP:'0.0.0.0', browserUsed:'Firefox', tags:['x']})" 2>&1 || true)"
      assert "wire: duplicate Person.id is rejected (NODE KEY, count unchanged)" "3" \
        "$(scalar "MATCH (n:Person) RETURN count(n) AS c")"
      assert "wire: the rejection is a constraint violation" "yes" \
        "$(printf '%s' "$REJECT_OUT" | grep -qi 'constraint' && echo yes || echo no)"

      # 5. Prove the online search paths work over the wire: TEXT CONTAINS + FULLTEXT queryNodes.
      assert "wire: TEXT CONTAINS 'content-1' finds po1" "po1" \
        "$(scalar "MATCH (p:Post) WHERE p.content CONTAINS 'content-1' RETURN p.id AS id")"
      assert "wire: FULLTEXT queryNodes('0') finds po0" "po0" \
        "$(scalar "CALL db.index.fulltext.queryNodes('post_content_fulltext', '0') YIELD node RETURN node.id AS id")"
    fi

    wire_cleanup
    SERVER_PID=""
    trap cleanup EXIT INT TERM
    info "hardened schema evidence: $EVIDENCE_DIR/{schema_constraints.txt, schema_indexes.txt}"
  else
    section "Step 5 — online schema-hardening demo SKIPPED (server/cli binaries unavailable)"
  fi
else
  section "Step 5 — online schema-hardening demo SKIPPED (RUN_WIRE=0)"
fi

# --------------------------------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------------------------------
section "Result"
printf '%s checks run, %s failures.\n' "$CHECKS" "$FAILURES"
if [ -f "$EVIDENCE_DIR/report.json" ]; then
  info "standardized evidence: $EVIDENCE_DIR/{report.json, report.md}"
fi
if [ "$FAILURES" -eq 0 ]; then
  printf '%s%sBULK-ETL DEMONSTRATION PASSED%s — Graphus generated a byte-identical seeded social\n' "$BOLD" "$GREEN" "$RESET"
  printf '%s\n' "network, bulk-imported it with the real graphus-bulk binary, proved a LOSSLESS"
  printf '%s\n' "import -> dump -> re-import round-trip by content hash, characterised the on-disk store"
  printf '%s\n' "footprint + amplification, and produced standardized ingest-throughput / RAM / CPU / time evidence."
  exit 0
else
  printf '%s%sBULK-ETL DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' "$BOLD" "$RED" "$RESET" "$FAILURES"
  exit 1
fi
