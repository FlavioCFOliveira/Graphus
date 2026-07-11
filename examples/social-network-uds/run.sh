#!/usr/bin/env bash
#
# Graphus MVP end-to-end demonstration — a social network over a Unix Domain Socket (Bolt/UDS).
#
# THIS EXAMPLE IS LOCAL-ONLY BY CONSTRUCTION (the documented exception in examples/CLAUDE.md). It OWNS
# the server's lifecycle, and it must, for three independent reasons:
#
#   1. PID SIGNALS — the durability proof is a real `kill -KILL` of the server process mid-write. You
#      cannot SIGKILL a process you do not own (and must never SIGKILL a shared instance).
#   2. PEER-CRED UID — the UDS gate authenticates the CALLER's kernel-supplied uid (SO_PEERCRED)
#      against `auth.admin_uid`, so the config must be generated for *this* process's uid. A
#      pre-existing server was configured for someone else's.
#   3. count==0 BOOTSTRAP — the run asserts the graph starts EMPTY and then asserts EXACT global
#      counts (`MATCH (n) RETURN count(n)`) across the restarts. Those assertions are only meaningful
#      on a store this script created; against a shared instance they are either wrong or destructive.
#
# The sibling `social-network-large` / `product-recommendations` examples are the ones to point at a
# running instance (`GRAPHUS_TARGET_*`); this one refuses, loudly, rather than pretend.
#
# It doubles as an executable E2E test: it drives the REAL `graphus-server` and `graphus-cli` binaries
# (no in-process shortcuts) over a UDS, asserts every expected result, and exits non-zero the moment
# any assertion fails. It proves, empirically:
#
#   1. UDS connectivity (kernel-protected, peer-cred + password auth).
#   2. A REALISTIC, CONCURRENT workload: many simultaneous Bolt/UDS clients build a seeded social graph
#      (thousands of Person nodes, FRIEND / FOLLOWS / POSTED edges), including a CELEBRITY supernode
#      that many writers append to at once — so Serializable Snapshot Isolation really is exercised and
#      the abort/retry rate is MEASURED, not assumed.
#   3. Schema: a UNIQUE constraint, a RANGE index, and a TEXT index — declared, listed, and used.
#   4. Search + traversal (friends, friend-of-friend, aggregation, index-backed filters, text search).
#   5. Mutation (SET / MERGE / DELETE / DETACH DELETE).
#   6. Durability, twice over:
#        * a GRACEFUL restart (SIGTERM → clean shutdown → reboot from the same store);
#        * a MID-FLIGHT CRASH: an ACKNOWLEDGED commit is issued, a LARGE un-acked write is launched,
#          and the server is SIGKILLed *while it is executing that write*. After the reboot the run
#          asserts the acked commit SURVIVED, the un-acked write left NO TRACE, and — crucially — that
#          ARIES recovery ACTUALLY REPLAYED THE WAL (a recovery-complete log line whose redo counters
#          are non-zero). A no-op recovery FAILS the run.
#   7. Evidence: real per-statement latency (p50/p99/p999), real throughput, real CPU/RSS/on-disk
#      footprint — every figure measured, none fabricated.
#
# Usage:
#   examples/social-network-uds/run.sh                       # build (incremental) + run
#   GRAPHUS_BIN_DIR=target/release examples/social-network-uds/run.sh   # use pre-built binaries
#   MVP_PROFILE=large examples/social-network-uds/run.sh     # a bigger graph (evidence scale)
#
# Requirements: a Unix host (Linux/macOS), bash. Fully self-contained: it creates its own temp store,
# config, and socket, and removes them on exit. The server-CPU mid-flight probe is Linux-only (/proc);
# on macOS the run still passes, using the weaker "client has not been acked yet" liveness signal.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../_harness/harness.sh
source "$(cd "$SCRIPT_DIR/../_harness" && pwd)/harness.sh"

BOLD="$HARNESS_BOLD"; GREEN="$HARNESS_GREEN"; RED="$HARNESS_RED"; DIM="$HARNESS_DIM"; RESET="$HARNESS_RESET"

# --------------------------------------------------------------------------------------------------
# Local-only guard — refuse an external target, and say exactly why.
# --------------------------------------------------------------------------------------------------
if [ "$(harness_target_mode)" = "external" ]; then
  cat >&2 <<EOF
${RED}${BOLD}social-network-uds cannot run against an external target.${RESET}

This example is LOCAL-ONLY BY CONSTRUCTION — it owns the server's lifecycle:

  * it SIGKILLs the server process mid-write to prove crash recovery (you cannot, and must not,
    kill a shared/remote instance);
  * the UDS peer-cred gate authenticates THIS process's uid, so the server must be booted from a
    config generated for it (auth.admin_uid = $(id -u));
  * it asserts the graph starts EMPTY and then asserts EXACT global counts across the restarts,
    which is only meaningful on a store it created.

Point ${BOLD}social-network-large${RESET} or ${BOLD}product-recommendations${RESET} at your instance instead — they are
built for the GRAPHUS_TARGET_* attach seam. See examples/README.md.
EOF
  exit 2
fi

# --------------------------------------------------------------------------------------------------
# Build (never run a stale binary) + locate the binaries
# --------------------------------------------------------------------------------------------------
harness_build "graphus-server + graphus-cli (release)" --release -p graphus-server -p graphus-cli
BIN_DIR="${GRAPHUS_BIN_DIR:-$REPO_ROOT/target/release}"
SERVER="$BIN_DIR/graphus-server"
CLI="$BIN_DIR/graphus-cli"
[ -x "$SERVER" ] || { echo "${RED}fatal: server binary not found at $SERVER${RESET}" >&2; exit 2; }
[ -x "$CLI" ]    || { echo "${RED}fatal: cli binary not found at $CLI${RESET}" >&2; exit 2; }

# --------------------------------------------------------------------------------------------------
# Profile — the workload's size. `fast` is the default (a full run in well under a minute).
# --------------------------------------------------------------------------------------------------
PROFILE="${MVP_PROFILE:-fast}"
case "$PROFILE" in
  fast)  WRITERS=6; BATCHES=2; BATCH=200; EDGE_WRITERS=4; EDGES_EACH=300; FOLLOW_WRITERS=6
         FOLLOWS_EACH=40; POST_WRITERS=4; POSTS_EACH=60; READERS=8; READ_ROUNDS=2
         POOL_PAGES=8192; INFLIGHT_ROWS=200000 ;;
  large) WRITERS=8; BATCHES=4; BATCH=250; EDGE_WRITERS=6; EDGES_EACH=400; FOLLOW_WRITERS=8
         FOLLOWS_EACH=60; POST_WRITERS=6; POSTS_EACH=100; READERS=16; READ_ROUNDS=3
         POOL_PAGES=32768; INFLIGHT_ROWS=400000 ;;
  *) echo "${RED}fatal: unknown MVP_PROFILE '$PROFILE' (use fast|large)${RESET}" >&2; exit 2 ;;
esac

PEOPLE=$(( WRITERS * BATCHES * BATCH ))         # Person nodes, uid 1..PEOPLE
FRIENDS=$(( EDGE_WRITERS * EDGES_EACH ))        # FRIEND edges
FOLLOWS=$(( FOLLOW_WRITERS * FOLLOWS_EACH ))    # FOLLOWS edges, ALL onto the celebrity (uid 1)
POSTS=$(( POST_WRITERS * POSTS_EACH ))          # Post nodes (one POSTED edge each)
CELEBRITY_UID=1
MAX_RETRIES=8                                   # SSI abort → retry budget per statement

# --------------------------------------------------------------------------------------------------
# Workspace: a private temp store + config + socket, removed on exit
# --------------------------------------------------------------------------------------------------
# NOTE: the socket path must stay short — a UDS path is capped at SUN_LEN (~104 bytes), so we mktemp
# under /tmp (not under a deep $TMPDIR) and keep the socket file name tiny.
WORKDIR="$(mktemp -d /tmp/graphus-mvp-XXXXXX)"
CONFIG="$WORKDIR/graphus.toml"
SOCKET="$WORKDIR/g.sock"
DATA_DIR="$WORKDIR/data"
STORE_FILE="$DATA_DIR/graphus.store"    # the data image (a file)
WAL_DIR="$DATA_DIR/graphus.wal"         # the WAL is a DIRECTORY of `seg.<lsn>` segments + `anchor`
DWB_FILE="$DATA_DIR/graphus.dwb"        # the doublewrite buffer (a fixed-size ring)
LAT_DIR="$WORKDIR/lat"                  # per-worker per-ATTEMPT latency samples (ms)
RETRY_DIR="$WORKDIR/retry"              # per-worker SSI-abort tallies (one line per abort)
OK_DIR="$WORKDIR/ok"                    # per-worker COMMIT tallies (one line per committed statement)
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
ADMIN_USER="alice"
ADMIN_PW="social-demo-pw-1"
mkdir -p "$LAT_DIR" "$RETRY_DIR" "$OK_DIR"

BOOT=0
SERVER_PID=""
SERVER_LOG=""
PEAK_RSS_BYTES=0        # max VmHWM (kernel high-water mark) across every server lifetime
SERVER_START_EPOCH=0

cleanup() {
  if [ -n "${SERVER_PID:-}" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

# A UDS-only configuration. No network listener is enabled, so no TLS material is needed; the JWT
# secret is set only because the security catalog mandates a >=32-byte secret even when unused. The
# admin user is bound to this process's uid so the UDS SO_PEERCRED gate admits our own connections.
cat > "$CONFIG" <<EOF
# Generated by examples/social-network-uds/run.sh — a UDS-only MVP demo configuration.
store_path = "$DATA_DIR"
buffer_pool_pages = $POOL_PAGES
uds_path = "$SOCKET"
rest_addr = ""
jwt_secret = "graphus-mvp-social-demo-uds-only-secret-32+"

[auth]
admin_user = "$ADMIN_USER"
admin_password = "$ADMIN_PW"
admin_uid = $(id -u)
EOF

# --------------------------------------------------------------------------------------------------
# Small portable helpers
# --------------------------------------------------------------------------------------------------
# A millisecond clock, and an HONEST answer about whether this host actually has one. GNU date has
# `%N`; BSD date (macOS) does NOT, and silently prints a literal "N" — which is exactly how a phase
# ends up "taking 0 ms" and a latency percentile ends up as a fabricated 0.000. We probe once:
#   * GNU date          → millisecond resolution;
#   * perl Time::HiRes  → millisecond resolution (the usual macOS fallback);
#   * otherwise         → SECOND resolution, and MS_CLOCK=no, which makes this script OMIT the latency
#                         percentiles from the report rather than emit zeros that look measured.
MS_CLOCK=no
if [ -n "$(date +%s%N 2>/dev/null | tr -d '0-9')" ] || [ -z "$(date +%s%N 2>/dev/null)" ]; then
  if command -v perl >/dev/null 2>&1 && perl -MTime::HiRes -e 1 >/dev/null 2>&1; then
    MS_CLOCK=perl
  fi
else
  MS_CLOCK=date
fi
now_ms() {
  case "$MS_CLOCK" in
    date) echo "$(( $(date +%s%N) / 1000000 ))" ;;
    perl) perl -MTime::HiRes=time -e 'printf("%.0f\n", time() * 1000)' ;;
    *)    echo "$(( $(date +%s) * 1000 ))" ;;    # second resolution — see MS_CLOCK above
  esac
}
# strip_ansi — the server's tracing subscriber colourises even when redirected to a file.
strip_ansi() { sed $'s/\033\\[[0-9;]*m//g'; }

# server_vmhwm <pid> — the kernel's PEAK RSS for the process (Linux: VmHWM, exact — not a sample).
# macOS has no VmHWM; fall back to the current RSS from `ps` (a sample, honestly weaker).
server_vmhwm() {
  local pid="$1" bytes=0
  if [ -r "/proc/$pid/status" ]; then
    bytes="$(awk '/^VmHWM:/ {print $2 * 1024}' "/proc/$pid/status" 2>/dev/null || echo 0)"
  elif command -v ps >/dev/null 2>&1; then
    bytes="$(( $(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || echo 0) * 1024 ))"
  fi
  echo "${bytes:-0}"
}
sample_peak_rss() {
  if [ -n "${SERVER_PID:-}" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    local rss; rss="$(server_vmhwm "$SERVER_PID")"
    [ "${rss:-0}" -gt "$PEAK_RSS_BYTES" ] && PEAK_RSS_BYTES="$rss"
  fi
  return 0
}
# server_cpu_ticks <pid> — cumulative "utime stime" in clock ticks (Linux /proc). Empty on macOS.
# /proc/<pid>/stat fields 14 (utime) and 15 (stime); after splitting off the "(comm)" they are the
# 12th and 13th of the remainder.
server_cpu_ticks() {
  local pid="$1"
  [ -r "/proc/$pid/stat" ] || return 0
  awk '{ n = split($0, f, ") "); split(f[n], g, " "); print g[12], g[13] }' "/proc/$pid/stat" 2>/dev/null
}
# accumulate_server_cpu — fold the LIVE server's CPU into the run totals. Called immediately before
# every shutdown/kill, because the process that did the work is GONE by the time the evidence is
# emitted: attributing the run's CPU to the surviving post-recovery pid would be a real number
# describing the wrong process (rmp #697).
CPU_UTIME_TICKS=0
CPU_STIME_TICKS=0
CLK_TCK="$(getconf CLK_TCK 2>/dev/null || echo 100)"
accumulate_server_cpu() {
  local u s
  if [ -n "${SERVER_PID:-}" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    read -r u s <<< "$(server_cpu_ticks "$SERVER_PID")"
    if [ -n "${u:-}" ] && [ -n "${s:-}" ]; then
      CPU_UTIME_TICKS=$(( CPU_UTIME_TICKS + u ))
      CPU_STIME_TICKS=$(( CPU_STIME_TICKS + s ))
    fi
  fi
  return 0
}

# dir_bytes <path> — total bytes of a file or of every regular file under a directory (BY PATH, so a
# WAL *directory* of `seg.<lsn>` files is counted as WAL — never misclassified by its leaf file name).
dir_bytes() {
  local p="$1"
  [ -e "$p" ] || { echo 0; return 0; }
  find "$p" -type f -exec ls -l {} + 2>/dev/null | awk '{s += $5} END {print s + 0}'
}
# wal_last_lsn — the durable WAL frontier: the highest `seg.<base-lsn>` plus that segment's size.
# (An LSN is a byte offset into the logical log; segment files are named for the LSN they start at.)
wal_last_lsn() {
  [ -d "$WAL_DIR" ] || { echo 0; return 0; }
  local last base size
  last="$(find "$WAL_DIR" -type f -name 'seg.*' 2>/dev/null | sort | tail -n1)"
  [ -n "$last" ] || { echo 0; return 0; }
  base="$(basename "$last" | sed 's/^seg\.0*//')"; base="${base:-0}"
  size="$(ls -l "$last" | awk '{print $5}')"
  echo $(( base + size ))
}

# --------------------------------------------------------------------------------------------------
# Server lifecycle (this example OWNS it)
# --------------------------------------------------------------------------------------------------
start_server() {
  BOOT=$((BOOT + 1))
  SERVER_LOG="$WORKDIR/server.$BOOT.log"     # one log per boot, so recovery can be attributed to THIS boot
  "$SERVER" "$CONFIG" >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  SERVER_START_EPOCH="$(date +%s)"
  local _
  for _ in $(seq 1 300); do
    [ -S "$SOCKET" ] && return 0
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      echo "${RED}server exited during startup; last log lines:${RESET}" >&2
      tail -n 20 "$SERVER_LOG" >&2
      exit 1
    fi
    sleep 0.1
  done
  echo "${RED}server did not bind UDS $SOCKET within timeout${RESET}" >&2
  tail -n 20 "$SERVER_LOG" >&2
  exit 1
}

stop_server_graceful() {
  sample_peak_rss
  accumulate_server_cpu
  if [ -n "${SERVER_PID:-}" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  SERVER_PID=""
}

# crash_server — a power-failure simulation: SIGKILL leaves the process no chance to flush or shut
# down. Recovery must then rely entirely on the durable WAL + store.
crash_server() {
  sample_peak_rss
  accumulate_server_cpu
  if [ -n "${SERVER_PID:-}" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -KILL "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -f "$SOCKET"   # the kernel does not unlink the socket file on SIGKILL
  SERVER_PID=""
}

# --------------------------------------------------------------------------------------------------
# The Cypher client seam. EVERY statement is timed and its latency recorded, so the evidence report's
# throughput + p50/p99/p999 are MEASURED, never invented.
#
# What the latency means, precisely: it is the CLIENT-OBSERVED END-TO-END cost of one `graphus-cli`
# invocation — process spawn + UDS connect + Bolt handshake + HELLO/LOGON + RUN/PULL + commit ack.
# That fixed client-side floor is itself measured (the calibration phase below) and reported as
# `client_overhead_p50_ms`, so nobody mistakes these figures for server-side query time.
# --------------------------------------------------------------------------------------------------
cypher() { GRAPHUS_PASSWORD="$ADMIN_PW" "$CLI" --uds "$SOCKET" --user "$ADMIN_USER" -c "$1"; }

# timed_cypher <lat-file> <stmt> — run ONE attempt, append its millisecond latency (every attempt is a
# real round-trip, so every attempt is a real latency sample), and propagate the exit status.
timed_cypher() {
  local lat="$1" stmt="$2" start rc=0
  start="$(now_ms)"
  cypher "$stmt" > /dev/null 2>&1 || rc=$?
  printf '%s\n' "$(( $(now_ms) - start ))" >> "$lat"
  return $rc
}

# tx <worker-id> <stmt> — the workload's unit of work: run the statement, retrying a TRANSIENT SSI
# abort (Neo.TransientError.Transaction.Outdated — "retry") exactly as a real driver would, and tally
# BOTH outcomes separately:
#   $LAT_DIR/<id>.lat    one line per ATTEMPT   (the latency distribution)
#   $RETRY_DIR/<id>.retry one line per ABORT    (the numerator of the measured abort rate)
#   $OK_DIR/<id>.ok      one line per COMMIT    (the ops count behind ops_per_sec)
tx() {
  local id="$1" stmt="$2" attempt=1
  while :; do
    if timed_cypher "$LAT_DIR/$id.lat" "$stmt"; then
      printf 'ok\n' >> "$OK_DIR/$id.ok"
      return 0
    fi
    if [ "$attempt" -ge "$MAX_RETRIES" ]; then
      echo "${RED}statement failed after $MAX_RETRIES attempts:${RESET} ${stmt:0:90}…" >&2
      cypher "$stmt" >&2 || true      # re-run once, un-silenced, so the failure is diagnosable
      return 1
    fi
    printf 'abort\n' >> "$RETRY_DIR/$id.retry"
    attempt=$((attempt + 1))
    sleep 0.05
  done
}

# count_lines <glob...> — total lines across the matching tally files (0 when none exist).
count_lines() { cat "$@" 2>/dev/null | wc -l | tr -d ' '; }

# scalar <stmt> — run a single-column, single-row query and print just the value (untimed: assertions
# must not pollute the workload's latency distribution).
scalar() {
  cypher "$1" | awk -F'|' '
    /^\|/ { rows++; if (rows == 2) { v = $2; gsub(/^[ \t"]+|[ \t"]+$/, "", v); print v } }
  '
}

# percentiles <files...> — nearest-rank p50/p99/p999 (+ count) over every recorded latency sample.
percentiles() {
  cat "$@" 2>/dev/null | sort -n | awk '
    { v[NR] = $1 }
    END {
      if (NR == 0) { print "0 0 0 0"; exit }
      p50  = v[int((NR * 50   + 999) / 1000)]
      p99  = v[int((NR * 99   + 99)  / 100)]
      p999 = v[int((NR * 999  + 999) / 1000)]
      printf "%d %d %d %d\n", NR, p50, p99, p999
    }'
}

# ==================================================================================================
# PHASE 1 — Boot Graphus, connect over UDS, and calibrate the client's own overhead
# ==================================================================================================
RUN_START_MS="$(now_ms)"
section "Phase 1 — Boot Graphus (local, this script owns the process) and connect over UDS"
start_server
info "server pid $SERVER_PID listening on $SOCKET (buffer pool $POOL_PAGES pages)"
assert "server answers a trivial query over UDS" "1" "$(scalar "RETURN 1 AS one")"
assert "graph starts empty" "0" "$(scalar "MATCH (n) RETURN count(n) AS c")"

# The client-overhead floor: how much of every measured latency is `graphus-cli` itself (spawn +
# connect + handshake + auth), independent of the server's query work.
CAL_LAT="$WORKDIR/calibration.lat"
for _ in $(seq 1 12); do timed_cypher "$CAL_LAT" "RETURN 1" || true; done
read -r CAL_N CAL_P50 CAL_P99 _ <<< "$(percentiles "$CAL_LAT")"
info "client-overhead floor over $CAL_N no-op statements: p50 ${CAL_P50} ms, p99 ${CAL_P99} ms"
assert "client-overhead calibration produced samples" "12" "$CAL_N"

# ==================================================================================================
# PHASE 2 — Schema: a UNIQUE constraint, a RANGE index and a TEXT index
# ==================================================================================================
section "Phase 2 — Declare the schema (UNIQUE constraint + RANGE index + TEXT index)"
cypher "CREATE CONSTRAINT person_uid_unique IF NOT EXISTS FOR (p:Person) REQUIRE p.uid IS UNIQUE" >/dev/null
cypher "CREATE INDEX person_city_range     IF NOT EXISTS FOR (p:Person) ON (p.city)" >/dev/null
cypher "CREATE TEXT INDEX post_text_search IF NOT EXISTS FOR (p:Post)   ON (p.text)" >/dev/null
assert "the uniqueness constraint is registered" "1" \
  "$(scalar "SHOW CONSTRAINTS YIELD name WHERE name = 'person_uid_unique' RETURN count(*) AS c")"
assert "the RANGE index is ONLINE" "ONLINE" \
  "$(scalar "SHOW INDEXES YIELD name, state WHERE name = 'person_city_range' RETURN state AS s")"
assert "the TEXT index is ONLINE" "ONLINE" \
  "$(scalar "SHOW INDEXES YIELD name, state WHERE name = 'post_text_search' RETURN state AS s")"

# ==================================================================================================
# PHASE 3 — Build the social graph with MANY SIMULTANEOUS Bolt/UDS clients
# ==================================================================================================
# The dataset is fully deterministic, so every count below can be asserted exactly:
#   Person  uid 1..$PEOPLE, name 'user<uid>', city CITIES[uid % 5], age 18 + uid % 50
#   FRIEND  i -> 1 + ((i * 7) % PEOPLE)                              (i = 1..FRIENDS)
#   FOLLOWS every follower -> the CELEBRITY (uid $CELEBRITY_UID)     — a real supernode, written to by
#           $FOLLOW_WRITERS clients AT THE SAME TIME, which is what makes SSI abort/retry observable
#   POSTED  one Post per author in the writer's range; text mentions one of four topics
section "Phase 3 — Concurrent write workload ($WRITERS + $EDGE_WRITERS + $FOLLOW_WRITERS + $POST_WRITERS simultaneous UDS clients)"
WORKLOAD_START_MS="$(now_ms)"

info "3a — $WRITERS concurrent writers × $BATCHES batches × $BATCH people = $PEOPLE Person nodes"
PIDS=()
for w in $(seq 0 $((WRITERS - 1))); do
  (
    for b in $(seq 0 $((BATCHES - 1))); do
      lo=$(( w * BATCHES * BATCH + b * BATCH + 1 )); hi=$(( lo + BATCH - 1 ))
      tx "w$w" "
        UNWIND range($lo, $hi) AS i
        CREATE (:Person {uid: i,
                         name: 'user' + toString(i),
                         city: ['Lisbon','Porto','Braga','Faro','Evora'][i % 5],
                         age:  18 + (i % 50),
                         joined: 2010 + (i % 16)})" || exit 1
    done
  ) &
  PIDS+=($!)
done
LOAD_FAILED=0
for p in "${PIDS[@]}"; do wait "$p" || LOAD_FAILED=1; done   # NEVER a bare `wait`: the server is a child too
assert "every concurrent person-writer committed" "0" "$LOAD_FAILED"
assert "all $PEOPLE people were created" "$PEOPLE" "$(scalar "MATCH (p:Person) RETURN count(p) AS c")"
sample_peak_rss

info "3b — $EDGE_WRITERS concurrent writers building $FRIENDS FRIEND edges"
PIDS=()
for w in $(seq 0 $((EDGE_WRITERS - 1))); do
  (
    lo=$(( w * EDGES_EACH + 1 )); hi=$(( lo + EDGES_EACH - 1 ))
    tx "e$w" "
      UNWIND range($lo, $hi) AS i
      MATCH (a:Person {uid: i}), (b:Person {uid: 1 + ((i * 7) % $PEOPLE)})
      WHERE a <> b
      CREATE (a)-[:FRIEND {since: 2010 + (i % 16)}]->(b)" || exit 1
  ) &
  PIDS+=($!)
done
EDGE_FAILED=0
for p in "${PIDS[@]}"; do wait "$p" || EDGE_FAILED=1; done
assert "every concurrent edge-writer committed" "0" "$EDGE_FAILED"
assert "all $FRIENDS friendships were created" "$FRIENDS" "$(scalar "MATCH ()-[r:FRIEND]->() RETURN count(r) AS c")"
sample_peak_rss

info "3c — $FOLLOW_WRITERS concurrent writers ALL appending FOLLOWS onto the SAME celebrity (uid $CELEBRITY_UID) — SSI contention"
PIDS=()
for w in $(seq 0 $((FOLLOW_WRITERS - 1))); do
  (
    lo=$(( 100 + w * FOLLOWS_EACH )); hi=$(( lo + FOLLOWS_EACH - 1 ))
    tx "f$w" "
      UNWIND range($lo, $hi) AS i
      MATCH (f:Person {uid: i}), (c:Person {uid: $CELEBRITY_UID})
      WHERE f <> c
      CREATE (f)-[:FOLLOWS {since: 2020 + (i % 6)}]->(c)" || exit 1
  ) &
  PIDS+=($!)
done
FOLLOW_FAILED=0
for p in "${PIDS[@]}"; do wait "$p" || FOLLOW_FAILED=1; done
assert "every concurrent follow-writer eventually committed" "0" "$FOLLOW_FAILED"
assert "all $FOLLOWS follows landed on the celebrity" "$FOLLOWS" \
  "$(scalar "MATCH ()-[r:FOLLOWS]->(:Person {uid: $CELEBRITY_UID}) RETURN count(r) AS c")"

info "3d — $POST_WRITERS concurrent writers publishing $POSTS posts"
PIDS=()
for w in $(seq 0 $((POST_WRITERS - 1))); do
  (
    lo=$(( 1000 + w * POSTS_EACH )); hi=$(( lo + POSTS_EACH - 1 ))
    tx "p$w" "
      UNWIND range($lo, $hi) AS i
      MATCH (a:Person {uid: i})
      CREATE (a)-[:POSTED {at: 1700000000 + i}]->(
        :Post {pid: i,
               likes: i % 50,
               text: 'post ' + toString(i) + ' about ' +
                     ['graphs','databases','durability','cypher'][i % 4]})" || exit 1
  ) &
  PIDS+=($!)
done
POST_FAILED=0
for p in "${PIDS[@]}"; do wait "$p" || POST_FAILED=1; done
assert "every concurrent post-writer committed" "0" "$POST_FAILED"
assert "all $POSTS posts were published" "$POSTS" "$(scalar "MATCH (:Post) RETURN count(*) AS c")"
sample_peak_rss

WRITE_MS=$(( $(now_ms) - WORKLOAD_START_MS ))
WRITE_STMTS="$(count_lines "$OK_DIR"/w*.ok "$OK_DIR"/e*.ok "$OK_DIR"/f*.ok "$OK_DIR"/p*.ok)"
WRITE_ABORTS="$(count_lines "$RETRY_DIR"/*.retry)"
info "write workload: $WRITE_STMTS committed statements in ${WRITE_MS} ms, $WRITE_ABORTS SSI abort(s) retried"

# ==================================================================================================
# PHASE 4 — Concurrent read battery (many simultaneous readers, while the writers' data is served)
# ==================================================================================================
section "Phase 4 — Concurrent read battery ($READERS simultaneous UDS clients × $READ_ROUNDS rounds)"
READ_START_MS="$(now_ms)"
PIDS=()
for r in $(seq 0 $((READERS - 1))); do
  (
    me=$(( (r * 37) % PEOPLE + 1 ))
    for _ in $(seq 1 "$READ_ROUNDS"); do
      tx "r$r" "MATCH (:Person {uid: $me})-[:FRIEND]-(f:Person) RETURN count(DISTINCT f) AS c" || exit 1
      tx "r$r" "
        MATCH (me:Person {uid: $me})-[:FRIEND]-(:Person)-[:FRIEND]-(fof:Person)
        WHERE fof <> me AND NOT (me)-[:FRIEND]-(fof)
        RETURN count(DISTINCT fof) AS c" || exit 1
      tx "r$r" "
        MATCH (p:Person)<-[:FOLLOWS]-(f:Person)
        RETURN p.uid AS uid, count(f) AS followers
        ORDER BY followers DESC, uid ASC LIMIT 3" || exit 1
      tx "r$r" "MATCH (p:Person {city: 'Lisbon'}) RETURN count(p) AS c" || exit 1
      tx "r$r" "MATCH (p:Post) WHERE p.text CONTAINS 'durability' RETURN count(p) AS c" || exit 1
      tx "r$r" "
        MATCH (a:Person)-[:POSTED]->(p:Post)
        RETURN a.uid AS author, sum(p.likes) AS likes
        ORDER BY likes DESC, author ASC LIMIT 5" || exit 1
    done
  ) &
  PIDS+=($!)
done
READ_FAILED=0
for p in "${PIDS[@]}"; do wait "$p" || READ_FAILED=1; done
READ_MS=$(( $(now_ms) - READ_START_MS ))
READ_STMTS="$(count_lines "$OK_DIR"/r*.ok)"
assert "every concurrent reader completed" "0" "$READ_FAILED"
assert "the read battery ran every query" "$(( READERS * READ_ROUNDS * 6 ))" "$READ_STMTS"
info "read workload: $READ_STMTS statements in ${READ_MS} ms across $READERS simultaneous clients"
sample_peak_rss

# ==================================================================================================
# PHASE 5 — Verify the traversals and searches return the RIGHT answers (deterministic dataset)
# ==================================================================================================
section "Phase 5 — Search and traverse (correctness of the concurrent build)"
# Every Lisbon person has uid % 5 == 1 → exactly PEOPLE/5 of them (PEOPLE is a multiple of 5).
assert "index-backed city filter is exact" "$(( PEOPLE / 5 ))" \
  "$(scalar "MATCH (p:Person {city: 'Lisbon'}) RETURN count(p) AS c")"
# The celebrity is, by construction, the most-followed person in the graph.
assert "the celebrity is the most-followed person" "$CELEBRITY_UID" \
  "$(scalar "MATCH (p:Person)<-[:FOLLOWS]-(f)
             WITH p, count(f) AS followers
             RETURN p.uid AS uid ORDER BY followers DESC, uid ASC LIMIT 1")"
assert "the celebrity's follower count is exact" "$FOLLOWS" \
  "$(scalar "MATCH (:Person {uid: $CELEBRITY_UID})<-[r:FOLLOWS]-() RETURN count(r) AS c")"
# Post texts cycle through four topics → exactly a quarter mention 'durability' (POSTS is a multiple of 4).
assert "TEXT-index search finds every 'durability' post" "$(( POSTS / 4 ))" \
  "$(scalar "MATCH (p:Post) WHERE p.text CONTAINS 'durability' RETURN count(p) AS c")"
# A friend-of-friend recommendation for person 1 must exclude self and existing friends.
FOF_1="$(scalar "MATCH (me:Person {uid: 1})-[:FRIEND]-(:Person)-[:FRIEND]-(fof:Person)
                 WHERE fof <> me AND NOT (me)-[:FRIEND]-(fof)
                 RETURN count(DISTINCT fof) AS c")"
info "friend-of-friend recommendations for person 1: $FOF_1"
assert "friend-of-friend recommendations are non-empty" "yes" \
  "$([ "${FOF_1:-0}" -gt 0 ] && echo yes || echo no)"

NODES_BEFORE="$(scalar "MATCH (n) RETURN count(n) AS c")"
RELS_BEFORE="$(scalar "MATCH ()-[r]->() RETURN count(r) AS c")"
assert "total node count is exactly people + posts" "$(( PEOPLE + POSTS ))" "$NODES_BEFORE"
assert "total relationship count is exactly friends + follows + posted" \
  "$(( FRIENDS + FOLLOWS + POSTS ))" "$RELS_BEFORE"

# ==================================================================================================
# PHASE 6 — Graceful restart: the data survives a clean shutdown + reboot
# ==================================================================================================
section "Phase 6 — Graceful restart (SIGTERM → clean shutdown → reboot from the same store)"
stop_server_graceful
assert "the socket is gone after a clean shutdown" "yes" "$([ -S "$SOCKET" ] && echo no || echo yes)"
start_server
info "server rebooted (pid $SERVER_PID) from $DATA_DIR"
assert "node count survived the graceful restart" "$NODES_BEFORE" "$(scalar "MATCH (n) RETURN count(n) AS c")"
assert "relationship count survived the graceful restart" "$RELS_BEFORE" "$(scalar "MATCH ()-[r]->() RETURN count(r) AS c")"
assert "a node property survived (user7's city)" "$(scalar "RETURN ['Lisbon','Porto','Braga','Faro','Evora'][7 % 5] AS c")" \
  "$(scalar "MATCH (p:Person {uid: 7}) RETURN p.city AS city")"
assert "the schema survived (the TEXT index is still ONLINE)" "ONLINE" \
  "$(scalar "SHOW INDEXES YIELD name, state WHERE name = 'post_text_search' RETURN state AS s")"

# ==================================================================================================
# PHASE 7 — Manipulate the data (SET / MERGE / DELETE / DETACH DELETE)
# ==================================================================================================
section "Phase 7 — Manipulate data (SET / MERGE / DELETE / DETACH DELETE)"
cypher "MATCH (p:Person {uid: 2}) SET p.city = 'Madrid' RETURN p.city AS city" > /dev/null
assert "SET moved person 2 to Madrid" "Madrid" "$(scalar "MATCH (p:Person {uid: 2}) RETURN p.city AS city")"

cypher "MATCH (a:Person {uid: 2}), (b:Person {uid: 3})
        MERGE (a)-[:FRIEND {since: 2026}]->(b) RETURN 1 AS ok" > /dev/null
assert "MERGE created the 2–3 friendship" "1" \
  "$(scalar "MATCH (:Person {uid: 2})-[r:FRIEND {since: 2026}]->(:Person {uid: 3}) RETURN count(r) AS c")"

DELETED_FOLLOWS="$(scalar "MATCH (:Person {uid: 100})-[r:FOLLOWS]->(:Person {uid: $CELEBRITY_UID}) RETURN count(r) AS c")"
cypher "MATCH (:Person {uid: 100})-[r:FOLLOWS]->(:Person {uid: $CELEBRITY_UID}) DELETE r" > /dev/null
assert "DELETE removed person 100's follow of the celebrity" "0" \
  "$(scalar "MATCH (:Person {uid: 100})-[r:FOLLOWS]->(:Person {uid: $CELEBRITY_UID}) RETURN count(r) AS c")"

cypher "MATCH (:Person {uid: 1000})-[:POSTED]->(post:Post) DETACH DELETE post" > /dev/null
assert "DETACH DELETE removed one post (and its POSTED edge)" "$(( POSTS - 1 ))" \
  "$(scalar "MATCH (:Post) RETURN count(*) AS c")"

NODES_AFTER_EDIT="$(scalar "MATCH (n) RETURN count(n) AS c")"
RELS_AFTER_EDIT="$(scalar "MATCH ()-[r]->() RETURN count(r) AS c")"
info "totals after manipulation: $NODES_AFTER_EDIT nodes, $RELS_AFTER_EDIT relationships"
sample_peak_rss

# ==================================================================================================
# PHASE 8 — MID-FLIGHT CRASH: acked commit survives, un-acked in-flight write leaves no trace
# ==================================================================================================
# The point of this phase is that the crash lands while the server is ACTIVELY EXECUTING a write.
# Killing an IDLE server proves nothing beyond a graceful stop: everything has already been flushed
# and acknowledged, so there is no committed-or-nothing boundary to test.
section "Phase 8 — Mid-flight crash (acked commit → SIGKILL during a large un-acked write)"

WORKLOAD_PEAK_RSS="$PEAK_RSS_BYTES"   # the peak of the GRAPH workload, before the crash phase's giant write
WAL_BYTES_BEFORE="$(dir_bytes "$WAL_DIR")"
WAL_LAST_LSN_BEFORE="$(wal_last_lsn)"
STORE_BYTES_BEFORE="$(dir_bytes "$STORE_FILE")"
info "durable WAL before the crash: ${WAL_BYTES_BEFORE} bytes, frontier LSN ${WAL_LAST_LSN_BEFORE} (store image ${STORE_BYTES_BEFORE} bytes)"
assert "the workload built a non-empty durable WAL to recover from" "yes" \
  "$([ "${WAL_BYTES_BEFORE:-0}" -gt 0 ] && echo yes || echo no)"
assert "the durable WAL frontier advanced past the header" "yes" \
  "$([ "${WAL_LAST_LSN_BEFORE:-0}" -gt 8 ] && echo yes || echo no)"

# (1) The LAST ACKNOWLEDGED COMMIT. `graphus-cli` only exits 0 after the server has acked the commit,
#     which the server only sends after the WAL is fsynced. This node MUST survive the crash.
ACK_MS="$(now_ms)"
cypher "CREATE (:CrashMarker {tag: 'last-acked-before-crash', at: $ACK_MS})" > /dev/null
assert "the pre-crash commit was acknowledged" "1" \
  "$(scalar "MATCH (m:CrashMarker) RETURN count(m) AS c")"
info "acked commit at ${ACK_MS} — this is the durability boundary the crash must not cross"

# (2) The IN-FLIGHT, UN-ACKED WRITE: one large single-statement transaction the server cannot possibly
#     finish before we kill it. Its client is still blocked awaiting the commit ack when the SIGKILL
#     lands, so NONE of it may survive (committed-or-nothing / atomicity).
INFLIGHT_LOG="$WORKDIR/inflight.log"
(
  cypher "UNWIND range(1, $INFLIGHT_ROWS) AS i
          CREATE (:InFlight {i: i, pad: 'this-write-must-never-survive-the-crash'})" \
    > "$INFLIGHT_LOG" 2>&1
  echo "exit=$?" >> "$INFLIGHT_LOG"
) &
INFLIGHT_PID=$!

# Prove the server is really WORKING on it: its CPU time must advance over the window (Linux /proc).
read -r CPU_U0 CPU_S0 <<< "$(server_cpu_ticks "$SERVER_PID") "
sleep 1
read -r CPU_U1 CPU_S1 <<< "$(server_cpu_ticks "$SERVER_PID") "
INFLIGHT_ALIVE="$(kill -0 "$INFLIGHT_PID" 2>/dev/null && echo yes || echo no)"
assert "the in-flight write is STILL UN-ACKED when the crash lands" "yes" "$INFLIGHT_ALIVE"
if [ -n "${CPU_U0:-}" ] && [ -n "${CPU_U1:-}" ]; then
  CPU_DELTA=$(( (CPU_U1 + CPU_S1) - (CPU_U0 + CPU_S0) ))
  info "server CPU advanced by ${CPU_DELTA} ticks while the un-acked write was executing"
  assert "the server was ACTIVELY executing the write at crash time (CPU advanced)" "yes" \
    "$([ "$CPU_DELTA" -gt 0 ] && echo yes || echo no)"
else
  info "server-CPU probe unavailable (no /proc — macOS); relying on the un-acked-client signal alone"
fi

sample_peak_rss
crash_server
info "SIGKILL delivered mid-write — no flush, no clean shutdown, no goodbye"
wait "$INFLIGHT_PID" 2>/dev/null || true
INFLIGHT_EXIT="$(sed -n 's/^exit=//p' "$INFLIGHT_LOG" | tail -n1)"
assert "the in-flight client never received a commit ack (non-zero exit)" "yes" \
  "$([ "${INFLIGHT_EXIT:-1}" -ne 0 ] && echo yes || echo no)"

# ==================================================================================================
# PHASE 9 — Recovery: prove ARIES really replayed the WAL (a no-op recovery FAILS this run)
# ==================================================================================================
section "Phase 9 — Reboot + ARIES WAL replay (asserted, not assumed)"
REC_START_MS="$(now_ms)"
start_server
REC_MS=$(( $(now_ms) - REC_START_MS ))
info "server recovered and re-bound the socket in ${REC_MS} ms (pid $SERVER_PID)"

# The server logs exactly WHAT recovery did (rmp #697). We parse THIS boot's log — one file per boot —
# so a line from an earlier boot can never satisfy the assertion.
REC_LINE="$(strip_ansi < "$SERVER_LOG" | grep -F 'wal recovery complete' | head -n1 || true)"
assert "the post-crash boot logged a completed WAL recovery" "yes" \
  "$([ -n "$REC_LINE" ] && echo yes || echo no)"
[ -n "$REC_LINE" ] && info "recovery: ${REC_LINE#*wal recovery complete }"

rec_field() { printf '%s' "$REC_LINE" | sed -n "s/.*$1=\([0-9][0-9]*\).*/\1/p" | head -n1; }
REC_SCANNED="$(rec_field records_scanned)"; REC_SCANNED="${REC_SCANNED:-0}"
REC_REDONE="$(rec_field redo_applied)";     REC_REDONE="${REC_REDONE:-0}"
REC_LOSERS="$(rec_field losers)";           REC_LOSERS="${REC_LOSERS:-0}"
REC_CLRS="$(rec_field clrs_written)";       REC_CLRS="${REC_CLRS:-0}"

# THE assertion the old version of this example lacked: recovery must have done REAL WORK. If the
# replay were a no-op (nothing scanned, nothing re-applied) the run FAILS here — which is exactly what
# a silently-skipped recovery would look like from the outside, because the *counts* alone can be
# satisfied by pages that happened to reach the device before the crash.
assert "recovery SCANNED the durable WAL (records_scanned > 0)" "yes" \
  "$([ "$REC_SCANNED" -gt 0 ] && echo yes || echo no)"
assert "recovery ADVANCED the store — redo re-applied logged changes (redo_applied > 0)" "yes" \
  "$([ "$REC_REDONE" -gt 0 ] && echo yes || echo no)"
info "ARIES: scanned $REC_SCANNED records, redid $REC_REDONE changes, undid $REC_LOSERS loser txn(s) writing $REC_CLRS CLRs"

# --- The committed-or-nothing crash partition ------------------------------------------------------
assert "the ACKED pre-crash commit SURVIVED" "1" \
  "$(scalar "MATCH (m:CrashMarker {tag: 'last-acked-before-crash'}) RETURN count(m) AS c")"
assert "…with its exact property intact" "$ACK_MS" \
  "$(scalar "MATCH (m:CrashMarker) RETURN m.at AS at")"
assert "the UN-ACKED in-flight write left NO TRACE" "0" \
  "$(scalar "MATCH (n:InFlight) RETURN count(n) AS c")"

# --- Everything committed before the crash is still there, exactly ---------------------------------
assert "node count survived the crash (+ the marker)" "$(( NODES_AFTER_EDIT + 1 ))" \
  "$(scalar "MATCH (n) RETURN count(n) AS c")"
assert "relationship count survived the crash" "$RELS_AFTER_EDIT" \
  "$(scalar "MATCH ()-[r]->() RETURN count(r) AS c")"
assert "the SET survived the crash (person 2 in Madrid)" "Madrid" \
  "$(scalar "MATCH (p:Person {uid: 2}) RETURN p.city AS city")"
assert "the MERGE survived the crash (2–3 friendship)" "1" \
  "$(scalar "MATCH (:Person {uid: 2})-[r:FRIEND {since: 2026}]->(:Person {uid: 3}) RETURN count(r) AS c")"
assert "the DELETE survived the crash (person 100 still unfollowed the celebrity)" "0" \
  "$(scalar "MATCH (:Person {uid: 100})-[r:FOLLOWS]->(:Person {uid: $CELEBRITY_UID}) RETURN count(r) AS c")"
assert "the DETACH DELETE survived the crash" "$(( POSTS - 1 ))" "$(scalar "MATCH (:Post) RETURN count(*) AS c")"
assert "the celebrity's followers survived the crash" "$(( FOLLOWS - DELETED_FOLLOWS ))" \
  "$(scalar "MATCH (:Person {uid: $CELEBRITY_UID})<-[r:FOLLOWS]-() RETURN count(r) AS c")"
assert "the schema survived the crash (UNIQUE constraint still enforced)" "1" \
  "$(scalar "SHOW CONSTRAINTS YIELD name WHERE name = 'person_uid_unique' RETURN count(*) AS c")"
# The recovered store still refuses a duplicate uid — the constraint is live, not just listed.
DUP_RC=0
cypher "CREATE (:Person {uid: 7, name: 'duplicate'})" >/dev/null 2>&1 || DUP_RC=$?
assert "a duplicate uid is still rejected after recovery" "yes" \
  "$([ "$DUP_RC" -ne 0 ] && echo yes || echo no)"

# ==================================================================================================
# PHASE 10 — Evidence: every figure below is MEASURED (nothing is a placeholder)
# ==================================================================================================
section "Phase 10 — Evidence (CPU / RAM / storage / throughput / latency)"
sample_peak_rss
accumulate_server_cpu          # fold in the RECOVERED server's CPU too — the third and final lifetime
RUN_MS=$(( $(now_ms) - RUN_START_MS ))
[ "$RUN_MS" -lt 1 ] && RUN_MS=1
SERVER_UPTIME_SECS=$(( $(date +%s) - SERVER_START_EPOCH ))
[ "$SERVER_UPTIME_SECS" -lt 1 ] && SERVER_UPTIME_SECS=1

# CPU across ALL THREE server lifetimes (boot → graceful restart → post-crash recovery). The workload
# ran on the FIRST one, which no longer exists, so we hand measure_server the CPU we accumulated
# ourselves rather than let it read the surviving pid and describe the wrong process.
CPU_FLAGS=()
CPU_NOTE="CPU: measured from the surviving (post-recovery) server pid only — this host has no /proc, so the crashed process's CPU could not be accumulated."
if [ "$CPU_UTIME_TICKS" -gt 0 ] || [ "$CPU_STIME_TICKS" -gt 0 ]; then
  CPU_USER_SECS="$(LC_ALL=C awk "BEGIN{printf \"%.3f\", $CPU_UTIME_TICKS / $CLK_TCK}")"
  CPU_SYS_SECS="$(LC_ALL=C awk "BEGIN{printf \"%.3f\", $CPU_STIME_TICKS / $CLK_TCK}")"
  CPU_WINDOW_SECS="$(LC_ALL=C awk "BEGIN{printf \"%.3f\", $RUN_MS / 1000}")"
  CPU_FLAGS=(--cpu-user-secs "$CPU_USER_SECS" --cpu-system-secs "$CPU_SYS_SECS"
             --cpu-window-secs "$CPU_WINDOW_SECS")
  CPU_NOTE="CPU is the SUM over the run's three server lifetimes (initial boot, graceful reboot, post-crash recovery), sampled from /proc/<pid>/stat immediately before each shutdown/kill — the workload's server is dead by evidence time, so reading the surviving pid would describe the wrong process. Window = the ${CPU_WINDOW_SECS}s run."
  info "server CPU across all lifetimes: ${CPU_USER_SECS}s user + ${CPU_SYS_SECS}s system over ${CPU_WINDOW_SECS}s"
fi

# Throughput + latency over the CONCURRENT workload (writes + reads): real statements, real window.
# The `< 1` guards are the macOS second-resolution safety net (rmp #697): a sub-second phase there
# reads as 0 ms, and 0 must never reach a division or be published as a measurement.
WORKLOAD_MS=$(( WRITE_MS + READ_MS ))
[ "$WORKLOAD_MS" -lt 1 ] && WORKLOAD_MS=1
WORKLOAD_STMTS=$(( WRITE_STMTS + READ_STMTS ))
SSI_ABORTS="$(count_lines "$RETRY_DIR"/*.retry)"
ATTEMPTS=$(( WORKLOAD_STMTS + SSI_ABORTS ))
read -r LAT_N LAT_P50 LAT_P99 LAT_P999 <<< "$(percentiles "$LAT_DIR"/*.lat)"
WORKLOAD_SECS="$(LC_ALL=C awk "BEGIN{printf \"%.6f\", $WORKLOAD_MS / 1000}")"
OPS_PER_SEC="$(LC_ALL=C awk "BEGIN{printf \"%.1f\", $WORKLOAD_STMTS / ($WORKLOAD_MS / 1000.0)}")"
# Abort rate = SSI aborts / attempts — MEASURED from the retry tallies, not assumed.
ABORT_RATE="$(LC_ALL=C awk "BEGIN{printf \"%.6f\", ($ATTEMPTS > 0 ? $SSI_ABORTS / $ATTEMPTS : 0)}")"
info "throughput: $WORKLOAD_STMTS committed statements in ${WORKLOAD_MS} ms = ${OPS_PER_SEC} statements/s"
info "SSI abort rate: ${ABORT_RATE} (${SSI_ABORTS} aborts over ${ATTEMPTS} attempts)"

# Latency percentiles: published ONLY when this host has a millisecond clock. On a host that does not
# (BSD `date` without %N and no perl), publishing p50/p99/p999 would mean publishing zeros that LOOK
# measured — the exact dishonesty this example was rebuilt to remove. We omit them instead, and say so.
LAT_FLAGS=()
LAT_NOTE="LATENCY: OMITTED — this host has no millisecond clock (BSD date without %N, no perl Time::HiRes), so no honest per-statement latency could be measured. Zeros are never published in their place."
if [ "$MS_CLOCK" != "no" ]; then
  LAT_FLAGS=(--p50-ms "$LAT_P50" --p99-ms "$LAT_P99" --p999-ms "$LAT_P999")
  LAT_NOTE="LATENCY SEMANTICS: p50/p99/p999 are CLIENT-OBSERVED END-TO-END per graphus-cli invocation (process spawn + UDS connect + Bolt handshake + HELLO/LOGON + RUN/PULL + commit ack), measured over all $LAT_N workload attempts. The client's own floor was calibrated on this host at p50 ${CAL_P50} ms / p99 ${CAL_P99} ms (12 no-op RETURN 1 statements) — subtract it to reason about server-side cost. These are NOT server-side query times."
  info "latency (client-observed end-to-end, incl. a ${CAL_P50} ms client floor): p50 ${LAT_P50} ms, p99 ${LAT_P99} ms, p999 ${LAT_P999} ms over ${LAT_N} attempts"
else
  info "latency percentiles OMITTED: no millisecond clock on this host (a zero placeholder is never emitted)"
fi

# Storage, decomposed BY PATH (the WAL is a DIRECTORY of seg.<lsn> files — classifying by leaf file
# name would count every WAL byte as store and report wal=0).
STORE_BYTES="$(dir_bytes "$STORE_FILE")"
WAL_BYTES="$(dir_bytes "$WAL_DIR")"
DWB_BYTES="$(dir_bytes "$DWB_FILE")"
TOTAL_BYTES="$(dir_bytes "$DATA_DIR")"
OTHER_BYTES=$(( TOTAL_BYTES - STORE_BYTES - WAL_BYTES - DWB_BYTES ))
info "on-disk: store ${STORE_BYTES} B, WAL ${WAL_BYTES} B, doublewrite ${DWB_BYTES} B, catalog/lock ${OTHER_BYTES} B (total ${TOTAL_BYTES} B)"
info "…of which the COMMITTED graph (measured just before the crash) was: store ${STORE_BYTES_BEFORE} B + WAL ${WAL_BYTES_BEFORE} B"

# Logical graph size: the exact user-visible property payload of the durable graph — the i64 property
# values (8 B each) plus the UTF-8 byte length of every string property this run wrote. It is computed
# from the deterministic dataset, NOT estimated, so the space-amplification ratio means something.
LOGICAL_GRAPH_BYTES="$(LC_ALL=C awk -v people="$PEOPLE" -v friends="$FRIENDS" -v follows="$FOLLOWS" \
                                    -v posts="$POSTS" 'BEGIN {
  split("Lisbon Porto Braga Faro Evora", city, " ")
  split("graphs databases durability cypher", topic, " ")
  total = 0
  for (i = 1; i <= people; i++)                       # uid + age + joined (i64) + name + city (UTF-8)
    total += 8 + 8 + 8 + length("user" i) + length(city[(i % 5) + 1])
  total += friends * 8                                # FRIEND.since
  total += follows * 8                                # FOLLOWS.since
  for (n = 0; n < posts; n++) {                       # Post.pid + Post.likes + POSTED.at + Post.text
    i = 1000 + n
    total += 8 + 8 + 8 + length("post " i " about " topic[(i % 4) + 1])
  }
  print total
}')"
# Space amplification of the COMMITTED graph = (store + WAL as they stood just before the crash) per
# logical byte. The post-crash figures also carry the pages the ABORTED 200k-row write extended, which
# say nothing about how Graphus stores a committed graph — so both are reported, each labelled.
SPACE_AMP_COMMITTED="$(LC_ALL=C awk "BEGIN{printf \"%.2f\", ($STORE_BYTES_BEFORE + $WAL_BYTES_BEFORE) / $LOGICAL_GRAPH_BYTES}")"
info "logical graph payload: ${LOGICAL_GRAPH_BYTES} B (exact property bytes, not an estimate)"
info "space amplification of the committed graph: ${SPACE_AMP_COMMITTED}x (store+WAL before the crash / logical payload)"

# The dev-only metering binary. Same anti-staleness rule as harness_build: it is REBUILT (cargo is
# incremental, so that is a no-op when nothing changed) rather than used because a file happens to
# exist — an example whose evidence was produced by a stale metering binary is an example that lies.
# The one exception is an explicit GRAPHUS_BIN_DIR that already carries it: the caller then owns those
# binaries deliberately. It is never silently skipped: without it there is no evidence, and an example
# with no evidence has failed its purpose.
if [ -n "${GRAPHUS_BIN_DIR:-}" ] && [ -x "$GRAPHUS_BIN_DIR/measure_server" ]; then
  MEASURE_BIN="$GRAPHUS_BIN_DIR/measure_server"
  info "using the prebuilt measure_server from GRAPHUS_BIN_DIR"
else
  section "Building the dev-only measure_server harness binary"
  ( cd "$REPO_ROOT" && cargo build -q -p graphus-examples-harness --bin measure_server )
  MEASURE_BIN="$REPO_ROOT/target/debug/measure_server"
fi

EVIDENCE_OK=no
if [ -x "$MEASURE_BIN" ] && [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
  rm -f "$EVIDENCE_DIR/report.json" "$EVIDENCE_DIR/report.md"
  "$MEASURE_BIN" \
    --evidence-dir "$EVIDENCE_DIR" \
    --scenario "social-network-uds" \
    --description "MVP over Bolt/UDS: a concurrent social-graph workload (schema + writes + reads), a graceful restart, and a MID-FLIGHT SIGKILL whose acked commit survives, whose un-acked write leaves no trace, and whose ARIES WAL replay is asserted to have actually run." \
    --pid "$SERVER_PID" \
    --uptime-secs "$SERVER_UPTIME_SECS" \
    --store "$STORE_FILE" \
    --wal "$WAL_DIR" \
    --nodes "$(scalar "MATCH (n) RETURN count(n) AS c")" \
    --rels "$(scalar "MATCH ()-[r]->() RETURN count(r) AS c")" \
    --peak-rss-bytes "$PEAK_RSS_BYTES" \
    --total-millis "$RUN_MS" \
    "${CPU_FLAGS[@]}" \
    --workload-ops "$WORKLOAD_STMTS" \
    --workload-secs "$WORKLOAD_SECS" \
    "${LAT_FLAGS[@]}" \
    --abort-rate "$ABORT_RATE" \
    --logical-graph-bytes "$LOGICAL_GRAPH_BYTES" \
    --param "connection=uds-bolt" \
    --param "profile=$PROFILE" \
    --param "buffer_pool_pages=$POOL_PAGES" \
    --param "concurrent_write_clients=$WRITERS" \
    --param "concurrent_read_clients=$READERS" \
    --param "ssi_aborts_retried=$SSI_ABORTS" \
    --param "statement_attempts=$ATTEMPTS" \
    --param "client_overhead_p50_ms=$CAL_P50" \
    --param "client_overhead_p99_ms=$CAL_P99" \
    --param "write_statements=$WRITE_STMTS" \
    --param "write_window_ms=$WRITE_MS" \
    --param "read_statements=$READ_STMTS" \
    --param "read_window_ms=$READ_MS" \
    --param "restarts=graceful+mid-flight-sigkill" \
    --param "wal_bytes_before_crash=$WAL_BYTES_BEFORE" \
    --param "wal_frontier_lsn_before_crash=$WAL_LAST_LSN_BEFORE" \
    --param "recovery_wall_ms=$REC_MS" \
    --param "recovery_records_scanned=$REC_SCANNED" \
    --param "recovery_redo_applied=$REC_REDONE" \
    --param "recovery_losers_undone=$REC_LOSERS" \
    --param "recovery_clrs_written=$REC_CLRS" \
    --param "storage_dwb_bytes=$DWB_BYTES" \
    --param "storage_catalog_other_bytes=$OTHER_BYTES" \
    --param "storage_total_bytes=$TOTAL_BYTES" \
    --param "storage_store_bytes_committed_graph=$STORE_BYTES_BEFORE" \
    --param "storage_wal_bytes_committed_graph=$WAL_BYTES_BEFORE" \
    --param "space_amplification_committed_graph=$SPACE_AMP_COMMITTED" \
    --param "peak_rss_bytes_graph_workload=$WORKLOAD_PEAK_RSS" \
    --phase "concurrent-writes=$WRITE_MS" \
    --phase "concurrent-reads=$READ_MS" \
    --phase "crash-recovery=$REC_MS" \
    --note "$LAT_NOTE" \
    --note "$CPU_NOTE" \
    --note "STORAGE SEMANTICS: classified BY PATH. store_bytes is the data image ($STORE_FILE); wal_bytes is the WAL DIRECTORY ($WAL_DIR — seg.<lsn> segments + anchor; classifying by LEAF FILE NAME would count every WAL byte as store and report wal=0). The doublewrite ring (${DWB_BYTES} B) and the catalog/lock files (${OTHER_BYTES} B) are reported as parameters, not folded into store_bytes; the on-disk total is ${TOTAL_BYTES} B." \
    --note "SPACE AMPLIFICATION: the reported ratio uses the FINAL on-disk bytes, which include the pages the ABORTED ${INFLIGHT_ROWS}-row write extended before the crash (the store image grew from ${STORE_BYTES_BEFORE} B to ${STORE_BYTES} B during it, holding no committed data). For the COMMITTED graph the ratio is ${SPACE_AMP_COMMITTED}x — see space_amplification_committed_graph." \
    --note "DURABILITY: the SIGKILL landed while the server was EXECUTING a ${INFLIGHT_ROWS}-row un-acked write (its client was still blocked awaiting the commit ack, and the server's CPU was advancing). After the reboot, ARIES recovery scanned ${REC_SCANNED} WAL records, re-applied ${REC_REDONE} logged changes and undid ${REC_LOSERS} loser transaction(s) (${REC_CLRS} CLRs) in ${REC_MS} ms; the last acked commit survived and NOT ONE of the ${INFLIGHT_ROWS} un-acked rows did." \
    --note "PEAK RSS is the kernel's VmHWM high-water mark (exact, not a sample), maximised across this run's three server lifetimes. It is dominated by the un-acked ${INFLIGHT_ROWS}-row transaction buffered in memory at crash time; the peak during the GRAPH workload alone was ${WORKLOAD_PEAK_RSS} B (see peak_rss_bytes_graph_workload)." \
    && EVIDENCE_OK=yes
  assert "evidence collection succeeded" "yes" "$EVIDENCE_OK"
  assert "evidence report.json was produced" "yes" \
    "$([ -f "$EVIDENCE_DIR/report.json" ] && echo yes || echo no)"
  assert "evidence report.md was produced" "yes" \
    "$([ -f "$EVIDENCE_DIR/report.md" ] && echo yes || echo no)"
  # Evidence honesty, GATED. These two assertions exist because the previous version of this example
  # shipped p50/p99/p999 = 0.000 placeholders and a total_millis that was the report's own emit time.
  assert "the report carries a REAL total_millis (the workload's wall-clock, not the emit time)" "yes" \
    "$(grep -q '"total_millis": *0\(\.0*\)\?,' "$EVIDENCE_DIR/report.json" && echo no || echo yes)"
  assert "total_millis matches the measured run window (±2 s)" "yes" \
    "$(LC_ALL=C awk -v want="$RUN_MS" '
         match($0, /"total_millis": *[0-9.]+/) {
           v = substr($0, RSTART, RLENGTH); sub(/.*: */, "", v)
           print ((v - want) < 2000 && (want - v) < 2000) ? "yes" : "no"; exit
         }' "$EVIDENCE_DIR/report.json")"
  if [ "$MS_CLOCK" != "no" ]; then
    assert "the report carries REAL latency percentiles (no zero placeholders)" "yes" \
      "$([ "${LAT_P50:-0}" -gt 0 ] && [ "${LAT_P99:-0}" -gt 0 ] && [ "${LAT_P999:-0}" -gt 0 ] && echo yes || echo no)"
  else
    info "latency-percentile assertion skipped: no millisecond clock (the percentiles were OMITTED, not zeroed)"
  fi
else
  echo "${RED}fatal: measure_server unavailable or the server died — no evidence can be collected${RESET}" >&2
  HARNESS_FAILURES=$((HARNESS_FAILURES + 1))
fi

# ==================================================================================================
# Summary
# ==================================================================================================
stop_server_graceful
section "Result"
printf '%s checks run, %s failures.  (profile: %s — %s people, %s friends, %s follows, %s posts)\n' \
  "$HARNESS_CHECKS" "$HARNESS_FAILURES" "$PROFILE" "$PEOPLE" "$FRIENDS" "$FOLLOWS" "$POSTS"
if [ -f "$EVIDENCE_DIR/report.json" ]; then
  info "standardized evidence: $EVIDENCE_DIR/{report.json, report.md}"
fi
if [ "$HARNESS_FAILURES" -eq 0 ]; then
  printf '%s%sMVP DEMONSTRATION PASSED%s — Graphus served %s simultaneous UDS clients, stored and searched a\n' \
    "$BOLD" "$GREEN" "$RESET" "$(( WRITERS + READERS ))"
  printf 'social graph of %s nodes / %s relationships under real SSI contention, preserved every committed\n' \
    "$NODES_AFTER_EDIT" "$RELS_AFTER_EDIT"
  printf 'change across a graceful restart AND a SIGKILL taken MID-WRITE, replayed %s WAL records on\n' "$REC_SCANNED"
  printf 'recovery (%s redone, %s loser txn undone), and lost NOTHING that was acked — nor kept ANYTHING\n' \
    "$REC_REDONE" "$REC_LOSERS"
  printf 'that was not.\n'
  exit 0
else
  printf '%s%sMVP DEMONSTRATION FAILED%s — %s assertion(s) did not hold.\n' \
    "$BOLD" "$RED" "$RESET" "$HARNESS_FAILURES"
  exit 1
fi
