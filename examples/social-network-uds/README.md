# Social network over UDS — the Graphus MVP demonstration

A real client talks to a real server over a **Unix Domain Socket (Bolt/UDS)**: many simultaneous
clients build and query a social graph, and every committed change survives a graceful restart **and
a crash taken while the server is mid-write**.

It is both a runnable **demonstration** and an executable **E2E test**: every step asserts its result
and the script exits non-zero if any assertion fails.

```bash
examples/social-network-uds/run.sh          # builds (incrementally) and runs — ~1 minute
MVP_PROFILE=large examples/social-network-uds/run.sh   # a bigger graph
GRAPHUS_BIN_DIR=target/release examples/social-network-uds/run.sh   # use pre-built binaries
```

## This example is LOCAL-ONLY — and that is deliberate

Every other example can be pointed at an already-running instance with `GRAPHUS_TARGET_*` (see
[`examples/README.md`](../README.md)). This one **refuses to**, and exits with a clear message if you
try. It is the documented exception in [`examples/CLAUDE.md`](../CLAUDE.md), for three independent
reasons — each of which makes an external target either impossible or destructive:

| Why | Detail |
|-----|--------|
| **PID signals** | The durability proof is a real `kill -KILL` of the server process, delivered *mid-write*. You cannot SIGKILL a process you do not own — and must never SIGKILL somebody's shared instance. |
| **Peer-cred uid** | The UDS gate authenticates the caller's kernel-supplied uid (`SO_PEERCRED`) against `auth.admin_uid`. The config must therefore be generated for **this** process's uid; a pre-existing server was configured for a different one. |
| **`count == 0` bootstrap** | The run asserts the graph **starts empty** and then asserts **exact global counts** (`MATCH (n) RETURN count(n)`) across both restarts. That is only meaningful on a store this script created; against a shared instance it is either wrong or destructive. |

For a wire-level workload against a live instance, use
[`social-network-large`](../social-network-large/) or
[`product-recommendations`](../product-recommendations/).

## What it demonstrates

| # | Capability | How it is shown |
|---|------------|-----------------|
| 1 | **UDS connectivity** | Boots `graphus-server` with a UDS-only config; the real `graphus-cli` connects over the socket (peer-cred + password auth). |
| 2 | **Schema** | A `UNIQUE` constraint (`Person.uid`), a `RANGE` index (`Person.city`) and a `TEXT` index (`Post.text`) — declared, listed via `SHOW`, used by the queries, and still enforced after the crash. |
| 3 | **Concurrent writes** | 6 + 4 + 6 + 4 simultaneous Bolt/UDS clients build the graph: `Person` nodes, `FRIEND` edges, `FOLLOWS` edges, and `POSTED` → `Post`. |
| 4 | **Real SSI contention** | All six follow-writers append to the **same celebrity node** at once. Serializable Snapshot Isolation aborts the conflicting transactions; the client retries them (as a driver would) and the **abort rate is measured**. |
| 5 | **Search + traversal** | Direct friends, friend-of-friend recommendations, most-followed aggregation, index-backed city filter, `CONTAINS` text search, top-authors aggregation — driven by 8 concurrent readers, then asserted exactly. |
| 6 | **Mutation** | `SET`, `MERGE`, `DELETE`, `DETACH DELETE`. |
| 7 | **Graceful restart** | `SIGTERM` → clean shutdown → reboot from the same store; counts, properties and schema unchanged. |
| 8 | **MID-FLIGHT crash (ACID D + A)** | See below. |
| 9 | **Evidence** | Real CPU / peak RSS / on-disk footprint / throughput / latency — every figure measured. |

## The durability proof

A SIGKILL delivered to an **idle** server proves nothing a graceful stop does not: everything has
already been flushed and acknowledged. This example therefore crashes the server **while it is
executing a write**:

1. **An acknowledged commit.** `CREATE (:CrashMarker {...})` returns only after the server acks the
   commit — which it sends only after the WAL is `fsync`ed. This is the durability boundary.
2. **A large un-acked write.** A single `UNWIND range(1, 200000) … CREATE (:InFlight …)` transaction
   is launched on another connection. Before the kill the run asserts that its client is **still
   blocked awaiting the ack** and that the **server's CPU time is advancing** (`/proc/<pid>/stat`) —
   so the crash provably lands mid-transaction, not between transactions.
3. **`kill -KILL`.** No flush, no clean shutdown.
4. **Reboot, then assert what recovery DID.** The server logs a `wal recovery complete` line carrying
   the ARIES `RecoveryReport` counters. The run parses **this boot's** log and fails unless recovery
   **scanned the WAL** (`records_scanned > 0`) *and* **re-applied logged changes**
   (`redo_applied > 0`).
5. **The crash partition.** The acked commit survived, with its exact property; **not one** of the
   200,000 un-acked rows did; and every pre-crash count, property, edge and constraint is intact.

Step 4 matters more than it looks. Recovery could be a **complete no-op** and steps 1–5's *counts*
would still pass, because pages that happened to reach the device before the crash satisfy them. That
was verified, not assumed: with `recover_device_with_dwb` stubbed out, this run **fails 10
assertions** — including the two recovery-counter assertions and "the ACKED pre-crash commit
SURVIVED" (committed data is silently lost without the replay). The same property is pinned in CI by
`crates/graphus-server/tests/mvp_social_network_uds.rs`.

## Evidence

`run.sh` writes the standardized, schema-versioned `evidence/report.json` + `report.md`
(git-ignored). Every number is measured; **nothing is a placeholder**. The figures below are one
observed run of the default `fast` profile on the development host (16-core x86_64 Linux, `rustc
1.96.0`, release binaries) — they are illustrative of the *shape* of the evidence, not a promise:

| Vector | Measured | Notes |
|--------|----------|-------|
| Graph | 2,640 nodes / 1,680 relationships | 2,400 `Person`, 240 `Post`; 1,200 `FRIEND`, 240 `FOLLOWS`, 240 `POSTED` |
| Throughput | **122 committed statements in 7.3 s** (16.7 stmt/s) | Statements are batches (200 people, or 300 edges, each in ONE transaction) — not per-row ops |
| Latency | **p50 41 ms, p99 4,865 ms** | Client-observed end-to-end per `graphus-cli` invocation, incl. a **measured 19 ms client floor** (process spawn + connect + handshake + auth). *Not* server-side query time. The p99 is a 300-edge write statement |
| SSI aborts | **1 abort / 123 attempts** (0.8%) | Six writers appending to the same celebrity node; the abort was retried and committed |
| CPU | **12.42 s user + 1.21 s system over 10.4 s** (1.31 cores) | Summed across the run's **three** server lifetimes — the process that ran the workload is dead by evidence time |
| Peak RSS | **870 MB** (kernel `VmHWM`) | Dominated by the un-acked 200k-row transaction buffered at crash time; during the **graph workload alone** the peak was **635 MB** |
| Storage (committed graph) | store **1.48 MB** + WAL **6.53 MB** | Measured immediately before the crash, classified **by path** |
| Storage (other) | doublewrite ring **8.87 MB**, catalog/lock 256 B | Reported separately, never folded into `store_bytes` |
| Space amplification | **72.4×** (committed graph) | (store + WAL) / **110,673 B** of logical payload — the exact property bytes the run wrote, computed from the deterministic dataset |
| Recovery | **50,494 WAL records scanned, 30 changes redone, 0 losers, 309 ms** | Kill → socket re-bound |

Reading the storage numbers: the WAL (6.53 MB) dwarfs both the data image (1.48 MB) and the logical
payload (0.11 MB) — the space amplification is overwhelmingly **WAL amplification**, not data-image
overhead. The `report.json` `space_amplification` field uses the **final** on-disk bytes, which also
include the pages the *aborted* 200k-row write extended (the image grew to 7.6 MB); the committed
graph's ratio is reported separately as `space_amplification_committed_graph`.

`write_amplification` stays `0.0` — the schema's honest "not measured" — because this example does not
instrument the logical bytes written per commit.

## Portability

* **Linux + macOS.** The mid-flight CPU probe and the exact `VmHWM` peak-RSS reading use `/proc`; on
  macOS the run still passes, falling back to the "client has not been acked yet" liveness signal and
  a sampled RSS.
* **No millisecond clock?** BSD `date` has no `%N`. The script probes for a millisecond clock (GNU
  `date`, else `perl Time::HiRes`) and, if it finds none, **omits** the latency percentiles from the
  report rather than publishing zeros that look measured. Phase timings fall back to second
  resolution and are floored at 1 ms so no division by zero can occur.

## CI coverage

`crates/graphus-server/tests/mvp_social_network_uds.rs` runs the same scenario under `cargo test`
against the real server binary:

* `mvp_social_network_over_uds_survives_restart_and_crash` — the end-to-end MVP walk.
* `mid_flight_crash_keeps_the_acked_commit_discards_the_unacked_and_proves_the_wal_replayed` — the
  `rmp` #697 regression: the crash is mid-flight, the acked commit survives, the un-acked write leaves
  no trace, and the WAL replay is asserted to have actually happened.
