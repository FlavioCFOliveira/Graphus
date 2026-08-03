# 04 — Technical Design (the "HOW")

This document is the **implementation-design layer** for Graphus. The functional baseline
(`00-overview.md`, `01-needs-survey.md`) defines *what* the server must do; the decision register
(`02-decision-register.md`) records the *ratified* choices. This document specifies *how* to build
it: concrete crate boundaries, on-disk layouts, byte-level record formats, algorithms, and the
control/data flow an engineer codes against.

It is written to be **prescriptive**. Where a choice is still gated on measurement (project rules
"measure to decide" and "never guess"), it is flagged inline and collected in §12. Decision IDs
(`D-…`) refer to `02-decision-register.md`; source short-names refer to §13 and to `03-sources.md`.

> **Inviolable constraints that gate every design here:** 100% ACID, 100% openCypher TCK,
> 100% Bolt protocol, and 100% PackStream.
> Wherever this document and those constraints could diverge, the constraint wins, and the
> divergence is escalated rather than silently resolved.

---

## 1. Architecture overview

### 1.1 Layered component model

Graphus is a single-node server with a strict layering. Upper layers depend only on the public API
of the layer immediately below; the storage/recovery core has **no** dependency on the network or
query layers, which keeps it testable in isolation and inside the deterministic simulator (§11).

```
                         ┌──────────────────────────────────────────────────────┐
   clients               │  Bolt driver (UDS)   Bolt driver (TCP/TLS)   HTTP/TLS │
                         └─────────┬───────────────────┬───────────────────┬─────┘
                                   │                    │                   │
 ┌─────────────────────────────────────────────────────────────────────────────────────┐
 │ CONNECTIVITY LAYER                                                                     │
 │  graphus-bolt  (PackStream codec, chunking, handshake, server-state machine)          │
 │  graphus-rest  (axum: transactional HTTP API, Jolt/CBOR, NDJSON streaming)            │
 │  graphus-auth  (SO_PEERCRED, JWT/Bearer, RBAC — shared by all three listeners)        │
 └───────────────────────────────────────┬───────────────────────────────────────────────┘
                                          │  Session / typed Value model (one model, three skins)
 ┌─────────────────────────────────────────────────────────────────────────────────────┐
 │ QUERY LAYER                                                                           │
 │  graphus-cypher  lexer → parser → AST → semantic analysis → logical plan →            │
 │                  physical plan → executor (Volcano + vectorized scans); plan cache    │
 └───────────────────────────────────────┬───────────────────────────────────────────────┘
                                          │  Cursor / Row stream over typed Values
 ┌─────────────────────────────────────────────────────────────────────────────────────┐
 │ ACCESS / TRANSACTION LAYER                                                            │
 │  graphus-txn   MVCC version store, SSI dangerous-structure tracker, lock/latch mgr,   │
 │                snapshot & timestamp oracle, GC of old versions                        │
 │  graphus-index B+-tree, token-lookup, composite & relationship-property indexes,      │
 │                constraint enforcement                                                 │
 └───────────────────────────────────────┬───────────────────────────────────────────────┘
                                          │  Page / record reads & writes, all WAL-logged
 ┌─────────────────────────────────────────────────────────────────────────────────────┐
 │ STORAGE / DURABILITY CORE                                                            │
 │  graphus-storage  record store (nodes/rels/properties/tokens), index-free adjacency  │
 │  graphus-bufpool  self-managed buffer pool, pin/latch, eviction, prefetch            │
 │  graphus-wal      ARIES WAL, group commit, checkpoints, three-phase recovery         │
 │  graphus-io       epoll/kqueue + optional io_uring; dedicated fsync threads          │
 └───────────────────────────────────────────────────────────────────────────────────────┘
```

Two cross-cutting crates wrap the whole stack:

- `graphus-sim` — the **deterministic environment** (clock, RNG, I/O, scheduler) that every other
  crate is parameterized over (§11). In production it forwards to the real OS; in tests it is a
  controllable, reproducible simulation with fault injection.
- `graphus-core` — shared vocabulary types depended on by everyone: `ElementId`, `PageId`, `Lsn`,
  `TxnId`, `Timestamp`, the `Value` enum (Cypher value space), error types, and the
  `Clock`/`Rng`/`FileSystem`/`Spawn` capability traits that `graphus-sim` implements.

### 1.2 Cargo workspace layout

A single Cargo workspace, Edition 2024, 64-bit-only targets (`D-target-matrix`). Library crates use
`thiserror` for concrete error enums; only the binary crates (`graphus-server`, `graphus-cli`) use
`anyhow` at their boundary.

| Crate | Kind | Responsibility |
| --- | --- | --- |
| `graphus-core` | lib | IDs, `Value`/type model, error taxonomy, capability traits (`Clock`,`Rng`,`FileSystem`,`Spawn`), constants (page size logic, magic numbers, format version). |
| `graphus-sim` | lib | Deterministic + production implementations of the capability traits; fault-injection hooks; the simulation scheduler. |
| `graphus-io` | lib | Async file/socket I/O; epoll/kqueue baseline + io_uring fast path with runtime fallback (`D-io-backend`); dedicated fsync threads. |
| `graphus-wal` | lib | WAL record format, log writer with group commit, LSN allocation, checkpointer, ARIES analysis/redo/undo, recovery driver. |
| `graphus-bufpool` | lib | Frame table, page latches, pin counts, eviction (CLOCK/2Q), prefetch, write-back coordination with WAL (WAL rule). |
| `graphus-storage` | lib | Page formats; node/relationship/property/label record codecs; index-free adjacency chains; token/dictionary store; free-space management; element-ID→physical-ID map. |
| `graphus-index` | lib | B+-tree, token-lookup index, composite & relationship-property indexes; constraint checks; index recovery. |
| `graphus-txn` | lib | Transaction lifecycle, MVCC version chains and their undo deltas, visibility, SSI conflict tracker, timestamp oracle, version GC, write-conflict detection (§5.7), latch policy. |
| `graphus-cypher` | lib | Full Cypher compile/execute pipeline; plan cache; runtime operators; error-phase split; result cursors. |
| `graphus-bolt` | lib | PackStream v1, chunked framing, handshake, Bolt server-state machine; transport-agnostic over UDS and TCP. |
| `graphus-rest` | lib | HTTP transactional API (axum/hyper), Jolt-style typed JSON + CBOR negotiation, NDJSON streaming, RFC 9457 errors. |
| `graphus-auth` | lib | `SO_PEERCRED` peer auth, JWT/Bearer verification, RBAC model, shared across listeners. |
| `graphus-sysres` | lib | Best-effort, one-shot **hardware-resource probe** run once at startup: logical CPUs, physical RAM (total/available), and the store filesystem's capacity/free space plus an SSD-vs-rotational hint. Isolates all OS-specific and `unsafe` probing (rustix `sysinfo`/`statvfs`, `/proc`, `/sys`, macOS `sysctl`) behind a safe API so `graphus-server` stays `#![forbid(unsafe_code)]`. A true leaf: no dependency on any other Graphus crate (`D-hw-autotune`, §9.5). |
| `graphus-server` | bin | Process entry point: config, listener wiring, runtime construction, admission control, graceful shutdown, observability. |
| `graphus-cli` | bin | Interactive shell + admin client (Bolt over UDS by default). |
| `graphus-tck` | test-harness lib+bin | openCypher TCK runner (Rust `cucumber`) + JVM `tck-api` oracle bridge. |
| `graphus-dst` | test bin | Deterministic simulation scenarios + fault schedules driving the whole engine through `graphus-sim`. |
| `graphus-bench` | bench | Criterion micro-benchmarks + LDBC SNB macro harness. |
| `graphus-elle` | test bin | History recorder + Elle/Jepsen-style anomaly export for isolation verification. |

> **Dependency rule (enforced by `cargo-deny` + an architecture test):** `graphus-storage`,
> `graphus-bufpool`, `graphus-wal`, `graphus-txn`, `graphus-index` must not depend on
> `graphus-bolt`, `graphus-rest`, `graphus-cypher`, or any network crate. The storage/txn core is a
> closed subsystem.

### 1.3 Request → commit data flow

A write query over Bolt, end to end:

1. **Ingress.** `graphus-bolt` reads chunked bytes from a UDS/TCP connection, reassembles a
   PackStream message, decodes it (`RUN`/`PULL`/`BEGIN`/…), and advances the Bolt server-state
   machine. Auth was established at `HELLO`/`LOGON`. The session holds a bounded inbound queue
   (backpressure, §9).
2. **Transaction binding.** The message maps to a `Session` operation. An explicit `BEGIN` (or an
   implicit auto-commit `RUN`) asks `graphus-txn` for a transaction: it is assigned a `TxnId` and a
   **begin timestamp** (snapshot) from the timestamp oracle. Access mode (read/write) is recorded.
3. **Compile.** The Cypher text + parameters go to `graphus-cypher`. The plan cache is keyed by the
   normalized query string + schema version; on miss, the pipeline runs lexer → parser → AST →
   semantic analysis (this is where **all compile-time TCK errors** must be raised, §7.3) → logical
   plan → physical plan. Parameters are *not* part of the cache key (they bind at execution).
4. **Execute.** The physical plan is a tree of operators pulling rows (Volcano) with vectorized leaf
   scans (§7.4). Reads go through `graphus-txn` visibility against the snapshot; index lookups go
   through `graphus-index`; raw record/page access goes through `graphus-bufpool` →
   `graphus-storage`. Writes are buffered as **versioned deltas** in the txn's private workspace and
   appended to the WAL as redo/undo log records (`graphus-wal`), but pages are modified under the
   **no-force / steal** policy (§4).
5. **Stream results.** Result rows are produced lazily and pushed back as PackStream `RECORD`
   messages (or NDJSON lines on REST), respecting the client's `PULL n` demand (flow control).
6. **Commit.** On `COMMIT`, `graphus-txn` runs **SSI validation**: it checks the transaction's
   read/write sets against the dangerous-structure tracker (rw-antidependencies). If a dangerous
   structure that can form a cycle is detected, the transaction is **aborted** (serialization
   failure → retriable error). Otherwise it is assigned a **commit timestamp**, a `COMMIT` WAL
   record is appended, and the commit blocks until the WAL is **group-committed and `fdatasync`'d**
   (`D-durability-mode`). Only then is `SUCCESS` returned. Constraint and uniqueness checks are part
   of validation (§6.5).
7. **Acknowledge.** `graphus-bolt` emits the trailing `SUCCESS` with the result summary. On any
   failure the connection enters the FAILED state and ignores messages until `RESET` (§8.1).

REST follows the same spine; only the codec (Jolt/CBOR), framing (NDJSON), and the transactional
URL surface differ (§8.2). **All three interfaces converge on one executor and one `Value` model.**

---

## 2. Storage engine

`graphus-storage` is a **custom record store with index-free adjacency**, built in-house from day
one (`D-storage-arch`). The design is in the lineage of Neo4j's fixed-size record store (Sources:
Neo4j storage internals) but is MVCC-native and owns its own recovery.

### 2.1 On-disk file organization

The database is a directory. All multi-byte integers are **little-endian** (assumed native for our
targets) but the byte order is **fixed in the format** and asserted on load; a 1-byte endianness
marker in the superblock guards against accidental cross-endian mounts.

```
<datadir>/
  graphus.super         # superblock: magic, format version, logical page size, endianness,
                        #   creation ULID, last clean checkpoint LSN, store UUIDs
  store/
    nodes.store         # fixed-size node records, paged
    rels.store          # fixed-size relationship records, paged
    props.store         # fixed-size property records (overflow-chained), paged
    strings.store       # variable-length large-string / large-list heap, block-chained
    tokens.store        # label / reltype / propkey dictionary (id ↔ name)
    idmap.store         # public ElementId → physical id mapping (persistent, append-mostly)
  index/
    <indexid>.idx       # one B+-tree file per index (token, range, composite, rel-prop)
  wal/
    0000000001.wal …    # segmented write-ahead log
    checkpoint/         # fuzzy-checkpoint snapshots of dirty-page table + active-txn table
  doublewrite.dwb       # doublewrite buffer for torn-write protection (§4.5)
```

Each `*.store` file is an array of **logical pages** (§3). A store's records are addressed by
`(page, slot)`; for the fixed-size stores the record id is a pure arithmetic function of its byte
offset, which makes index-free adjacency a constant-time pointer chase.

### 2.2 Logical IDs vs physical IDs

- **Physical id** (`u64`): the in-store record number (node id, relationship id, property id). Dense,
  compact, used for *all* internal pointers (adjacency chains, property chains, index leaves). May be
  **reused** after a record is freed and GC'd, exactly because it is private and never exposed.
- **Public `ElementId`**: a stable, **never-reused** 128-bit ID (ULID or UUIDv7 — `D-element-id`;
  exact choice in §12-Q1). Exposed to clients (`elementId()`), embedded in Bolt/REST payloads,
  stable across compaction and id reuse. Stored in `idmap.store` as a sorted/searchable mapping
  `ElementId → physical id (+ kind)`, with the reverse direction held inline in each record header
  (the record stores its own `ElementId`, so id→record needs no second lookup).

> **TCK tension (`D-element-id`, open Q in §12).** The TCK and some Cypher semantics historically
> assume integer `id()` that may be reused. Graphus exposes the never-reused `ElementId` as the
> canonical identity; the legacy integer `id()` is supported as a compatibility surface mapped to
> the physical id, with reuse semantics documented. The exact reconciliation is escalated, not
> guessed.

### 2.3 Record layouts

Records are **fixed-size** within each store (cache- and arithmetic-friendly). Variable data
(strings, large lists) lives in `strings.store` and is referenced by id. Every record carries an
MVCC header so versioning is intrinsic to the store, not bolted on.

All layouts below are the **logical fields**; sizes are the design target, and the frozen byte-exact
layouts are in `05-storage-format.md` §9. The §12 version-storage spike that once gated this section
is **resolved** (`D-version-representation`, 2026-08-02): the MVCC header is **inline** in every
record, and `version_ptr` is the head of that entity's unified undo-delta chain (§5.1).

**Common MVCC record header (in every node/rel/property record):**

| Field | Bytes | Meaning |
| --- | --- | --- |
| `flags` | 1 | in-use, is-tombstone, has-overflow, dense-node bits |
| `xmin` | 8 | creating transaction's commit timestamp (or txid while uncommitted) |
| `xmax` | 8 | deleting/superseding transaction's commit timestamp (0 = live) |
| `version_ptr` | 8 | physical id of older version (undo/version chain head; 0 = none) |

**Node record (`nodes.store`), fixed 40–48 B target:**

| Field | Bytes | Meaning |
| --- | --- | --- |
| MVCC header | 25 | as above |
| `element_id` | 16 | stable public ID (ULID/UUIDv7) |
| `first_rel` | 8 | physical id of head of this node's relationship incidence chain (or `dense_ptr` if dense) |
| `first_prop` | 8 | physical id of head of property chain (0 = none) |
| `labels` | 8 | inline label-set ref: small sets bit-packed; large sets → token-list block id |

**Relationship record (`rels.store`), fixed ~64 B target — the heart of index-free adjacency:**

| Field | Bytes | Meaning |
| --- | --- | --- |
| MVCC header | 25 | as above |
| `element_id` | 16 | stable public ID |
| `type` | 4 | reltype token id |
| `start_node` | 8 | physical id of source node |
| `end_node` | 8 | physical id of target node |
| `start_prev_rel` | 8 | prev relationship in the **start node's** incidence chain |
| `start_next_rel` | 8 | next relationship in the **start node's** incidence chain |
| `end_prev_rel` | 8 | prev relationship in the **end node's** incidence chain |
| `end_next_rel` | 8 | next relationship in the **end node's** incidence chain |
| `first_prop` | 8 | head of property chain |
| `chain_flags` | 1 | first-in-chain markers (for each endpoint) to store degree on the first record |

Each relationship participates in **two** doubly-linked lists simultaneously — one threaded through
its start node and one through its end node. This is the index-free adjacency invariant: from a node
you reach `first_rel`, then walk `start_*`/`end_*` pointers (choosing the correct pair by checking
which endpoint the current node is) to enumerate incident edges in O(degree) with no index probe.

**Property record (`props.store`), fixed ~40 B target:**

| Field | Bytes | Meaning |
| --- | --- | --- |
| MVCC header | 25 | as above |
| `key` | 4 | propkey token id |
| `type_tag` | 1 | BOOLEAN/INTEGER/FLOAT/STRING/LIST/DATE/TIME/DATETIME/DURATION + inline-vs-overflow bit |
| `value_inline` | 8 | the value if it fits (i64, f64, bool, short string, small temporal); else `strings.store` block id |
| `next_prop` | 8 | next property in this entity's chain (0 = end) |

Property chains are singly linked per entity. Under `D-version-representation` a property assignment
**updates the property record in place** and records the previous value in a `SetProperty` delta on
the entity's undo chain (§5.1.1); it does not tombstone the old version and prepend a new one, which
is the present O(M²) behaviour that task #967 removes (§5.1.5).

**Temporal values.** All v1 temporal types (`DATE`, `LOCAL TIME`, `ZONED TIME`, `LOCAL DATETIME`,
`ZONED DATETIME`, `DURATION`) are encoded with **nanosecond** resolution. Zoned types carry both an
IANA zone id (token-encoded into `tokens.store`) and the resolved UTC offset, per the ratified data
model. The on-disk encoding is fixed-width where possible (e.g., `DATE` = days-since-epoch i32;
`LOCAL DATETIME` = (i64 seconds, u32 nanos)); `DURATION` is a (months i64, days i64, seconds i64,
nanos i32) tuple. Spatial `POINT` is deferred (`D-temporal-spatial`).

### 2.4 Parallel edges and self-loops

Both fall out of the model with **no special case**: a relationship has its own identity
(`element_id` + physical id), so N parallel edges between the same `(start_node, end_node, type)` are
simply N distinct relationship records threaded into both incidence chains. A **self-loop**
(`start_node == end_node`) appears **twice** in the same node's single chain — once via its
`start_*` pointers and once via its `end_*` pointers — and the traversal code must dedupe self-loops
by relationship id when a query asks for distinct incident relationships. This is the canonical LPG
multigraph behavior (Source: openCypher property-graph model).

### 2.5 Dense nodes

A super-node (very high degree) would make the doubly-linked chain expensive to maintain. When a
node's degree crosses a threshold (default 50; tunable; **value to be measured**, §12), the node is
promoted to **dense**: its `first_rel` field is reinterpreted as a `dense_ptr` to a small per-node,
per-(type, direction) group structure (a compact B+-tree-backed or grouped chain), so
type-filtered traversals from a super-node remain sub-linear. This mirrors Neo4j's dense-node
representation (Source: Neo4j storage internals).

### 2.6 Token / dictionary store

`tokens.store` holds three namespaces — **labels**, **relationship types**, **property keys**
(and IANA zone names) — each as a bidirectional dictionary `id (u32) ↔ UTF-8 name`. Tokens are
small, append-only, and fully cached in memory at startup behind an `FxHashMap<&str,u32>` /
`Vec<Box<str>>` pair. Token creation is itself a WAL-logged, transactional operation (it participates
in the same recovery), because creating a new label/type/key during a write must be atomic with that
write.

### 2.7 Free-space management

Each store keeps a **free list** of released record ids (a WAL-logged stack/bitmap per store).
Allocation pops a free id or extends the store by a page; deletion (after MVCC GC, §5.5) pushes the
id back. Because physical ids may be reused but `ElementId`s never are, freeing a record removes its
`idmap.store` entry but the `ElementId` is permanently retired.

---

## 3. Buffer pool & page management

`graphus-bufpool` is a **self-managed buffer pool** (`D-buffer-mgmt`), explicitly **not** `mmap`
(rationale: the CIDR 2022 "Are You Sure You Want to Use MMAP" critique — we need control over
eviction ordering, write-back vs WAL ordering, and torn-write protection; Source: Crotty et al.).

### 3.1 Logical page size

The DB page size is a **logical constant decoupled from the OS page size** (`D-buffer-mgmt`). The
default logical page is **8 KiB** (target; final value measured in §12). At startup the server
**queries the OS page size at runtime** (`sysconf(_SC_PAGESIZE)`; **16 KiB on Apple Silicon**, 4 KiB
typical on x86-64, 4/16 KiB on Raspberry Pi depending on kernel config) and uses it only to align
buffers and choose direct-I/O parameters — never to define record offsets. Stored offsets are always
in logical pages, so a database file is portable across machines with different OS page sizes.

### 3.2 Page structure

A **slotted page** layout for variable-occupancy stores; fixed-record stores use a denser
record-array layout but share the same header/footer.

```
 ┌──────────────────────────── logical page (e.g. 8 KiB) ─────────────────────────────┐
 │ PageHeader:                                                                          │
 │   magic:u16  page_type:u8  flags:u8                                                  │
 │   page_lsn:u64     ← LSN of the last WAL record that modified this page (WAL rule)   │
 │   checksum:u32     ← CRC32C / xxh3 over the page with this field zeroed (§4.6)       │
 │   slot_count:u16   free_start:u16   free_end:u16   special_ptr:u16                   │
 ├──────────────────────────────────────────────────────────────────────────────────── │
 │ slot directory  [ (offset:u16, len:u16) … ]  →  grows downward                       │
 │ ……………………………………… free space ……………………………………………………                                  │
 │ record / tuple heap  ←  grows upward                                                 │
 ├──────────────────────────────────────────────────────────────────────────────────── │
 │ optional B+-tree "special area" (rightmost-sibling ptr, level, etc.)                 │
 └──────────────────────────────────────────────────────────────────────────────────────┘
```

`page_lsn` is load-bearing for recovery (it tells redo whether a logged change is already reflected)
and for the **WAL rule** (a dirty page may not be flushed until the WAL is durable up to its
`page_lsn`). `checksum` is verified on every read from disk and recomputed before every write.

### 3.3 Frame table, pinning, and latching

- The pool is a fixed array of **frames** (page-sized aligned buffers). A `frame_table`
  (`PageId → frame index`) is a sharded concurrent map; the shard count is padded to cache lines
  (§10) to avoid false sharing on the hot lookup path.
- **Pin protocol.** A reader/writer `pin`s a page (increments an atomic pin count, `Acquire`), works
  on it, then `unpin`s (`Release`). Pinned pages are never evicted.
- **Latch protocol.** Each frame has a **reader-writer latch** (`parking_lot::RwLock` or a custom
  hybrid; **measured** in §12) distinct from MVCC locks: latches protect the *physical* page bytes
  for the duration of a single read/modify, are short-lived, and are **never held across `.await`**
  (clippy `await_holding_lock` enforced). B+-tree traversal uses **latch coupling** (crabbing):
  acquire child latch before releasing parent.
- **Lock ordering** to prevent latch deadlock: always latch pages in a fixed global order (by store
  then page id) for multi-page operations; B+-tree uses crabbing with a documented top-down
  discipline.

### 3.4 Eviction

Default policy: **CLOCK-sweep with a small 2Q-style admission filter** to resist scan pollution
(large sequential scans should not flush the hot working set). Dirty victims are written back only
after the WAL rule is satisfied; write-back is handed to the I/O layer (§3.6). The choice between
plain CLOCK, 2Q, and a sampled-LRU is **measurement-gated** (§12) against the LDBC SNB working set.

### 3.5 Prefetch

Two prefetch sources: (a) **sequential** detection for scans (read-ahead N pages), and (b)
**adjacency-aware** prefetch — when walking an incidence chain, the next relationship record's page
is prefetched while the current record is processed, hiding latency on long traversals. Prefetch
requests are non-blocking hints to `graphus-io`.

### 3.6 Async I/O integration

Page reads/writes are submitted to `graphus-io`: epoll/kqueue baseline, **io_uring fast path on
Linux with runtime fallback** (`D-io-backend`). Crucially, **CPU-heavy work never runs on the I/O
path and durability `fsync` runs off the executor workers** (dedicated fsync threads or io_uring
`FSYNC`), so a stalled disk cannot starve query execution. Buffers for direct I/O are aligned to the
OS page size discovered in §3.1.

---

## 4. WAL, durability & recovery

`graphus-wal` implements **ARIES** (Source: ARIES; CMU 15-445 recovery) with **steal + no-force**
buffer management, **group commit + `fdatasync`** durability (`D-durability-mode`), **fuzzy
checkpoints**, mandatory **torn-write protection**, **per-page checksums**, and **PANIC on
fsync failure** (Source: fsyncgate).

### 4.1 Log record format

The WAL is a sequence of segment files of variable-length records. Every record:

| Field | Bytes | Meaning |
| --- | --- | --- |
| `lsn` | 8 | this record's Log Sequence Number (monotonic, = file offset based) |
| `prev_lsn` | 8 | previous LSN **of the same transaction** (back-chain for undo) |
| `txn_id` | 8 | owning transaction (0 for non-txn records like checkpoints) |
| `type` | 1 | BEGIN, UPDATE, INSERT, DELETE, COMMIT, ABORT, CLR, CHECKPOINT-BEGIN, CHECKPOINT-END, FULL-PAGE-IMAGE, ALLOC/FREE |
| `page_id` | 8 | page affected (where applicable) |
| `len` | 4 | payload length |
| `redo` | var | redo image / logical redo (how to re-apply) |
| `undo` | var | undo image / logical undo (how to roll back) |
| `crc32c` | 4 | integrity check over the record |

Physiological logging: redo is page-oriented (idempotent re-apply keyed on `page_lsn`), undo is
logical-per-record so a rollback can be applied even after page reorganization.

### 4.2 Group commit & fdatasync strategy

Committing transactions append their `COMMIT` records and then **park on a commit queue**. A single
**log-flush worker** batches all pending records up to the current log tail, issues **one**
`write()` + **one** `fdatasync()` (data + size metadata, not full `fsync`, on filesystems where
`fdatasync` is sufficient — verified per-platform), and then wakes every parked committer whose LSN
is now durable. This amortizes the sync cost across concurrent commits (Source: WAL/ARIES, Postgres
group commit). A **per-transaction synchronous** mode (`synchronous_commit=on` per session) bypasses
batching for callers that need it; an explicit relaxed mode is **not** offered as a default because
it would violate NFR-1.

### 4.3 Steal + no-force

- **No-force:** a committing transaction does **not** force its dirty data pages to disk — only its
  WAL must be durable. Recovery's redo phase reconstructs committed-but-unflushed changes.
- **Steal:** dirty pages of *uncommitted* transactions **may** be evicted to disk. Recovery's undo
  phase rolls them back. This is what makes large transactions possible without unbounded buffer
  pressure, and it is the reason undo logging is mandatory.

### 4.4 CLRs (Compensation Log Records)

During undo (rollback or recovery), each undone action writes a **CLR** recording the compensating
change and an `undo_next_lsn` pointer to the next record still to be undone. CLRs are **redo-only**;
they make undo itself idempotent and crash-safe (a crash mid-rollback resumes from the last CLR
rather than re-undoing). This is the standard ARIES guarantee against repeated undo.

**A live rollback that fails leaves its transaction OPEN.** That ARIES guarantee is about *crash*
recovery, which restarts the undo from the durable log. A *live* rollback has no such restart point:
its WAL undo, its compensation replay into the buffer pool and its catalog reload are one indivisible
repair, and once the WAL manager has consumed the transaction's active-transaction entry a second
call finds no undo chain and would report success over pages it never repaired. So a live rollback
releases the transaction's active-set entry only after every fallible step has succeeded. A failure —
or an unwind out of the `fdatasync` panic of §4.9 — therefore leaves the transaction visibly **active**
and holding uncommitted state, which is the truth: its writes are still on the page. Every gate that
asks "is a writer holding uncommitted state?" (notably the constraint-DDL guard) keeps answering
*yes*, so it fails closed rather than open. The engine then takes that database — and only that
database — to the same safe stopped state §4.6 mandates for an unrepairable corruption event, pending
a controlled restart; the transaction is never quietly discarded to make the state look tidy.

### 4.5 Torn-write protection — recommendation: **doublewrite buffer**

A logical page (8 KiB) spans multiple device sectors; a power loss mid-write can leave a **torn
page** (some sectors new, some old) whose checksum fails and which redo alone cannot repair (the
base image is corrupt). Two standard defenses (Source: Percona torn-pages):

- **Full-page writes (FPW):** the first modification of a page after each checkpoint logs a full
  image of the page into the WAL; recovery restores the whole page from that image before replaying
  deltas. Simpler; inflates WAL volume right after checkpoints.
- **Doublewrite buffer (DWB):** before writing a page to its home location, write it first to a
  dedicated `doublewrite.dwb` area and `fdatasync`; only then write it home. On recovery, any page
  failing its checksum is restored from the DWB copy. Constant WAL size; one extra sequential write.

**Recommendation: doublewrite buffer**, because (a) it decouples torn-write protection from WAL
volume (our WAL is already on the latency-critical commit path and group commit makes WAL bandwidth
precious), (b) the extra write is sequential and batchable with eviction, and (c) it composes
cleanly with per-page checksums (the checksum is the torn-page *detector*; the DWB is the *repair*).
FPW remains the documented fallback if the §12 measurement shows DWB write-amplification dominating
on a given target. **This is a measurement-gated final call (§12).**

### 4.6 Per-page checksums

Every page carries a `checksum` (§3.2) computed with **CRC32C** (hardware-accelerated on both x86-64
SSE4.2 and aarch64 CRC extensions — feature-detected, §10) or `xxh3` (**which one is measured**,
§12). Verified on every read from disk; a mismatch on a page that the DWB cannot repair is a
**corruption event** → the database is taken to a safe stopped state and the operator is alerted
(integrity is inviolable; we never serve a page we cannot trust).

### 4.7 Fuzzy checkpoints

A **fuzzy checkpoint** does not quiesce the system. The checkpointer:

1. Writes a `CHECKPOINT-BEGIN` record and snapshots the **Dirty Page Table** (DPT: `page_id →
   recovery_lsn`) and the **Active Transaction Table** (ATT: `txn_id → last_lsn, state`).
2. Lets normal operation continue; lazily flushes dirty pages in the background respecting the WAL
   rule.
3. Writes a `CHECKPOINT-END` record embedding the DPT+ATT snapshot, and records its LSN in the
   superblock as the **last clean checkpoint LSN**.

Recovery starts from the checkpoint's DPT (the oldest `recovery_lsn` therein), not from the start of
the log. Checkpoint cadence is time- and log-volume-based and is itself WAL-logged so a crash during
checkpointing is handled.

### 4.8 Three-phase ARIES recovery

On startup, if the superblock is not marked cleanly shut down:

1. **Analysis.** Scan forward from the last checkpoint. Rebuild the DPT and ATT: discover which
   transactions were in-flight (losers) and which pages were dirty. Compute the **redo start LSN** =
   min `recovery_lsn` in the reconstructed DPT.
2. **Redo (repeating history).** Replay **every** logged change (winners *and* losers) from the redo
   start LSN forward, but only where `record.lsn > page.page_lsn` (otherwise the change is already on
   the page). This deterministically restores the exact pre-crash page state, including uncommitted
   work — repeating history is what makes logical undo sound. Torn pages are first repaired from the
   DWB (§4.5).
3. **Undo.** Roll back all **loser** transactions, following each one's `prev_lsn` back-chain,
   writing **CLRs** as it goes, until every loser is fully undone. Multiple losers are undone in a
   single backward pass over the merged LSN order.

After recovery the system writes a fresh checkpoint and marks the superblock clean. Recovery itself
runs inside `graphus-sim` in tests, so crash-at-any-LSN scenarios are exhaustively replayable (§11).

### 4.9 PANIC on fsync failure

Per the fsyncgate findings, a failed `fsync`/`fdatasync` may **clear** the kernel's dirty-page error
state, so a naive retry can falsely "succeed" while data is lost. Graphus therefore treats **any**
fsync/fdatasync error on the WAL or data path as **unrecoverable**: it logs the error, refuses to
acknowledge the affected commits, and **PANICs the process** (controlled abort) rather than risking
silent data loss. On restart, ARIES recovery brings the database to the last durable consistent
state. This is mandated by `D-durability-mode` and NFR-1.

---

## 5. MVCC + SSI transaction manager

`graphus-txn` implements **MVCC** with **Serializable Snapshot Isolation (SSI)** as the default
(`D-concurrency-control`, `D-isolation-level`), with **Snapshot Isolation** available as a documented
opt-in. The reference is Cahill/Fekete SSI and the PostgreSQL SSI implementation (Sources: Cahill
2009 / Ports & Grittner VLDB 2012; Postgres README-SSI).

### 5.1 Version representation — ratified: **newest version in place, one unified undo-delta chain**

**Ratified on 2026-08-02 as `D-version-representation`** (`02-decision-register.md`, "Ratified
decision (2026-08-02) — the MVCC-native engine"). This **closes §12 item 2**, the spike that the
specification itself declared to be blocking the record header and the undo area.

**The choice.** The **newest version of an entity lives in place**, in its home record in the record
store. Every older version is reconstructed by walking a **single undo-delta chain per entity**,
newest to oldest, applying each delta in turn to a copy of the in-place image. The chain is anchored
by the record's `undo_ptr` (§2.3, `05-storage-format.md` §7), which is the head of that chain.
"Unified" is the operative word: **one chain per entity carries every mutation kind** — creation,
deletion, property assignment, label change, and incidence-list change alike — instead of the five
separate mechanisms that stand in for it today.

The alternative that was weighed and rejected is **append-only newest-first**, in which an update
writes a whole new version record and links it to the old one, as PostgreSQL's heap does (Source, read
2026-08-02: `/data/refsrc/postgres/src/include/access/htup_details.h:86-98`, where `t_ctid` points at
the replacement version; the new tuple is stamped in `src/backend/access/heap/heapam.c:3808`). It
simplifies garbage-collection ordering, but it bloats the hot store and breaks adjacency locality,
which is precisely the property index-free adjacency exists to protect: a traversal reads the *latest*
committed version of nearly every record it touches, and under in-place-latest that is one record
fetch with no chain walk at all. Only a reader on an older snapshot pays to walk deltas.

The model adopted is Memgraph's (Source, read 2026-08-02:
`/data/refsrc/memgraph/src/storage/v2/delta.hpp:244-392`, the `Delta` record;
`delta_action.hpp:17-33`, its action enumeration) and, in its broad shape, InnoDB's rollback
segments. **The InnoDB parallel is cited from MySQL's official documentation only — no InnoDB source
tree was read, because none is present in `/data/refsrc`.** Every statement below that describes a
concrete field, call site, or control flow is grounded in the Memgraph source or in this repository's
own code, at the line cited.

**The measured grounding.** The decision was not taken on preference. Property assignment today is a
tombstone pass over the whole property chain followed by a prepend
(`RecordStore::tombstone_props_for_key`, `crates/graphus-storage/src/store.rs:5646-5666`), which is
**O(M²)** in the number of properties set on one entity — measured at **15.1 µs/op at M = 1000** and
**97.8 µs/op at M = 8000**. A delta chain replaces that walk with a constant-cost prepend.

#### 5.1.1 The delta

A **delta** is one immutable, fixed-size record describing **how to undo one change to one entity**.
It is not a description of the change; it is the inverse of it. This inversion is the single most
important convention in this section, and it is the one a reader is most likely to get backwards:
**creating an entity writes a `DeleteObject` delta**, because deleting the entity is what undoes the
creation. Memgraph names its actions the same way and for the same reason — creating an edge calls
`CreateAndLinkDelta(..., Delta::RemoveOutEdgeTag(), ...)` on the source vertex
(`/data/refsrc/memgraph/src/storage/v2/inmemory/storage.cpp:892` and `:895` for the target vertex),
and the first delta of any newly created object is a `DELETE_OBJECT`
(`/data/refsrc/memgraph/src/storage/v2/mvcc.hpp:236-249`).

Graphus defines **seven delta actions**, one for each mutation the engine can perform on an entity:

| Action | Written when the transaction… | Payload it carries | Applying it restores |
| --- | --- | --- | --- |
| `DeleteObject` | **creates** a node or relationship | nothing | the entity's non-existence |
| `RecreateObject` | **deletes** a node or relationship | nothing | the entity's existence |
| `SetProperty` | sets, changes, or removes a property | the property key token and the **old** value (`NULL` when the property did not exist before) | the previous value of that one property, or its previous absence |
| `AddLabel` | **removes** a label from a node | the label token | that label's membership |
| `RemoveLabel` | **adds** a label to a node | the label token | that label's absence |
| `AddIncidentEdge` | **removes** an incident relationship from a node | the relationship type token, the other endpoint's physical id, the relationship's physical id, and the direction | that one incidence entry |
| `RemoveIncidentEdge` | **adds** an incident relationship to a node | the same four fields as `AddIncidentEdge` | the absence of that incidence entry |

Two properties of this set matter downstream. First, **a delta is per-entity and per-change, never
per-record-image**: an entity with a thousand properties that changes one of them writes one small
delta, not a copy of the entity. Second, **the incidence actions name a single incidence entry**, not
a chain-head pointer, so undoing an edge insertion is the removal of one entry rather than the
restoration of a pointer word that a concurrent writer may meanwhile own — which is exactly the
failure mode that forced the present ad-hoc compare-and-set undo
(`crates/graphus-storage/src/record.rs:114-123`).

The delta record's on-disk layout, its size, and the store that holds it are frozen in
`05-storage-format.md` §12.

#### 5.1.2 Delta lifecycle and ownership

**The transaction owns its deltas; the entity only borrows the head of the chain.** A delta is
allocated from the writing transaction's own delta arena, and Memgraph makes the same split — the
transaction holds `delta_container deltas`
(`/data/refsrc/memgraph/src/storage/v2/transaction.hpp:234`) while the object holds only a pointer to
the chain head. The lifecycle has five steps:

1. **Conflict check.** Before any delta is created, the writer checks the entity's MVCC header for a
   write-write conflict and aborts immediately if there is one (§5.7).
2. **Allocation.** The delta is allocated in the undo area under the writing transaction's ownership,
   carrying the action, its payload, the transaction's `command_id` (below), and a reference to the
   transaction's shared commit-info slot (below) — **not** a timestamp of its own.
3. **Linking.** The delta is prepended to the entity's chain and the entity's `undo_ptr` is advanced
   to it. The link order is fixed and non-negotiable, because garbage collection and concurrent
   readers walk the chain while it is being modified: set the new delta's `next` to the current head
   **first**, and publish the new head **last**, so the chain is a valid list at every instant
   (Memgraph's `CreateAndLinkDelta` documents and enforces exactly this order —
   `/data/refsrc/memgraph/src/storage/v2/mvcc.hpp:314-359`).
4. **In-place mutation.** Only then does the writer change the home record, so the newest value is in
   place and its predecessor is recoverable from the delta just linked.
5. **Resolution.** On commit, the transaction publishes its commit timestamp once (below) and its
   deltas become the historical versions other snapshots read. On abort, the transaction walks **its
   own** deltas and applies each one, which restores exactly the state it found — a *logical* undo, in
   contrast with today's physical byte-level ARIES undo (`RecordStore::rollback`,
   `crates/graphus-storage/src/store.rs:3644`). Memgraph's abort is the same walk
   (`/data/refsrc/memgraph/src/storage/v2/inmemory/storage.cpp:1489-1560`).

A delta becomes reclaimable once no live snapshot can reach it, which is the same watermark rule the
version GC already uses (§5.5).

#### 5.1.3 The commit indirection point

**A delta does not carry a commit timestamp. It carries a reference to a commit-info slot shared by
every delta of its transaction, and that slot is published by a single atomic store at commit.** This
one indirection is the load-bearing part of the whole design, and it is worth stating why in full.

Without it, committing a transaction that touched *k* records means writing *k* timestamps, and every
one of those writes must be made durable and must be found again after a crash. Graphus pays that cost
today: a committed writer's records keep an in-flight stamp until a **freeze sweep** rewrites each one
in place, scanning `[freeze_low, high_water)` across all three stores
(`crates/graphus-storage/src/store.rs:617-625`). The frontier is a correctness-critical invariant of
its own, it has needed its own release-active audit (`store.rs:442-455`), and moving it past a live
writer caused a silent-data-loss defect (rmp #522). With the indirection, commit is **one atomic store
into one slot**, and every delta of that transaction becomes committed at the same instant, because
every one of them reads its timestamp through the slot. Memgraph does exactly this, in one line:
`transaction_.commit_info->timestamp.store(*commit_timestamp_, std::memory_order_release)`
(`/data/refsrc/memgraph/src/storage/v2/inmemory/storage.cpp:1299`), against the `CommitInfo` structure
at `delta.hpp:40-49`; every reader resolves a delta's status by loading through it
(`mvcc.hpp:57`, `:114`).

The contrast with the append-only alternative is instructive and is a second, independent reason for
the representation choice. PostgreSQL has no such shared slot: it stamps each tuple with a transaction
id and then consults the commit log per tuple, caching the answer in per-tuple **hint bits**
(`/data/refsrc/postgres/src/include/access/htup_details.h:204`, `HEAP_XMIN_COMMITTED`, set by
`SetHintBits`, `src/backend/access/heap/heapam_visibility.c:198-199`). Hint bits are that design's
answer to the same problem the freeze sweep answers here. The shared commit slot removes the problem
instead of answering it.

**Consequences to hold.** The slot is per-transaction, so it must outlive the transaction object and
be reclaimed only when the last delta referring to it is reclaimed. It is read on every visibility
decision, so it is a read-mostly, heavily-shared cache line and must be sized and padded accordingly
(§10.2). And because publication is a single release store, a reader either sees the whole transaction
as committed or none of it — which is atomicity (the **A** of ACID) expressed directly in the data
structure rather than reconstructed by a sweep.

#### 5.1.4 Statement-level isolation: `command_id`

Each delta records the **`command_id`** of the statement that produced it: a counter incremented once
per statement within the transaction. It exists so that a statement can be shown the state that
preceded it, even for changes its own transaction made — the "read-your-own-writes but not
your-own-current-statement's-writes" rule that Cypher's `MERGE` and multi-clause updates depend on.
Memgraph's read path takes both a snapshot **and** a view (`OLD` or `NEW`) and compares `command_id`
to decide whether to undo a delta belonging to the reader's own transaction
(`/data/refsrc/memgraph/src/storage/v2/mvcc.hpp:72-94`).

**Graphus has no `command_id` today**: the identifier has **zero occurrences** across
`crates/graphus-txn` and `crates/graphus-storage`, so no statement-level isolation exists. It is
introduced with the delta record and is the subject of task **#972**.

#### 5.1.5 What the unified chain replaces

**Five** mechanisms currently stand in for the version chain, and they exist only because there is no
chain to carry the change. The table below lists each of the five (rows 1–5) with its replacement and
the task that retires it, preceded by row 0 — the missing foundation all five depend on, which is the
undo area itself. This table is the authoritative list; the decision register
(`02-decision-register.md`) summarises it and does not restate it.

| # | Mechanism today | Where it lives now | Replaced by | Retired in |
| --- | --- | --- | --- | --- |
| 0 | ~~**No undo area at all.** `undo_ptr` is reserved in every record and always written `0`, so there is no chain to anchor.~~ **CLOSED.** | was `crates/graphus-storage/src/record.rs`; now `crates/graphus-storage/src/undo.rs` + `StoreKind::Undo` / `StoreKind::Commit` | The undo area and the delta record; `undo_ptr` is the live chain head | **#966 — done** |
| 1 | **Property tombstone plus chain prepend.** Setting a property walks the entity's whole property chain to tombstone the previous version, then prepends a new one — **O(M²)** over M assignments (15.1 µs/op at M = 1000; 97.8 µs/op at M = 8000). | `RecordStore::tombstone_props_for_key`, `crates/graphus-storage/src/store.rs:5646-5666` | One `SetProperty` delta carrying the old value; the home property record is updated in place | **#967** |
| 2 | **Label bitmap mutated in place, with the version history held only in memory.** The history is an in-process structure shared by `Arc`; nothing about it is durable, so labels are not versioned on disk. | `crates/graphus-storage/src/label_history.rs:143` | `AddLabel` / `RemoveLabel` deltas on the same durable chain as every other change | **#968** |
| 3 | **Ad-hoc compare-and-set undo for chain heads and the label word.** A bespoke undo per field, needed because a whole-record pre-image undo would revert words a concurrently-committed writer legitimately owns. | `crates/graphus-storage/src/record.rs:114-123`; `store.rs:2507` (`write_chain_head`), `:2541` (label word) | `AddIncidentEdge` / `RemoveIncidentEdge` deltas naming one incidence entry, so no shared pointer word is ever rewritten by an undo | **#969** |
| 4 | **Physical ARIES rollback.** Undo reverts bytes. This is the origin of the recurring defect family rmp #220 / #172 / #239 / #301 / #578 / #772, each one a case of one transaction's byte-level undo damaging another's committed state. | `RecordStore::rollback`, `crates/graphus-storage/src/store.rs:3644` | Logical rollback: the transaction walks its own deltas and applies them | **#970** |
| 5 | **Write-lock table plus wait-for-graph deadlock detector.** The only true blocking in the engine, with the cycle detection and lock-wait timeout that blocking requires. | `crates/graphus-txn/src/lock.rs`; driven from `crates/graphus-txn/src/manager.rs:472-552` | Conflict detection on the entity's MVCC header, aborting immediately without waiting (§5.7) | **#971** |

Two further tasks complete the model rather than replacing a mechanism: **#972** introduces
`command_id` and statement-level isolation, and the deterministic writer scheduler required by
`D-dst-writer-scheduler` extends `07-dst-simulator.md` §5 so that multi-writer behaviour is certified
from a seed rather than from a race.

**Status of this section.** Row 0 is **closed**: task #966 built the undo area, the delta record, the
commit-info slot and the chain, and brought `undo_ptr` to life. The engine writes a `DeleteObject`
delta when it creates a node or relationship and a `RecreateObject` delta when it deletes one, publishes
each transaction's commit with a single store into its slot, reclaims chains by watermark at GC, and
validates every chain in the consistency checker. `command_id` is carried in every delta and is always
`0` until **#972** introduces statement-level isolation.

Rows 1–5 are still the **specified target**, not present behaviour: property assignment, label change
and incidence change still use the mechanisms listed, rollback is still physical, and the write-lock
table is still in place. Each row names the task that closes it. The transaction manager likewise still
runs against a placeholder store — "the real `graphus_storage` does not yet implement version-chain
mechanics", and wiring it up "is a follow-up task, intentionally **out of scope** here"
(`crates/graphus-txn/src/store.rs`).

### 5.2 Timestamps and snapshots

A central **timestamp oracle** issues monotonically increasing logical timestamps:

- **begin timestamp** at transaction start = the transaction's snapshot. A version is visible iff
  `xmin` committed ≤ begin_ts **and** (`xmax` is 0, or `xmax` committed > begin_ts, or `xmax`
  belongs to an uncommitted/aborted txn).
- **commit timestamp** assigned atomically at commit, after SSI validation succeeds.

Uncommitted versions are tagged with the writer's `TxnId` (distinguished from committed timestamps by
a high bit) so visibility checks can resolve in-flight writers via the Active Transaction Table.

### 5.3 Visibility rules

A transaction `T` with snapshot `s` sees version `v` iff:

1. `v.xmin` is committed with `commit_ts(xmin) ≤ s`, **and**
2. `v.xmax` is 0, OR `v.xmax` is uncommitted, OR `v.xmax` aborted, OR `commit_ts(xmax) > s`.

A transaction always sees its **own** uncommitted writes (its `TxnId` matches). This yields
Snapshot Isolation reads; SSI (below) upgrades correctness to Serializable without adding read
locks.

**Read polarity: which reads owe this predicate, and which owe something else.** Every read of the
record store returns raw physical state — the slot's current contents, including MVCC tombstones the
GC has not reclaimed, versions whose writer has not committed, and (for labels, which are mutated in
place) a word a rollback will change back. Nothing about that is wrong; what is wrong is using one
polarity's read where another polarity's answer was owed, and that single mistake produced three
CRITICAL defects. A read therefore has to state which of **three** obligations it is discharging:

| Polarity | Obligation | Who re-checks | Cost of a wrong answer |
|---|---|---|---|
| **Superset** | must CONTAIN every row any snapshot could need | the consumer, against its own snapshot | a missing row is unrecoverable; an extra row is dropped by the re-check |
| **Decision** | must be EXACTLY what the deciding snapshot sees | nobody | a wrong row is written into the schema, or into a uniqueness verdict |
| **Conservative** | must never EXCLUDE on unproven state | nobody, for the excluded range | an excluded range disappears before any re-check runs |

*Superset* is index population. A refill has no reader and therefore no snapshot; it populates a
candidate structure that every consumer re-checks, and the asymmetry that makes that safe runs one
way only — **a re-check can remove a candidate, but it can never resurrect one**. So a refill indexes
every property version with no visibility filter, and gates label membership on the union of the live
word with every retained bitmap, because the live word is a *subset* while an uncommitted
`REMOVE n:L` is open.

*Decision* is constraint validation. A `CREATE CONSTRAINT` walk produces a verdict that is written
durably into the catalogue and is never re-checked, so it must see exactly the graph a `MATCH` in the
same transaction would see. Reading the superset there counted a committed `REMOVE n.p` as a present
value: `IS UNIQUE` was refused over a duplicate no query could find, and `IS NOT NULL` was accepted
over a property that was gone.

*Conservative* is a data-skipping structure. A zone map **prunes**: the per-row re-check only ever
runs on the ids the summary did not exclude, so a narrowed zone removes a whole id range before any
re-check can see it, and nothing rebuilds a zone map afterwards. A pruning structure may therefore
only narrow on state it can prove, which in practice means its rebuild takes the same superset gates a
refill takes — the live-OR-retained label union, and *every* property version rather than the newest,
since the newest may belong to an open writer and even a committed one leaves an older reader
resolving the version underneath it. A rebuild whose scan faults abandons the column instead of
summarising the part of the store it managed to read, and a column that has never been summarised
end-to-end **declines** ("scan everything") rather than pruning against an empty summary.

The conservative polarity has a second obligation that is about the *consumer* rather than the
summary: a pruning structure yields **candidates**, and the re-check that turns them into rows must run
at the reader's snapshot, on a seam that owns one. Performing it on a seam that holds no snapshot is a
dirty read in both directions — an uncommitted creation returned to every reader, and a committed row
hidden by an uncommitted label removal — and when rows rather than candidates are returned, nothing
downstream can repair either. The skip query therefore sits on the statement seam and shares the same
per-candidate re-check body as every index seek, so the accelerated answer and the scan it replaces are
the same set by construction.

Two shapes sit outside the three and must not be mistaken for them. The **write path** reads the
entity's current image, because the state it is announcing or indexing is the state it has just
written — there is no snapshot to resolve against. And a **memoization with a total fallback** (the
columnar accelerator) may read the current image because a row it omits falls through to the
authoritative property read, so a hole costs a decode rather than a row.

The first two polarities are separated in the type system: the decision-grade store read takes the
snapshot as a parameter and returns a view that has no other constructor, so a validation helper
cannot be handed a raw chain, and the raw view cannot be walked without naming the polarity out loud.
The label axis cannot be separated the same way — all three label reads deal in the same bitmap — so
it is held by an enforced census that also records every raw read the engine performs on purpose,
with its justification.

### 5.4 SSI: dangerous-structure detection and abort

Pure SI permits **write-skew** and other serialization anomalies. SSI adds detection of the
**rw-antidependency** pattern: a transaction `T1` reads a version that `T2` then overwrites
(`T1 --rw--> T2`). Cahill's theorem: a non-serializable execution always contains a transaction with
**both** an incoming and an outgoing rw-antidependency (a "**dangerous structure**" / pivot). SSI
tracks these and aborts a pivot to break every potential cycle.

Implementation:

- **SIREAD locks (read tracking).** Reads record predicate/granular read markers (SIREAD locks in
  Postgres terminology) at node/relationship/index-range granularity. These do **not** block writers;
  they exist only to detect rw-edges.
- **Conflict edges.** When a write occurs on something another transaction SIREAD-locked, an
  rw-antidependency edge is registered between them (in-flight and recently-committed transactions
  are tracked).
- **Pivot abort at commit.** At `COMMIT`, if the committing transaction is a pivot (has both an
  inbound and an outbound rw-edge, with the outbound edge to a transaction that committed first or is
  concurrent), it is **aborted** with a serialization-failure error (retriable). The exact abort
  policy follows the Postgres SSI safe-retry rules to guarantee at least one transaction in any
  unsafe set commits (no livelock of mutual aborts).
- **Read-only optimization.** Read-only transactions that cannot complete a dangerous cycle are
  exempted (the SSI read-only deferral optimization), important under read-heavy graph workloads.

Predicate-read granularity for index ranges (to catch phantoms) is tracked at the B+-tree leaf/range
level (§6.4). Getting predicate locking right is essential for **TCK + serializability** and is a
prime DST/Elle target (§11).

### 5.5 Garbage collection of old versions

A background **vacuum** reclaims versions no longer visible to any live snapshot. The GC watermark =
the oldest active begin timestamp (the "low-water mark" from the timestamp oracle). Any version with
`xmax` committed ≤ watermark is dead and its storage (undo delta / superseded record / freed physical
id) is reclaimed and pushed to the store free list (§2.7). GC is incremental and WAL-aware (it does
not break recovery of in-flight transactions). Long-running read transactions hold the watermark
back; this is surfaced as an observability metric (NFR-10) so a stuck reader pinning GC is visible.

### 5.6 Interaction with the record store and indexes

Under `D-version-representation` the store is **MVCC-native** (§2.3): versioning is a property of the
record itself, not a layer above a single-version store. Six consequences follow, and they are the
contract between §5 and the rest of the engine.

- **A write mutates the home record in place and leaves a delta behind.** The writer allocates the
  delta, links it at the head of the entity's chain, advances `undo_ptr`, and only then changes the
  record body (§5.1.2, steps 2–4). The MVCC header keeps its meaning unchanged from §5.2: `xmin` is
  the creating transaction, `xmax` the expiring one, and `undo_ptr` is now the live head of the undo
  chain rather than a permanently-zero reserved word.
- **A read of the latest committed version costs one record fetch.** This is the whole point of
  in-place-latest, and it is what protects index-free adjacency: a traversal that reads the current
  version of every record it visits walks no chains at all. A reader on an older snapshot walks the
  chain from `undo_ptr` backwards, applying deltas until it reaches the version its snapshot may see
  (§5.3).
- **Every delta is WAL-logged and recovered by the same ARIES machinery** as the record it belongs to
  (§4.8). The undo area is an ordinary region of ordinary logical pages (`05-storage-format.md` §12),
  not a side structure with its own recovery rules, so a crash mid-chain is recovered by redo exactly
  as a crash mid-record is. This is what makes labels durably versioned for the first time: today
  their history is in memory only (`crates/graphus-storage/src/label_history.rs:143`) and is lost on
  restart.
- **Indexes are unchanged and stay unversioned (§6.3).** An index entry points at a record; visibility
  is resolved by reading that record's MVCC header and, where the entry's key was itself changed by an
  in-flight transaction, by resolving the delta chain. The three read polarities of §5.3 are
  unaffected: what changes is *how* an older version is reconstructed, not *which* answer each
  polarity owes. In particular, a **superset** read still returns every version any snapshot could
  need — under the delta model that is the in-place image plus its reachable chain, rather than the
  in-place image plus a retained in-memory bitmap.
- **Constraint checks keep their timing and their polarity.** Uniqueness and existence validation runs
  at commit time against the committed snapshot (§6.5), and it remains a **decision**-polarity read
  (§5.3): it must see exactly the graph a `MATCH` in the same transaction would see, which under the
  delta model means resolving the chain at the validating snapshot rather than reading the raw
  in-place image.
- **Garbage collection reclaims deltas, not just records.** The watermark rule of §5.5 is unchanged —
  the oldest active begin timestamp — but the reclaimable unit becomes the delta below that watermark
  as well as the dead record. Two obligations follow: a delta may not be reclaimed while any live
  snapshot can still reach it through a chain, and the transaction's commit-info slot (§5.1.3) may not
  be reclaimed while any delta still refers to it.

**What disappears from this interface.** The freeze sweep does. Today a committed writer's records
carry in-flight stamps until a sweep rewrites each one in place across
`[freeze_low, high_water)` (`crates/graphus-storage/src/store.rs:617-625`); with the commit
indirection point (§5.1.3) a transaction's commit timestamp is published once, so there is nothing
left to rewrite and no frontier to maintain.

### 5.7 Latches, conflict detection, and multi-writer execution

**Ratified on 2026-08-02 as `D-write-conflict-detection` and `D-multi-writer`**
(`02-decision-register.md`). Graphus has exactly **one** blocking primitive — the latch — and **no
logical lock of any kind**. There is no lock table, no lock wait, no lock-wait timeout, and no
deadlock detector, because a transaction never waits for another transaction.

**Latches (physical, short) are the only blocking.** They protect page bytes and in-memory structures
(§3.3), are held for the duration of a memory operation rather than a transaction, and are ordered to
be deadlock-free by construction (§3.3, lock ordering). What makes a chain safe to walk while it is
being extended is the publication order of §5.1.2 step 3, not a transaction-scoped lock: the new delta
is written in full first, its `next` is set to the current head, and the record's `undo_ptr` is
published **last**, under the latch of the record's own page. A concurrent reader, or the GC, therefore
observes either the old chain or the new one, never a partially-linked one.

**Write-write conflicts are detected on the entity's own MVCC state, and abort immediately.** Before
writing, a transaction reads the head of the entity's delta chain and decides in constant time:

| State of the chain head | Verdict |
| --- | --- |
| The chain is empty | proceed |
| The head belongs to **this** transaction | proceed |
| The head belongs to a transaction that **committed before this transaction's start timestamp** | proceed |
| Anything else — the head belongs to another transaction that is in flight, or that committed after this transaction started | **abort now**, with a retriable serialization failure |

The writer never waits for the outcome of the conflicting transaction, so no wait-for edge is ever
created, so no cycle can form, so **there is nothing for a deadlock detector to detect**. This is
Memgraph's `PrepareForWrite` (Source, read 2026-08-02:
`/data/refsrc/memgraph/src/storage/v2/mvcc.hpp:112-137`), which returns `false` — a serialization
error — instead of blocking, and which gates the entire write surface: every mutating accessor calls
it first (`vertex_accessor.cpp:191,203,265,277,425,511,580,639`;
`edge_accessor.cpp:194,261,315,360`).

**Two properties of this rule matter for the inviolable ACID requirement.** First, it is
*first-writer-wins*, not first-updater-wins-after-a-wait: the transaction that reached the entity
first keeps it, and the second is told to retry. Second, aborting on conflict is **more** conservative
than waiting, never less: a transaction that would have been permitted to proceed after a wait is
merely asked to retry, whereas no transaction that must abort is ever allowed to commit. The
serialization failure is retriable and is surfaced through the existing retriable-error contract, so
the client-visible behaviour of a conflicting write is unchanged in kind.

**SSI is unaffected.** Read tracking, rw-antidependency edges, pivot detection and the abort policy of
§5.4 are untouched: SIREAD markers never blocked anything and still do not. Conflict detection covers
**write-write**; SSI covers **read-write**. They are complementary, and both are required for
serializability.

**Multi-writer.** Because two writers interact only through a constant-time header check that either
succeeds or aborts, **N transactions write to the same database in parallel** (`D-multi-writer`), and
the single-writer engine thread is retired. This supersedes the writer-side facet of
`D-read-parallelism` — "keep the single-writer-thread engine model"; that decision's read-side
deferral had already been discharged by the off-thread reader pool (rmp #336). Readers still never
block writers and writers still never block readers (NFR-4); what changes is that writers no longer
block one another either — they either proceed or abort.

**Certification.** Multi-writer correctness is certified from a **deterministic writer schedule**, not
from an unreproducible race: `D-dst-writer-scheduler` requires the DST simulator to dispatch several
concurrent writers against one database from a seeded schedule, extending the cooperative interleaver
of `07-dst-simulator.md` §5 to the write path and narrowing the fidelity ceiling named in §5.1 of that
document. This is a prerequisite of the multi-writer sign-off, not a follow-up to it.

**What is retired, and when.** The write-lock table and the wait-for-graph deadlock detector exist
today in `crates/graphus-txn/src/lock.rs` (`LockTable`, `find_deadlock_victim`), driven from
`crates/graphus-txn/src/manager.rs:472-552`. They are removed in task **#971**, which is where the
header check specified above becomes the engine's only conflict mechanism. Until then, this section
describes the specified target and the code implements first-updater-wins with deadlock detection.

---

## 6. Indexing

`graphus-index` provides four core v1 index kinds (`D-v1-index-types`): **token-lookup**,
**range/B-tree**, **composite**, and **relationship-property** indexes; plus uniqueness/existence
**constraints**. A **full-text index** — a Phase-2 capability under `D-v1-index-types` option (b) —
was delivered ahead of schedule alongside the core set and is specified separately in §6.7; it does
not change the four-kind core baseline.

### 6.1 B+-tree — recommendation and rationale

The range/ordered index is a **B+-tree** (not LSM). Rationale (Source: TiKV B-tree vs LSM): graph
workloads are read- and point-lookup-heavy with in-place updates dominated by MVCC versioning; a
B+-tree gives predictable read latency, natural range scans for Cypher range predicates, and
straightforward ARIES-style WAL integration (LSM compaction would fight our buffer-pool/WAL design).
Each index is its own file of logical pages using the slotted/special-area page (§3.2), with
**latch-coupled (crabbing)** concurrent traversal and B-link right-sibling pointers for
lock-free-ish descent under splits.

> **Page fanout** (keys per internal node) is a function of key size and logical page size and is
> **measured** (§12) rather than guessed.

### 6.2 Index kinds

- **Token-lookup index** (a.k.a. label/type scan store): for each label (and reltype) token, an index
  from token → set of node (rel) ids, enabling `MATCH (n:Label)` without a full scan. Implemented as a
  B+-tree keyed by `(token_id, element_physical_id)` (range-scannable per token).
- **Range/B-tree property index:** keyed by `(token, property_value)` → record id, supporting
  equality and range predicates with Cypher's type-aware ordering (§7.6).
- **Composite index:** keyed by `(label/type, prop_value_1, …, prop_value_k)` in declared order;
  used for multi-property equality and leading-prefix range predicates.
- **Relationship-property index:** same as the property index but over relationship records, keyed by
  `(reltype, prop_value)`; required by `D-v1-index-types`.

Values in keys are encoded with an **order-preserving byte encoding** so that B+-tree byte-order
equals Cypher value order (handling i64 sign, IEEE-754 float ordering incl. NaN placement, UTF-8
collation for strings, and temporal ordering). This encoding is a small, heavily property-tested
module (§11).

### 6.3 MVCC-versioning of indexes

Indexes are **not separately versioned**; they point at records and **defer visibility to the
record's MVCC header**. An index lookup returns candidate record ids; the txn layer filters by
visibility against the reader's snapshot. Inserts add an index entry when a new version is created;
the old entry is removed lazily by GC once the old version is dead (§5.5). This keeps indexes
single-structure while remaining serializable, and avoids index bloat proportional to version count.
Index **range reads register SIREAD/predicate markers** (§5.4) so phantoms are caught by SSI.

### 6.4 Crash recovery of indexes

Index pages are ordinary logical pages: every index modification is **WAL-logged** (redo + undo) and
recovered by the same ARIES machinery (§4.8). There is no separate index rebuild on crash; indexes
come back consistent with the base store because they share one log and one recovery. (Offline index
*rebuild* exists only as an admin/repair tool, not as a recovery requirement.)

### 6.5 Constraint enforcement (uniqueness / existence)

- **Existence constraints** (property must be present) are checked when a record version is written.
- **Uniqueness constraints** are enforced via a **unique index** and validated at **commit time**
  against the committed state, so two concurrent transactions inserting the same key cannot both
  succeed: the unique index insert participates in SSI conflict detection, and the second committer
  fails with a constraint-violation error. Doing the final check at commit (not just at statement
  time) is what makes uniqueness serializable rather than merely snapshot-correct.
- Constraint violations surface as the appropriate **Cypher error** (TCK-conformant error class,
  §7.3), not as a panic.
- **Validating a constraint against existing data is a `decision`-polarity read (§5.3).** The walk
  runs inside the DDL's own serializable transaction and judges exactly the entities and values that
  transaction's snapshot sees. It must never reach for the reads an index refill uses: those are
  deliberately supersets, and the constraint verdict is the one answer in the engine that nothing
  downstream re-checks.

### 6.6 Planner use of indexes

The planner (§7) consults the **index catalog** (a system structure listing indexes, their keys,
and selectivity hints) during physical planning to choose index seeks/scans over full scans. v1 uses
**heuristic/rule-based** planning with index awareness; a cost-based optimizer with statistics is
Phase 2 (`00-overview.md` §6). Plans record which indexes they depend on so the **plan cache** is
invalidated on schema/index change (§7.5).

### 6.7 Full-text index (advanced; delivered ahead of Phase 2, rmp #72)

> **Status.** The full-text index is an **advanced capability delivered ahead of Phase 2** (rmp
> task #72). It corresponds to `D-v1-index-types` option (b); the ratified outcome remains option (a)
> (the four core kinds of §6), and this delivery does **not** re-baseline the v1 index set. It was
> shipped early in the same spirit as the other Phase-2 capabilities already in the codebase
> (encryption at rest, fine-grained RBAC, and incremental backup + PITR). The description below is
> faithful to the implementation; it documents only behavior that exists.

A full-text index maps a single node **label** plus an ordered list of string **properties** to the
nodes whose text matches a query string. It is built from two cooperating halves — an in-memory
inverted index that does the matching and a durable name-keyed catalog that records the index's
existence — and it is exposed through a Cypher **procedure** for querying and a server **DDL** surface
for lifecycle management.

**Analyzers.** Two analyzers are supported, selected per index at creation time:

- **`standard`** (the default): tokenizes on Unicode non-alphanumeric boundaries (each maximal run of
  alphanumeric characters is one token; every other character — whitespace, punctuation, symbols,
  including `_`, `-`, `.`, `@` — is a separator and is discarded), then **lowercases** each token with
  full Unicode case folding, then **removes stop words**. The stop-word filter applies **only** to the
  standard analyzer and **after** lowercasing; the set is a fixed list of 35 common English words
  (`a, an, and, are, as, at, be, but, by, for, if, in, into, is, it, no, not, of, on, or, such, that,
  the, their, then, there, these, they, this, to, was, will, with`).
- **`keyword`**: trims the input and treats the **entire** trimmed string as a **single lowercased
  term**; it performs no tokenization and no stop-word removal. Whitespace-only input yields no terms.

The same analyzer is applied at index time and at query time, so the indexed and queried term sets are
produced identically.

**In-memory ephemeral inverted index.** Matching is served by an in-memory inverted index (a term →
sorted node-id postings map, plus a forward node → terms map so that updates and deletes are bounded
by the node's term count). This structure is **ephemeral**: it is never persisted as a structure and
needs no separate crash-recovery path. On open it is **rebuilt from the record store** — when at least
one full-text index is declared, the engine scans every in-use node and re-indexes its covered label
and string property values, reconstructing the inverted index from durable data.

**Durable name-keyed catalog.** The existence of each full-text index is recorded in a **durable,
server-unique-name-keyed catalog** held in the `graphus-storage` `Statistics`/meta image (the metadata
page), mirroring the rmp #90 node-property index catalog. Each entry records the label token, the
ordered covered-property tokens, the analyzer (stored as its raw discriminant byte, so storage does
not depend on `graphus-index`), and the build state. The catalog block is appended last in the
`Statistics` image, so a pre-#72 database decodes to an empty full-text catalog (backward-compatible
by end-of-input detection), and it rides the same durability lifecycle as the rest of the metadata
(checkpointed at commit, reloaded on rollback and on open).

**Transactional maintenance (`reindex_node`).** On every node write the engine's `reindex_node`
path — which already maintains the label and property indexes at the transaction's snapshot — also
maintains **every** registered full-text index for the node. For each index, if the node carries the
covered label, the covered string properties are concatenated in the index's declared property order,
analyzed with the index's analyzer, and the node is re-indexed wholesale (its stale terms are
replaced); if the node no longer carries the covered label, it is **removed** from that index.
Stale-term removal is eager, so a full-text query never returns a node whose text no longer matches.

**MVCC + RBAC candidate filtering.** A query first obtains candidate node ids from the inverted index,
then filters them so that results are both **transactionally** and **authorization** correct. The
record-store layer re-checks each candidate against the reader's **MVCC** snapshot (and that the node
still carries the covered label) and registers the SIREAD/read markers needed for SSI; the
authorization layer additionally drops any candidate that is **not RBAC-visible** to the caller, so an
RBAC-invisible node never reaches the result. The procedure body re-checks node existence through the
same graph seam, so MVCC and RBAC compose.

**Online background build (Populating → Online).** Creating a full-text index does **not** scan the
graph synchronously. The catalog entry is committed in the **`Populating`** state, the index is
registered in memory, and a background build is enqueued over a snapshot of the node ids. The build
advances in bounded chunks; on completion it **durably flips the catalog entry to `Online`** in a
committed transaction and promotes the in-memory state, keeping the engine responsive throughout. This
mirrors the rmp #91 non-blocking incremental index population. On crash recovery, any entry recovered
as `Populating` is promoted to `Online` after the in-memory inverted index has been fully rebuilt from
the recovered store.

**Query procedure `db.index.fulltext.queryNodes`.** Querying is exposed as the built-in procedure
`db.index.fulltext.queryNodes(indexName :: STRING, queryString :: STRING)` (name resolution is
case-insensitive), yielding two columns:

- **`node`** — a structural `Node` (bound to the materialized node at the result-egress boundary, so
  it composes with MVCC + RBAC materialization).
- **`score`** — a **best-effort** relevance score of type `FLOAT`. The score is a simple
  **term-overlap count**: the number of distinct query terms the node contains. A repeated query term
  counts once; it is explicitly **not** a TF-IDF/BM25 relevance score.

An unknown index name is a clear procedure failure (not an empty result), so a typo surfaces as an
error. Rows are ordered by **descending score, then ascending node id**, for relevance-first,
deterministic output.

**DDL surface.** Full-text indexes are managed through an admin/index statement surface in the server
(Neo4j-compatible, case-insensitive keywords, backtick-quotable names):

```
CREATE FULLTEXT INDEX <name> FOR (<var>:<Label>) ON EACH [<var>.<prop>, …]
                                                  [OPTIONS { analyzer: '<analyzer>' }]
DROP   FULLTEXT INDEX  <name>
SHOW   FULLTEXT INDEXES
```

`ON EACH [ … ]` requires at least one `<var>.<prop>` reference. `OPTIONS` accepts only the `analyzer`
key with a quoted string value; the default analyzer is `standard`, and an unknown analyzer name is
rejected as a compile error with no side effect. `CREATE`/`DROP` take the singular `INDEX`; `SHOW`
takes the plural `INDEXES` and returns `name`, `label`, `properties`, `analyzer`, and `state`
(`online`/`populating`).

**Procedure-name parser refinement.** Because `db.index.fulltext.queryNodes` contains the Cypher
keyword `index` as a name segment, the procedure-name parser was refined so each dotted segment of a
namespaced procedure name accepts a **keyword-spelled** segment (a reserved word as well as a plain
identifier), mirroring how labels and property keys already accept keyword spellings. The original
source spelling of a keyword-spelled segment is preserved.

### 6.8 Named node-property indexes and index DDL (rmp #623–#626)

Every node-property index (the range/B-tree and composite kinds of §6.2, declared over a node label
and a property) carries a **name**, and the four Cypher index-DDL statements of `FR-IX-15` are
Neo4j-conformant. This completes the v1 DDL surface for the core index set; it adds neither a new
index kind nor a change to the four-kind baseline of §6.

**DDL statements.** The node-property index-DDL surface is Neo4j-compatible: keywords are
case-insensitive and a name is an identifier or a backtick-quoted string.

```
CREATE INDEX [<name>] [IF NOT EXISTS] FOR (<var>:<Label>) ON (<var>.<property>)
CREATE INDEX ON :<Label>(<property>)                       -- legacy anonymous form
DROP   INDEX <name> [IF EXISTS]                             -- by name
DROP   INDEX FOR (<var>:<Label>) ON (<var>.<property>)      -- by target
DROP   INDEX ON :<Label>(<property>)                        -- legacy by-target form
SHOW   INDEXES
```

- **`CREATE INDEX`** declares an index over `(Label, property)`. The `<name>` is optional. When it is
  present, it is the index's server-unique name; when it is omitted — including the legacy
  `CREATE INDEX ON :Label(property)` form — the engine assigns a deterministic auto-name (below). A
  create starts a **non-blocking** background build: the catalog entry is committed in the
  `Populating` state and promoted to `Online` when the build completes, the same online-build
  lifecycle as the full-text index of §6.7 (rmp #91).
- **`DROP INDEX`** removes an index either **by name** (`DROP INDEX <name>`) or **by target**
  (`DROP INDEX FOR (n:Label) ON (n.property)`, or the legacy `DROP INDEX ON :Label(property)`),
  cancelling any in-progress build. The drop is durable: it removes both the catalog entry and the
  in-memory index.
- **`SHOW INDEXES`** lists every declared node-property index with the Neo4j driver columns
  (below). It is a read (query type `r`), not a schema change.

**Naming and the auto-name (`D-named-index-autoname`).** When a `CREATE INDEX` omits the name, the
engine derives a deterministic, stable auto-name of the form `index_<label>_<property>`, with each
part reduced to the identifier character set `[A-Za-z0-9_]` (every other character becomes `_`). The
base name is a **pure function** of the label and property, so the same `(label, property)` always
yields the same base name across restarts and rebuilds. Because the base can collide — two distinct
`(label, property)` pairs can reduce to the same string, or the base can equal an explicitly declared
name — the engine resolves a collision **deterministically**: it appends the token suffix
`_<label_token>_<property_token>` and, if that candidate is still in use, increments a deterministic
counter (`_2`, `_3`, …) until the name is free in **every** catalog. The resolved name is then
persisted durably, so the resolution is computed at most once and remains stable thereafter. This
auto-naming design is registered as decision **`D-named-index-autoname`** (`02-decision-register.md`).

**Global name uniqueness.** Index and constraint names are **globally unique across the whole
schema**. A `CREATE` that requests a name already used by a *different* catalog is rejected, while
each catalog keeps its own re-declare (replace) semantics. The uniqueness check spans every index and
constraint name catalog: the node-property index catalog, the full-text index catalog (§6.7), and the
constraint catalog (§6.5).

> **Flag — spatial (point) index name catalog.** The implementation also maintains a spatial (point)
> index name catalog that participates in the same global name-uniqueness rule. The specification does
> not yet document a point/spatial index (`FR-IX-8` in `01-needs-survey.md` remains `[ADV]` and
> deferred), so this document intentionally does not specify it. This specification-versus-code gap
> predates the named-index work and is surfaced for a separate decision; it does not affect the
> node-property index behavior specified here.

**Idempotent `IF NOT EXISTS` / `IF EXISTS`.** The idempotency modifiers follow Neo4j's
"changed nothing" contract:

- **`CREATE INDEX … IF NOT EXISTS`** — if an equivalent index (same label and property) already
  exists, or the requested name is already in use, the statement is a **no-op success**. Without the
  modifier, the same situation is an **error** (an equivalent index already exists, or the requested
  name is already in use).
- **`DROP INDEX <name> IF EXISTS`** — dropping a missing named index is a **no-op success**. Without
  the modifier, dropping a missing named index is an **error**.
- **`DROP INDEX` by target** (`FOR (n:Label) ON (n.property)` or the legacy form) — dropping a missing
  index by target is an **idempotent no-op success** and needs no modifier.

A no-op reports the Neo4j "changed nothing" summary: query type `s`, **no** side-effect counters, and
`containsUpdates() == false` (in particular a `0` `indexes-added` / `indexes-removed` count). A create
or drop that does change the schema reports `indexes-added: 1` or `indexes-removed: 1` with
`contains-updates: true` (`06-bolt-and-error-shapes.md` §3.1).

**SHOW INDEXES columns.** `SHOW INDEXES` returns the Neo4j driver column shape, one row per
node-property index:

| Column | Value |
| --- | --- |
| `name` | the index name |
| `type` | `RANGE` (the node-property index kind) |
| `entityType` | `NODE` |
| `labelsOrTypes` | a single-element list `[<Label>]` |
| `properties` | a single-element list `[<property>]` |
| `state` | `online` or `populating` (lower-case, for coherence with the full-text `SHOW … INDEXES` surface of §6.7) |

**Durability and backward compatibility.** The name → `(label_token, property_token)` mapping is a
**durable, append-only name catalog** appended last in the `graphus-storage` `Statistics`/meta image,
mirroring the node-property index catalog it names (§6.7 describes the same append-last pattern for the
full-text catalog). It is **crash-atomic** with the index catalog: both are checkpointed together
through the metadata checkpoint, so a name and its index never diverge across a crash. A pre-#623
image — in which every declared index is nameless — decodes to an **empty** name catalog by
end-of-input detection; on open, the coordinator **backfills a deterministic auto-name** for each such
legacy index and persists it, so after one open every index is named end-to-end (droppable by name,
listed with a name in `SHOW INDEXES`) and the names are stable thereafter. The store enforces a
**one-name-per-target** invariant at the write path (a target holds at most one name), because a
two-names-per-target image is rejected at decode and would otherwise leave the store unopenable.

The MVCC visibility of index entries (§6.3) and the crash recovery of index data (§6.4) are
unchanged: only the small, append-only name catalog is added to the metadata image.

---

## 7. Cypher engine

`graphus-cypher` targets **100% openCypher TCK** (NFR-3) on the pinned 2024.x M-series snapshot
(`D-cypher-line`), feature-flagging the newest constructs. The pipeline is a textbook compiler
front-end plus a graph-aware execution back-end.

### 7.1 Pipeline

```
 query text + params
   │
   ▼  lexer (logos)        → token stream
   ▼  parser (hand-written recursive descent / Pratt)  → AST
   ▼  semantic analysis    → validated AST  (★ all COMPILE-TIME errors raised here)
   ▼  logical planner      → logical plan (relational-graph algebra: Expand, NodeScan, Filter,
   │                          Project, Apply, Optional, Merge, Create, SetProperty, …)
   ▼  physical planner      → physical plan (index seeks, expand-into vs expand-all, hash vs
   │                          nested-loop join, sort, limit pushdown)
   ▼  executor (Volcano + vectorized leaves)  → row cursor
```

Parser choice: a **hand-written recursive-descent + Pratt** expression parser (precise error
positions and recovery, which the TCK error scenarios need), with `logos` for lexing. A grammar test
oracle cross-checks against the openCypher grammar artifacts.

### 7.2 The Cypher value/type model in Rust

The value space is one `enum` in `graphus-core`, used identically by storage results, the executor,
PackStream, and Jolt/CBOR:

```rust
pub enum Value {
    Null,
    Boolean(bool),
    Integer(i64),               // Cypher INTEGER
    Float(f64),                 // Cypher FLOAT
    String(GString),            // Unicode; GString = SmallString|Arc<str> (measured, §12)
    List(Vec<Value>),           // ordered, heterogeneous at runtime; homogeneous when persisted
    Map(OrderedMap<GString, Value>),
    // temporal (all v1, nanosecond, IANA + offset)
    Date(Date),
    LocalTime(LocalTime),
    ZonedTime(ZonedTime),
    LocalDateTime(LocalDateTime),
    ZonedDateTime(ZonedDateTime),
    Duration(Duration),
    // structural (only in results, never persisted as property values)
    Node(NodeRef),              // id + labels + properties (lazy)
    Relationship(RelRef),       // id + type + endpoints + properties (lazy)
    Path(Path),                 // alternating node/relationship sequence
    // POINT deferred (D-temporal-spatial)
}
```

Property values are restricted to the **property subtype** (no Node/Relationship/Path/Map as stored
property values; lists must be homogeneous when persisted) — enforced at write time. Structural and
`Map` values exist only in query results. This split mirrors the openCypher type system CIP
(Source: openCypher type-system CIP).

### 7.3 Compile-time vs runtime error-phase split (TCK requirement)

The TCK distinguishes errors that must be raised **at compile time** (e.g., `SyntaxError`,
`ProcedureError`, `ParameterMissing`, unknown function arity, type errors detectable statically,
undefined variables) from those raised **at runtime** (e.g., division by zero on actual data, type
coercion failures on actual values, constraint violations). (Over the pinned corpus every
statically-detectable fault is a `SyntaxError` bar two `CALL` exceptions; the only `SemanticError` is a
runtime one — the frozen classification lives in `06-bolt-and-error-shapes.md` §2.2.) Graphus enforces this by construction:

- **Semantic analysis** is the *only* phase allowed to emit compile-time errors and it runs to
  completion **before any side effect**. A plan that compiles is guaranteed past all compile-time
  checks.
- **The executor** never raises a compile-time error class. Runtime error classes are raised only
  during row production.
- An **error-classification table** maps every internal error to its TCK `(phase, type, detail)`
  triple; a CI test asserts the phase split against TCK expectations so we cannot regress the
  classification. This table is derived from the *verbatim* TCK error shapes of the pinned tag and is
  **frozen in `06-bolt-and-error-shapes.md` §2** (resolves `02-decision-register.md` Q2; grounded in
  `crates/graphus-cypher/src/errors.rs`).

### 7.4 Execution model — recommendation: **Volcano with vectorized leaves**

- **Volcano (iterator) model** for the operator tree: each operator is a `next()`-style cursor.
  Rationale: it streams results lazily (essential for `PULL n` flow control and NDJSON streaming,
  §8), composes cleanly with the row-by-row semantics of many Cypher operators, and keeps memory
  bounded under large result sets (NFR-5).
- **Vectorized leaf scans:** node/label/index scans and property fetches operate on **batches** of
  record ids to amortize visibility checks and exploit cache locality and SIMD (CRC, comparison,
  filter masks) on the adjacency hot path. This is a pragmatic hybrid: vectorize where it pays
  (scans/filters), stay tuple-at-a-time where semantics demand it.
- CPU-heavy operators (large sorts, hash aggregations, big expands) run on a **dedicated CPU pool**,
  off the Tokio runtime workers (`D-runtime-model`, §9), so they never stall I/O or other sessions.

### 7.5 Plan cache & parameter binding

- **Plan cache** keyed by `(normalized_query_text, schema_version, feature_flags)`; value is the
  compiled physical plan. Capacity-bounded (LRU), invalidated on DDL/index/constraint change
  (schema_version bump). Literal auto-parameterization (replacing inline literals with parameters) is
  applied during normalization so structurally identical queries share a plan — a TCK-safe
  transformation (it must not change observable semantics).
- **Parameters** bind at execution, never at compile, so the cache is parameter-independent. Bound
  parameter types are validated against the plan's expectations at bind time (runtime phase).

### 7.6 Three-valued logic, ordering, equality

These are pure-correctness, TCK-critical modules implemented to the letter of the Cypher semantics
(Source: Neo4j values-and-types; openCypher spec):

- **Three-valued logic (TRUE/FALSE/NULL):** `AND`/`OR`/`NOT`/comparisons propagate `NULL` per the
  Kleene truth tables; `WHERE` keeps a row only on `TRUE`. A dedicated `Ternary` type makes this
  explicit rather than smuggling it through `Option<bool>`.
- **Ordering** (`ORDER BY`, aggregation grouping): the total order across types follows Cypher's
  defined ordering of value classes (e.g., the documented relative order of numbers, strings,
  booleans, temporal, lists, null), with the **distinct float/NaN and signed-zero** rules and the
  documented ascending placement of `NULL`. The order-preserving key encoding (§6.2) is derived from
  exactly this order so indexes and `ORDER BY` agree.
- **Equality vs equivalence:** Cypher's `=` (with `NULL` propagation), `IN`, and the *equivalence*
  used by `DISTINCT`/grouping (where `NULL` groups with `NULL` and `NaN` with `NaN`) are **distinct**
  operations and implemented as such. These are notorious TCK edge cases and get dedicated proptest +
  TCK coverage (§11).

### 7.7 Result streaming, timeout, cancellation

- Results stream as a **cursor** consumed by the connectivity layer at the client's demand rate
  (`PULL n` / NDJSON pull). Backpressure flows from the slow client through bounded channels back to
  the executor (§9).
- **Timeout / cancellation:** every executing query carries a `CancellationToken` and a deadline.
  Operators poll the token at safe points (between rows / between batches); on trip, execution unwinds
  cleanly, the transaction rolls back (undo via WAL), and a TCK-appropriate error/`IGNORED` is
  returned. `tokio::select!` branches that touch the executor are audited for cancellation safety
  (no half-applied state — the WAL undo guarantees atomic rollback regardless of where cancellation
  lands).

### 7.8 Query prefixes — `EXPLAIN` and `PROFILE` (delivered, rmp #752)

`graphus-cypher` implements the two Neo4j-style **query prefixes** that return a statement's
execution plan (`FR-QL-13`; decision `D-query-prefixes`, `02-decision-register.md`). They differ in
exactly one respect — whether the statement runs:

- **`EXPLAIN <statement>`** compiles and plans the statement but **never executes it**: the executor
  returns before any operator is built, so no operator does storage work and no side effect is
  possible (`EXPLAIN CREATE (:X)` creates nothing, by construction rather than by promise). The
  statement produces **zero records**, but the `RUN` `SUCCESS` still reports the statement's real
  `fields` (column names) — matching Neo4j's `ExplainExecutionResult`. The plan is delivered in the
  result summary under the `plan` key (`06-bolt-and-error-shapes.md` §3.1).
- **`PROFILE <statement>`** executes the statement normally (writes included), returns its records,
  and delivers the plan under the `profile` key (`06-bolt-and-error-shapes.md` §3.1), annotated with
  each operator's **measured** `rows` and `dbHits`.

Exactly one of `plan` / `profile` is ever emitted, never both; neither appears for an unprefixed
statement.

**Parser recognition (conformance-critical).** `EXPLAIN` and `PROFILE` are **not reserved words** —
openCypher does not define them as tokens (Neo4j recognises them in a pre-parser), and the TCK relies
on their staying usable as identifiers, labels, relationship types, property keys and aliases
(`RETURN 1 AS explain`, `MATCH (n:Profile)` and `n.explain` all remain valid). The lexer therefore
emits an ordinary identifier, and the prefix is recognised **only** as the statement's first token,
ahead of any `USE` clause, in the one position where a bare identifier can never begin a valid
statement (a statement always opens with a clause keyword). At most one prefix may appear; a
backtick-quoted leading identifier (`` `EXPLAIN` … ``) is never the prefix. The prefix binds to the
whole statement and rides on the compiled plan (`crates/graphus-cypher/src/ast.rs`, `parser.rs`).

**One renderer.** The plan is rendered from the compiled physical plan into a single
protocol-neutral `Value` tree in `crates/graphus-cypher/src/plan_description.rs`, the crate that owns
the operator model; the Bolt and REST seams only pick the metadata key (`plan` vs `profile`) and
serialise the tree, so the two interfaces can never disagree. The wire shape (node keys, the leaf
`children` omission, the `PROFILE`-only top-level `rows`/`dbHits`, the root-only
`EstimatedRows`/`planner`/`runtime`, and the omitted `pageCache*`/`time` counters) is frozen in
`06-bolt-and-error-shapes.md` §3.1.

**`dbHits` — Graphus's own measured definition.** Neo4j documents a DbHit as an abstract unit of
storage-engine work whose accounting is internal to that engine; Graphus does **not** claim to
reproduce Neo4j's numbers. It reports its own precisely-defined, **measured** quantity:

> A `dbHit` is **one record obtained from the `GraphAccess` storage seam** by that operator.

Concretely (`crates/graphus-cypher/src/profile.rs`): a **set-returning** read counts **one per record
it returns** (and 1 when it returns none) — so the fused scan-and-filter access path (`NodeLabelScanEq`)
reports the records it **examined**, not merely those it matched, and a million-node label scan
reports about 1,000,000 hits while the index seek that replaces it reports the handful it fetched; a
**scalar** read counts **1**; a **write** counts **1**. Pure-metadata calls are deliberately **not**
counted — the transaction's own in-memory tombstone check made before every property access, and
catalogue/statistics lookups — because the store did no record work for them. Every number is an exact
count of calls through the one seam all store access passes through; nothing is estimated or
synthesised.

**The candidates an access path examined (rmp #991).** `dbHits` charges an operator for what it
**matched**, which leaves the cost of Graphus's *candidate + re-verification* access model unmeasured.
Every index access path answers from a derived, MVCC-unaware structure, so the index yields a
**superset** of the matching ids and the read body re-reads each candidate to test visibility and
re-apply the predicate. Two scalability brakes therefore had no signal at all: a seek examining a
million candidates to return ten rows looked exactly as cheap as one examining ten, and the blanket
`mark_all_live_nodes` predicate footprint every **non-equality** node seek registers unconditionally
cost one SIREAD marker per live node whatever the seek returned. A `PROFILE` now reports, per
operator, `CandidatesExamined`, `CandidatesRejectedByVisibility`, `CandidatesRejectedByFilter`,
`ReadMarkers` and `PredicateMarkers` (wire shape frozen in `06-bolt-and-error-shapes.md` §3.1).

The three candidate counters are **disjoint** — examined minus the two rejection reasons is the
number of candidates that **survived the re-verification**, which is deliberately *not* a claim about
the operator's rows: de-duplication of an id named by both a stale and a live index entry collapses
two survivors into one row, and a self-loop under an undirected pattern reports one survivor on both
of its sides (both measured and pinned in `candidate_instrumentation.rs`). The two marker counters are
counted at the point of emission, never inferred. The
measurement lives on the storage seam (`GraphAccess::take_read_tally`, implemented by
`RecordStoreGraph` and the off-thread `ReadOnlyGraph`, forwarded by the RBAC and profiling
decorators), the attribution in `ProfileRecorder`, and the rendering in `plan_description.rs`. Each
counter is emitted only when non-zero, so absence means a *measured* zero — distinct from the
permanently omitted `pageCache*`/`time`. PostgreSQL's `EXPLAIN ANALYZE` makes the same distinction
with *"Rows Removed by Filter"* and is the direct precedent; the names are Graphus's own because the
measured quantity is Graphus's own. Recorded baselines for the four access paths this sprint targets
are pinned as executable assertions in
`crates/graphus-cypher/tests/candidate_instrumentation.rs::the_recorded_baseline_for_the_four_access_paths_991`.

**Cost on each path.** A `PROFILE`d statement runs **serially** — intra-query morsel parallelism is
disabled for it (`crates/graphus-cypher/src/executor.rs`) — because the morsel workers read the store
through a seam the profiling decorator does not sit on, so a parallel profiled run would silently
*under*-count. Serial execution keeps every storage access attributable; a profiled query may
therefore be slower than the same query run normally (a diagnostic-only cost, exactly as Neo4j warns
for `PROFILE`). An **unprofiled** statement pays nothing: no instrumentation is constructed (no
recorder, no operator shim, no extra branch on the row path — confirmed by the executor row-path
benchmark). The one always-on half is the seam's own accumulation into its `ReadTally`, which has two
shapes and only one of them is batched: **candidates** are counted into plain locals and flushed with
three `Cell` read-modify-writes per access, while **markers** cost one `Cell` read-modify-write *each*,
because they are emitted from many scattered sites rather than from one loop (120 of them for 40
candidates on the measured unselective range seek). An unprofiled statement never drains the result.

That half is measured over the real record store by `crates/graphus-cypher/benches/read_seam.rs`.
Criterion detected **no change at the mean** on any of the four access paths (all `p > 0.05`); two of
the four *medians* are distinguishable from zero in **opposite** directions (+3.1 % and −2.8 %), which
is code-layout drift between binaries rather than a cost of the counters, since added per-candidate
work cannot make a label scan faster. With 30 samples the run does **not** exclude a regression below
roughly 12 % on the shortest path (`seek_eq_selective`, ~7.5 µs). `graphus-bench/RESULTS.md` §11.2
carries the full numbers and the limits of that evidence.

**Known limitation (measured).** A plain **auto-commit read** is dispatched to the off-thread reader
pool, whose seam does not currently serve property-index seeks: it declines them and the executor
falls back — correctly but expensively — to a scan. So a `PROFILE` of an indexed auto-commit read
reports `NodeIndexSeek` in its plan (the planner *did* choose the index) while its `dbHits` are those
of a full scan; inside an explicit transaction the same seek serves the index (measured: 2 `dbHits`
for the seek versus 201 for the scan over 200 nodes). The rows are identical either way, which is why
`PROFILE` is what makes the discrepancy visible.

---

## 8. Connectivity

Three listeners, **one executor and one `Value` model** behind them. The connectivity crates only
translate framing/serialization; they never embed query or storage logic.

### 8.1 Bolt over UDS and TCP

`graphus-bolt` implements **Bolt 5.x** with **PackStream v1** (Sources: Neo4j Bolt docs; verified
2026-06). The same Bolt state machine and codec run over a `UnixStream` (UDS) and a `TcpStream`
(TCP, **TLS-wrapped**); only the transport and auth differ.

- **Target version:** implement **Bolt 5.x**. The v1 target is **pinned to Bolt 5.4** (5.0 baseline
  through the 5.4 message set) in `06-bolt-and-error-shapes.md` §1 (resolves §12 item 11). The
  **5.7+ "Manifest v1" handshake** is deferred to Phase 2 (`06` §1.2); the legacy 4-slot handshake is
  mandatory regardless.
- **Handshake.** Client sends the 4-byte magic preamble **`60 60 B0 17`**, then four big-endian
  32-bit version proposals (range-encoded since 4.3; `00 00 00 00` placeholder for unused slots). The
  server replies with the single chosen version (or `00 00 00 00` to reject). Manifest handshake
  (client proposes `00 00 01 FF`) is optional and only if we adopt 5.7+.
- **Chunking.** Each message is framed as one or more chunks: a **2-byte big-endian length** header
  (max 65 535 payload bytes per chunk) followed by that many payload bytes, terminated by a
  **zero-length chunk `00 00`**. A bare `00 00` with no preceding data is a **NOOP** (keep-alive).
- **PackStream v1** encodes the `Value` model: null, boolean, integer (1/2/4/8-byte int markers),
  float64, UTF-8 string, list, dictionary, and **structures** (tagged composite types) for `Node`,
  `Relationship`, `UnboundRelationship`, `Path`, and the temporal types. Our `Value` enum (§7.2) maps
  1:1 onto PackStream structures.
- **Messages.** Client: `HELLO`(0x01), `LOGON`(0x6A), `LOGOFF`(0x6B), `TELEMETRY`(0x54),
  `RUN`(0x10), `DISCARD`(0x2F), `PULL`(0x3F), `BEGIN`(0x11), `COMMIT`(0x12), `ROLLBACK`(0x13),
  `RESET`(0x0F), `GOODBYE`(0x02), `ROUTE`(0x66, replied to as single-node). Server: `SUCCESS`(0x70),
  `RECORD`(0x71), `IGNORED`(0x7E), `FAILURE`(0x7F).
- **Server-state machine.** `CONNECTED → (HELLO) → AUTHENTICATION → (LOGON) → READY →
  (RUN/BEGIN) STREAMING/TX_READY/TX_STREAMING → READY …`, with `FAILED` and `INTERRUPTED` states.
- **Fail-then-ignore-until-RESET rule.** On a `FAILURE`, the connection enters `FAILED`; the server
  **must ignore all subsequent client requests** (replying `IGNORED`) **until the client sends
  `RESET`**, which clears the failure and returns to `READY`. This is mandatory Bolt semantics and is
  modeled explicitly as a guard in the state machine.

### 8.2 REST transactional API

`graphus-rest` (axum/hyper) exposes a **transactional HTTP API** mirroring the executor's
transaction lifecycle (Source: Neo4j Query/HTTP transactional API), strictly following HTTP semantics
(RFC 9110/9112), JSON (RFC 8259), CBOR (RFC 8949), and **RFC 9457 Problem Details** for errors.

- **Surface (representative):**
  - `POST /db/{db}/tx` → open an explicit transaction, returns a tx URL + expiry.
  - `POST /db/{db}/tx/{id}` → run statements within the open transaction (keep-alive resets timeout).
  - `POST /db/{db}/tx/{id}/commit` → run final statements and commit.
  - `DELETE /db/{db}/tx/{id}` → rollback.
  - `POST /db/{db}/tx/commit` → single-statement auto-commit shortcut.
- **Serialization (`D-serialization`):** **typed JSON (Jolt-style)** by default and **CBOR via
  content negotiation** (`Accept`/`Content-Type`). The **int53 problem is fixed from day one**:
  64-bit integers are **string-encoded** in JSON (and typed) so no precision is lost crossing a
  JS/JSON boundary; CBOR carries native 64-bit ints.
- **Streaming:** large result sets stream as **NDJSON** (one JSON object per line), so the client can
  consume rows incrementally and the server keeps bounded memory — the HTTP analogue of Bolt's
  `PULL n` pull model. The same executor cursor (§7.7) feeds both.
- **Access mode:** read/write access-mode selection for REST is **specified in
  `06-bolt-and-error-shapes.md` §4** (resolves `02` Q5): an `access_mode` request member with values
  `"READ"` / `"WRITE"`, defaulting to `"WRITE"` when absent, matching the Bolt `BEGIN` semantics.

### 8.3 One executor, one value model

All three listeners construct the same `Session`/`Transaction` objects and pass parameters as the
same `Value` enum; results come back as the same `Value` cursor. There is exactly one place that
turns `Value` into bytes per protocol (PackStream / Jolt / CBOR). This guarantees identical query
semantics across interfaces (a TCK and cross-interface conformance requirement) and means new value
types are added once.

### 8.4 TLS and auth

- **UDS:** no TLS (kernel-protected local channel); auth by **`SO_PEERCRED`** (peer uid/gid) +
  filesystem socket permissions (`D-auth-scheme`).
- **Bolt TCP & REST:** **TLS mandatory** (rustls). Bolt TCP uses Bolt **native auth** (`LOGON`)
  carrying credentials over TLS; REST uses **Bearer/JWT** (RFC 6750/7519). All three resolve to the
  **shared RBAC** model in `graphus-auth` (users, roles, privileges), so an identity has the same
  authorization regardless of entry point.

---

## 9. Concurrency & runtime

`D-runtime-model` (hybrid) and `D-io-backend` drive this layer. The shape is **validated on a
traversal-heavy benchmark before being locked** (measurement-gated).

### 9.1 Hybrid Tokio + sharded write path

- **Tokio multi-thread (work-stealing) runtime** is the baseline: it accepts connections, drives the
  Bolt/REST protocol state machines, and runs the lightweight async glue. It runs on macOS too (a
  thread-per-core runtime like glommio/monoio would not — hence the hybrid choice).
- **Sharded write/ACID path.** The transactional commit path (WAL append, SSI validation, version
  installation) is funneled through a **small set of shards** to minimize cross-core contention on the
  log tail and the SSI conflict tracker. Candidate designs (to be measured, §12): (a) a single log
  shard with group commit (simplest; group commit already amortizes the serialization point), or
  (b) partitioned logging keyed by data partition with a global LSN order — only if (a) is shown to
  bottleneck. Reads are fully parallel and lock-free against committed versions.
- **CPU-heavy work off the runtime workers.** Query operators that burn CPU (sorts, aggregations,
  large traversals) and the WAL fsync run on **dedicated pools** (a `rayon`-style CPU pool and
  dedicated I/O/fsync threads), so the async runtime never blocks. This is a hard rule (no blocking
  syscalls, no heavy loops, no `std::thread::sleep` on runtime workers).

### 9.2 Lock-free structures

Lock-free/atomics are used **deliberately and narrowly**: the timestamp oracle (atomic counter), the
WAL LSN allocator, pin counts, the frame-table shards, and the SSI conflict-edge set hot path. Every
such unit ships with documented memory-ordering rationale and **loom + Miri + aarch64** tests
(NFR-9, §10). Everything else uses `parking_lot`/`std` locks held for short, non-`await` critical
sections.

### 9.3 Backpressure, admission control, load shedding (NFR-5)

- **Bounded queues everywhere** on the request path (inbound per-connection, executor submission,
  result egress). No unbounded channel touches a production path (anti-pattern guard).
- **Admission control.** A global `Semaphore` (or token bucket) bounds concurrently executing
  queries; excess requests either queue within a bounded buffer or are **fast-rejected** with a
  retriable "server busy" error rather than driving the box into memory exhaustion.
- **Load shedding** is *explicit and observable*: rejections, queue depths, and admission waits are
  metrics (NFR-10). Under overload the server degrades by **rejecting cleanly**, never by unbounded
  growth or collapse.

### 9.4 Graceful shutdown

On `SIGTERM`/admin shutdown (Source: Tokio graceful-shutdown pattern): stop accepting new
connections; drain in-flight transactions (commit or roll back to a consistent state); flush and
`fdatasync` the WAL; write a final checkpoint; mark the superblock **clean**; then exit. A hard
deadline forces rollback of stragglers (always safe — uncommitted work is undone by recovery anyway).

### 9.5 Hardware-aware startup auto-tuning

Ratified as decision `D-hw-autotune` (`02-decision-register.md`) and realizing `FR-AR-6`
(`01-needs-survey.md`). Graphus ships a single binary that must run well on everything from a 4-core
Raspberry Pi 5 to a many-core server without hand-tuning. To that end the server **detects the host's
hardware once at startup** and **derives the defaults** for its resource-sizing parameters, while the
operator keeps full, explicit control. The rule is a strict three-level precedence:

> **operator configuration (TOML file or `GRAPHUS_*` env var) > hardware-derived value > built-in floor.**

A value the operator sets explicitly always wins; only an unset parameter is auto-derived; and a
built-in floor guarantees a safe minimum when the hardware cannot be probed. Detection runs **once,
before any database is opened**, is **best-effort**, and **never panics or blocks the server start**.

**Detection model — `graphus-sysres`.** A dedicated leaf crate, `graphus-sysres` (§1.2), performs a
single, one-shot probe that produces a `HardwareResources` snapshot with three independent fields:

- `logical_cpus` — the number of schedulable logical CPUs, from
  `std::thread::available_parallelism`.
- `MemoryInfo { total, available }` — total and currently-available physical RAM, in bytes. On Linux
  and Raspberry Pi OS, `total` is read from rustix `system::sysinfo` and `available` from
  `/proc/meminfo` `MemAvailable`; on macOS, `total` is read from `sysctl hw.memsize` (`available`
  may be absent there).
- `StorageInfo { total, available, rotational }` — the store filesystem's total and free capacity in
  bytes (from `statvfs` on the store path), plus an optional `rotational` hint (`Some(true)` =
  rotational disk, `Some(false)` = SSD/flash, `None` = unknown). The hint is read from `/sys/block`
  on Linux and is `None` on other platforms.

Every probe is **independent and best-effort with graceful degradation**: a probe that fails yields
`None` for its field, and the consumer falls back to the built-in default or floor. `graphus-sysres`
**isolates all OS-specific and `unsafe` probing** (the rustix syscalls, the `/proc` and `/sys`
parsing, and the macOS `sysctl` FFI) behind a safe API, so that `graphus-server` — the crate that
consumes the snapshot — stays `#![forbid(unsafe_code)]`. The crate depends on no other Graphus crate
(a true leaf) and is independently auditable.

**The `0 = auto` sentinel.** Each auto-tunable numeric parameter uses `0` as the *auto* sentinel: a
configured `0` (the default) means "derive from hardware", while any value `> 0` pins the parameter
verbatim. This generalizes the convention already shipped for `reader_threads` and
`morsel_parallelism` (§9.3) to the memory dimension (`buffer_pool_pages`, §3).

| Precedence | Trigger | Value used |
| --- | --- | --- |
| 1 (highest) | Parameter set to a non-sentinel value in the TOML file or its `GRAPHUS_*` env var | The operator's value, verbatim |
| 2 | Parameter left at its `0` (auto) sentinel and the relevant hardware probe succeeded | The hardware-derived value (per the table below) |
| 3 (floor) | Parameter left at `0` (auto) but the hardware probe returned `None` | The built-in floor (a safe minimum) |

**Per-parameter tuning policy.**

| Parameter | Dimension | Auto-derived value (when `0`) | Floor / ceiling |
| --- | --- | --- | --- |
| `buffer_pool_pages` | Memory | `clamp( floor(0.125 × available_RAM_bytes ÷ 8192), FLOOR, CEIL )` | FLOOR = 4096 pages (32 MiB); CEIL = 262144 pages (2 GiB) |
| `reader_threads` (§9.3) | CPU | `min(logical_cpus, 16)` | Floor 1; cap 16 |
| `morsel_parallelism` (§9.3) | CPU | `min(logical_cpus, 16)` | Floor 1 (`1` = fully serial); cap 16 |

- **`buffer_pool_pages` (memory).** The auto value takes a **conservative 1/8 (12.5%) fraction of
  *available* RAM** (`MemoryInfo.available`, i.e. Linux `MemAvailable`), converts it to 8192-byte
  pages (the fixed logical page size, §3.1), and clamps the result to `[4096, 262144]` pages
  (`[32 MiB, 2 GiB]`). If `available` is unknown, the basis falls back to `total`; if RAM is entirely
  unknown, it falls back to the FLOOR. The fraction is deliberately small because **the buffer pool is
  per-database** — every opened database gets its own pool of `buffer_pool_pages` (`dbcatalog`) — and
  RAM is shared with the WAL, index structures, result buffers, and the OS, so taking 1/8 of available
  RAM leaves headroom even with several databases open. The **FLOOR equals today's fixed default
  (4096 pages)**, so auto-tuning is never worse than the prior status quo and never reintroduces the
  known tiny-pool hazard; the **CEIL bounds worst-case resident-set growth**. An operator who needs a
  larger pool sets `buffer_pool_pages` (or the `GRAPHUS_BUFFER_POOL_PAGES` env var) explicitly, which
  overrides the derived value under precedence 1.
- **`reader_threads` / `morsel_parallelism` (CPU).** Behavior is unchanged: auto resolves to
  `min(logical_cpus, 16)` (§9.3). They are documented here because the value is now sourced from the
  same unified `graphus-sysres` detection rather than an ad-hoc `available_parallelism` call, and they
  are the shipped precedent this decision generalizes.
- **Storage (reported, not yet auto-applied).** In this first cut, the detected storage capacity, free
  space, and the rotational/SSD hint are **detected and surfaced in the startup log only**. They may
  inform future tuning (for example prefetch depth, §3.5, or a free-space preflight), but **no
  parameter is auto-changed from a storage reading yet** — stated explicitly to avoid over-promising.

**Startup summary log contract.** Immediately after detection and parameter resolution, the server
emits **one structured log line** at startup that records, at minimum:

- the detected hardware: logical CPUs; total and available RAM; the store filesystem's total and free
  space; and the rotational/SSD hint (rendered "unknown" when a probe returned `None`);
- the **resolved** value of each auto-tuned parameter (`buffer_pool_pages`, `reader_threads`,
  `morsel_parallelism`); and
- the **provenance** of each resolved value — operator-overridden (precedence 1), hardware-derived
  (precedence 2), or the built-in floor (precedence 3).

This single line makes the effective sizing auditable from the logs on every host.

**Acceptance criteria.**

1. With no configuration, on a host where all probes succeed, each auto-tuned parameter resolves to
   its hardware-derived value: `buffer_pool_pages = clamp(floor(0.125 × available_RAM ÷ 8192), 4096,
   262144)` and `reader_threads = morsel_parallelism = min(logical_cpus, 16)`.
2. An explicit non-zero value set in the TOML file or the matching `GRAPHUS_*` env var is used
   verbatim and is never overridden by detection.
3. When a probe fails, its parameter falls back to the built-in floor; the server starts normally
   (detection never panics and never blocks the start).
4. `graphus-server` compiles under `#![forbid(unsafe_code)]`; all OS-specific and `unsafe` probing
   lives in `graphus-sysres`.
5. The startup summary log line is emitted once and reports the detected hardware, each resolved
   value, and its provenance.

---

## 10. Cross-platform / architecture concerns

Targets (`D-target-matrix`): **Linux x86_64 + aarch64, macOS aarch64** Tier 1; 64-bit only; CI on
x86 + aarch64.

### 10.1 Atomic ordering discipline (ARM weak memory model)

x86-64 is strongly ordered (TSO); **aarch64 is weakly ordered**, so code that "happens to work" on
x86 can be broken on ARM (Sources: ARM-vs-x86 memory model; *Rust Atomics and Locks*). Discipline:

- Use the **weakest correct `Ordering`** for each atomic op, with a **`// SAFETY:` / `// ORDERING:`
  comment justifying it** (acquire/release pairing reasoning). Default to `Acquire`/`Release` for
  handoffs and `Relaxed` only for independent counters; reserve `SeqCst` for genuinely
  multi-variable ordering.
- **Every** lock-free/`unsafe` unit has **loom** (exhaustive interleavings), **Miri** (UB + some
  weak-memory checks), and a **real aarch64 CI run** (loom doesn't model ARM hardware reordering, so
  hardware testing on aarch64 is non-negotiable — NFR-9).

### 10.2 Cache-line padding

False sharing is worse on ARM (and the Apple Silicon / Raspberry Pi cache lines differ). Hot
shared-but-independent atomics (per-shard counters, frame-table shard heads, the commit queue) are
**`CachePadded`** (Source: crossbeam `CachePadded`), which pads to the largest relevant line —
**128 bytes on aarch64 (Apple Silicon)**, 64 on x86-64 — using crossbeam's per-arch constant rather
than a hardcoded number.

### 10.3 Page-size handling

The logical DB page size is fixed in the file (§3.1); the **OS page size is queried at runtime**
(`sysconf(_SC_PAGESIZE)`) and used only for buffer alignment and direct-I/O. Apple Silicon's
**16 KiB** OS pages and Raspberry Pi kernels' 4/16 KiB are handled transparently; a database created
on one is readable on another.

### 10.4 SIMD feature-gating

SIMD (CRC32C, batched comparisons/filters in vectorized scans, order-key encoding) is **runtime
feature-detected** (`is_x86_feature_detected!` / aarch64 equivalents) with a scalar fallback, or via
`std::simd` portable SIMD + a `multiversion`-style dispatch (Sources: portable SIMD; multiversion).
No SIMD path is assumed present; the scalar path is always correct and tested.

### 10.5 CI matrix

| Axis | Values |
| --- | --- |
| OS / arch | Linux x86_64, Linux aarch64, macOS aarch64 |
| Toolchain | pinned stable (MSRV recorded), plus nightly for Miri/`-Zsanitizer` jobs |
| Gates | `fmt --check`, `clippy -D warnings`, `nextest`, doctests, `cargo-deny`, **TCK 100%**, Criterion regression gate, Miri (unsafe modules), loom (lock-free modules), a DST smoke run, an Elle anomaly run |
| Sanitizers | ASan/TSan (nightly) on FFI/raw-pointer/concurrency tests |

---

## 11. Testing & verification architecture

Verification is a **deliverable**, not an afterthought (Sources: DST/Antithesis/madsim; Jepsen/Elle;
loom; Miri; proptest; cargo-fuzz; Criterion). The four inviolable requirements are **proven**, not
asserted: ACID by DST and Elle (§11.1, §11.3), Cypher TCK by the TCK harness (§11.2), and the Bolt
protocol and PackStream by protocol-conformance and driver-interoperability tests against the
certified driver matrix (§12 item 11), with PackStream round-trip and fuzz coverage in §11.4.

### 11.1 Deterministic Simulation Testing — built in from the start (`D-dst-investment`)

The whole engine is written against **capability traits** (`Clock`, `Rng`, `FileSystem`/IO, `Spawn`)
defined in `graphus-core` and implemented in `graphus-sim`. There is no direct `std::time::now`,
`rand::thread_rng`, raw `std::fs`, or bare `tokio::spawn` inside the core crates — they go through the
injected capabilities (a lint/architecture test enforces this).

- **Production mode:** capabilities forward to the real OS/runtime.
- **Simulation mode:** a single-threaded deterministic scheduler drives time, RNG (seeded), task
  interleaving, and a model filesystem. The **entire storage/txn/cypher stack runs inside the
  simulator** in one thread, so a run is **fully reproducible from a seed**.
- **Fault injection points:** the model FS injects torn writes, short writes, **fsync failures**
  (to exercise §4.9 PANIC), reordered/dropped writes, and crashes **at arbitrary LSNs**; the
  scheduler injects task delays and unfavorable interleavings; the network layer injects partitions
  and message drops. A failing seed is a one-line reproducer.
- **What DST proves here:** crash-consistency of ARIES recovery (crash at any LSN → recover to a
  consistent committed state), group-commit durability (no acknowledged commit lost), and absence of
  torn-page corruption — i.e., **NFR-1/NFR-2 empirically**, which is exactly why `D-storage-arch`
  (custom engine, highest risk) mandated this investment.

### 11.2 TCK harness (`D-tck-harness`)

- **Primary (CI gate):** a Rust **`cucumber`** runner (`graphus-tck`) executes the pinned openCypher
  TCK feature files against the real engine through the same `Value` model and error-classification
  table (§7.3). 100% pass is a hard gate (NFR-3). The exact pinned TCK tag and its scenario count are
  recorded empirically, not quoted from memory (`02` Q1).
- **Oracle (periodic):** the JVM **`tck-api`** runs as a ground-truth oracle in a slower scheduled
  job to catch any divergence between our harness interpretation and the canonical one.

### 11.3 Anomaly checking — Elle/Jepsen

`graphus-elle` records transaction histories (read/write observations with versions) and exports them
to an **Elle**-style checker (Sources: Jepsen/Elle) to detect serialization anomalies (write-skew,
G2, lost update, …). This independently validates the SSI implementation (§5.4): under the default
Serializable level the checker must find **zero** anomalies; under opt-in Snapshot Isolation it must
find **only** the anomalies SI is allowed to exhibit — confirming both the strength and the honesty
of each level.

### 11.4 loom / Miri / proptest / fuzz / Criterion

- **loom:** exhaustive interleavings for every lock-free/atomic unit (§9.2). **Miri:** UB and
  aliasing for all `unsafe`; runs the unsafe-bearing modules' tests. **aarch64 hardware run:** because
  loom doesn't model ARM reordering (§10.1).
- **proptest:** for the high-value pure modules — the order-preserving key encoding (§6.2),
  three-valued logic / ordering / equivalence (§7.6), PackStream and Jolt/CBOR round-trips, temporal
  arithmetic, and record codecs (round-trip and invariant properties).
- **cargo-fuzz:** for every parser/decoder boundary — the Cypher parser, PackStream decoder, Jolt/CBOR
  decoders, WAL-record and page decoders (a malformed page/log record must never panic or UB; it must
  surface a controlled corruption/parse error).
- **Criterion + macro LDBC SNB:** micro-benchmarks (traversal, index seek, commit throughput) with a
  **CI regression gate** (NFR-7), plus the LDBC SNB macro benchmark for end-to-end realism. Results
  are reported with hardware + toolchain + flags; improvements inside the noise band are ignored.

### 11.5 Fault-injection points (summary)

| Layer | Injected fault | Verifies |
| --- | --- | --- |
| Model FS | torn write, short write, fsync error, reorder, crash@LSN | ARIES recovery, DWB repair, PANIC-on-fsync |
| Scheduler | delays, adversarial interleavings | SSI correctness, latch deadlock freedom |
| Network | partition, drop, dup, slow client | backpressure, Bolt state machine, timeouts |
| Memory | (Miri) UB, (loom) reordering | unsafe/lock-free soundness |

---

## 12. Open technical questions to resolve (spikes / measurements before/while coding)

Each is a concrete TODO; none may be silently decided ("never guess"). Several restate or extend the
escalations already in `02-decision-register.md`.

1. **Public `ElementId` encoding — ULID vs UUIDv7** (`D-element-id`). Both are time-sortable 128-bit
   IDs; decide on lexicographic sortability of the textual form, monotonicity within a millisecond,
   and ecosystem expectations. *Resolve before the record header is frozen (§2.2/§2.3).* Also resolve
   the **TCK integer-`id()` reuse vs never-reused ElementId** reconciliation (`02` Q3).
2. **MVCC version storage: in-place + logical undo deltas vs append-only newest-first** (§5.1).
   **Resolved (2026-08-02) — `D-version-representation`: newest version in place, with older versions
   reconstructed by walking one unified undo-delta chain per entity.** Append-only newest-first
   (PostgreSQL's heap: `/data/refsrc/postgres/src/include/access/htup_details.h:86-98`) is rejected
   because it bloats the hot store and breaks the adjacency locality that index-free adjacency exists
   to protect, while in-place-latest makes the overwhelmingly common read — the latest committed
   version — a single record fetch with no chain walk. The measured ground for the delta half of the
   choice is the present property path, a tombstone walk plus prepend that is **O(M²)** in the number
   of assignments to one entity (`RecordStore::tombstone_props_for_key`,
   `crates/graphus-storage/src/store.rs:5646-5666`; **15.1 µs/op at M = 1000**, **97.8 µs/op at
   M = 8000**), which a constant-cost delta prepend replaces. The model is Memgraph's
   (`/data/refsrc/memgraph/src/storage/v2/delta.hpp:244-392`, `delta_action.hpp:17-33`); the InnoDB
   parallel is cited from official documentation only, as no InnoDB source tree is present in
   `/data/refsrc`. *This unblocks the record header and the undo area, which were explicitly blocked
   on it:* the delta actions, lifecycle, ownership and commit indirection point are specified in §5.1,
   and the on-disk undo-area format in `05-storage-format.md` §12.
3. **Torn-write protection: doublewrite buffer (recommended) vs full-page-writes** (§4.5). Measure
   write-amplification and commit-latency impact per target before locking.
4. **Logical page size** (default 8 KiB) and **B+-tree fanout** (§3.1, §6.1) — measure against LDBC
   SNB working set and key sizes; confirm interaction with 16 KiB Apple-Silicon OS pages.
5. **Page checksum algorithm: CRC32C vs xxh3** (§4.6) — measure on x86-64 (SSE4.2) and aarch64 (CRC
   ext); both must have a correct scalar fallback.
6. **Buffer-pool eviction: CLOCK vs 2Q vs sampled-LRU** (§3.4) — measure scan resistance + hit rate.
7. **Frame latch: `parking_lot::RwLock` vs a custom hybrid latch** (§3.3) — measure under high
   read concurrency on aarch64.
8. **Sharded write path: single log shard + group commit vs partitioned logging** (§9.1) — measure
   on the traversal-heavy benchmark that `D-runtime-model` requires before locking the runtime shape.
   **Resolved (SPIKE #8) — keep candidate (a): single log shard + group commit.** The Criterion
   commit-path benchmark (`crates/graphus-bench/benches/commit_path.rs`, results in
   `crates/graphus-bench/RESULTS.md`) measured the real `RecordStore` commit path on x86_64: sustained
   short write transactions run at p50 3.4 µs / **p99 7.2 µs** / ~173 K commits·s⁻¹ single-thread, with
   p99 **flat across a 1 K→50 K transaction stream** (no log-tail saturation) and bounded across a
   1→256-ops/commit WAL-volume sweep (group commit amortizes sub-linearly per op). Partitioned logging
   (b) is therefore **not built** — per §9.1 it is warranted "only if (a) is shown to bottleneck", and
   nothing in the single-node envelope shows that. **Revisit (b)** only if the multi-threaded
   group-commit benchmark (the follow-up needing the §9.1 commit queue) shows a p99 saturation knee vs
   offered concurrency. The aarch64 run is deferred to capable hardware (the benchmark is the reusable
   instrument). *No p99 regression vs the 1-op baseline (6.2 µs).*
9. **Allocator** (`D-allocator`): system default first; benchmark mimalloc/jemalloc per target before
   adopting (jemalloc has Apple-Silicon friction). Decision is per-target, evidence-gated.
10. **Dense-node promotion threshold** (§2.5) — measure the degree at which the grouped representation
    beats the plain doubly-linked chain.
11. **Bolt maximum minor version + Manifest-v1 handshake** (§8.1). **Resolved (SPIKE #9) — see
    `06-bolt-and-error-shapes.md` §1:** the v1 target is pinned to **Bolt 5.4** (5.0 baseline through
    the 5.4 message set), legacy 4-slot handshake mandatory; the **5.7+ Manifest-v1 handshake is
    deferred to Phase 2**. Re-confirm against the certified driver matrix before adopting any minor
    beyond 5.4.
12. **`GString` representation** (§7.2) — `SmallString`/inline vs `Arc<str>` vs `Box<str>` for query
    values vs stored strings; measure on string-heavy workloads.
13. **Pinned openCypher TCK tag + scenario/feature count** (`02` Q1/Q2). The tag is pinned to
    `2024.3` (`02-decision-register.md` "TCK target"). **The error-classification table is resolved
    (SPIKE #9) — see `06-bolt-and-error-shapes.md` §2:** derived from the verbatim TCK detail strings
    and frozen against `crates/graphus-cypher/src/errors.rs`. **Deferred:** the verbatim Neo4j
    two-letter Bolt status-code mapping (needs the pinned TCK and certified driver artifacts; `06`
    §2.4).
14. **REST access-mode selection** (`02` Q5, §8.2). **Resolved (SPIKE #9) — see
    `06-bolt-and-error-shapes.md` §4:** an `access_mode` request member with values `"READ"` /
    `"WRITE"`, defaulting to `"WRITE"` when absent, validated otherwise, matching the Bolt `BEGIN`
    semantics.

---

## 13. Sources

Primary authorities behind the design above (full URLs in `03-sources.md`):

- **Recovery / WAL:** ARIES (Mohan et al.); CMU 15-445 Crash Recovery notes; Write-Ahead Logging
  (Sookocheff). — §4
- **Durability / torn writes / fsync:** fsyncgate + PostgreSQL Fsync Errors wiki; Percona "two
  databases / torn pages"; Evan Jones on Linux durability; "Are You Sure You Want to Use MMAP in Your
  DBMS?" (Crotty/Leis/Pavlo, CIDR 2022). — §3, §4
- **Concurrency control / SSI:** Cahill/Röhm/Fekete Serializable Snapshot Isolation; Ports & Grittner,
  *SSI in PostgreSQL* (VLDB 2012); PostgreSQL README-SSI; Berenson et al., *A Critique of ANSI SQL
  Isolation Levels*. — §5
- **Storage internals / adjacency / MVCC stores:** Neo4j storage internals & concurrent data access;
  Memgraph storage/MVCC/durability; TiKV B-tree vs LSM; redb (CoW B+-tree). — §2, §3, §6
- **Data model & query language:** openCypher property-graph model; openCypher TCK; openCypher
  type-system CIP; Cypher 9 reference; Neo4j Cypher values-and-types (ordering/equality/temporal);
  ISO/IEC 39075:2024 (GQL). — §2, §7
- **Connectivity / serialization:** Neo4j Bolt protocol (handshake, messages, PackStream, server
  states); Neo4j transactional HTTP/Query API + Jolt result formats; RFC 9110/9112 (HTTP), RFC 8259
  (JSON), RFC 8949 (CBOR), RFC 9457 (Problem Details), RFC 6750/7519 (Bearer/JWT); `unix(7)`
  (`SO_PEERCRED`). — §8
- **Runtime / performance / portability:** Tokio runtime & scheduler; io_uring (tokio-uring; DBMS
  paper; seccomp constraints); ScyllaDB/Seastar shard-per-core; ARM-vs-x86 memory model; *Rust Atomics
  and Locks* (Mara Bos); crossbeam `CachePadded`; portable SIMD / multiversion; Rust platform-support
  tiers. — §9, §10
- **Verification:** Deterministic Simulation Testing (Antithesis, madsim); Jepsen/Elle; loom; Miri;
  proptest/quickcheck; cargo-fuzz; Criterion.rs; LDBC Social Network Benchmark. — §11

> Bolt handshake/message/framing details in §8 were read from the Neo4j Bolt current documentation
> (handshake, message, packstream pages) on 2026-06-05 and reflect Bolt 5.x / PackStream v1.
