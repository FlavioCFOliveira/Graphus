# 04 — Technical Design (the "HOW")

This document is the **implementation-design layer** for Graphus. The functional baseline
(`00-overview.md`, `01-needs-survey.md`) defines *what* the server must do; the decision register
(`02-decision-register.md`) records the *ratified* choices. This document specifies *how* to build
it: concrete crate boundaries, on-disk layouts, byte-level record formats, algorithms, and the
control/data flow an engineer codes against.

It is written to be **prescriptive**. Where a choice is still gated on measurement (project rules
"measure to decide" and "never guess"), it is flagged inline and collected in §12. Decision IDs
(`D-…`) refer to `02-decision-register.md`; source short-names refer to §13 and to `03-sources.md`.

> **Inviolable constraints that gate every design here:** 100% ACID and 100% openCypher TCK.
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
| `graphus-txn` | lib | Transaction lifecycle, MVCC version chains, visibility, SSI conflict tracker, timestamp oracle, version GC, deadlock/latch policy. |
| `graphus-cypher` | lib | Full Cypher compile/execute pipeline; plan cache; runtime operators; error-phase split; result cursors. |
| `graphus-bolt` | lib | PackStream v1, chunked framing, handshake, Bolt server-state machine; transport-agnostic over UDS and TCP. |
| `graphus-rest` | lib | HTTP transactional API (axum/hyper), Jolt-style typed JSON + CBOR negotiation, NDJSON streaming, RFC 9457 errors. |
| `graphus-auth` | lib | `SO_PEERCRED` peer auth, JWT/Bearer verification, RBAC model, shared across listeners. |
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

All layouts below are the **logical fields**; exact field packing (and whether the MVCC header is
inline vs side-tabled) is finalized after the §12 version-storage spike. Sizes are the design
target.

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

Property chains are singly linked per entity; a property update under MVCC creates a new version of
the *entity* (or a property-version record) rather than mutating in place (§5.6).

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

### 5.1 Version representation — recommendation: **version chains with logical undo deltas**

Each record's MVCC header (§2.3) holds `xmin`, `xmax`, and a `version_ptr` to the prior version.
Newest version lives in the main store ("newest-to-oldest" chain); older versions are reachable via
`version_ptr` into the undo/version area.

**Recommendation:** store the **newest version in place** and keep older versions as **logical undo
deltas** in the WAL-backed undo area (an MVCC scheme close to in-place + undo, à la Memgraph's
delta chains; Source: Memgraph storage). Rationale: traversals (the hot path) overwhelmingly read
the *latest* committed version, which is then a single record fetch with no chain walk; only
concurrent readers on older snapshots pay to walk deltas. The alternative — append-only new versions
with the chain newest-first in the main store (Postgres-style) — simplifies GC ordering but bloats
the hot store and hurts adjacency locality. **The final pick (in-place+delta vs append-only) is a
spike in §12**, measured on a traversal-heavy workload, because it interacts directly with
index-free-adjacency cache behavior.

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

- **Writes** create new versions linked via `version_ptr`; the MVCC header carries `xmin/xmax`. The
  store is therefore MVCC-native (§2.3), not an MVCC layer on top of a single-version store.
- **Index entries are MVCC-aware (§6.3):** an index points at a record; visibility is resolved by
  reading the record's MVCC header, and index entries for dead versions are GC'd alongside.
- **Constraint checks** (uniqueness/existence) run at **commit time** against the committed snapshot
  to be serializable-correct (§6.5).

### 5.7 Latch vs lock granularity; deadlock handling

- **Latches** (physical, short) protect page bytes and in-memory structures (§3.3); they are ordered
  to be deadlock-free by construction.
- **MVCC has no read locks** (SSI uses non-blocking SIREAD markers). The only true blocking is
  **write-write**: two transactions writing the same record — the second either waits for or, under
  SI/SSI "first-updater-wins", is aborted on conflict. Because write-write conflicts can cycle, a
  **wait-for graph deadlock detector** runs over write-lock waits; on a cycle it aborts the
  youngest (or lowest-progress) transaction with a retriable error. A configurable lock-wait timeout
  is the backstop.
- This split — deadlock-free latches + a bounded-scope write-lock deadlock detector + non-blocking
  reads — is what lets readers never block writers (NFR-4).

---

## 6. Indexing

`graphus-index` provides four index kinds in v1 (`D-v1-index-types`): **token-lookup**,
**range/B-tree**, **composite**, and **relationship-property** indexes; plus uniqueness/existence
**constraints**.

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

### 6.6 Planner use of indexes

The planner (§7) consults the **index catalog** (a system structure listing indexes, their keys,
and selectivity hints) during physical planning to choose index seeks/scans over full scans. v1 uses
**heuristic/rule-based** planning with index awareness; a cost-based optimizer with statistics is
Phase 2 (`00-overview.md` §6). Plans record which indexes they depend on so the **plan cache** is
invalidated on schema/index change (§7.5).

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
`SemanticError`, unknown function arity, type errors detectable statically, undefined variables) from
those raised **at runtime** (e.g., division by zero on actual data, type coercion failures on actual
values, constraint violations). Graphus enforces this by construction:

- **Semantic analysis** is the *only* phase allowed to emit compile-time errors and it runs to
  completion **before any side effect**. A plan that compiles is guaranteed past all compile-time
  checks.
- **The executor** never raises a compile-time error class. Runtime error classes are raised only
  during row production.
- An **error-classification table** maps every internal error to its TCK `(status, classification,
  phase)` triple; a CI test asserts the phase split against TCK expectations so we cannot regress the
  classification. This table is derived from the *verbatim* TCK error shapes of the pinned tag
  (escalated open item in `02-decision-register.md` Q2).

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

---

## 8. Connectivity

Three listeners, **one executor and one `Value` model** behind them. The connectivity crates only
translate framing/serialization; they never embed query or storage logic.

### 8.1 Bolt over UDS and TCP

`graphus-bolt` implements **Bolt 5.x** with **PackStream v1** (Sources: Neo4j Bolt docs; verified
2026-06). The same Bolt state machine and codec run over a `UnixStream` (UDS) and a `TcpStream`
(TCP, **TLS-wrapped**); only the transport and auth differ.

- **Target version:** implement **Bolt 5.x** (5.0 baseline through at least 5.4 message set). Whether
  to also implement the **5.7+ "Manifest v1" handshake** is a small scoping call (§12-Q); the legacy
  4-slot handshake is mandatory regardless. *Exact maximum minor is pinned in §12 against the driver
  versions we certify.*
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
- **Access mode:** read/write access-mode selection for REST is an **open item** (`02` Q5) — Bolt's
  `BEGIN` carries it but the REST equivalent must be specified (likely a request field), escalated
  not guessed.

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
loom; Miri; proptest; cargo-fuzz; Criterion). The two inviolable requirements are **proven**, not
asserted.

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
2. **MVCC version storage: in-place + logical undo deltas vs append-only newest-first**
   (§5.1). Spike both on a traversal-heavy workload; decide on hot-path cache behavior + GC cost.
   *Blocks finalizing the record header and the undo area.*
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
9. **Allocator** (`D-allocator`): system default first; benchmark mimalloc/jemalloc per target before
   adopting (jemalloc has Apple-Silicon friction). Decision is per-target, evidence-gated.
10. **Dense-node promotion threshold** (§2.5) — measure the degree at which the grouped representation
    beats the plain doubly-linked chain.
11. **Bolt maximum minor version + Manifest-v1 handshake** (§8.1) — pin the exact Bolt 5.x minor and
    decide whether to implement the 5.7+ manifest handshake, against the specific driver versions we
    certify (read the verbatim spec for the pinned version, don't assume).
12. **`GString` representation** (§7.2) — `SmallString`/inline vs `Arc<str>` vs `Box<str>` for query
    values vs stored strings; measure on string-heavy workloads.
13. **Pinned openCypher TCK tag + scenario/feature count** (`02` Q1/Q2) — read verbatim from the
    pinned tag; derive the error-classification table (§7.3) from its exact error shapes.
14. **REST access-mode selection** (`02` Q5, §8.2) — specify the read/write access-mode field for the
    REST transactional API (no documented Bolt-`BEGIN` equivalent).

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
