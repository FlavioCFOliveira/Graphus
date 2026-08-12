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
| `graphus-chainhead` | lib | The **prepend publication protocol** every chain head in the storage core shares — `first_rel`, `first_prop` and the MVCC `undo_ptr` (§5.7.1): the four ordered steps, the retry a refused publication demands, and the `ChainHead` trait that states the two obligations the underlying medium must honour. A true **leaf**: it depends on no other crate, and that is a requirement rather than an accident. `--cfg loom` is a global rustflag, so a protocol that must be model-checked cannot live in a crate that reaches `graphus-bufpool`, whose own loom seam would then stop matching. `#![forbid(unsafe_code)]`. |
| `graphus-freezefloor` | lib | The **freeze frontier** of the fixed-record stores (§5.6): the lower bound below which the incremental GC's freeze sweep has already visited every record, and the three — and only three — operations its algebra admits. It **descends** by `fetch_min` (a writer announcing a stamp below it), it **rises** only by a compare-exchange against the value the sweep started from (so a descent that lands mid-sweep refuses the raise instead of being swallowed), and it is stored into only to initialise it. A plain store in either of the first two roles strands a committed writer's stamp below the frontier, where no later sweep visits it — the silent-data-loss shape of tasks `#522` and `#778`. A true **leaf** for the same reason as `graphus-chainhead`, and the type is the one `RecordStore` holds, so the `loom` models check the production cell rather than a copy of it. `#![forbid(unsafe_code)]`. |
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
   **begin timestamp** — its snapshot, which is the published commit-visibility horizon of §5.2, read
   once by the store and handed back rather than sampled twice. Access mode (read/write) is recorded.
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
- **A mutation that may decline to happen must not stamp the page.** The pool offers a declining
  variant of its stamped write: the closure reports whether it wrote, and the frame is marked dirty
  and stamped with the record's LSN **only** if it did (`BufferPool::with_page_mut_lsn_if`,
  `crates/graphus-bufpool/src/concurrent.rs:849`; added for the chain-head publication of §5.7.1).
  **Advancing `page_lsn` without a write is corruption, not a harmless over-approximation**: redo
  skips every record whose LSN is at or below `page_lsn`, so a page carrying an LSN it never applied
  silently loses every legitimate record logged at or below it, and nothing reports the loss. Marking
  the frame dirty without a write is the milder half of the same mistake — it schedules a pointless
  write-back and, on a page whose `page_lsn` is still zero, trips the WAL-rule guard. The frame's
  write latch is taken whether or not the write happens, because the decision itself must be made
  under it.
- **Latch ranks.** Every blocking primitive in the engine carries a **rank**, and a thread acquires
  ranks in ascending order, innermost last: **5** the engine's session latches, **10** catalog / DDL,
  **20** commit sequencer and active-transaction table, **25** the per-store physical-id allocation
  latch, **27** the page **log-apply-order** latch (§5.7.2), **30** the WAL, **40** the buffer-pool
  frame latch, **50** the page-table shard, **60** the device and the doublewrite stager. Rank **22**,
  the GC's maintenance latch, sits between 20 and 25 (task #1014). An acquisition out of rank order is permitted only as a
  `try_lock`, which creates no wait edge. Ranks 10, 22, 25 and 27 admit **at most one holder per
  thread**: two locks of the same rank cannot be ordered by rank at all, so two threads that acquire a
  different pair in a different order deadlock. Ranks 25 and 27 are also **released before any I/O** —
  held across store growth, across a page fetch that may evict, or across a durability barrier, either
  one convoys every writer that shares it behind a single `fdatasync`.

  The two ends of the order are pinned from opposite directions, and mechanically. Rank **22** is a
  **leaf**: nothing may be acquired while it is held, so a GC pass snapshots the set it is draining and
  works with the latch dropped (task #1014). Rank **10**, the catalog latch (task #1015), is the
  **root**: it refuses to be entered while any inner latch is held, so it is taken first or not at all
  — and, being outermost, it is the one latch that MAY span I/O, because the operation it protects (a
  checkpoint of the catalog) *is* the I/O. Debug builds check every one of these obligations with
  thread-local tripwires (`graphus_core::latch`) armed at the WAL barrier, at `BufferPool::fetch`, at
  the store-page growth path and at each scope's own construction; a release build pays nothing for
  them.

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

Committing transactions append their `COMMIT` records and then **park on a commit queue**. An engine
worker batches all pending records up to the current log tail; that batch costs **one** `write()` and
**one** `fdatasync()` (data + size metadata, not full `fsync`, on filesystems where
`fdatasync` is sufficient — verified per-platform), and the worker then wakes every parked committer
whose LSN is now durable. This amortizes the sync cost across concurrent commits (Source: WAL/ARIES,
Postgres group commit). **Which thread performs that `fdatasync`, and how many run at once, is the
subject of the two paragraphs below.** A **per-transaction synchronous** mode (`synchronous_commit=on` per session) bypasses
batching for callers that need it; an explicit relaxed mode is **not** offered as a default because
it would violate NFR-1.

**The `fdatasync` is pipelined, not inline** (task **#532**). `begin_harden` writes a batch's records
to the log file *without* syncing them and hands back a **deferred job**; the worker offers that job
to the database's fsync group leader, prepares the **next** consecutive commit batch while the sync
runs off its own thread, then waits for the job, completes the harden, and only then acknowledges its
committers. So the durability sync of batch *K* overlaps the CPU preparation of batch *K+1* instead of
an engine worker blocking on every `fdatasync`. Between the write and the completion the WAL has
`durable_len < written_len`; the buffer pool shares the same WAL manager, so an eviction that must
write home a data page whose `page_lsn` falls inside that window hardens the written range **inline**,
and the WAL-before-data rule is never suspended. The synchronous, non-pipelined path is retained for
the deterministic simulator, so that a DST replay is bit-identical (`07-dst-simulator.md`).

**One fsync group leader per database engine, never one per worker** (decision `D-wal-group-leader`,
task **#1040**). Each engine worker runs its own commit pipeline, so several workers can sit between
`begin_harden` and `complete_harden` at the same time, and every one of their jobs is offered to the
**single** leader. The leader runs one job at a time and folds the rest into one pending slot, keeping
the job with the largest target; a worker whose job was folded away is released by the job that ran,
because that job's range subsumes its own. This is the trade PostgreSQL's `XLogFlush` makes when one
backend's flush satisfies every backend waiting on a smaller LSN. **Depth-1 is a property of the
database, not of a worker: at most one `fdatasync` is in flight for the whole engine**, whatever the
worker count — so the crash tail is the tail of **one** un-synced interval rather than of several
interleaved ones. The structure this replaced was one fsync thread **per worker**, which documented
itself as strict depth-1 and stopped being true the day the engine became multi-worker: each worker
was depth-1 for itself, so the system reached depth `W`, issuing `W` duplicate `fdatasync`s of
overlapping ranges over one WAL manager with no coalescing between them.

**The sink contract the coalescing rests on.** Discarding one worker's job because another worker's
job subsumes it is sound only under three properties of the log sink. They are **normative**, and each
is pinned by a test that fails if it is broken:

1. **A job hardens at least its whole declared range** `[covers_from, target_len)` — it syncs the
   whole files spanning the range, not the byte range one caller happened to append.
2. **`covers_from` is the sink's global durable frontier** at the moment the job was created, never a
   per-worker frontier. This is what makes the newest job's range a superset of every older live
   job's.
3. **Completion is a monotone maximum** (`durable_len = max(durable_len, target_len)`), and a
   committer is acknowledged only against a `durable_len` read **after** that advance — so a waiter
   may legitimately complete with the watermark the **group** reached rather than its own.

All three held before task #1040 and **none of them was declared anywhere**, which is exactly how a
later move to `sync_file_range`, to a per-worker durable frontier, or to a sync per segment rather
than per file would have turned a correct engine into one that acknowledges commits whose bytes were
never synced. The deferred job therefore carries the range it hardens **explicitly** — both ends, not
only its end — so the contract is machine-checkable rather than prose, and **every discard is
adjudicated by an always-on tripwire** against the sink's own attested durable frontier. The leader
learns that frontier independently, because each offer reports it, which is also how it observes that
an eviction's inline harden advanced durability behind its back; without that second source the
tripwire would mistake a legitimate advance for a broken sink contract. A failed `fdatasync` fails
**every** waiter whose bytes were in the range — the correct blast radius, since the WAL tail they
share is precisely what did not reach the platter — and it does so **before** any committer of that
batch is acknowledged (§4.9).

### 4.3 Steal + no-force

- **No-force:** a committing transaction does **not** force its dirty data pages to disk — only its
  WAL must be durable. Recovery's redo phase reconstructs committed-but-unflushed changes.
- **Steal:** dirty pages of *uncommitted* transactions **may** be evicted to disk. Recovery's undo
  phase rolls them back. This is what makes large transactions possible without unbounded buffer
  pressure, and it is the reason undo logging is mandatory.

**What undo logging still decides, and what it no longer decides** (task **#970**). Undo logging
stays mandatory, for two reasons that outlive the move to logical rollback. It is how recovery rolls
back the **losers** of a crash (§4.8, phase 3), and it is the inverse of a **maintenance**
transaction — a GC reclamation, a corpse splice, a freeze sweep — whose writes are physical space
management naming no MVCC version. What it is no longer is the mechanism of **isolation**: a live
data transaction is rolled back by applying its own deltas against the current state of each record
it touched, never by reverting the bytes it wrote (§5.1.5 row 4). One test selects between the two
paths — whether the transaction owns a commit-info slot (§5.1.3), which it does if and only if it
linked a delta: `RecordStore::rollback` (`crates/graphus-storage/src/store.rs:5941`) dispatches to
`rollback_logical` (`:5840`) or to `rollback_physical` (`:6062`).

### 4.4 CLRs (Compensation Log Records)

During undo (rollback or recovery), each undone action writes a **CLR** recording the compensating
change and an `undo_next_lsn` pointer to the next record still to be undone. CLRs are **redo-only**;
they make undo itself idempotent and crash-safe (a crash mid-rollback resumes from the last CLR
rather than re-undoing). This is the standard ARIES guarantee against repeated undo.

**CLRs belong to the physical undo path.** Recovery's undo phase writes them, and so does the
rollback of a transaction that owns no commit-info slot (§4.3). The **logical** rollback of a data
transaction writes none: it repairs each record with an ordinary redo-logged write and then ends the
transaction in the log with a single `ABORT` record and no compensation at all
(`WalManager::abort`, `crates/graphus-wal/src/manager.rs:550`). That record is load-bearing rather
than cosmetic — recovery's loser set is exactly the transactions that have log records and neither a
`COMMIT` nor an `ABORT` (`crates/graphus-wal/src/recovery.rs:255-259`) — so without it the next
recovery would undo the repairs themselves.

**A third form of page-update record: redo-only**, beside the record whose undo image is a physical
pre-image and the record whose undo image is a compare-and-set (§5.1.5 row 3). A write whose inverse
is *logical* logs a redo image and an **empty** undo image
(`WalManager::log_update_redo_only`, `crates/graphus-wal/src/manager.rs:378`), so neither a rollback
nor recovery's undo phase compensates it: recovery writes its CLR and applies nothing
(`crates/graphus-wal/src/recovery.rs:296-301`). The chain-head publications of the storage core are
the case it exists for — the prepend onto `undo_ptr` / `first_rel` / `first_prop` and the relink of
the head it displaces. Their inverse is to **unlink the entry**, computed from the state at abort
time and carried by the transaction's own deltas (§5.1.5 row 3), and the state such a write leaves
after recovery is a head naming a `!in_use` record: a corpse, which every walk in the storage core
already threads through and the GC splice reclaims.

**A chain-head publication's redo image is itself conditional** (task #1028, §5.7.1). The record
carries the word's expected pre-value beside its post-value (`paging::encode_cas_patch`,
`crates/graphus-storage/src/paging.rs:131`), and `paging::apply_patch` (`:150`) — the one applier that
serves a live rollback and recovery's redo alike — installs the post-value only where the word still
holds the expected one. **No WAL record type, format version or recovery step changes to obtain
this**: the conditional patch shape already existed, because it was the shape of the compare-and-set
*undo* images, and it is reused unchanged. It buys two things. The record replays to the verdict the
live system reached even when the page image it replays onto already carries the publication — which
happens whenever an unrelated writer on the same page regressed `page_lsn` and made recovery start
further back than it needed to. And the record states the precondition of its own write, so a replay
that would not have been valid declines instead of clobbering. **A publication that is refused
appends no record at all** (§5.7.1), so the log never carries a record for a write that did not
happen.

**A live rollback that fails leaves its transaction OPEN.** That ARIES guarantee is about *crash*
recovery, which restarts the undo from the durable log. A *live* rollback has no such restart point:
its undo — WAL images on the physical path, its own deltas on the logical one — and everything the
repair depends on are one indivisible operation, and once the WAL manager has consumed the
transaction's active-transaction entry a second call finds nothing left to undo and would report
success over records it never repaired. So a live rollback
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

**The measured grounding.** The decision was not taken on preference. Property assignment was, when it
was taken, a tombstone pass over the whole property chain followed by a prepend
(`RecordStore::tombstone_props_for_key`), which is **O(M²)** in the number of properties set on one
entity — measured at **15.1 µs/op at M = 1000** and **97.8 µs/op at M = 8000**. The delta chain
replaced that walk with a constant-cost prepend (task #967, §5.1.5 row 1).

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
| `AddIncidentEdge` | **removes** an incident relationship from a node — *frozen but unwritten; no write path emits it (below)* | the relationship type token, the other endpoint's physical id, the relationship's physical id, and the direction | that one incidence entry |
| `RemoveIncidentEdge` | **adds** an incident relationship to a node | the same four fields as `AddIncidentEdge` | the absence of that incidence entry |

Two properties of this set matter downstream. First, **a delta is per-entity and per-change, never
per-record-image**: an entity with a thousand properties that changes one of them writes one small
delta, not a copy of the entity. Second, **the incidence actions name a single incidence entry**, not
a chain-head pointer, so undoing an edge insertion is the removal of one entry rather than the
restoration of a pointer word that a concurrent writer may meanwhile own — which is exactly the
failure mode that forced the present ad-hoc compare-and-set undo
(`crates/graphus-storage/src/record.rs:114-123`).

**A third property is specific to the incidence actions: they anchor on the RELATIONSHIP, not on the
endpoint node** (`D-incidence-anchor`, ratified 2026-08-04; task **#969**). The node is where the
incidence chain *head* lives, so the node looks like the natural anchor, and the first draft of #969
used it. It is the wrong one, and the reason is measured rather than argued.

With the node anchor, a node's chain grows by one delta per edge inserted on it, and **every property
or label read of that node walks its chain**: one visible-property read on a hub cost **220 ns at
degree 0 and 488 µs at degree 4000**. The growth does not end at the next collection either — §5.5's
chain reclamation frees a chain only when *every* delta on it is dead, so a hub under sustained
insertion never prunes. That is a direct regression of the acceptance criterion task #967 established
(a visible-property read touches one property record, whatever the entity's history).

The relationship carries the same information and none of the cost. It is a **fresh slot private to
its creator**, so three things follow at once: incidence deltas never interleave with another
transaction's, the commit ordering the read path's `Stop` rule depends on (§5.3) is undisturbed, and
**an edge insertion never conflicts with anything** — the supernode write concurrency `rmp` #220 built
is preserved exactly, with no relaxation of §5.1.2 step 1 needed anywhere.

The price is accepted deliberately: **every** edge pays two deltas, including in a bulk load. The
endpoint-anchored draft could skip them when the endpoint was created by the same transaction — such a
node is invisible to every other snapshot — and the relationship-anchored one cannot, because the
relationship always was created by the writing transaction. Measured at **898 B/edge** of WAL for an
edge between two committed endpoints.

Memgraph anchors on the vertex and must, and the difference is representational rather than a matter
of taste. Its `in_edges` / `out_edges` are a plain container **inside the vertex** with no per-element
version (`/data/refsrc/memgraph/src/storage/v2/vertex.hpp:41-44`), so a vertex's adjacency can only be
reconstructed from that vertex's delta chain. It pays for that twice over: the chain is walked on
every expansion, and edge creation had to be given an explicit escape from the write-conflict rule
(`PrepareForNonSequentialWrite`, `mvcc.hpp:150`; the permitted set is exactly the two edge-creation
actions, `delta.hpp:394-396`) to keep edge-heavy imports viable. Graphus reconstructs adjacency from
nothing — every relationship carries its own MVCC header and the incidence walk filters per element
(§2.4) — so it needs neither the walk nor the escape.

The same difference decides where `AddIncidentEdge` is written, and the answer is **nowhere**.
Memgraph's `DeleteEdge` erases the edge from both containers in place, so it must write the restoring
delta. Graphus's deletion is a tombstone: the relationship keeps its slot and its links so an older
snapshot can still traverse to it (§5.3), and the adjacency is not mutated at all — the version that
covers the deletion is the relationship's own `RecreateObject`. Physically unlinking on delete
instead would sever an off-thread reader mid-traversal, which is the `rmp` #811 defect class.

`AddIncidentEdge` is therefore **frozen but unwritten**: the format keeps it so the pair of incidence
actions is complete, and no write path emits it. Task **#970** did not change that, and it is the
detail a reader is most likely to get backwards. What its logical rollback *applies* is
`RemoveIncidentEdge` — the delta an edge insertion left behind, whose application removes that one
incidence entry (`RecordStore::undo_own_incidence`,
`crates/graphus-storage/src/store.rs:5718`). An `AddIncidentEdge` delta found on a chain is treated
as corruption and fails the rollback, because nothing in this build can have removed an incidence
entry for it to restore (`apply_own_delta`, `:5420-5424`).

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

   **When this check arrives, and at what granularity** (`D-property-write-conflict`, ratified
   2026-08-03). The check lands with **task #967**, the first task to put a value on the chain, and
   it is keyed on **the entity** — the node or relationship that owns the property — not on the
   property cell. That is the granularity §5.7 already specifies, and it is Memgraph's
   (`PrepareForWrite`, `/data/refsrc/memgraph/src/storage/v2/mvcc.hpp:112-137`, called by the
   property accessor at `vertex_accessor.cpp:425` immediately before the delta link at `:450` and
   the in-place mutation at `:451`). Concretely: the writer reads the head of the entity's undo
   chain and aborts with a retriable serialization failure if that head belongs to another
   transaction that is still open.

   It is a **prerequisite** of the property migration rather than a consequence of it, because
   three separate things depend on it and none of them is sound without it:

   - the in-place overwrite is an **update** rather than a lost update;
   - the entity's chain is **commit-ordered**, which is what lets a reader stop walking as soon as
     it reaches a version its snapshot may see (§5.3);
   - the abort-time **pre-image of the in-place cell is provably exact**, because no other writer
     can have touched it between the delta link and the rollback.

   Task **#971** later consumes this check rather than replacing it: what #971 removes is the lock
   table and the deadlock detector (§5.7), not the check itself. **#971 is done**: the lock table
   is gone and this check is the engine's only conflict mechanism.

   **The Cypher seam already imposes exactly this rule.** `RecordGraph::set_node_property` calls
   `note_write(node_ssi_key(node.0))` (`crates/graphus-cypher/src/record_graph.rs:6045`), and
   `note_write` (`:540`) captures a "write-write conflict … retry (serialization failure)" when the
   entity is held by another transaction. The coordinated path's behaviour therefore **does not
   change**; what becomes newly constrained is the **direct `RecordStore` callers**, which today
   reach the property path without passing through that seam.
2. **Allocation.** The delta is allocated in the undo area under the writing transaction's ownership,
   carrying the action, its payload, the transaction's `command_id` (below), and a reference to the
   transaction's shared commit-info slot (below) — **not** a timestamp of its own.
3. **Linking.** The delta is prepended to the entity's chain and the entity's `undo_ptr` is advanced
   to it. The link order is fixed and non-negotiable, because garbage collection and concurrent
   readers walk the chain while it is being modified: set the new delta's `next` to the current head
   **first**, and publish the new head **last**, so the chain is a valid list at every instant
   (Memgraph's `CreateAndLinkDelta` documents and enforces exactly this order —
   `/data/refsrc/memgraph/src/storage/v2/mvcc.hpp:314-359`).

   **Publishing the head is a compare-and-publish against the head the delta was linked to**, and it
   is the same protocol every other chain head in the storage core uses — §5.7.1 specifies it in
   full. A refusal re-reads the head, re-points the delta's `next` at that head, and tries again. On
   the undo chain, and only there, a refusal also **re-runs the conflict check of step 1 against the
   freshly re-read head**. That is not optional: the check is what makes the reader's early stop of
   §5.3 true, and a check evaluated once against a head that has since been displaced is a stale
   check that would wave a second open transaction's delta onto the chain.
4. **In-place mutation.** Only then does the writer change the home record, so the newest value is in
   place and its predecessor is recoverable from the delta just linked.
5. **Resolution.** On commit, the transaction publishes its commit timestamp once (below) and its
   deltas become the historical versions other snapshots read. On abort, the transaction walks **its
   own** deltas in the reverse of the order it linked them and applies each one against the
   **current** state of the entity, which restores exactly the state it found; it then detaches them
   from the chains they are on — always a head prefix, never a splice in the middle — reclaims them
   together with its commit slot, and ends in the log with an `ABORT` record and no compensation
   (`RecordStore::rollback_logical`, `crates/graphus-storage/src/store.rs:5986`). This is a *logical*
   undo, and since task **#970** it is what the rollback of a data transaction is; the physical
   byte-level ARIES undo it replaced survives only for transactions that own no commit slot (§4.3).
   Memgraph's abort is the same walk
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
(`crates/graphus-storage/src/store.rs:778-786`). The frontier is a correctness-critical invariant of
its own, it has needed its own release-active audit (`store.rs:571-576`), and moving it past a live
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
(§10.2). And because the slot is published by a single release store, **every delta of the transaction
becomes committed at the same instant** — which is atomicity (the **A** of ACID) expressed directly in
the data structure rather than reconstructed by a sweep.

That single store settles the deltas; it is not the whole of publication. A commit also has to appear
in the in-memory commit registry, which is what resolves an in-flight stamp still sitting in a record
header, so publication is **two writes in two media** and cannot be made instantaneous the way
Memgraph's is. What guarantees that no reader ever observes the transaction half-published is
therefore not the store's atomicity but the horizon of §5.2: the commit timestamp stays unpublished —
and no snapshot may reach it — until both writes are done.

#### 5.1.4 Statement-level isolation: `command_id`

Each delta records the **`command_id`** of the statement that produced it: a counter incremented once
per statement within the transaction, carried in the four bytes `05-storage-format.md` §12.2 froze at
offset 4. It exists so that a statement can be shown the state that preceded it, even for changes its
own transaction made — the "read-your-own-writes but not your-own-current-statement's-writes" rule
that Cypher's `MERGE` and multi-clause updates depend on. **Task #972 delivered it**, and the rest of
this section specifies the mechanism that is in the engine (decision `D-statement-isolation`, ratified
2026-08-05).

**The rule.** A read carries a **view** alongside its snapshot — `New` (the default) or `Old` — and
the view decides nothing about other transactions. It decides only what the reader sees of its **own**
transaction's uncommitted deltas, and the whole of it is one comparison operator:

| The delta was written at | `View::New` undoes it when | `View::Old` undoes it when |
| --- | --- | --- |
| `CommandId::NONE` | never | never |
| a real command `c` | `c > current` | `c >= current` |

`graphus_txn::command_hides_own_write` is that table and nothing else, and
`Snapshot::hides_own_command` is the same rule bound to a snapshot's own `command` and `view`. Under
`New` a later command's write cannot normally exist, because statements run one at a time; the
comparison is `>` rather than a blanket "never" so that the rule stays total and no future
concurrent-statement path can read a command that has not run.

Memgraph carries the same two-valued distinction (`/data/refsrc/memgraph/src/storage/v2/view.hpp`)
and writes the same rule the other way round — it *stops* the chain walk where Graphus *undoes* —
at `/data/refsrc/memgraph/src/storage/v2/mvcc.hpp:72-94`, where `View::NEW` stops on
`cid <= transaction->command_id` and `View::OLD` on `cid < transaction->command_id`. PostgreSQL
expresses the same thing over the tuple header: a tuple the reader's own transaction inserted is
invisible when `HeapTupleHeaderGetCmin(tuple) >= snapshot->curcid`
(`/data/refsrc/postgres/src/backend/access/heap/heapam_visibility.c:965`, in
`HeapTupleSatisfiesMVCC`), with `curcid` captured when the snapshot is taken
(`src/backend/storage/ipc/procarray.c:2455`) and advanced by `CommandCounterIncrement`
(`src/backend/access/transam/xact.c:1129-1171`).

**`CommandId::NONE` is a carve-out, not an edge case.** A delta written outside any statement — by
recovery, by a maintenance pass, by the catalog — carries `NONE`, and **no view ever undoes it**. Such
a write belongs to the transaction's **baseline** rather than to one of its statements. Without the
carve-out, `NONE >= NONE` would make a maintenance transaction's own `Old` read erase its own work.
For the same reason `CommandId::FIRST` is `1` and not `0`: the `Old` view of the first statement must
exclude every delta that transaction could possibly have written, so `0` has to stay reserved for "no
statement has run".

**The counter saturates rather than wrapping.** `CommandId::next` saturates at `u32::MAX`, because
wrapping to `0` would make a later statement's own writes look **older** than its first — a visibility
error rather than an overflow. PostgreSQL declines the same wrap by raising an error at the same
ceiling ("cannot have more than 2^32-2 commands in a transaction", `CommandCounterIncrement`).

**Where the counter lives, and who may stamp a delta.** The counter is one field of the writing
transaction's active-transaction entry **inside the record store**: `RecordStore::begin_command` opens
the next statement and returns its id, and `RecordStore::command_of` reads the current one. **The
store is the single source of truth and no other component keeps a copy.** One explicit transaction
runs many statements over many query-seam instances, and each new instance re-derives the counter from
the store, so an attached seam continues the transaction's numbering instead of restarting it; a
restart would let the `Old` view of statement 2 hide statement 1's writes. `RecordStore::link_delta`
stamps `command_id` from that counter, and `creation_chain_head` does the same for the `DeleteObject`
delta a creation publishes. **No caller may supply a `command_id` of its own**, for the same reason no
caller may supply a `commit_info`: a caller that could would be able to stamp a delta with a statement
that is not running, and the `Old` view would then silently resolve against it.

**Where the counter advances — two points, and only two.**

1. **At cursor open**, the seam every caller funnels through — the server, the TCK harness, the CLI
   and the tests alike, and the same seam that already fixes the statement's temporal instant, which
   every zero-argument temporal constructor in the statement reads. The advance
   sits *after* the `EXPLAIN` early return, so an explained statement leaves the counter exactly where
   it found it (`EXPLAIN` executes nothing and must therefore consume nothing), and *before* the
   operator tree is built, because that is where leaf scans read the store and the scan must run at
   **this** statement rather than the previous one.
2. **At a `WITH` that follows a write**, through the dedicated `AdvanceCommand` operator the planner
   inserts when — and only when — the plan accumulated so far already performs a write. The operator
   **drains its input first** and advances only then: the input is still producing the previous
   command's writes, and advancing while it runs would stamp the tail of them with the next command's
   id, giving a downstream `Old` read a split-brain view of one clause. This is Memgraph's rule
   transcribed: `GenWith` computes `advance_command = is_write` and threads it into the projection,
   while `GenReturn` passes a literal `false` because a `RETURN` ends the query and nothing after it
   can read the graph (`/data/refsrc/memgraph/src/query/plan/rule_based_planner.cpp:872` in `GenWith`,
   against `:857` in `GenReturn`). It is the behaviour the TCK pins in
   `clauses/create/Create3.feature`, scenario [3] "MATCH-CREATE-WITH-CREATE":
   `MATCH () CREATE () WITH * MATCH () CREATE ()` over a graph of two nodes has the side effect
   `+nodes 10`, because the second `MATCH` runs at a **new** command and therefore does see the first
   `CREATE`'s rows, while neither `MATCH` sees its own.

The counter deliberately does **not** advance at the coordinator's per-statement graph-seam factory
(`TxnCoordinator::statement`), which is called again on **every resume** of a suspended cursor.
Advancing there would hide from a long-running `CREATE` the rows it had already applied in earlier
batches of the same statement. Nor does it advance when a correlated sub-plan opens a seeded cursor
(the body of an `EXISTS { … }`): that is a sub-plan of the statement already running, not a statement
of its own, and advancing would move every write the enclosing statement has yet to perform to a later
command than the one its own projection reads at — so the outer `RETURN` would stop seeing its own
`CREATE`.

**What the view changes on the read path.** The view is resolved against the entity's undo chain,
never against the record header, because `05-storage-format.md` §12.2 put the `command_id` on the
**delta** and not in the live record (§5.3). Two seams consume it, and between them they cover every
read that can observe a change:

- `scan_polarity::delta_verdict` decides what a snapshot must do with one delta while reconstructing
  an older version. Its "this snapshot's own in-flight writer" arm is where statement granularity
  enters: the delta is **applied** (undone) when `Snapshot::hides_own_command` says so, and otherwise
  the walk **stops**. This gives statement granularity to the two folds that already walked the
  chain — a property's value and a node's label bitmap.
- `read_view::entity_visible_at` decides whether a node or a relationship **exists** as of the
  snapshot, which is also what makes an edge traversable. It refines `graphus_txn::is_visible`
  exactly where the two header words run out of information, by applying the transaction's own
  `DeleteObject` / `RecreateObject` deltas.

`entity_visible_at` costs nothing on the paths that do not need it, and that is by construction rather
than by measurement. Three gates run in order and an ordinary read fails the first: under `View::New`
the two answers are identical, so no walk is entered; the question can only arise for an entity **this**
transaction created or deleted while still in flight; and an entity with no chain has no statement to
distinguish. A read fault inside the walk **fails closed** — the answer is an error, never the header's
own verdict, which is the answer the chain was consulted to correct. That is the same
fail-closed-on-read-fault contract the label and property folds already owe (`rmp` #733): an answer
that cannot be resolved fails the read rather than being guessed either way.

**Polarity per clause.** Which view a clause reads under is a fixed table, not a per-operator
judgement. It is `Old` for everything that is an access path and `New` — the default — for everything
else:

| View | Clause or operator |
| --- | --- |
| **`Old`** | every node and relationship scan; **every index seek, of every kind**; every relationship expansion, including variable-length, shortest-path, quantified-path and named-path reconstruction; the `Filter` of a `MATCH`; `UNWIND`; a **read-only** procedure `CALL`; and any fused morsel pipeline that subsumes one of these scans |
| **`New`** | the match sub-plan of `MERGE`; `CREATE`, `SET`, `REMOVE`, `DELETE` and `FOREACH` (targets and right-hand sides); the projection of `RETURN` and `WITH`; aggregation, `ORDER BY`, `SKIP` and `LIMIT`; a **writing** procedure `CALL`; and every operator that reads no store at all |

Three properties of that table are normative:

- **A seek and the scan it replaces read the same view.** An index seek that read `New` while its
  fallback scan read `Old` would make `CREATE INDEX` change the answer — the defect class of
  `rmp` #738 and #894. For the same reason the view filter is applied **per candidate the index
  returns**, never only at candidate generation: an index is a candidate generator, and every
  candidate is re-checked for statement-granular existence before it becomes a row.
- **An operator sets the view around its own accesses only, never around a child's.** Wrapping a
  child would impose one operator's polarity on a whole subtree, which is exactly what the table
  exists to prevent: a `Filter` is `Old`, but the `Create` beneath it is `New`. The switch is always
  restored, including on the error path, so nesting is safe — a `Filter` reading under `Old` may drive
  an `EXISTS { … }` sub-plan whose projection reads under `New` and hands `Old` back on the way out.
- **A procedure is `New` unless it is known to be read-only.** The classification fails safe: a
  procedure the registry cannot vouch for runs under `New`, because a writing procedure must see what
  it has just written.

Memgraph plants the same polarity in the same place: `ScanAll` and every `ScanAllBy*` variant declare
`storage::View view = storage::View::OLD` as their default
(`/data/refsrc/memgraph/src/query/plan/operator.hpp:565`, the first of thirteen such declarations in
that header), and its label-property index re-verifies each candidate under that view rather than
trusting the index entry
(`/data/refsrc/memgraph/src/storage/v2/inmemory/label_property_index.cpp:444`).

**Coexistence with the planner's `Eager` barriers.** The planner's eagerness barriers are **all
retained**, deliberately. `Eager` and `command_id` solve different halves of the same family:
`Eager` decouples **row production** across a clause boundary, while the view re-polarises
**visibility** across it. Removing the barriers in the same task that introduced the views would let
the two mechanisms mask each other — a test that passes because the barrier is still there proves
nothing about the view, and vice versa. Reforming the barriers in the light of statement-level
isolation is therefore separate work, and until it is done the optimiser's own invariant holds: a pass
may **add** a read-write `Eager` barrier and may never remove one.

#### 5.1.5 What the unified chain replaces

**Five** mechanisms stood in for the version chain, and they existed only because there was no chain
to carry the change. The table below lists each of the five (rows 1–5) with its replacement and the
task that retired it, preceded by row 0 — the missing foundation all five depended on, which is the
undo area itself. **Every row is now closed**, and the table is kept as the authoritative record of
what each mechanism was replaced by; the decision register (`02-decision-register.md`) summarises it
and does not restate it.

| # | Mechanism, and what became of it | Where it lives now | Replaced by | Retired in |
| --- | --- | --- | --- | --- |
| 0 | ~~**No undo area at all.** `undo_ptr` is reserved in every record and always written `0`, so there is no chain to anchor.~~ **CLOSED.** | was `crates/graphus-storage/src/record.rs`; now `crates/graphus-storage/src/undo.rs` + `StoreKind::Undo` / `StoreKind::Commit` | The undo area and the delta record; `undo_ptr` is the live chain head | **#966 — done** |
| 1 | ~~**Property tombstone plus chain prepend.** Setting a property walks the entity's whole property chain to tombstone the previous version, then prepends a new one — **O(M²)** over M assignments (15.1 µs/op at M = 1000; 97.8 µs/op at M = 8000).~~ **CLOSED.** | was `RecordStore::tombstone_props_for_key`; now the one property write path, `RecordStore::set_entity_property_encoded`, `crates/graphus-storage/src/store.rs:8282` | One `SetProperty` delta carrying the old value; the home property record is updated in place, and a **removal** is an empty cell in place rather than a tombstone (below) | **#967 — done** |
| 2 | ~~**Label bitmap mutated in place, with the version history held only in memory.** The history is an in-process structure shared by `Arc`; nothing about it is durable, so labels are not versioned on disk.~~ **CLOSED.** | was `crates/graphus-storage/src/label_history.rs`; now `RecordStore::link_label_deltas`, `crates/graphus-storage/src/store.rs:3751` | `AddLabel` / `RemoveLabel` deltas on the same durable chain as every other change | **#968 — done** |
| 3 | ~~**Ad-hoc compare-and-set undo for chain heads.**~~ **CLOSED.** A chain-head publication and the relink of the head it displaces are logged **redo-only** (§4.4); their inverse is to unlink the entry, never to restore the word. **What survives is a different mechanism, deliberately kept:** the node's `labels` word and the MVCC header word keep a compare-and-set undo, because each is a whole-word write whose inverse *is* the word — and that undo is now consumed only by recovery, since a data transaction's live rollback applies no WAL undo image at all. | was `store.rs` `write_chain_head` (pre-image, then compare-and-set) and `write_rel_field_keep`. `write_chain_head` **no longer exists**: since task **#1028** a chain-head **prepend** publishes through `RecordStore::compare_and_publish_chain_head` (`crates/graphus-storage/src/store.rs:3960`), driven by `prepend_chain_head` (`:4087`) over the `graphus-chainhead` protocol; its redo image is conditional and its undo image is still empty (§5.7.1, which also names the two *unlink* paths that still install a head with a whole-record write). The displaced head's relink writes only the fields it changes, through `RecordStore::write_field_redo_only` (`:3869`). The surviving compare-and-set undo is `patch_header_word_cas` (`:3801`) and `write_node_labels` (`:5692`) | `AddIncidentEdge` / `RemoveIncidentEdge` deltas naming one incidence entry, so no shared pointer word is ever rewritten by an undo | **#969** (the deltas) + **#970 — done** (the compensations) |
| 4 | ~~**Physical ARIES rollback.** Undo reverts bytes. This is the origin of the recurring defect family rmp #220 / #172 / #239 / #301 / #578 / #772, each one a case of one transaction's byte-level undo damaging another's committed state.~~ **CLOSED for every transaction that holds MVCC state.** | was `RecordStore::rollback`; now `RecordStore::rollback_logical`, `crates/graphus-storage/src/store.rs:5986`. `rollback_physical`, `:6062`, survives as the inverse of a maintenance or catalog-only transaction — one that owns no commit slot (§4.3) | Logical rollback: the transaction walks its own deltas and applies them | **#970 — done** |
| 5 | ~~**Write-lock table plus wait-for-graph deadlock detector.**~~ **CLOSED.** | was `crates/graphus-txn/src/lock.rs` | Conflict detection on the entity's MVCC header, aborting immediately without waiting (§5.7) | **#971 — done** |

Two further tasks complete the model rather than replacing a mechanism. **#972 — done** introduced
`command_id` and statement-level isolation (§5.1.4). **#973 — done** built the deterministic thread
scheduler required by `D-dst-writer-scheduler`, so that multi-writer behaviour is certified from a
seed rather than from a race: the mechanism and its yield points are specified in
`07-dst-simulator.md` §5.2, and what it did and did not move is in §5.1 of that document. What that
task delivered is the **scheduler**; the N-concurrent-writer scenarios that consume it are **#975**,
and until they exist the four write-path yield points are installed but not yet exercised.

**Status of this section: rows 0–5 are closed.** #966 built the undo area, the delta record, the
commit-info slot and the chain, and brought `undo_ptr` to life; #967 moved the property path onto that
chain; #968 versioned labels on it and retired the in-memory label history; #969 versioned adjacency
on the relationship's chain; #970 made the rollback of a data transaction logical and retired the
chain-head compensations; #971 retired the lock table and the deadlock detector. Every mutation kind
the engine performs is therefore a delta on one chain, each transaction's commit is a single store
into its slot, chains are reclaimed by watermark at GC, and the consistency checker validates every
one of them.

**What is still the specified target rather than present behaviour** is the seeded dispatch of
**several concurrent writers** against one database, which `D-dst-writer-scheduler` names as the
prerequisite of multi-writer certification. The scheduler that makes such a run reproducible is no
longer outstanding — **#973** built it, and the `rmp` #811 class (garbage collection racing an
off-thread reader at page-latch granularity) is now reproducible from a seed
(`07-dst-simulator.md` §5.2) — but the writers it is to order are not created until **#975**.
`command_id` is likewise no longer outstanding: **#972** made it live, so a delta carries the
statement that wrote it and is `0` only when the write happened outside any statement (§5.1.4). The
`graphus-txn` transaction manager also still runs against a
placeholder store — "the real `graphus_storage` does not yet implement version-chain mechanics", and
wiring it up "is a follow-up task, intentionally **out of scope** here"
(`crates/graphus-txn/src/store.rs`); that is a statement about the SSI harness's own test seam (§5.7),
not about the storage engine, whose chain is live.

**Row 2, second consequence: the label creator gate is narrowed to the creating statement.** Row 2's
replacement links an `AddLabel` or `RemoveLabel` delta per changed bit, with one exception: a node the
writing transaction created itself is not versioned, because no reader can ask what its labels were
before it existed. **#972** narrowed that exception, and the narrowing is a behaviour change rather
than a restatement. Once statements are isolated from each other, "created by this transaction" is no
longer the condition under which the question cannot be asked: a node created by statement 1 and
labelled by statement 2 **is** visible to statement 2's `Old` view, which would then read the live
word and see a label statement 2 had just added. The gate in `RecordStore::link_label_deltas`
therefore tests "created by **this statement**", which is the precise condition. The test is `O(1)`
against a per-statement set of created entities that `RecordStore::begin_command` clears when it opens
the next statement, and the bulk-create fast path — `CREATE (:L)`, which creates and labels within one
statement — is unaffected: the same test that pins the narrowing asserts that this path still links no
label delta (`crates/graphus-storage/tests/command_isolation_972.rs`,
`a_node_created_by_an_earlier_statement_has_its_labels_versioned`).

**Row 4 in detail: what a rollback costs, and what it stopped costing.** The physical path is
`O(store)`, and not incidentally: it calls `reload_catalog`, which rebuilds the whole in-memory
catalog — every free list, the token dictionary, the whole `Statistics` — from the durable metadata
page, and must then restore, from pre-rollback snapshots, everything that reload discarded and that
did not belong to the aborting transaction: the free lists (rmp #578), the live-record counters
(#866), the physical-id and `ElementId` high-water marks (#220/#172), the token dictionary and the
schema-catalog superset (#534/#734). The logical path discards nothing, so it restores nothing: every
id the transaction consumed is returned by the action that retires its record, its counter movements
are withdrawn as its own exactly-invertible delta, high-water marks and tokens are never lowered, and
its schema DDL is reverted entry by entry on the live catalog. The cost is therefore bounded by the
transaction's own writes rather than by the size of the store. Measured over a fixed set of writes
(`crates/graphus-storage/tests/rollback_cost_970.rs`): **66 µs → 21 µs** on a 500-node store, and
**1 087 µs → 25 µs** on a 16 000-node store with 4 000 interned property keys — a 16× spread with
store size, replaced by a flat one. The structural contract, not the clock, is what the test pins: a
data transaction's rollback performs **no catalog reload at all**.

**Row 4, second consequence: the slots an abort orphans are parked, not reused immediately.**
Retiring a record the aborting transaction created (applying its `DeleteObject` delta) frees the
record's property chain and zeroes its 25-byte MVCC header, but does **not** return its physical id to
the free list. The id is held in an in-memory pending set and returned by a GC phase that runs after
the tombstone sweeps (`RecordStore::gc_reclaim_orphan_slots`,
`crates/graphus-storage/src/store.rs:5866`). The abort knows the slot is unreachable — it is what
unlinked it — so the restraint is deliberate, and its reason lies outside the storage engine: the
latest-state TEXT, FULLTEXT and SPATIAL indexes are in-memory (§6.7) and **not transactional**, and
key their documents by **physical node id**. An aborted node's posting survives its rollback as a
harmless false positive that the re-check filters out; handing the id straight back out instead turns
the next writer's *insert* into what the index reads as the **replacement of a still-committed
document**, which is the shape `rmp` #756 must fail closed on — the freshness marker is poisoned and
every text or spatial seek degrades to a full scan until a rebuild. Parking keeps the space guarantee
(the slots do come back, so an abort-heavy workload does not grow the store) while moving the recycle
to a maintenance boundary; it becomes unnecessary once the indexes are version-aware. The set is in
memory only, and losing it to a crash costs nothing: the slot is `!in_use` on the page, so no read can
reach it and no invariant is broken — it is space the next store rebuild reclaims, exactly like an
undo-area orphan.

**Row 1 in detail: what a property removal becomes** (`D-property-removal`, ratified 2026-08-03).
`REMOVE n.p` — and `SET n.p = null`, which Cypher defines as the same removal — rewrites the
property cell **in place** to an **empty cell**: `type_tag = 0, value_inline = 0`. The cell keeps its
`in_use` bit and its position in the entity's `first_prop` chain, and the old value descends onto the
entity's undo chain in a `SetProperty` delta, exactly as an ordinary overwrite does. **A removal is
therefore not an `xmax` tombstone**, and it is not a distinct delta action: there is one action for
setting, changing and removing a property, and the removal case is the one whose *new* value is
empty.

This is Memgraph's representation. Its removal is a `SetProperty` whose new value is an empty
`PropertyValue`: `PropertyStore::SetProperty`
(`/data/refsrc/memgraph/src/storage/v2/property_store.cpp:2829`) erases the property when
`value.IsNull()` (`:2831`, `:2841`), while the delta written just before it
(`vertex_accessor.cpp:450`) carries the **old** value. There is no removal action and no tombstone in
that design either.

Three consequences are **normative**:

1. **Exactly one owner names any `strings.store` overflow chain.** The live cell owns the **current**
   value; a delta owns **each historical** value; the two sets are **disjoint**. No overflow chain is
   ever named by both a cell and a delta, or by two deltas. This is what makes the representation
   safe to reclaim: GC frees an overflow chain when its single owner is reclaimed, with no
   reference counting and no scan for co-owners.
2. **A later `SET` of the same key reuses the empty cell, with no allocation.** The cell is already
   in the chain and already `in_use`, so re-setting the key writes the new `type_tag` and
   `value_inline` into it. This is the second half of the O(M²) fix: repeated assignment to one key
   allocates nothing and walks nothing.
3. **`expired_ts` is never again written by a property operation**, and
   `RecordStore::tombstone_props_for_key`
   (`crates/graphus-storage/src/store.rs:6710-6753`) is **retired**. The property path stops
   expiring cells altogether; expiry remains meaningful only for the entity records themselves.

### 5.2 Timestamps and snapshots

A central **timestamp oracle** issues monotonically increasing logical timestamps:

- **begin timestamp** at transaction start = the transaction's snapshot, which is the **published
  commit-visibility horizon** specified below and never the oracle's allocation counter. A version is
  visible iff `xmin` committed ≤ begin_ts **and** (`xmax` is 0, or `xmax` committed > begin_ts, or
  `xmax` belongs to an uncommitted/aborted txn).
- **commit timestamp** issued at the start of commit, after SSI validation succeeds. Issuing it and
  making it visible are **two distinct instants**, and the second one is what a snapshot may observe.

Uncommitted versions are tagged with the writer's `TxnId` (distinguished from committed timestamps by
a high bit) so visibility checks can resolve in-flight writers via the Active Transaction Table.

**The snapshot invariant is normative** (`D-published-snapshot-horizon`, ratified 2026-08-12, task
**#1056**):

> A snapshot taken at timestamp `V` sees every transaction whose commit timestamp is at or below `V`.

Every reader in the engine already *assumed* it. `graphus_txn::visibility::is_visible` admits a
committed creator exactly when its commit timestamp is ≤ the snapshot's, the chain walk of §5.3 stops
on the same test, and the SSI tracker of §5.4 reads `commit_ts ≤ begin_ts` as "committed before it
began" and therefore forms no rw-antidependency edge. What no mechanism did was **establish** it.

**Why the allocation clock is not a snapshot.** A commit publishes itself in two writes in two media —
the durable commit-info slot of §5.1.3, then the in-memory commit registry — while the commit
timestamp is issued *before* both. Handing out the allocation clock as a begin timestamp therefore
promises a reader a commit that neither visibility oracle will yet admit. While one thread owned the
write path the two instants could not be told apart; under `D-multi-writer` they can, and a
transaction that begins inside that window reads the pre-commit value of every record the committing
transaction wrote. When that transaction is itself a writer, it computes its own write from the value
it was not entitled to see and overwrites the newer one: a **lost update**, the cardinal ACID
violation, measured on roughly one run in five at eight engine workers and never at one. Neither
backstop catches it — the write-write check of §5.7 inspects a head whose transaction is by then
genuinely committed at a timestamp ≤ the reader's, and the SSI tracker declines to form an edge for
exactly the same reason. Both are reading the timestamp correctly; the timestamp was the thing that
lied.

**The commit sequencer.** The store keeps the set of commit timestamps that have been **issued but
have not finished publishing**, and derives the horizon from it:

```text
    horizon = lowest_pending - 1,  or the whole allocation clock when nothing is pending
```

- The horizon is the **contiguous published prefix**, not "every timestamp that has published". With
  `12` pending and `13` already published the horizon stays `11`, because a snapshot at `13` would
  claim to include `12`. This is conservative in the *freshness* of a snapshot and never in its
  *consistency*.
- It is published with an atomic maximum, so it is **monotone** whichever order two workers recompute
  it in: a stale recomputation can fail to advance the horizon, never move it backwards.
- A commit timestamp is released to the horizon **only after both halves of publication are done** —
  the durable slot and the registry entry — and never between them. A read-only commit (§4.2, the
  `rmp` #529 fast path) publishes nothing and so releases its timestamp as soon as it stops being
  pending.

**The sequencer's latch is rank 20** (§3.3), which is the rank the engine's latch order already
reserved for it by name, and it is acquired through a **single door**: one function takes it, and
nothing may be acquired while it is held. Its leaf property is therefore a fact about that one
function rather than a convention spread over call sites. The cost is two short critical sections per
commit — one insertion when the timestamp is issued, one removal when it is released — and **nothing
on the read path**: taking a snapshot remains a single atomic load, because the horizon is maintained
entirely by committers.

**Issuing a timestamp and registering it as pending are one indivisible step, and its release is
unconditional.** Both happen inside the same critical section; split, a second worker
could recompute the horizon between the two, find nothing pending, and hand out a snapshot at the very
timestamp just issued, which is the defect reintroduced in a two-line window. Symmetrically, **every
exit from commit must release the timestamp** — publishing it on success, abandoning it on failure.
The commit path is therefore split into a timestamp-issuing wrapper and a fallible body, so that
release is a property of one caller rather than of every fallible step inside it. A timestamp that
leaks holds the horizon down **permanently**: one failed commit would pin every later reader in the
process to a snapshot taken before it. An abandoned timestamp is skipped and never reissued, exactly
as a sequence value consumed by a rolled-back statement is; the horizon closes over the gap when the
next pending timestamp is released.

**A transaction uses the timestamp it was handed, never a re-read of the clock.** `begin` returns the
horizon it captured, and the commit path returns the timestamp it assigned. Reading the clock a second
time beside the call was correct only while one thread could be committing: under `D-multi-writer` a
second read is a second instant, and it returns a sibling worker's timestamp or — since the horizon now
lags an in-flight commit — a timestamp below the transaction's own. Neither value is this
transaction's, so both the write-conflict check of §5.7 and the SSI tracker of §5.4 would then be
deciding against a number that belongs to no transaction they are ruling on. One read, one answer,
used by everything downstream.

**Naming, to avoid a collision.** The **commit sequencer** specified here owns the *visibility
horizon*: which issued timestamps may be seen. It is not the commit ordering that task #977 is to
deliver for parallel writers, which owns *total commit order and SSI validation*. The two are
complementary and neither subsumes the other.

Nothing here changes an on-disk format: the horizon is derived in memory from state the store already
maintains, and it is recomputed from the recovered commit-timestamp high-water when a store is opened.

### 5.3 Visibility rules

A transaction `T` with snapshot `s` sees version `v` iff:

1. `v.xmin` is committed with `commit_ts(xmin) ≤ s`, **and**
2. `v.xmax` is 0, OR `v.xmax` is uncommitted, OR `v.xmax` aborted, OR `commit_ts(xmax) > s`.

A transaction always sees its **own** uncommitted writes (its `TxnId` matches). This yields
Snapshot Isolation reads; SSI (below) upgrades correctness to Serializable without adding read
locks.

**This two-clause rule is the answer *between* transactions, and it is complete as such.** It is not
the whole answer *within* one, and it structurally cannot be: the two header words record **which
transaction** created or expired a version and never **which statement of it**, because
`05-storage-format.md` §12.2 put the `command_id` on the undo **delta** rather than in the live
record. So the "own uncommitted writes" override above is stated at *transaction* granularity, which
is the strongest answer those two words support. `graphus_txn::is_visible` implements exactly this
rule and deliberately answers nothing finer.

**Statement granularity is resolved one layer down, against the entity's undo chain** (§5.1.4). Two
functions divide the work and neither duplicates the other:

- `graphus_storage::read_view::entity_visible_at` answers **existence** — whether a node or a
  relationship is there as of the reader's statement. It starts from `is_visible`'s verdict and
  refines it only where the header cannot decide, by applying the reader's own transaction's
  `DeleteObject` and `RecreateObject` deltas. Under `View::New` the two answers are identical by
  construction, so the refinement costs one comparison and no chain walk.
- `graphus_storage::scan_polarity::delta_verdict` applies the same statement rule while a fold
  reconstructs a **value**: a property's current value and a node's label bitmap. Its own-writer arm
  is where the two views diverge — the delta is undone when the reader's view hides the command that
  wrote it, and otherwise the walk stops.

A caller that needs the statement-granular answer must use those seams. A read fault inside either of
them fails closed: an entity whose existence or whose value cannot be resolved fails the read and is
never answered with the header's own verdict, which is precisely the answer the chain was consulted to
correct.

**The view and the read polarity below are orthogonal, and a read names both.** The `New` / `Old`
**view** settles *which version* a read is entitled to see of its own transaction; the three
**polarities** that follow settle *which obligation* the read is discharging — a superset, a decision,
or a conservative summary. Neither substitutes for the other.

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

**Concurrency between two transactions is decided on the same boundary as visibility.** A transaction
that committed at a timestamp **at or below** another's begin timestamp is *not* concurrent with it:
the second one saw its writes, so it owes it no rw-antidependency edge — which is the same reading
§5.3 gives those same two numbers. The two must agree, because an edge is what stops a transaction
acting on a value it did not see, so declining to form one is sound only if it did see it. The test is
therefore `≤`, and it is sound **only because a begin timestamp is the published horizon of §5.2**.
Task #1056 is what happens when that does not hold: the tracker was handed begin timestamps off the
allocation clock, correctly declined an edge for a commit the transaction had in fact not seen, and
stood down while a lost update went through. Its reading was right and the timestamp it was given was
wrong, so **this test must not be tightened to `<`** — that would abort every transaction that
legitimately begins at the timestamp of the commit it has just read, which is the ordinary case. If
the boundary ever looks wrong again, the horizon is what to check.

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
record itself, not a layer above a single-version store. Seven consequences follow, and they are the
contract between §5 and the rest of the engine.

- **A write mutates the home record in place and leaves a delta behind.** The writer allocates the
  delta, links it at the head of the entity's chain, advances `undo_ptr`, and only then changes the
  record body (§5.1.2, steps 2–4). The MVCC header of the **entity record** keeps its meaning
  unchanged from §5.2: `xmin` is the creating transaction, `xmax` the expiring one, and `undo_ptr` is
  now the live head of the undo chain rather than a permanently-zero reserved word. **This sentence
  is about the entity record and must not be read as extending to the property cell** — the cell's
  stamp is settled by the next bullet.
- **The undo chain is the sole visibility oracle for a property's value**
  (`D-property-visibility`, ratified 2026-08-03). A reader resolves which value of a property it is
  entitled to see by starting from the **in-place image** and walking the **entity's** undo chain,
  applying `SetProperty` deltas backwards until it reaches the version its snapshot may see (§5.3).
  It **never** decides by comparing the property cell's own `created_ts`. That stamp becomes
  **informative** — useful in diagnostics and in the consistency checker, load-bearing in no
  visibility decision. What the cell's MVCC header keeps is its **structural** meaning: `in_use` for
  slot occupancy and corpse threading.

  The ground for this is a property of the frozen format, not a preference. The 56-byte delta of
  `05-storage-format.md` §12.2 has **no field for the old `created_ts`** — its `SetProperty` payload
  is `token`, `type_tag` and `value_inline`, and nothing else. A logical undo therefore *cannot*
  restore that stamp, so the stamp must not be something correctness depends on; under this decision
  nothing does. The direct consequence is that **task #970 was a rollback change only**: because the
  chain was already the oracle when #970 landed, logical rollback replaced physical undo with no
  second rewrite of the read path.
- **A property read must observe the cells and the chain head at ONE instant** (**#1057**). The two
  halves of the reconstruction above live in **different records, on different pages, under different
  latches** — the current values in `props.store` cells, the chain head in the `undo_ptr` word of the
  entity's own record — so a reader that samples them at two instants can reconstruct a version the
  store never held. The bullet above fixes the write order (delta linked and `undo_ptr` advanced
  **before** the cell is rewritten), and the abort path publishes the same two halves in the
  **opposite** order (`apply_own_deltas` restores the cells, then `detach_own_deltas` unlinks the
  deltas — §4.4), so no single read order is safe against both. The obligation is therefore stated on
  the reader and is a **validation**, not an order: it reads the entity's cells and accepts them only
  once it has observed the chain head **unchanged across that walk**, re-reading otherwise. Every
  mutation of an entity's property cells is preceded by linking a delta onto that entity's chain
  (there are no exceptions since #970 — an unversioned cell is a hole, not a shortcut), so an
  unmoved head is a witness that no cell under it was rewritten in between. A read that cannot obtain
  that witness fails **retriably** rather than answering, which is the fail-closed-on-read-fault rule
  of §5.3 applied to atomicity. Before #1057 the head was sampled first and never revalidated, and an
  off-thread reader summing 50 balances returned a total off by exactly one transfer leg — one leg of
  a transaction observed without the other, and the transaction in question had not committed at all.

  **The witness is an equality test, so it does not detect an ABA sequence, and this is known**
  (task **#1059**). A link, a cell write and a rollback that all fit inside one reader's window return
  the head to the value it started from; the validation compares equal and accepts cells that changed
  underneath it. #1057 neither introduced this nor closes it — the residual is tracked separately, and
  a witness that survives it needs a value the sequence cannot restore rather than a tighter read
  order.
- **A read of the latest committed version costs one record fetch.** This is the whole point of
  in-place-latest, and it is what protects index-free adjacency: a traversal that reads the current
  version of every record it visits walks no chains at all. A reader on an older snapshot walks the
  chain from `undo_ptr` backwards, applying deltas until it reaches the version its snapshot may see
  (§5.3).
- **Every delta is WAL-logged and recovered by the same ARIES machinery** as the record it belongs to
  (§4.8). The undo area is an ordinary region of ordinary logical pages (`05-storage-format.md` §12),
  not a side structure with its own recovery rules, so a crash mid-chain is recovered by redo exactly
  as a crash mid-record is. This is what made labels durably versioned for the first time (**#968**):
  their history used to live in memory only, in an in-process structure shared by `Arc`, and was lost
  on restart.
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
`[freeze_low, high_water)` (`crates/graphus-storage/src/store.rs:778-786`); with the commit
indirection point (§5.1.3) a transaction's commit timestamp is published once, so there is nothing
left to rewrite and no frontier to maintain.

### 5.7 Latches, conflict detection, and multi-writer execution

**Ratified on 2026-08-02 as `D-write-conflict-detection` and `D-multi-writer`**
(`02-decision-register.md`). Graphus has exactly **one** blocking primitive — the latch — and **no
logical lock of any kind**. There is no lock table, no lock wait, no lock-wait timeout, and no
deadlock detector, because a transaction never waits for another transaction.

**Latches (physical, short) are the only blocking.** They protect page bytes and in-memory structures
(§3.3), are held for the duration of a memory operation rather than a transaction, and are ordered to
be deadlock-free by construction (§3.3, latch ranks). What makes a chain safe to walk while it is
being extended is the publication order of §5.1.2 step 3, not a transaction-scoped lock: the new delta
is written in full first, its `next` is set to the current head, and the record's `undo_ptr` is
published **last**. A concurrent reader, or the GC, therefore observes either the old chain or the new
one, never a partially-linked one. What makes the publication itself safe **against a second writer**
is the protocol of §5.7.1, which is a different guarantee and needs its own mechanism: the order above
keeps the chain well-formed at every instant, but on its own it does not stop two writers from
publishing over each other.

**Write-write conflicts are detected on the entity's own MVCC state, and abort immediately.** Before
writing, a transaction reads the head of the entity's delta chain and decides in constant time:

| State of the chain head | Verdict |
| --- | --- |
| The chain is empty | proceed |
| The head belongs to **this** transaction | proceed |
| The head belongs to a transaction that **committed at or before this transaction's start timestamp** | proceed |
| Anything else — the head belongs to another transaction that is in flight, or that committed after this transaction started | **abort now**, with a retriable serialization failure |

The writer never waits for the outcome of the conflicting transaction, so no wait-for edge is ever
created, so no cycle can form, so **there is nothing for a deadlock detector to detect**. This is
Memgraph's `PrepareForWrite` (Source, read 2026-08-02:
`/data/refsrc/memgraph/src/storage/v2/mvcc.hpp:112-137`), which returns `false` — a serialization
error — instead of blocking, and which gates the entire write surface: every mutating accessor calls
it first (`vertex_accessor.cpp:191,203,265,277,425,511,580,639`;
`edge_accessor.cpp:194,261,315,360`).

**Both rows of that table that refuse are enforced, and the second one arrived with task #1056.**
`D-write-conflict-detection` names the two in one sentence — the writer aborts unless the head belongs
to a transaction that "is neither itself nor committed before its own start timestamp" — but only the
*in-flight holder* arm was implemented. The gap is not academic. A head committed after this writer
began is, by the visibility rule of §5.3, a version this writer **cannot see**; so it read the value
underneath, and it is about to overwrite the newer one with a result computed from the older. Two
acknowledged increments, one increment applied. The engine therefore now refuses a chain head whose
transaction committed after the writer's start timestamp, with the same retriable serialization
failure as the in-flight case.

**The comparison is "at or before" — `≤`, not `<` — and the ratified wording must be read that way.**
"Committed before my start" is measured against the *visibility* horizon, and a begin timestamp **is**
that horizon (§5.2): it is the largest timestamp every one of whose commits has finished publishing,
and a version at exactly that timestamp is visible. A strict `<` would refuse the ordinary sequential
case — a transaction that begins after a commit, reads its value, and writes on top of it, whose begin
timestamp equals that commit's timestamp by construction — and would abort roughly every second write
in a serial workload. The operator is `≤` **because** the horizon is honest, which is also why this arm
could not have been added on its own: against the allocation clock of §5.2 the writer would be asking
whether the head committed after a start timestamp that already equalled the head's own timestamp, and
neither operator was correct. The two halves were measured independently — withdrawing the horizon
loses the snapshot-honesty property, withdrawing this arm loses updates — and neither is sufficient
alone.

The check is **skipped for a writer that holds no recorded start timestamp**: recovery, a maintenance
pass and a bulk import all write without ever taking a snapshot, so there is nothing to compare
against. Both reference engines refuse on the same boundary. Memgraph's `PrepareForWrite`, cited
above, returns `false` unless the head's timestamp is the transaction's own or below its
`start_timestamp`; PostgreSQL raises `could not serialize access due to concurrent update` when an
updater whose isolation level pins its snapshot meets a tuple whose updater committed after that
snapshot (`/data/refsrc/postgres`, commit `0fd30e2`,
`src/backend/executor/nodeModifyTable.c:2892`, the `TM_Updated` branch of `ExecUpdate` guarded by
`IsolationUsesXactSnapshot()`; the delete path does the same at `:1978`).

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
concurrent writers against one database from a seeded schedule. This is a prerequisite of the
multi-writer sign-off, not a follow-up to it. The scheduling mechanism arrived with task **#973** and
is specified in `07-dst-simulator.md` §5.2: a single execution token handed between real OS threads at
declared yield points, with the successor drawn from a seeded RNG, so the global order of operations
becomes a pure function of the seed. It narrows the fidelity ceiling named in §5.1 of that document —
garbage collection racing an off-thread reader at page-latch granularity is now seed-reproducible —
without removing it. **The certification itself is not yet complete**: the write-path yield points are
installed but not exercised, because a database still has one writer thread. Task **#975** creates the
concurrent writers the schedule is meant to order.

**What was retired — CLOSED by task #971.** The write-lock table and the wait-for-graph deadlock
detector lived in `crates/graphus-txn/src/lock.rs`; the file is gone, and with it the lock-wait
timeout and the cycle search. The header check specified above is now the engine's **only** conflict
mechanism.

The substitution was certified cell by cell over the full holder × challenger matrix, run once with
the lock table and once with its acquisition ablated: 287 of 289 cells identical, and the two that
differed were **gaps in the lock's coverage that the header check closes**, not the reverse. Two
findings came out of that exercise and were fixed before the removal, because each one loses a
committed write once the lock is gone:

* `add_label` / `remove_label` exited early on an idempotent no-op — "the label is already present" —
  *before* reaching the conflict check. The word they tested is the **live** one, so it already
  carried a bit an open transaction had written in place: a dirty read reported as a successful
  write, and the label vanishes when that transaction aborts. The check now runs first. The
  bulk-import path never passed through the Cypher seam, so it never had even the lock's protection.
* In the three property-write functions the liveness test ran before the check, so a challenger that
  met an entity tombstoned by an **unresolved** holder was told `Storage("not in use")` — not
  retriable at the Bolt seam, not covered by the statement-level rollback, and not even true from
  that challenger's snapshot. The check now runs first there too.

The `TxnManager` in `crates/graphus-txn/src/manager.rs` is **not** the server's transaction engine —
the server uses `TxnCoordinator` — and it is kept, without any locking, as the harness the SSI
certification suites (`tests/isolation.rs`, `tests/elle_no_anomalies.rs`, `tests/ssi_staggered.rs`)
run against. Its first-updater-wins rule is now expressed directly over its own writer set.

#### 5.7.1 The chain-head publication protocol (task #1028)

A **chain head** is a single word inside a record that names the first entry of a chain hanging off
that record. The storage core has three of them — a node's `first_rel`, an entity's `first_prop`, and
the MVCC `undo_ptr` — and every writer that adds to such a chain does so by **prepending** to it.

**The defect this closes.** Until task #1028 a chain head was published with a plain byte write, so
the read-the-head / write-the-head pair was not atomic. Two writers that read the same head both
publish, the second overwrites the first, and the first's entry silently leaves the chain: a
committed relationship gone from its node's incidence chain, a committed property version gone from
its owner's chain, a committed delta gone from the undo chain that decides visibility. That is the
`rmp` #220 defect class, latent only while a database has a single writer thread and live the instant
the N writers of this section arrive.

**The protocol has four steps, and their order is normative.**

1. Read the head `H`.
2. Write the new entry `E` in full, with `E.next := H`. `E` is private at this point: no chain names
   it, so neither a reader nor a GC pass can reach it.
3. Publish `head := E` by **compare-and-publish against `H`** — the store installs `E` if and only if
   the head still holds `H`, and reports whether it did.
4. Only then, and only after a **winning** publication, fix the displaced predecessor's back-pointer
   `H.prev := E`. This step applies to doubly-linked chains only, which means the relationship
   incidence chain.

**Step 4 comes after step 3, and that is not an implementation detail.** A writer that has read `H`
but has not yet published holds no claim on `H` at all. Relinking first and then losing the
compare-and-publish would leave that writer having overwritten the `H.prev` the winner legitimately
owns. Winning the compare-and-publish with the expected value `H` is precisely what makes a writer
the one that displaced `H`, so only the winner relinks, and two writers can never relink the same
predecessor. The publication primitive therefore returns **the head it displaced**, and that value —
not the head originally read — is the only one a caller may use for step 4.

**A refusal re-links the entry and retries.** The retry cannot live inside the publication itself,
because a refusal invalidates `E.next`: the entry is linked to a head that is no longer the head, and
publishing it as it stands would fork the chain and orphan everything below the winner. A refusal
therefore re-reads the head, rewrites `E.next` to that head, and tries again. The loop is **lock-free**
in the technical sense — an attempt is refused only when some other publisher succeeded — so the
system as a whole always progresses and a live-lock is impossible. The bound of 65 536 attempts is
not there to break a live-lock; it exists so that a head being written by something *outside* the
protocol surfaces as a loud, attributable error instead of an unkillable thread inside a database.

**The protocol lives in its own leaf crate.** `graphus-chainhead` (§1.2) holds the four steps and the
retry, generic over a `ChainHead` trait that models the head cell. The trait states **two obligations
on the medium**, not on the protocol, and getting either wrong reintroduces the lost prepend with no
symptom the protocol itself could detect:

- **Atomicity.** The comparison and the store are one indivisible step with respect to every other
  publisher of the same head.
- **Durable order.** The order in which publications enter the log equals the order in which they take
  effect on the page. Recovery replays in log order, so if the two orders differ, replay reaches a
  different verdict from the one the live system reached — and after a crash the *replayed* verdict is
  the one that survives.

**The storage core honours both with a sharded rank-27 latch.** Its head cell is an
8-byte word on a WAL-logged page, and one shard of the latch is held across three steps that have to
be one: peek at the word, append the redo record, apply it. Splitting them is exactly what breaks
durable order — the record is appended under the WAL mutex (rank 30) and applied under the frame
latch (rank 40), and nothing else ties those two instants together, so two publishers can enter the
log in one order and take effect on the page in the other.

> **The latch's key changed after this section was written.** Task #1028 keyed it by
> `(store kind, record id)`; task **#1062** re-keyed it by the **device page** and routed every logged
> page write through it, because the same divergence turned out to afflict ordinary writes that are
> not chain heads at all. The re-keying is a **strict widening** — every writer of a record is a writer
> of its page and maps to the same shard — so everything this section states about the publication
> protocol holds unchanged, and the two publishers above are still ordered. The general invariant, the
> single logging door and the measurement that forced the widening are **§5.7.2**
> (`D-page-write-order`). Read the rest of this section with "one shard per head word" replaced by
> "one shard per device page"; nothing else in it is affected.

Three consequences are normative:

- **The page is mapped and pinned before the latch is taken**, and the latch is released before the
  frame is unpinned. Rank 27 is never held across store growth, across a page fetch that may evict, or
  across a durability barrier: held across any of them it convoys every publisher of the shard behind
  one `fdatasync`. Debug builds enforce this at the WAL barrier, at `BufferPool::fetch` and at the
  store-page growth path (§3.3).
- **At most one holder per thread** (§3.3). A relationship publishes its start endpoint's head and its
  end endpoint's head strictly one after the other, precisely so that this stays true. The two
  endpoints are two independent chains and therefore two independent publications, each with its own
  retry loop; if the second is refused after the first has won, the intermediate state is correct
  rather than torn — the record really is the head of the start node's chain and not yet of the end
  node's — and the retry completes it.
- **The shard count is a contention parameter only.** Correctness requires nothing more than that one
  page always maps to one shard (one *head word* always mapped to one shard before the #1062
  re-keying; the widened rule implies the narrower one).

**A refused publication appends no record.** Under the latch the word is observed first, and the redo
record is appended only if it still holds the expected value, so the log never carries a record for a
write that did not happen and recovery has nothing to reason about. This is deliberately stronger
than tolerating an inert orphan record: an orphan is harmless only while log order matches the order
in which the page actually changed, and that is precisely the property a second writer removes.

**The publication remains redo-only** (`D-chain-head-redo-only`, §4.4). Its inverse is to unlink the
entry, computed at abort time from the transaction's own deltas, and never the restoration of the
word. Task #970 proved that restoring the word is unsound even when the restoration is itself a
compare-and-set, because it restores an **id**, and an id means something only while it names the same
record. The compare-and-publish specified here runs in the opposite direction: it is the *forward*
publication, whose expected value is a head this writer read moments ago and whose new value is a slot
this writer owns.

**The same latch covers two further writes, because the head word alone is not the whole story.** The
first is part of a prepend; the second is a different operation on the same word, brought under the
primitive so that no writer of that word stores into it unconditionally.

- **The `chain_flags` byte of a displaced relationship.** One byte packs the first-in-chain markers of
  **both** sides of a relationship, and a relationship can be the head of two different nodes' chains —
  its start node's and its end node's. Two writers prepending onto those two nodes therefore both
  displace that record and both clear a bit of that one byte. Computed outside and written whole, that
  is a lost update: whichever write lands second resurrects the other's marker, and a record that
  still claims first-in-chain while a committed prepend sits above it is exactly what lets the GC
  reclaim it as a head. The clear is therefore an atomic read-modify-write under the same rank-27
  shard latch — keyed on the record being modified when task #1028 wrote this, on that record's device
  page since task #1062 (§5.7.2) — and it takes a **mask** rather than a finished
  byte — which makes it commutative, so two clears of disjoint bits compose to the same result in
  either order.
- **The GC's corpse splice.** When a collapsed run of corpses starts at the node head, the splice
  repoints the head word through the same publication primitive instead of rewriting the node record.
  The principle behind that conversion is general: a compare-and-set is sound only to the extent that
  the writers of the word pass through it, because a single writer that stores unconditionally makes
  every other writer's comparison meaningless. Refusal in the splice is fail-closed — a GC pass holds
  the store exclusively, so the head cannot move under it, and if it ever does, the run that pass
  computed describes a chain that no longer exists and splicing it would sever live structure.

**An operation writes only the fields it changes.** The splice above used to read the whole
`NodeRecord` and write it back with `first_rel` replaced. A whole-record write built from a snapshot
taken before the write reverts every field a concurrent writer changed in between — here `first_prop`,
`labels` and the MVCC header — which is the #772 clobber class arriving without any new mechanism. The
rule is stated positively: an operation that changes a chain head, a chain pointer or a chain marker
writes exactly those fields and nothing else.

**What task #1028 covers, stated exactly.** The protocol and the latch cover **prepending** — the
operation that *adds* an entry to a chain — at all six prepend sites of the storage core (both
endpoint heads of a new relationship, the self-loop's single chain, a node's and a relationship's
`first_prop`, and the undo chain's `undo_ptr`), plus the GC corpse splice's repointing of a node head.
Task #1030 brought the two **unlink** sites under the same protocol — `RecordStore::unlink_side_with`
publishes a node's `first_rel` conditionally and restarts the unlink when refused (a refusal means a
concurrent prepend has made the record no longer the head, so the neighbour branch is now correct), and
`RecordStore::set_owner_first_prop` publishes an owner's `first_prop` conditionally and fails closed,
because its only caller is a GC pass under which the head cannot legitimately move.

**The enumeration, redone.** The list this section used to carry named TWO uncovered sites and was
wrong. A full sweep of every writer of `first_rel`, `first_prop` and `undo_ptr` (task #1030) found
more, and — the part that mattered — four of them were ordinary transactional paths rather than GC.
Three had been missed because the previous framing looked for "an unconditional whole-record write":
they wrote a single word or a header region instead, which defeats the compare-and-publish just as
thoroughly while not matching the description. The enumeration's shape was hiding them.

Task #1030 brought all of them through the mechanism except one, which is exempt with its reason
stated at the site:

| Site | Was | Now | Class |
| --- | --- | --- | --- |
| `unlink_side_with` | whole `NodeRecord` write installing `first_rel` | conditional publication of the word; the unlink restarts when refused | transactional |
| `set_owner_first_prop` | whole owner-record write installing `first_prop` | conditional publication, fail-closed | GC |
| `retire_own_prop_cell` | unconditional 8-byte write of `first_prop` | conditional publication, fail-closed | transactional |
| `detach_own_deltas` | unconditional header-word write repointing the live `undo_ptr` | conditional publication, fail-closed | transactional |
| `repoint_neighbour` | whole `RelRecord` write carrying `first_prop` and `undo_ptr` | only the back-pointer word(s) that changed and the first-in-chain marker bit beside them — no field it does not change, and all of it in one frame-latch hold (task #1054) | transactional |
| `undo_own_creation` | zeroes the whole MVCC header, `undo_ptr` included | **unchanged, exempt**: the transaction created the record, the slot has never been visible to another writer, and no chain reaches it by the time this runs — there is no head for anyone to be publishing | transactional |
| `relink_run_endpoint`, `reclaim_node`, `reclaim_rel`, `gc_splice_corpses` phase 3, `free_undo_chain` | whole-record or header writes carrying head words | unchanged, covered by GC exclusivity | GC only |

Two properties of the unlink conversions are load-bearing and are recorded here rather than left to
the code. First, the publication is **conditional**, not merely latched: under the rank-27 latch the
word cannot move, but the read that DECIDES headship happens outside it, so a concurrent prepend in
that window makes the record no longer the head and an unconditional store would publish over the
entry that prepend just linked in. A refusal is therefore not an error at `unlink_side_with` — it is
the news that this is no longer the head, and the unlink restarts and takes the neighbour branch.
Second, `repoint_neighbour` writes **per word, not per block**: two unlinks can legitimately touch the
same neighbour at once, one facing its start node and one facing its end node, and a block write from
a stale read would have each revert the other's side. It no longer carries a single foreign field —
not `first_prop`, not the MVCC header, not the chain words it does not touch — and it never restores
one, because its images are redo-only and there is no pre-image for a rollback or a recovery to
re-apply.

**Non-clobbering and atomic at the same time (task #1050).** Writing less than the whole record and
writing it atomically were, with the primitives of the time, mutually exclusive, and task #1050 was
filed on exactly that: a whole-record write is one acquisition of the frame write latch and therefore
atomic against a reader taking the read latch, but it clobbers; per-word writes do not clobber and are
not atomic — a reader lands between the re-pointed back-pointer and the marker that has not yet been
set, which is a state no consistent snapshot contained. The chain-pointer words are contiguous
(`61..93`) but `chain_flags` sits at `101`, so no single region write covers both.

Task #1050 offered two routes. Moving `chain_flags` next to the pointer block, so one contiguous
region write covers both, would have cost a format version and a migration path for every existing
`rels.store` — and would still have been **unsound**, for two reasons independent of that cost: a
region image is a plain post-image, so it cannot express the compare-and-set the repair needs, which
re-opens the lost update task #1054 measured and closed; and the marker byte carries both sides' bits, so its
post-image has to be computed under the latch rather than taken from the caller's unlatched read (the
shared-byte read-modify-write of task #1028). The route taken instead — `RecordStore::patch_chain_words`,
a multi-region primitive that takes the frame write latch **once** and applies every staged word and
the marker inside that one hold — costs no format change and no migration; it pays one WAL record per
word instead of one per block, and nothing at all in recovery, because `paging::apply_patch` already
applies both image shapes. The decision was therefore structural rather than measured: no throughput
number can choose between a route that expresses the required semantics and one that cannot.

Both halves are asserted, separately, in `crates/graphus-storage/tests/chain_word_atomicity_1050.rs`:
a WAL extent oracle requires every image logged against the neighbour's record to fall inside the
back-pointer word or the marker byte, and eight real reader threads require that a live relationship's
back-pointer and its first-in-chain marker are never observed disagreeing. The second is a thread test
and not a deterministic-simulator one on purpose: `patch_chain_words` runs inside a `NoSwitchScope`, so
under the DST scheduler no other logical thread can be scheduled anywhere within it and a scheduled
reader would report a split write as sound. The frame latch is an ordinary reader-writer lock and a
production reader is not scheduler-mediated, which is why the original measurement needed eight
OS-level readers.

The GC rows are safe for the same reason the corpse splice's refusal is fail-closed: a GC pass holds
the store exclusively. That exclusivity is a single-writer convention documented in prose, not a lock —
`gc` takes `&self` — so it is one of the things task #1016 has to re-establish rather than inherit.

One writer class neither this section nor the code comments mentioned before #1030: the **deferred WAL
undo** of a whole-record write is a second writer of all three words, re-applied at
`rollback_physical` and at crash recovery from a pre-image taken before the write. `repoint_neighbour`
is out of that class entirely since task #1054: `patch_chain_words` logs redo-only records, so its
writes carry no pre-image for anything to re-apply. The GC whole-record writers still have it.

**How this is proved.** Two suites, deliberately different in kind, because neither can stand in for
the other:

- **A `loom` model** — `crates/graphus-chainhead/tests/loom_chainhead.rs` — drives the production
  protocol unchanged over a modelled medium (an atomic head word and an array of `next` slots) and
  requires that every entry prepended is reachable from the head, that a pre-existing tail is never
  orphaned, and that a refused publication leaves neither a fork nor a cycle. A fourth model runs the
  identical protocol over a cell whose publication is a plain load-then-store and **requires that at
  least one interleaving loses an entry**, so the pair asserts both "the protocol is correct" and "the
  atomicity it rests on is doing the work". A real-thread test cannot replace this: the window needs
  two writers to read one head before either publishes, and a run in which that window never opens
  certifies nothing.
- **A DST crash scenario** — `crates/graphus-dst/tests/chain_head_publication_recovery_1028.rs` —
  proves the durable half: every committed publication replays, and a refused publication leaves no
  trace for recovery to find. See `07-dst-simulator.md` §10.

#### 5.7.2 Log order is apply order, per page (task #1062)

`D-page-write-order`. §5.7.1 ordered the writers of a **chain head**. This section states the general
rule that ordering turned out to be one instance of, and specifies the mechanism that supplies it for
every logged page write.

**The invariant.**

> For every page, the order in which logged writes against that page enter the WAL is the order in
> which those writes take effect on that page.

Equivalently, and this is the form worth testing against: **what recovery rebuilds for a page is what
the last logged write to that page applied.**

**Why it does not hold for free.** A logged page write is **two instants in two media**. The record
enters the log under the WAL mutex (rank 30); the change takes effect on the cached page under the
frame latch (rank 40). Nothing about those two latches couples them, so two writers of one page can
enter the log in one order and apply in the other. ARIES replays **strictly in log order** and gates
each record on the page's `page_lsn`, so when the two orders differ, recovery reconstructs an image
the live system never held. The failure has a property that makes it particularly dangerous: the
crash-free answer and the post-crash answer are each internally consistent and neither is wrong on its
own terms, so **no result-checking test can see it**. Only an oracle on the ordering itself can.

**The observable signature** is a page being offered an LSN **below** the one its header already
carries — a *page-LSN descent*. The buffer pool counts descents under the frame write latch, so the
count is exact rather than sampled, and the record store surfaces it. Zero descents is the property
the suite asserts.

**Why a monotone `page_lsn` is not the fix.** The stamp takes the maximum of the page's current LSN
and the record's, and has done so since task #1029, so it never descends. It was therefore **already
in the tree while the divergence below was measured**. A monotone stamp hides a divergence only if the
page's *content* is monotone too, and content is not: recovery still rebuilds a different image from
the one the runtime produced. Worse, relying on the stamp alone would be actively harmful — redo skips
every record whose LSN is at or below `page_lsn`, so a page carrying an LSN it never applied silently
loses every legitimate record logged at or below it, and nothing reports the loss (§3.3). Clamping the
symptom converts a mis-ordering into a **skipped** record.

**The mechanism.** The rank-27 section of §5.7.1, **re-keyed by the device page**, is the one door
through which a logged page write happens. Inside one section, for one page, in this order:

1. **Capture the undo pre-image** from the page.
2. **Append the WAL record** (redo, and undo where the write is not redo-only).
3. **Apply the post-image** to the cached page.
4. **Stamp `page_lsn`** with the record's LSN.

Step 1 must be inside the section and not before it: a pre-image read outside can be overwritten by
another writer of that region before this record is appended, and the undo would then restore a state
that was never this writer's to restore. Steps 2 and 3 are the two instants the invariant couples.

**The obligations on the section.**

- **The page is mapped and pinned before the section is entered**, and unpinned after it is left. The
  section is never held across a page fetch that may evict, across store growth, or across a
  durability barrier (§3.3). Held across any of them it convoys every writer of the shard behind one
  `fdatasync`.
- **At most one holder per thread** (§3.3), for the reason every same-rank latch carries: two locks of
  one rank cannot be ordered by rank, so two threads taking a different pair in a different order
  deadlock.
- **There is exactly one door to appending a WAL record against a page**, and it asserts that the
  caller holds the section for that page. Ten append sites in the record store pass through it, plus
  the rollback path's compensation append, which holds the section explicitly and asserts it. The
  count is of **sites**, not of appends: one site sits in a loop and appends once per word.
- **The shard count is a contention parameter only.** Correctness requires nothing beyond "one page
  always maps to one shard". The shard index is derived by multiplicative (Fibonacci) hashing, which
  mixes the low-entropy input — device page ids are dense and consecutive — instead of aliasing every
  *N*-th page onto one shard. It is a mixing function, **not** a perfect distribution: two unrelated
  pages can land on one shard and then serialize needlessly, which costs throughput and never
  correctness.
- **Debug builds check every obligation with thread-local tripwires**; a release build compiles the
  checks out. The latch and the door exist in every build — what a release build gives up is the
  *diagnosis* of a violation, not the protection.

**Why the key is the page and not the record.** `page_lsn` is a property of the **page**. Redo is
gated on `record.lsn > page_lsn` and replayed in log order, so two writers of two *different* records
that share a page must be ordered exactly as much as two writers of one record. Keying by page is a
**strict widening** of §5.7.1's key: every writer of a record is a writer of its page and maps to the
same shard, so the chain-head guarantee is preserved exactly rather than re-derived.

**The two rejected routes, and why neither is available here.**

- **Append under the frame latch**, so the LSN is assigned while the page is held. This inverts ranks
  30 and 40, and the WAL barrier refuses **by tripwire** to run with a frame latch held. It is the
  same inversion §5.7.1 rejected for the head word, arriving for the general write path.
- **Apply under the WAL mutex**, so append and apply are one section under the WAL lock. This violates
  the store's absolute rule that it never holds its own WAL lock across a buffer-pool call that can
  trigger a write-back, because the write-back re-enters the WAL rule's durability check and would
  take the WAL lock again — a wait cycle between threads, and a non-reentrant self-deadlock in one.

**What it cost.** Two writers of one page now serialize where before they did not. That widening of
contention is deliberate and accepted: page-level serialization is what the durability model requires,
and the alternative is a database whose recovered state disagrees with the state it just served.

**How it is proved.** The deterministic simulator, on
`crates/graphus-dst/tests/page_log_apply_order_1062.rs` and its sister scenario
`det_scheduler_checkpoint_inversion_1055` — two writers, four commits each, sixteen seeds:

- **Before the fix: 32 page-LSN descents across the sixteen seeds, and not one on a chain head.** The
  pages that descended were the catalog image (`write_region`), the commit slot
  (`patch_commit_slot_word`, which reaches the log through `write_region`), the undo area
  (`write_undo_area_create`) and a node's label word (`write_node_labels`) — all ordinary
  transactional writes, none of them the path §5.7.1 had already closed. This is the measurement that
  decided the key.
- **The divergence in full**, seed `0x1`: a reopen recovered `[9, 5, 4]`, transaction 1004's image,
  while the last page write in the recorded schedule was transaction 2004's `[9, 4, 5]`.
- **Non-vacuity.** "Zero descents" is satisfied trivially by a run whose writers never share a page, so
  two facts are asserted rather than hoped for: that at least one frame was LSN-stamped by two
  different logical threads, read out of the recorded schedule; and that the run really committed under
  contention, with the writes read back **out of the store** rather than from a counter the writer loop
  incremented.
- **The positive control.** With the section ablated to a bare call and everything else identical, the
  invariant test fails on **13 of the 16 seeds**, 1 to 4 descents each, 30 in total, while the
  non-vacuity assertions still pass. With the section restored, all sixteen seeds report zero.

**One limitation, stated plainly.** The B+-tree index layer (`crates/graphus-index/src/btree.rs`) has
**eight WAL-append sites** that do **not** go through this door, and cannot: the section and the door
are internal to the record store, and the index crate has no access to them. Those eight sites satisfy
the invariant today by **Rust exclusivity and by construction**, not by the mechanism this section
specifies:

- every mutating `BTree` method takes `&mut self`;
- each tree owns its buffer pool **by value** — the single-threaded pool, whose mutating API is itself
  `&mut self` — rather than sharing one;
- each tree owns its own base-page range, and as wired in production each tree is handed a
  brand-new device and log sink of its own, so two trees never contend for a page.

No two threads can therefore be writing one tree page at all, and the invariant holds vacuously. **That
is a sound argument about the engine as it stands and it is not the invariant this section states.** The
moment the index layer becomes multi-writer over one tree, the defect reappears there in full — and it
will reappear *silently*, because those pages are stamped outside the concurrent pool's instrumented
path, so the page-LSN-descent oracle does not observe them and would report zero while they diverged.
Two further sharp edges belong to the same limitation: the tree's single-threaded ownership is a
property of its construction and its API, **not** a compiler-enforced `!Send`/`!Sync` marker; and the
tree exposes an `&self` accessor that hands out a mutable WAL manager, which is a door to appending
outside any section. Any task that makes an index tree writable by more than one thread MUST bring
these sites under an equivalent mechanism **before** the writers arrive, not after — the same sequencing
`D-chain-head-publication` was ratified to respect.

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
visibility against the reader's snapshot. This keeps indexes single-structure while remaining
serializable. Index **range reads register SIREAD/predicate markers** (§5.4) so phantoms are caught
by SSI.

#### 6.3.1 An index entry belongs to a transaction (`rmp` #992, slice 1)

An index write names its writer. The polarity is in the type — `IndexWriter::{Txn(TxnId),
Population}` — because the two families of writer carry opposite *obligations*, not merely different
values:

- a **transactional** entry is part of that transaction's atomic unit of work, so a rollback removes
  the entries the transaction **created**;
- a **population** entry belongs to an index build, belongs to no transaction, and is never undone —
  a build deliberately indexes every not-yet-reclaimed version with no visibility filter, because a
  candidate structure owes the **superset** polarity of §5.3: a per-candidate re-check can remove a
  candidate but can never resurrect one.

Only entries the backing tree reports as *newly created* are logged for the rollback, because a write
re-indexes the entity's whole current state and would otherwise take back an entry a **committed**
version warrants. That guard holds only while the tree is complete with respect to committed state,
so any population write invalidates every open transaction's log.

#### 6.3.2 A dead version's entries are reclaimed (`rmp` #992, slice 2)

The old entry **is** removed once the version that warranted it is dead, so an index no longer grows
with the number of versions of a rewritten key. The reclaimer is the §5.5 version GC, because it is
the component that already knows when a version stops existing:

1. **The GC reports what it destroyed.** Freeing an entity's undo chain reports each `SetProperty`
   delta's old value and each `AddLabel` delta's label; physically reclaiming an entity reports the
   entity itself plus every label and value it still held. Nothing is reported outside the property
   keys the index layer declares an interest in, so a dead value belonging to no index is never even
   decoded (decoding can mean an overflow-heap read).
2. **The index layer re-checks before it removes.** A reported key says *a* version died, not that
   *every* version did — `SET n.age = 31` then `SET n.age = 30` kills a version holding `30` while
   `30` is exactly what the entity still has. So a removal happens only when a **superset-polarity**
   read of the entity (its live cells and every value its undo chain can still reconstruct; its live
   bitmap and every label an `AddLabel` delta could restore) shows nothing occupying that index key.
   The comparison is made on the **encoded index key**, not on value equality, because the two differ
   in both directions: `Integer(30)` and `Float(30.0)` are Cypher-equal but occupy different keys,
   and two different `Duration`s can share one.
3. **The error directions are not symmetric, and every judgement resolves the safe way.** An entry
   removed too eagerly is a committed row lost from every future seek; an entry left behind is a
   false positive the re-check drops. So a read fault, a missing witness, a full report queue and an
   uncertain slot all retain.

Physical reclamation is also the point at which a leftover entry stops being harmless: the slot
returns to the free list and the next allocation gives that id to a different logical entity. The
entity-keyed index kinds (full-text, spatial, text, vector, bitmap), which hold one posting per
entity rather than one per value and cannot be addressed by a value key, are purged there.

**The witness is read under one hold and acted on under another, and that split is guarded.** Reading
the store and mutating the trees are two separate holds — the engine takes no two-cell hold on the
write path — so between them lies a time-of-check-to-time-of-use window. It is empty while the engine
has a single writer thread, and this sprint exists to end that, so the window is gated rather than
assumed away: the index is asked whether any transaction other than the collecting one has entries in
flight — evaluated under the hold that then performs the removals — and the store's commit high-water
is compared across the witness, which is dormant under today's exclusive hold and starts paying under
a shared one. Either abandons the whole batch, keeping every entry: always safe, free under one
writer, and visible as `graphus_index_collections_abandoned_total`. The residue they do **not** cover
is a writer committing in the instant between the two holds, which has already drained its in-flight
entries; closing that needs the decision and the removal to be indivisible, and is `rmp` #1022 —
which **blocks** the layers that admit the second writer, so the residue cannot outlive the
assumption that makes it harmless. The keys are decided in
batches for an unrelated reason: the witness holds decoded values per entity, and a pass that
reclaims entities by the million must not hold a witness proportional to the pass.

**Not yet reclaimed: composite indexes.** A composite key is the tuple `(v1, …, vk)` in declared
order, and a reported key names one property; the other fields' values at that version are not
recoverable from it, and guessing them would delete live entries. The composite trees therefore still
grow with the version count. That is a bounded *retention* residual — false positives the re-check
drops — never a destruction one.

**Historical note (2026-08-06).** Before `rmp` #992 this section claimed both of the above and
neither was true: nothing removed an index entry (the removal primitives existed but the engine never
called them, and the GC pass did not touch the index set), and an index write carried a fixed,
never-committed transaction id, so an entry belonged to no transaction and survived its rollback.
Every correctness guarantee rested on candidate-plus-re-check propped up by a family of global
freshness, rebuild-watermark and poison gates (`rmp` #467, #733, #755, #765, #803), each — so the
premise went — a compensation for the index not being MVCC-native. Slices 1 and 2 close the two halves
above; §6.3.3 audits that premise gate by gate and finds it only half true.

#### 6.3.3 The nine global gates, audited one by one (`rmp` #992, slice 3)

`rmp` #992's measure of success is not that a mechanism was added but that the **compensations for its
absence go away**: each of the nine global gates the derived-index layer carries must be removed, or
justified in writing. This is that audit, taken after slices 1 and 2 were in place.

**The premise it was opened under is half false, and the correction is the useful part.** Four of the
nine (`labels_usable`, `rebuild_gap`, `wipe_generation`, `degraded`, all `rmp` #733) do not compensate
for the absence of MVCC at all. They answer a **read fault**: a store read that failed while a build or
a refill was filling a tree, leaving it incomplete and trusted. A perfectly MVCC-native index has the
same exposure — versioning a tree does not make the disk under it readable — so these are not a debt
this task can pay off, and a design that retired them would be strictly worse. They are **kept by
design**, not tolerated.

The other five are genuine compensations, and none of them is retired by slices 1 and 2, for a reason
worth stating precisely rather than in aggregate:

| Gate | Compensates | Verdict |
| --- | --- | --- |
| `rebuilt_trees_trustworthy_from` (#755/#765) | A `clear`-and-refill rebuild destroys entries an older reader is still entitled to. | **Kept.** Orthogonal to slices 1–2: those remove an entry only when the GC watermark proves no snapshot can want it, whereas a rebuild's wipe is gated by nothing at all. What would retire it is a **non-destructive rebuild** — fill the replacement tree beside the live one and swap — never a finer removal rule. |
| `ft_spatial_trustworthy_from` (#467) | Full-text/spatial hold only the newest state, so a committed replace strips the old posting an older reader needs. | **Kept.** This is the *opposite* polarity to the one #992 fixes: a hole, not a leftover. Nothing about giving entries an owner or collecting dead ones fills a hole. |
| `ft_spatial_inflight` (#467) | The same hole while the replace is still uncommitted. | **Kept**, for the same reason. |
| `ft_spatial_removers` (#756) | Discriminates a rolled-back *remove/replace* (which leaves a hole) from a rolled-back *insert* (which leaves a filterable false positive). | **Kept.** Slice 1 removes an aborting transaction's *created* entries — the second case. The first case is what this gate is for and slice 1 cannot describe it: a log of created entries does not describe an absence. |
| `ft_spatial_poisoned` (#467/#756/#803) | The hole a rolled-back remover actually left. | **Kept**, as the enforcement arm of the row above. |

**What would retire the last four, together.** They exist because the entity-keyed indexes are
*destructive per entry* on the write path: a rewrite drops the old posting as the write happens, which
is the one thing a candidate structure owing the superset polarity of §5.3 must never do. Make that
write path **purely additive** — a write only ever unions the new state in, and the *only* remover is
the GC-driven collection of §6.3.2 — and the hole cannot form, so all four gates lose their subject at
once. That is what "MVCC-native index" means for these kinds, and it is now reachable precisely because
slice 2 supplied the missing remover.

The primitive already exists for two of them and is used on the build path today, which is the same
superset argument: `SpatialIndex::merge_point` (`rmp` #779) and `TrigramIndex::merge_value` (`rmp`
#773) union a version in without dropping any. Full-text has no such method yet (`index_document` is
last-wins); the value bitmaps need only stop removing; and the vector index is the hard case, since
HNSW is id-keyed — one vector per id — so retaining two versions of one entity needs a level of
indirection the others do not. That asymmetry, not the principle, is why this is tracked as its own
task rather than folded in here.

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
  large traversals) and the WAL `fdatasync` run **off the async runtime**, so it never blocks: a
  `rayon`-style CPU pool for the operators, and for durability **one dedicated fsync group leader
  thread per database engine** — one leader shared by every engine worker, not one thread per worker
  (§4.2, decision `D-wal-group-leader`). This is a hard rule (no blocking
  syscalls, no heavy loops, no `std::thread::sleep` on runtime workers).

### 9.2 Lock-free structures

Lock-free/atomics are used **deliberately and narrowly**: taking a snapshot (a single atomic load of
the published commit-visibility horizon — **issuing** a commit timestamp is not lock-free, it happens
under the rank-20 commit sequencer latch of §5.2), the WAL LSN allocator, pin counts, the frame-table
shards, and the SSI conflict-edge set hot path. Every
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
- **Scheduled-thread mode:** reproducibility is **not** confined to a single thread. A run may also
  install the deterministic **thread** scheduler (`07-dst-simulator.md` §5.2, task #973), which hands
  one execution token between **real OS threads** at declared yield points and draws the successor
  from a seeded RNG. Several real threads sharing one store then produce a byte-identical history for
  a given seed. It is gated on the `det-sched` cargo feature, costs production builds nothing, and is
  mutually exclusive with ThreadSanitizer and `loom`, which own the interleaving themselves.
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

- **loom:** exhaustive interleavings for every lock-free/atomic unit (§9.2), and for the chain-head
  prepend publication protocol (§5.7.1). **Miri:** UB and aliasing for all `unsafe`; runs the
  unsafe-bearing modules' tests. **aarch64 hardware run:** because loom doesn't model ARM reordering
  (§10.1).
- **A protocol that is to be model-checked must sit in a leaf crate.** `--cfg loom` is a global
  rustflag, so building a model flips the loom seam of **every** crate in the dependency graph at
  once: a protocol living inside a crate that reaches `graphus-bufpool` could not be checked at all,
  because its `std::sync` types would stop matching that crate's `loom::sync` types. This is why
  `graphus-pagemap` (task #721), `graphus-groupsync` (task #994), `graphus-chainhead` (task #1028,
  §1.2) and `graphus-freezefloor` (task #1014, §1.2) carry **no edge to `graphus-bufpool`**: the first
  two depend on `graphus-core` alone, and the last two on nothing at all. It is a design constraint on
  where a model-checkable protocol may live, not an accident of packaging.
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

### 11.6 Retiring a mechanism: how "all existing tests stay green" is read

**Ratified on 2026-08-03 as `D-retired-mechanism-tests`** (`02-decision-register.md`). This is a
general rule of the project's testing obligations, not a rule about any one task.

A task that **retires a mechanism** deletes the code that mechanism's tests exercise. Those tests
then fail to compile, or fail outright, and the cheapest way to make the suite green again is to
delete them along with the mechanism. That is exactly what must not happen, because the tests were
never protecting the *mechanism*; they were protecting the **semantics** the mechanism happened to
implement, and those semantics survive it.

**The rule.** When a task retires a mechanism, an acceptance criterion of the form "all existing
tests stay green" is read as:

> **every semantic those tests protected remains asserted by a test that fails if the semantic
> breaks.**

Two obligations follow, and both are checkable:

1. **Each retired mechanism test is replaced by a named semantic-equivalent that is at least as
   strong.** "At least as strong" means the replacement fails in every case the original would have
   failed, against the new mechanism. A replacement that only asserts the new mechanism's internals
   is weaker, and does not discharge the obligation.
2. **The replacement is listed in the task's closure summary**, by name, paired with the test it
   replaces. A reader of the closure summary must be able to see the correspondence without
   re-deriving it from the diff.

**Why the rule is written down.** This is the project's recurring defect class in which a test passes
— or simply never runs — while the feature is broken. `VERIFICATION.md` gate 11 records the reference
case: the only suite that would have caught `rmp` #960 sat behind an opt-in feature that no gate ever
enabled, so when the defect landed "every gate that *does* run stayed green, start to finish".
Deleting a mechanism's tests along with the mechanism reaches the same end state by a different
route — a suite that is green because nothing is asking the question any more. The non-vacuity
requirement of §11.1 and §11.3 is the same principle applied to a single test; this is that principle
applied to a task.

**Worked instance.** Task **#967** retires `RecordStore::tombstone_props_for_key` (§5.1.5 row 1) and,
with it, every test that asserts a property tombstone's `expired_ts`, its chain position, or its
deferred reclamation. The semantics those tests protected — an older snapshot still reads the
previous value; a removed property reads as absent; an overwritten property's overflow chain is
freed exactly once; the chain stays well-formed for the consistency checker — all survive under the
empty-cell-plus-delta representation, and each one needs a named replacement asserting it against
the undo chain.

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
   `crates/graphus-storage/src/store.rs:6710-6753`; **15.1 µs/op at M = 1000**, **97.8 µs/op at
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
