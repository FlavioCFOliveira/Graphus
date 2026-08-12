# 02 — Decision Register

These are the open design decisions surfaced by the needs survey and the supporting research.
Per the project rule "you are not authorized to make decisions on your own", each is presented
with options and a recommendation, and **must be ratified by the project owner** before the
detailed per-domain functional specification and the implementation sprints are finalized.

Each decision is a `Decision` node in the Knowledge Graph (status `open`) with an `AFFECTS` edge
to the domain/component it constrains. On ratification, the chosen option is recorded on the node
and its status set to `ratified`.

> **Status: all 24 decisions of the original 2026-06-05 round are ratified.** The chosen option is
> recorded on each `Decision` node (`status: ratified`, property `chosen`). Twenty-five further
> decisions were ratified after that round; they are recorded in the same index below, each carrying
> its own ratification date. The register therefore holds **49 decisions** in total. The decision index in
> the next section is the canonical enumeration; the options tables below it are kept for the
> rationale and trade-offs, and are not a decision list.

Legend: ★ = recommended option.

## Decision index (canonical)

This section is the **single canonical enumeration of every decision in this register**. Each
decision has exactly one row here, and every row carries the decision's key, its status, the date it
was ratified, and the ratified choice. A tool that needs the list of decisions MUST read this table
and only this table: keys mentioned in the prose, in the options tables, or in the notes below are
cross-references, not entries.

Parse contract, to be preserved by any future edit:

- The table lies between the `decision-index` begin and end markers below.
- Every row is one decision. The `ID` cell holds the decision key alone, in backticks.
- `Status` is exactly one of `ratified` or `open`.
- `Ratified on` is an ISO-8601 date (`YYYY-MM-DD`), or `—` when the status is `open`.
- Adding, retiring, or re-ratifying a decision means editing this table.

<!-- BEGIN decision-index -->

| ID | Status | Ratified on | Ratified choice |
| --- | --- | --- | --- |
| `D-cypher-line` | ratified | 2026-06-05 | openCypher 2024.x line, feature-flagged; certify the M-series milestone first; pin a tagged commit |
| `D-tck-harness` | ratified | 2026-06-05 | Rust `cucumber` crate for CI + periodic JVM `tck-api` as ground-truth oracle |
| `D-element-id` | ratified | 2026-06-05 | Internal compact physical IDs + a stable, never-reused public element ID (ULID/UUIDv7) |
| `D-temporal-spatial` | ratified | 2026-06-05 | All temporal types in v1; spatial `POINT` deferred to a later phase |
| `D-concurrency-control` | ratified | 2026-06-05 | MVCC + Serializable Snapshot Isolation (SSI) |
| `D-isolation-level` | ratified | 2026-06-05 | Serializable (SSI) default; Snapshot Isolation as an opt-in documented mode |
| `D-durability-mode` | ratified | 2026-06-05 | Group commit + `fdatasync` default; per-transaction synchronous available; torn-write protection + page checksums + PANIC-on-fsync-failure |
| `D-buffer-mgmt` | ratified | 2026-06-05 | Custom self-managed buffer pool (not pure `mmap`) |
| `D-storage-arch` | ratified | 2026-06-05 | **Custom record store with index-free adjacency from day one; transactional + recovery layer built in-house** *(override of recommended staged-hybrid; raises storage-correctness risk — reinforces DST)* |
| `D-runtime-model` | ratified | 2026-06-05 | Hybrid: Tokio multi-thread baseline + a sharded write/ACID path (validate on a traversal-heavy benchmark) |
| `D-io-backend` | ratified | 2026-06-05 | Portable epoll/kqueue baseline + optional io_uring fast path on Linux with runtime fallback |
| `D-allocator` | ratified | 2026-06-05 | System allocator first; adopt mimalloc/jemalloc only with per-target before/after benchmarks |
| `D-target-matrix` | ratified | 2026-06-05 | Linux x86_64 + aarch64 and macOS aarch64 as Tier 1 tested; 64-bit only; CI on x86 + aarch64 |
| `D-wire-protocol` | ratified | 2026-06-05 | **Adopt Neo4j Bolt directly as the UDS wire protocol (PackStream)** *(override of recommended custom protocol)* |
| `D-bolt-compat` | ratified | 2026-06-05 | **Add a Bolt TCP listener (`bolt://`) for the Neo4j driver ecosystem — a third network interface beyond the originally-stated UDS + REST** *(override; requires TLS + network security for the Bolt TCP endpoint)* |
| `D-serialization` | ratified | 2026-06-05 | Typed JSON (Jolt-style) for REST + CBOR via negotiation; PackStream for Bolt (UDS + TCP); fix int53 from day one |
| `D-auth-scheme` | ratified | 2026-06-05 | UDS `SO_PEERCRED` + socket perms; REST Bearer/JWT over TLS + RBAC; Bolt TCP native auth over TLS; shared RBAC |
| `D-v1-topology` | ratified | 2026-06-05 | Single-node only in v1, clustering-ready internal interfaces |
| `D-v1-index-types` | ratified | 2026-06-05 | Token-lookup + range/B-tree + composite (incl. relationship-property) indexes in v1 |
| `D-graph-algos` | ratified | 2026-06-05 | **Full GDS-style graph-algorithms library (centrality, community detection, similarity, embeddings, in-memory projection engine)** *(override of recommended native-only; a large dedicated workstream/phase orthogonal to the ACID/TCK core)* |
| `D-multi-db` | ratified | 2026-06-05 | Single database in v1; catalog abstraction (catalog→schema→graph) designed in |
| `D-vector-index` | ratified | 2026-06-05 | Out of scope for v1; deferred to a later phase |
| `D-security-scope` | ratified | 2026-06-05 | Auth + RBAC + TLS (REST + Bolt) + user/role management in v1; fine-grained access control / encryption-at-rest / auditing in Phase 2 |
| `D-dst-investment` | ratified | 2026-06-05 | Scaffold a deterministic simulation testing harness from the start with fault injection |
| `D-vopr` | ratified | 2026-06-14 | **External, totally-deterministic VOPR simulator: drive the REAL Bolt/PackStream + REST protocol stacks and the REAL engine over a SIMULATED transport + clock + disk (seed-reproducible), with misbehaved-client / fault / load coverage and four oracles (ref-model, Elle isolation, invariants/liveness, crash-durability)** *(extends `D-dst-investment` to the connectivity/protocol layer; "external" = real protocols, no backdoor, over an in-memory transport — not real OS sockets. See `07-dst-simulator.md`.)* |
| `D-read-parallelism` | ratified | 2026-06-15 | **DEFER read-query parallelism for single-node production; keep the single-writer-thread engine model.** Lock-free snapshot reads are the long-term direction, but parallelizing reads is a large, high-risk change to the inviolable ACID guarantees, gated on a prerequisite migration. *(Post-ratification, sprint 19. Accepted-as-is; tracked as rmp #146. See note below.)* |
| `D-perf-deferrals` | ratified | 2026-06-15 | **DEFER three higher-risk efficiency optimizations (per-commit catalog write, per-row slot model, streaming SHOW INDEXES/CONSTRAINTS).** Each is either a durability/identity risk, a TCK-correctness-sensitive executor rewrite, or a negligible-benefit change. *(Post-ratification, sprint 19. Accepted-as-is; tracked as rmp #159. See note below.)* |
| `D-bulk-import-network` | ratified | 2026-07-01 | **Network bulk import over a dedicated REST streaming-upload endpoint**, reusing the existing local CSV / `.gcol` payload formats, gated by the global `Admin` privilege, with per-batch commit plus mandatory crash-consistent session resumability. Both **Mode A** (fresh/empty database, exclusive `Loading` lifecycle state) and **Mode B** (already-live, already-serving database; every batch a first-class, SSI-participating transaction) are in scope. *(Override on the target-database-scope facet: the owner added the non-recommended option (b) on top of (a). Mode B is gated on a prerequisite `graphus-bulk` fix.)* Facet table in the "Ratified decision (2026-07-01)" section below; full design in `08-network-bulk-import.md`. |
| `D-hw-autotune` | ratified | 2026-07-08 | **Hardware-aware startup auto-tuning:** the `0 = auto` sentinel plus a strict precedence — operator configuration > hardware-derived value > built-in floor — adopted project-wide; auto `buffer_pool_pages = clamp( floor(0.125 × available_RAM_bytes ÷ 8192), 4096, 262144 )`; all OS-specific and `unsafe` probing isolated in the `graphus-sysres` leaf crate so `graphus-server` stays `#![forbid(unsafe_code)]`. Detected storage capacity/free space and the SSD-versus-rotational hint are logged only, and drive no automatic parameter change in this cut. Facet table in the "Ratified decision (2026-07-08)" section below; design in `04-technical-design.md` §9.5. |
| `D-named-index-autoname` | ratified | 2026-07-08 | **Anonymous and legacy `CREATE INDEX ON :Label(property)` forms take a deterministic, stable auto-name of the form `index_<label>_<property>`** — a pure function of the label and property tokens — disambiguated by a deterministic token suffix and, if needed, a counter, until the name is free in every schema catalog; the resolved name is then persisted durably. Completes the already-ratified core requirement `FR-IX-15` under `D-v1-index-types` option (a); no ratified outcome changes. See the "Post-ratification note (2026-07-08)" below; design in `04-technical-design.md` §6.8. |
| `D-query-prefixes` | ratified | 2026-07-14 | **`EXPLAIN` plans a statement without executing it; `PROFILE` executes it and annotates the plan with measured per-operator counters; exactly one of `plan` / `profile` is ever emitted.** `dbHits` is Graphus's own measured quantity, not a reproduction of Neo4j's DbHit accounting; unmeasured counters (per-operator time, page-cache counters) are omitted rather than fabricated — this supersedes the "timing" wording of `FR-QL-13`; a `PROFILE`d statement runs serially; the planner's cardinality estimate is reported on the root only. Completes the already-ratified core requirement `FR-QL-13`; no ratified outcome changes. See the "Post-ratification note (2026-07-14)" below; design in `04-technical-design.md` §7.8 and `06-bolt-and-error-shapes.md` §3.1. |
| `D-async-commit` | ratified | 2026-07-23 | **Declined — Graphus does NOT adopt a deferred (asynchronous) WAL flush, whether time- or count-triggered.** Ack-after-fsync stays unconditional for every workload, and ingest acceleration goes through the `SuspendPersistence` campaign instead. Evaluated against measured evidence on 2026-07-23 and declined by the owner; refines `D-durability-mode`, whose "per-transaction synchronous available" facet is unchanged. Evidence and rationale in the "Ratified decision (2026-07-23)" section below. |
| `D-version-representation` | ratified | 2026-08-02 | **Newest version in place, older versions reconstructed by walking one unified undo-delta chain per entity** (the Memgraph / InnoDB model), over append-only newest-first. This closes `04-technical-design.md` §12 item 2, which the specification itself declared to be blocking the record header and the undo area. Every mutation kind — create, delete, set property, add or remove label, add or remove incident edge — becomes a delta on that one chain; the chain is anchored by the record's `undo_ptr`, which task **#966** brought to life (it was provably dead when this decision was ratified). Design in `04-technical-design.md` §5.1 and §5.6; on-disk format in `05-storage-format.md` §12. |
| `D-write-conflict-detection` | ratified | 2026-08-02 | **A write-write conflict is detected on the entity's own MVCC header and aborts the writer immediately, with no waiting** (the Memgraph `PrepareForWrite` model). The writer inspects the head of the entity's delta chain: if that head belongs to a transaction that is neither itself nor committed before its own start timestamp, it aborts at once with a retriable serialization failure. **The write-lock table and the wait-for-graph deadlock detector are retired**, and with them every lock wait and every lock-wait timeout. Design in `04-technical-design.md` §5.7. |
| `D-multi-writer` | ratified | 2026-08-02 | **Graphus is multi-writer: N transactions write to the same database in parallel.** MVCC becomes the central and only concurrency-control mechanism, and the single-writer-thread engine model is retired. This supersedes the "keep the single-writer-thread engine model" facet of `D-read-parallelism` (rmp #146), whose read-side deferral was already discharged by the off-thread reader pool (rmp #336). Design in `04-technical-design.md` §5.7; the runtime shape that carries it is §9.1. |
| `D-dst-writer-scheduler` | ratified | 2026-08-02 | **The DST simulator gains a deterministic writer scheduler, and it is a prerequisite of multi-writer certification.** Multi-writer correctness may not be signed off on non-deterministic evidence alone: the simulator must dispatch several concurrent writers against one database from a seeded schedule, so that any lost update, resurrection, or torn chain is reproducible from its seed. This extends the cooperative interleaver of `D-vopr` (`07-dst-simulator.md` §5) to the write path and narrows the named fidelity ceiling of `07-dst-simulator.md` §5.1. The scheduling mechanism was delivered by task **#973**; the concurrent writers it is to order arrive with **#975**, so the decision is **partly discharged**. See the "Post-ratification note (2026-08-05) — `D-dst-writer-scheduler`" below; design in `07-dst-simulator.md` §5.2. |
| `D-property-write-conflict` | ratified | 2026-08-03 | **The write-write conflict check arrives with task #967, at entity granularity.** Before a property write links any delta, the writer reads the head of the entity's undo chain and aborts with a retriable serialization failure if that head belongs to another transaction that is still open. This makes `04-technical-design.md` §5.1.2 step 1 real at the granularity §5.7 already specifies — the entity's own MVCC state, not the property cell's. It is a prerequisite of the property migration rather than a consequence of it, because the in-place overwrite, the commit-ordering of the chain, and the exactness of the abort-time pre-image all depend on it. Task **#971** later consumes this check rather than replacing it. Refines `D-write-conflict-detection` by fixing when and at what granularity it lands; no ratified outcome changes. Design in `04-technical-design.md` §5.1.2 and §5.7. |
| `D-incidence-anchor` | ratified | 2026-08-04 | **An incidence delta anchors on the RELATIONSHIP, not on the endpoint node.** The node is where the incidence chain *head* lives, so it looks like the natural anchor, and an earlier draft of task **#969** used it. It is the wrong one, and the reason is measured rather than argued: a node's chain would grow by one delta per edge inserted on it, and every property or label read of that node walks its chain — **220 ns at degree 0 against 488 µs at degree 4000** for one visible-property read — with the growth not ending at the next GC pass, because `gc_reclaim_undo_chains` frees a chain only when *every* delta on it is dead and a hub under sustained insertion never prunes. That regresses the acceptance criterion `rmp` #967 established. The relationship carries the same information and none of the cost: it is a fresh slot private to its creator, so incidence deltas never interleave with another transaction's, the commit ordering the read path's `Stop` rule depends on is undisturbed, and **an edge insertion never conflicts with anything** — which is what keeps the supernode write concurrency `rmp` #220 built. The price, accepted deliberately, is that every edge pays two deltas (~112 B of undo plus WAL), including in a bulk load: the endpoint-anchored draft could skip them when the endpoint was created by the same transaction, and the relationship-anchored one cannot, because the relationship always is. Supersedes the withdrawn `D-incidence-non-sequential`, whose whole purpose — letting two transactions interleave incidence deltas on one node's chain — the anchor removes the need for. Design in `04-technical-design.md` §5.1.1. |
| `D-property-removal` | ratified | 2026-08-03 | **`REMOVE n.p` (and `SET n.p = null`) rewrites the property cell in place to an empty cell — `type_tag = 0, value_inline = 0` — and is not an `xmax` tombstone.** The cell keeps its `in_use` bit and its position in the `first_prop` chain; the old value descends onto the entity's undo chain in a `SetProperty` delta. Two consequences are normative: **exactly one owner names any `strings.store` overflow chain** (the live cell owns the current value, a delta owns each historical value, and the two sets are disjoint), and a later `SET` of the same key reuses the empty cell with no allocation. `expired_ts` is never again written by a property operation, and `RecordStore::tombstone_props_for_key` is retired. Design in `04-technical-design.md` §5.1.5 row 1; format in `05-storage-format.md` §12.2. |
| `D-property-visibility` | ratified | 2026-08-03 | **The undo chain is the sole visibility oracle for a property's value.** The property cell's own `created_ts` becomes informative rather than authoritative: a reader resolves which value it is entitled to see by starting from the in-place image and walking the entity's undo chain, never by comparing the cell's stamp. The cell's MVCC header keeps its structural meaning — `in_use` for slot occupancy and corpse threading. The ground is that the frozen 56-byte delta of `05-storage-format.md` §12.2 has no field for the old `created_ts`, so no logical undo can ever restore it, and under this decision none needs to. This is what allows task **#970** to be a rollback change only, with no second rewrite of the read path. Design in `04-technical-design.md` §5.6. |
| `D-retired-mechanism-tests` | ratified | 2026-08-03 | **When a task retires a mechanism, an acceptance criterion of the form "all existing tests stay green" is read as "every semantic those tests protected remains asserted by a test that fails if the semantic breaks".** Each retired mechanism test must be replaced by a named semantic-equivalent that is at least as strong, and the replacement must be listed in the task's closure summary. A general rule of the project's testing obligations, not a #967-only one. Specified in `04-technical-design.md` §11.6. |
| `D-rollback-dispatch` | ratified | 2026-08-05 | **A rollback is dispatched by one test — whether the transaction owns a commit-info slot — and there are exactly two paths.** A transaction that linked any delta owns a slot, so every change it made to MVCC state is on an undo chain and is undone **logically**: it applies its own deltas newest-first against the *current* state, detaches them (always a head prefix, never a splice in the middle), reclaims them with its slot, and ends in the log with an `ABORT` record carrying no compensation. A transaction with **no** slot linked no delta; two kinds reach that case — a maintenance pass (GC reclamation, corpse splice, freeze sweep), whose writes are physical space management naming no MVCC version, and a catalog-only writer, whose effects are in-memory schema that the metadata page settles — and both keep the **physical** ARIES path, because physical undo is the right inverse of a physical change and a GC pass is a single non-yielding call, so no concurrent writer can stale its pre-images. Retiring the physical path outright belongs to the tasks that version the catalog and make collection concurrent, not to task **#970**. Closes `04-technical-design.md` §5.1.5 row 4; design in `04-technical-design.md` §4.3, §4.4 and §5.1.5. |
| `D-chain-head-redo-only` | ratified | 2026-08-05 | **A chain-head publication (`undo_ptr`, `first_rel`, `first_prop`) and the relink of the head it displaces are logged redo-only, with an empty undo image.** Their inverse is to *unlink the entry*, computed at abort time from the transaction's own deltas, and never the restoration of the word. Neither form of restoration could be made safe: a plain pre-image undo of a shared head clobbers a concurrently-committed prepend (the whole of `rmp` #220), and the compare-and-set undo that replaced it was narrower but still unsound, because it restores an **id**, and once a slot can be freed and handed out again the id it restores may name a different record. The state a redo-only write leaves after recovery is a head naming a `!in_use` record — a **corpse**, which every chain walk in the storage core already threads through and the GC splice reclaims — and that is the state `rmp` #220 / #172 already designed the header-only creation undo around. Two exceptions are deliberate: the GC's clearing of `undo_ptr` keeps a physical undo, because it is not a prepend; and the compare-and-set undo itself is **not** retired, surviving on the node's `labels` word and on the MVCC header word, where a whole-word write's inverse *is* the word. Closes the chain-head half of `04-technical-design.md` §5.1.5 row 3; design in `04-technical-design.md` §4.4, and format consequences in `05-storage-format.md` §7 and §12.5. |
| `D-orphan-slot-parking` | ratified | 2026-08-05 | **A record slot that a logical rollback orphans is parked in memory until the next garbage-collection pass, not returned to the free list by the abort itself.** The abort knows the slot is unreachable — it is what unlinked it — so the restraint is deliberate, and its reason lies outside the storage engine: the latest-state TEXT, FULLTEXT and SPATIAL indexes are in memory, **not transactional**, and key their documents by **physical node id**. An aborted node's posting survives its rollback as a harmless false positive that the re-check filters out, but recycling the id immediately turns the next writer's *insert* into what the index reads as the **replacement of a still-committed document** — the one shape `rmp` #756 must fail closed on, at the cost of a poisoned freshness marker and of every text or spatial seek degrading to a full scan until a rebuild. Parking keeps the space guarantee (the slots do come back, so an abort-heavy workload does not grow the store) while moving the recycle to a maintenance boundary; the GC phase is guarded on the record still being retired, so a slot legitimately re-used by some other path is never double-freed. The parking becomes unnecessary once those indexes are version-aware. Design in `04-technical-design.md` §5.1.5. |
| `D-statement-isolation` | ratified | 2026-08-05 | **A statement does not observe its own writes, and the rule is one comparison operator over the delta's `command_id`.** Every read carries a **view** — `New` (the default) or `Old` — beside its snapshot; the view decides nothing about other transactions and only whether the reader's own uncommitted deltas are undone (`New`: written by a later command; `Old`: written by a later command **or by the current one**). A delta written outside any statement carries `command_id = 0` and is undone by **no** view, because it belongs to the transaction's baseline rather than to a statement. The counter lives in the record store, which is its single source of truth, and it advances at exactly **two** points: when a cursor opens, and at a `WITH` that follows a write. Polarity is fixed per clause: `Old` for every scan, every index seek, every relationship expansion, a `MATCH`'s `Filter`, `UNWIND` and a read-only procedure `CALL`; `New` for `MERGE`'s match sub-plan, every update clause, projection, aggregation and ordering, and a writing procedure `CALL`. The planner's `Eager` barriers are **all retained**: they decouple row production while the view re-polarises visibility, and reforming them is separate work. Closes the `command_id` half of `04-technical-design.md` §5.1.4; design in `04-technical-design.md` §§5.1.4, 5.3 and `05-storage-format.md` §12.2. |
| `D-chain-head-publication` | ratified | 2026-08-09 | **A chain head is published by a compare-and-publish held atomic by a short publication latch, and a refused publication logs nothing.** The unconditional byte write through which a **prepend** published `first_rel`, `first_prop` and `undo_ptr` is retired: a prepend now reads the head, writes its entry linked to that head, publishes the entry **only if** the head still holds what it read, and fixes the displaced predecessor's back-pointer only **after** it has won — so two writers can never relink the same predecessor. A refusal re-reads the head, re-links the entry and retries. The protocol lives in the dependency-free leaf crate `graphus-chainhead`, where `loom` can model-check it. Atomicity and, equally, **durable order** (log order must equal the order in which publications take effect on the page) are supplied by a sharded latch at **rank 27**, between the allocation latch (25) and the WAL (30), taken with the page already pinned, admitting one holder per thread, and never held across I/O — mechanically enforced in debug builds. The redo image is a compare-and-set patch, which needs **no** new WAL record type, format version or recovery step. The write stays **redo-only** (`D-chain-head-redo-only` is unchanged). The same latch covers two further writes, because the head word alone is not the whole prepend: the shared `chain_flags` byte of the displaced relationship, which a prepend clears with a commutative mask instead of a computed byte, and the GC corpse splice's repointing of a node head, converted so that no writer of that word stores into it unconditionally. Facet table in the "Ratified decision (2026-08-09) — chain-head publication" section below; design in `04-technical-design.md` §5.7.1. **Post-ratification (2026-08-12, task #1062): the rank-27 latch is now keyed by the device page instead of by `(store kind, record id)`. The widening is strict — every writer of a record is a writer of its page and maps to the same shard — so this decision's guarantee is unchanged, and chain-head publication is now a particular case of `D-page-write-order`. See the "Post-ratification note (2026-08-12) — `D-chain-head-publication`" below.** |
| `D-wal-group-leader` | ratified | 2026-08-11 | **One shared fsync group leader hardens the WAL for every engine worker, and the per-worker fsync thread is retired.** The pipelined group commit of task **#532** offloads a commit batch's `fdatasync` so that the durability sync of batch *K* overlaps the CPU preparation of batch *K+1*. Its documented invariant was **strict depth-1** — a job channel of depth one, and the engine waiting for the outstanding job before submitting the next, so at most one batch is ever written-but-un-synced and a crash tail is the tail of one batch. That invariant became **false** the moment the engine grew to `W` workers: each worker spawned its own fsync thread over the **one** `WalManager` they share behind `SharedWal`, so each was depth-1 for itself while the system reached depth `W`, and a crash tail could hold interleaved batches from several workers. The ack-after-fsync rule was not actually violated, but only because of three properties of the sink that **no contract declared** — a job hardens whole files and therefore at least its entire declared range; every `begin_harden` starts at the sink's **global** durable frontier; and completion is a monotone maximum that the acknowledgement is taken after. This decision promotes those three to **the sink contract**, declared normatively and each pinned by a test, and makes the job carry the range it hardens explicitly (`covers_from`, `target_len`) so the contract is machine-checkable rather than prose. **One fsync group leader per database engine** then replaces the per-worker thread: workers offer their job to the leader, at most one `fdatasync` is in flight system-wide, a newer offer subsumes and discards an older pending one, and each worker is released once the group's hardened watermark passes its own target — the `XLogFlush` shape of PostgreSQL. **Depth-1 is restated where it is now true**: one `fdatasync` in flight for the whole engine, so the crash tail is again the tail of one un-synced interval rather than of `W` interleaved ones. Every discard is adjudicated by an **always-on tripwire** against the sink's own attested durable frontier, so a per-worker frontier or a sync narrowed to a byte range trips it instead of silently acknowledging un-synced bytes. Refines `D-multi-writer` by fixing the durability mechanism its parallel writers share; leaves `D-async-commit` untouched, since ack-after-fsync remains unconditional and nothing here defers or batches a sync in time; supersedes no ratified outcome, and changes no on-disk format. Facet table in the "Ratified decision (2026-08-11) — the WAL fsync group leader" section below; design in `04-technical-design.md` §4.2 and §9.1. |
| `D-published-snapshot-horizon` | ratified | 2026-08-12 | **A snapshot timestamp is the published commit-visibility horizon, never the commit-timestamp allocation clock.** A commit timestamp is issued at the start of commit and the commit publishes itself only afterwards, in **two writes in two media** — the durable commit-info slot and the in-memory commit registry — so the issuing clock names commits that neither visibility oracle will yet admit. Handing that clock out as a begin timestamp became a **lost update** the moment `D-multi-writer` allowed a second worker to begin inside that window: the transaction read the pre-commit value of every record the committing transaction wrote and, being itself a writer, overwrote it — two acknowledged increments, one applied, on roughly one run in five at eight engine workers and never at one. The store now holds the set of commit timestamps that are **issued but not yet published** and derives the horizon as the **contiguous published prefix** (the lowest pending timestamp minus one, or the whole allocation clock when nothing is pending), advanced by an atomic maximum so it is monotone under any interleaving. The set is guarded by the **rank-20 commit sequencer latch**, entered through a single acquisition door, a leaf, and off the read path entirely: taking a snapshot remains one atomic load. An issued timestamp is released on **every** exit — published once both halves of publication are done, abandoned on failure and thereafter skipped, never reissued — because a leaked timestamp freezes the horizon for the life of the process; the commit path is therefore split into a timestamp-issuing wrapper and a fallible body, so release is a property of one caller rather than of every fallible step. `begin` and the commit path **return** the timestamp they captured or assigned, and callers use that value instead of re-reading a clock a sibling worker may have moved. Refines `D-version-representation` by fixing what a snapshot timestamp *means*, and `D-write-conflict-detection` by making its second arm answerable; supersedes no ratified outcome and changes no on-disk format. Facet table in the "Ratified decision (2026-08-12) — the published snapshot horizon" section below; design in `04-technical-design.md` §5.2, §5.1.3 and §5.7. |
| `D-page-write-order` | ratified | 2026-08-12 | **For every page, the order in which logged writes enter the WAL is the order in which they take effect on that page.** A logged page write is two instants — the record enters the log under the WAL mutex (rank 30), the change takes effect on the cached page under the frame latch (rank 40) — and until task **#1062** nothing tied them together. With one writer per database that is latent; with several, two writers of one page could enter the log in one order and apply in the other, and because ARIES replays strictly in log order the durable state after a crash **differed** from the state a crash-free execution left, with neither wrong on its own terms and no result-checking test able to see it. The invariant is supplied by the **rank-27 section re-keyed from `(store kind, record id)` to the device page**, with the page pinned before the latch is taken: capture the undo pre-image, append the record, apply the post-image and stamp `page_lsn` are **one indivisible section per page**, and every one of the record store's ten WAL-append sites — plus the rollback path's compensation append — passes through the single door that enters it. Three alternatives are rejected: a **monotone `page_lsn` stamp alone** (already in the tree since task #1029 while the divergence was measured, and worse than useless on its own, because a page stamped with an LSN it never applied makes redo **skip** a legitimate record); **appending under the frame latch** (it inverts ranks 30 and 40, and the WAL barrier refuses by tripwire to run with a frame latch held); and **applying under the WAL mutex** (it violates the absolute rule that the store never holds its WAL lock across a buffer-pool call that can trigger a write-back). `D-chain-head-publication` is absorbed as a particular case, unchanged, because keying by page is a strict widening of keying by record. No byte of any on-disk format changes, and no recovery step changes. Facet table in the "Ratified decision (2026-08-12) — log order equals apply order, per page" section below; design in `04-technical-design.md` §5.7.2 and §3.3. |

<!-- END decision-index -->

**Four owner overrides of the recommendation** (recorded with a `note` on their KG nodes) reshape the
scope and are propagated into `00-overview.md` and `01-needs-survey.md`:
1. **D-storage-arch → custom from day one.** The transactional/recovery engine (WAL/ARIES/SSI) is
   built in-house from the start; this is the highest-risk work and is the reason DST (D-dst-investment)
   and the full verification arsenal are scaffolded immediately.
2. **D-wire-protocol → Bolt directly**, and **D-bolt-compat → add a Bolt TCP listener.** Graphus now
   exposes **three interfaces**: Bolt over UDS, Bolt over TCP (`bolt://`), and the Web REST API. These
   decisions extended the two-interface model in the original project definition; `CLAUDE.md` now
   records the three-interface model (see the note in `00-overview.md`).
3. **D-graph-algos → full library.** A complete graph-algorithms library plus an in-memory projection
   engine is committed as a dedicated workstream (its own phase), in addition to the ACID/TCK core.

> **Post-ratification note (2026-06-12) — `D-v1-index-types`.** The ratified outcome remains
> **option (a)** (token-lookup + range/B-tree + composite incl. relationship-property), and the v1
> index baseline is **not** re-ratified. The **full-text** capability of option (b) was nevertheless
> **delivered early by rmp #72**, ahead of its Phase-2 schedule, in the same manner as the other
> Phase-2 capabilities already shipped in this codebase without re-baselining (encryption at rest,
> fine-grained RBAC, and incremental backup + PITR). It is specified in `04-technical-design.md` §6.7
> and tracked as `FR-IX-7` (still `[ADV]`); it adds a capability without altering the four-kind core
> set that option (a) ratifies.

> **Post-ratification note (2026-07-08) — `D-named-index-autoname` (named node-property indexes).**
> This note records a **design decision**, not a scope change: node-property indexes and their Cypher
> DDL (`CREATE`/`DROP INDEX`, `SHOW INDEXES`) were always part of the v1 core set (`FR-IX-15`,
> ratified) and of `D-v1-index-types` option (a). Named node-property indexes (rmp #623–#626) make
> that DDL **Neo4j-conformant**: an index carries a name (`CREATE INDEX [<name>] [IF NOT EXISTS]
> FOR (n:Label) ON (n.property)`, `DROP INDEX <name> [IF EXISTS]`), `SHOW INDEXES` returns the Neo4j
> driver columns, and `IF NOT EXISTS`/`IF EXISTS` are idempotent no-ops.
> **`D-named-index-autoname`** captures the specific design choice for how the anonymous and legacy
> `CREATE INDEX ON :Label(property)` forms are named: a **deterministic, stable** auto-name of the
> form `index_<label>_<property>` (a pure function of the label and property tokens), disambiguated by
> a deterministic token suffix and, if needed, a counter, until the name is free in every schema
> catalog; the resolved name is then persisted durably, so it is computed at most once and stays
> stable across restarts. Names are globally unique across the schema's index and constraint catalogs,
> and the name catalog is durable (an append-only block in the storage `Statistics` image, crash-atomic
> with the index catalog; pre-existing anonymous indexes are backfilled with an auto-name on open). No
> ratified outcome changes; this is the completion of an already-ratified core requirement. Specified in
> `04-technical-design.md` §6.8 and recorded as a `Decision` node in the KG.

> **Post-ratification note (2026-07-14) — `D-query-prefixes` (`EXPLAIN` / `PROFILE`).** This note
> records a **design decision**, not a scope change: the two Cypher query prefixes are the ratified
> core requirement `FR-QL-13`, delivered by rmp #752. `EXPLAIN` compiles and plans a statement without
> executing it (zero records, the statement's real `fields`, plan under the `plan` key); `PROFILE`
> executes it and returns a plan annotated with measured per-operator counters under the `profile`
> key. Exactly one of `plan` / `profile` is ever emitted. `D-query-prefixes` captures the specific
> choices made in delivering it:
> 1. **`dbHits` is Graphus's own measured quantity** — one record obtained from the `GraphAccess`
>    storage seam by an operator — **not** an attempt to reproduce Neo4j's internal DbHit accounting.
>    A fused scan-and-filter path reports the records it *examined*, so a full-scan fallback cannot
>    masquerade as cheap.
> 2. **Unmeasured counters are omitted, never fabricated.** Graphus reports no per-operator
>    wall-clock `time` and no `pageCacheHits` / `pageCacheMisses` / `pageCacheHitRatio` (all optional
>    on the wire; drivers default them to `0`). This **supersedes the "timing" wording of `FR-QL-13`**:
>    PROFILE reports measured `rows` and `dbHits`, but not per-operator time.
> 3. **A `PROFILE`d statement runs serially** (intra-query morsel parallelism disabled) so every
>    storage access is attributable; an unprofiled statement builds no instrumentation and pays
>    nothing.
> 4. **The planner's cardinality estimate is reported on the root only** (`EstimatedRows`), never
>    invented per operator.
>
> Each choice follows the project's "measure to decide" rule and its refusal to synthesise a number it
> did not measure. No ratified outcome changes; this completes an already-ratified core requirement.
> Specified in `04-technical-design.md` §7.8 and `06-bolt-and-error-shapes.md` §3.1, and recorded as a
> `Decision` node in the KG.

> **Post-ratification note (2026-06-15) — sprint-19 performance/architecture deferrals.**
> Two performance/architecture findings were evaluated during the sprint-19
> production-readiness closure and **deferred** (accepted-as-is for the single-node
> production sign-off, scheduled as future work). Both dispositions are
> measurement-/audit-grounded and follow the project's "measure to decide" rule and the
> inviolable ACID requirement: a certified-green engine is not destabilized for
> non-correctness gains. Each finding is recorded as a `Decision` node
> (`status: deferred`) tracked against its `rmp` task.
>
> **`D-read-parallelism` (rmp #146) — DEFER read-query parallelism.**
> An architectural audit found that all queries, reads included, currently funnel through
> a single engine OS thread via an `mpsc` channel, which serializes them; a stress test
> measured about 166 connections per second under 400-way concurrency on a trivial read.
> Parallelizing reads is the documented long-term direction (lock-free snapshot reads):
> the pure `is_visible` MVCC snapshot algebra in `graphus-txn` already exists, and a
> loom-verified `ConcurrentBufferPool` already exists. It is nevertheless a large to
> very-large, high-risk change to the inviolable ACID guarantees, and it is gated on a
> prerequisite migration. The live `RecordStore` read path is `&mut self` over the
> single-threaded `BufferPool`, and the store, index, token, and commit-registry views
> are `Rc<RefCell<…>>` (`!Send` / `!Sync`). The single-writer model currently delivers
> 100% ACID cleanly. The recommended path is a prerequisite epic:
> (a) migrate `RecordStore` reads onto `ConcurrentBufferPool`;
> (b) publish snapshot-consistent read views;
> (c) add the off-thread read executor and the engine routing — reassessed only after (a).
> **Status:** accepted-as-is for single-node production; tracked as rmp #146.
>
> **Note (2026-08-05).** The paragraph above is the state of the engine **as it was read in sprint
> 19**, and is kept as that record rather than maintained — the same treatment this register gives
> the 2026-08-02 evidence table. Three of its premises have since been discharged and must not be
> quoted as current: (a) the `RecordStore` read path moved onto `ConcurrentBufferPool` in rmp #337,
> and `RecordStore` has asserted `Send + Sync` ever since; (b) snapshot-consistent read views and the
> off-thread read executor landed in rmp #336/#543, so the prerequisite epic (a)–(c) is complete and
> `D-read-parallelism` is superseded by `D-multi-writer`; (c) the `Rc<RefCell<…>>` views became
> `Send` shared cells in rmp #1009/#1010 (layers 1–2 of #975), so the `!Send`/`!Sync` claim is no
> longer true of any of them. What remains of the single-writer barrier is **not** a `Send` problem
> at all: it is the `&mut self` exclusivity of the store's write methods, which #975's later layers
> retire.
>
> **`D-perf-deferrals` (rmp #159) — DEFER three higher-risk efficiency optimizations.**
> Each of the three is deferred for its own reason:
> 1. **Per-commit catalog write (A1).** `RecordStore::commit` unconditionally rewrites the
>    whole catalog every commit (it clones the `TokenStore` and `Statistics`, serializes,
>    and page-writes). A dirty-flag gate is high-risk because the catalog persists
>    monotonic high-water marks — `commit_ts_hw`, `element_id_next`, the per-store physical
>    id high-water, and the token dictionary — that are not all WAL-recoverable; a missed
>    dirty-set is a silent durability or identity-reuse bug. The only genuinely
>    catalog-clean commit is a read-only one, whose payoff is marginal.
> 2. **Per-row slot model (B1/B2).** `Row` is a parallel `Vec<String>` with linear-scan
>    name lookup and a full clone per row. Resolving names to plan-time slot indices is a
>    large, TCK-correctness-sensitive (column order and rebind semantics), non-incremental
>    executor rewrite that belongs with the future cost-based-planner / typed-schema work.
>    A cheap, low-risk interim — an `Arc<[Arc<str>]>` shared column schema to remove the
>    per-row name-vector deep clone — is noted as a possible separate small task.
> 3. **Streaming SHOW INDEXES / CONSTRAINTS (C11).** The handler collects rows into a `Vec`
>    before replying, but the result is bounded by schema cardinality (tens of rows) and
>    the source is already an in-memory `Vec`; the benefit is negligible. Accept-as-is.
> **Status:** accepted-as-is for production; tracked as rmp #159.

## Ratified decision (2026-07-01) — `D-bulk-import-network`

> **`D-bulk-import-network` — Network bulk import (remote streaming bulk load).** Unlike the two
> sprint-19 entries above, this decision was **not** dispositioned by an internal audit against an
> already-ratified requirement — it was a genuinely new capability, proposed after an empirical
> load test (2026-06-30, against a live remote instance) established that no existing mechanism can load a
> large-scale dataset (order of 1,000,000 nodes, hundreds of millions of relationships) into an
> already-running Graphus server, local or remote (`08-network-bulk-import.md` §1). It was
> presented with options and a recommendation on six facets, and the two highest-impact,
> least-reversible facets were flagged for sequential owner ratification. **The project owner
> ratified this decision on 2026-07-01**, confirming the recommended RBAC option and — on the
> target-database-scope facet — selecting the **non-recommended, higher-risk option**: network
> bulk import must support an already-live, already-serving database, not only a fresh/empty one.
> Full rationale, the resulting concurrency-safe design, and its independent validation
> (`storage-systems-auditor`, 2026-07-01) are in `08-network-bulk-import.md`; this entry is the
> register's summary of that document.
>
> **Status: ratified.**
>
> | Facet | Options | Ratified choice |
> | --- | --- | --- |
> | Transport | (a) new Bolt message type; (b) Bolt, bounded chunks over standard `RUN`/`PULL` only; ★(c) dedicated REST streaming-upload endpoint, exempt from the general 4 MiB body limit | **(c), as recommended.** Option (a) is a genuine Bolt-spec compliance violation (no reserved extension range in the spec) and PackStream's `BYTES_32` size tier is capped at ~2 GiB by the specification itself, ruling out a single large payload value regardless. Option (b) is spec-conformant but pays a full RUN/PULL/PackStream round trip per chunk for what is, at that point, opaque bytes. HTTP chunked transfer-encoding (RFC 9112/9113) has no such ceiling and is the standards-native fit; `graphus-rest` already established the symmetric egress-streaming pattern (rmp #475). See `08` §3. |
> | Payload format | (a) reuse the existing local CSV / `.gcol` formats `graphus-bulk` already parses; (b) a new network-specific binary format | **(a), as recommended.** Reuses already-certified (sprint 7) parsing/import logic unmodified; only the byte source changes. See `08` §4. |
> | Target-database scope | (a) fresh, empty database only (matches today's offline-importer precondition); **(b) — RATIFIED, the non-recommended option** — support incremental load into an already-live, already-serving database, in addition to (a) | **Both (a) and (b) — the owner chose to add (b) on top of, not instead of, (a).** (b) requires the low-level import path to participate in MVCC/SSI conflict detection and inline index maintenance against concurrent transactions — flagged as being in the same risk family as the already-deferred `D-read-parallelism` (rmp #146). Unlike that deferral, this was ratified: `08` §7.2 is the resulting concurrency-safe design (every batch is a first-class, SSI-participating `TxnCoordinator` transaction, never a raw low-level store bypass), independently validated against the actual concurrency-control code before being written into the spec. Named **Mode A** ((a), exclusive, `08` §5.1–§5.2) and **Mode B** ((b), concurrent, `08` §5.3) in the spec. |
> | Exclusivity mechanism | Mode A: ★a new `Loading` database lifecycle state (engine running, ordinary client traffic rejected) alongside the existing `Online`/`Offline`; Mode B: no exclusivity mechanism, correctness from MVCC/SSI alone | **Both, one per mode — as designed.** Mode A mirrors the existing `RESTORE DATABASE` precedent (stopped first, started explicitly after) while keeping the engine alive to receive the stream; scoped to one database, every other database unaffected (`D-multi-db`). Mode B stays `Online` throughout and relies entirely on the same SSI machinery that already protects ordinary concurrent Cypher transactions. See `08` §5.2/§5.3. |
> | RBAC privilege | ★(a) the existing global `Admin` privilege (same gate as `BACKUP`/`RESTORE`/`CREATE DATABASE`), for both modes; (b) a new, narrower graph-scoped privilege | **(a), as recommended — confirmed by the owner, no change, applies to both Mode A and Mode B.** The operation can take exclusive control of a database (Mode A) or write at import scale against live traffic while bypassing the ordinary Cypher write path's fine-grained RBAC checks (Mode B), so it should not be reachable by a data-level `Write` grant alone. A narrower privilege remains a possible follow-up once the core capability is in production. See `08` §6. |
> | Atomicity / resumability | ★(a) extend the already-ratified `D-bulk-import-non-atomic` (per-batch commit, whole session non-atomic) and add mandatory, crash-consistent session-checkpoint resumability; (b) require the whole import to be all-or-nothing | **(a), as recommended, both modes.** Does not weaken the inviolable ACID requirement: every committed batch is a fully durable, consistent transaction; only the *session as a whole* is non-atomic, exactly as already ratified for the offline case. Resumability is the correct response to network unreliability, not a workaround for it. **Mode B additionally requires** a prerequisite fix in `graphus-bulk` (the `id_map` staging bug, `08` §7.2.2) before its automatic batch retry can be enabled safely — see the note below. See `08` §7. |
>
> **Prerequisite fix required before Mode B ships.** The independent validation
> (`storage-systems-auditor`, 2026-07-01) surfaced a **pre-existing, must-fix correctness bug** in
> `graphus-bulk::BulkImporter`: its external-id→physical-id map is mutated eagerly during row
> ingestion, before the enclosing transaction commits, and is never reverted on rollback. This is
> harmless for today's offline, no-retry, empty-database path, but Mode B's batch-retry-on-abort
> requirement (an expected, ordinary event under live-database concurrency, `08` §7.2.1) would
> turn it into a live data-corruption risk (spurious duplicate-id failures, or silently orphaned
> nodes and corrupted relationship-pass joins under `DuplicatePolicy::SkipDuplicate`). Registered
> as KG Finding `bulk-idmap-not-abort-safe` (severity high, status open). **This fix is a
> precondition of Mode B's acceptance criteria** (`08` §11), not a follow-up.
>
> DoS/resource-limit requirements (byte quotas, disk-space preflight, session timeouts,
> backpressure, engine-thread-yielding fairness for Mode B) and the two required new DST scenarios
> (`network_bulk_ingest_mode_a`, `network_bulk_ingest_mode_b`) are specified in
> `08-network-bulk-import.md` §8 and §10 respectively; they are implementation requirements of the
> ratified design, not separate decisions.

## Ratified decision (2026-07-08) — `D-hw-autotune`

> **`D-hw-autotune` — Hardware-aware startup auto-tuning.** At startup the server probes the host
> hardware (logical CPUs, total/available physical RAM, and the store filesystem's capacity/free
> space plus an SSD-vs-rotational hint) and derives sane defaults for its resource-sizing parameters,
> while every value stays operator-overridable. It is motivated by `FR-AR-6` (the same binary must
> scale from a 4-core Raspberry Pi 5 to a many-core server without hand-tuning) and by the observation
> that `buffer_pool_pages` shipped as a fixed 4096-page (32 MiB) default regardless of host RAM,
> whereas `reader_threads` / `morsel_parallelism` already auto-sized from the CPU count. This decision
> unifies both under one detection path and one precedence rule. The full design is
> `04-technical-design.md` §9.5.
>
> **Status: ratified.**
>
> | Facet | Ratified choice |
> | --- | --- |
> | Precedence & sentinel | **The `0 = auto` sentinel plus a strict three-level precedence — operator configuration (TOML file or `GRAPHUS_*` env var) > hardware-derived value > built-in floor — is adopted as the project-wide auto-tuning convention.** A value the operator sets explicitly always wins; a parameter left at its `0` sentinel is hardware-derived; a built-in floor guarantees a safe minimum when a probe fails. This generalizes the already-shipped `reader_threads` / `morsel_parallelism` behavior (`04` §9.3) to the memory dimension. |
> | Buffer-pool sizing | **Auto `buffer_pool_pages = clamp( floor(0.125 × available_RAM_bytes ÷ 8192), 4096, 262144 )` — a conservative 1/8 of *available* RAM (falling back to total RAM, then to the floor), floored at 4096 pages (32 MiB) and capped at 262144 pages (2 GiB).** The 1/8 fraction is deliberately conservative **because the buffer pool is per-database** (each opened database gets its own pool) and RAM is shared with the WAL, indexes, result buffers, and the OS; the floor equals today's fixed default, so auto is never worse than the status quo, and the ceiling bounds worst-case resident-set growth. |
> | Probe isolation | **All OS-specific and `unsafe` hardware probing is isolated in a new, independently-audited `graphus-sysres` leaf crate** (`04` §1.2), so `graphus-server` stays `#![forbid(unsafe_code)]`. Every probe is best-effort with graceful degradation (a failed probe yields `None` and the floor is used); detection never panics or blocks server start. |
>
> **Scope note.** In this first cut, the detected storage capacity/free space and the rotational/SSD
> hint are **detected and reported in the startup log only**; they may inform future tuning but drive
> no automatic parameter change yet (`04` §9.5). The resolved values and their provenance
> (operator-overridden, hardware-derived, or floor) are recorded in a single structured startup log
> line.

## Ratified decision (2026-07-23) — `D-async-commit`

> **`D-async-commit` — Deferred (asynchronous) WAL flush. DECLINED.** A time- or count-triggered WAL
> flush — the equivalent of Memgraph's `--storage-wal-file-flush-every-n-tx` (default `100000`) or
> PostgreSQL's `synchronous_commit = off` — was evaluated on 2026-07-23 as an alternative route to the
> ingest throughput that the `SuspendPersistence` campaign (`rmp` #829–#854) targets. **The owner
> declined it: ack-after-fsync remains unconditional, and ingest acceleration goes through
> `SuspendPersistence`.**
>
> **Status: ratified (as a declination).**
>
> This is recorded because the option is cheap to re-propose and the evidence behind the refusal is
> not self-evident — on the throughput axis the alternative measured as a genuine contender, not as an
> inferior one.
>
> | Measured quantity | Value |
> | --- | --- |
> | `fdatasync` cost on the evaluation host | **2.90 ms fixed + ~0.35 ms per MiB** accumulated (a 344 sync/s device ceiling) |
> | Durability share, statement-at-a-time | **~84%** of a 3.45 ms statement (the measured 280–290 ops/s write ceiling) |
> | Durability share, `UNWIND`-batched ingest | **~14%** (`social-network-uds`, after subtracting its measured 18 ms client overhead from the 39 ms p50) |
> | Predicted gain, **either** design | **~6×** statement-at-a-time; **~1.16×** batched |
>
> **Why the two designs share a ceiling.** Both remove exactly the same thing from the critical path —
> the commit `fdatasync` — and both leave the same residual (~0.55 ms/statement: parse and plan, wire
> framing, constraint checking, per-row secondary-index maintenance, SSI bookkeeping, encoding),
> because the ratified `SuspendPersistence` scope waives **durability only** and keeps A, C and I fully
> enforced. A deferred flush would additionally have cost no extra RAM (the WAL still reaches disk,
> avoiding the in-memory undo retention that suspension forces — `rmp` #313 measured an unread
> in-memory WAL at 72% of peak RSS), required no resynchronization on resume, stayed revocable at any
> moment, and not required the graph to fit in RAM. Per PostgreSQL's documented guarantee, the risk it
> carries is "data loss, not data corruption", bounded by a declarable window.
>
> **Why it was declined regardless.** It relaxes durability *unconditionally, for every workload*,
> whereas `SuspendPersistence` confines the waiver to an explicit, operator-opened window. Against the
> four inviolable requirements of `CLAUDE.md`, an always-on relaxation of D is a different class of
> change from a bounded, opt-in suspension — and that distinction, not throughput, decided it.
>
> **Two consequences to hold, both measured.** First, `SuspendPersistence` must **not** be positioned
> as a read accelerator: read-only transactions already perform zero WAL appends and zero `fdatasync`
> (`rmp` #529), so the ceiling of any read gain is the −2.4% (1 client) to −8.2% (8 clients) that
> concurrent writers were measured to cost readers in `examples/product-recommendations`, and the
> retained in-memory undo chain pushes the other way. Second, the batched-ingest gain of ~1.16× is why
> the campaign's value rests on sprint 81 (per-row cost and prepare-side parallelism) rather than on
> the suspension itself.

## Ratified decision (2026-08-02) — the MVCC-native engine

> **Four decisions, ratified together on 2026-08-02, make MVCC the central and only
> concurrency-control mechanism of Graphus.** They are recorded as one section because they are not
> independent: the version representation determines how a conflict is detected, conflict detection
> without waiting is what makes several writers safe, and a deterministic writer scheduler is what
> makes several writers provable. Each refines an already-ratified decision rather than replacing it:
> `D-concurrency-control` (MVCC + SSI) and `D-isolation-level` (Serializable by default) are
> unchanged, and every one of the four inviolable requirements of `CLAUDE.md` stands as written.
>
> **Status: ratified (all four).**
>
> **Why now — the measured state of the engine.**
>
> The decisions were put to the owner after this sprint's audits established, empirically, that
> Graphus today has **no version chain at all**, and that five separate ad-hoc mechanisms stand in
> for the one the specification always described. Each fact below was read from the code in this
> repository, at the cited line.
>
> | Finding | Evidence |
> | --- | --- |
> | `undo_ptr` is dead. The field is reserved in every node, relationship and property record and is **never written non-zero in production**, so no version chain exists. | `crates/graphus-storage/src/record.rs:74` (`MvccHeader::live` always sets `undo_ptr: 0`); `crates/graphus-storage/src/check.rs:1196-1199`, which states in the consistency checker's own documentation that "the per-value version chain is a documented follow-up, so today `undo_ptr` is always `0`". 8 bytes per record are reserved and unused. |
> | The transaction manager was written against a **placeholder** store because the representation was an open spike. | `crates/graphus-txn/src/store.rs:6-8` and `:27-31`: "the real `graphus_storage` does not yet implement version-chain mechanics" and wiring it up "is a follow-up task, intentionally **out of scope** here". |
> | Property updates are a tombstone plus a chain prepend, and the tombstone pass walks the whole chain. Measured cost is **O(M²)** in the number of properties set on one entity. | The chain walk is `RecordStore::tombstone_props_for_key`, `crates/graphus-storage/src/store.rs:6710-6753`. Measured: **15.1 µs/op at M = 1000** and **97.8 µs/op at M = 8000**. |
> | Labels are a bitmap **mutated in place**, whose version history exists **only in memory** and is therefore not durable and not recoverable. | `crates/graphus-storage/src/label_history.rs:143` (`pub struct LabelHistory`), an in-process structure shared by `Arc` between the engine thread and the reader pool. |
> | Chain heads and the label word are undone by an **ad-hoc compare-and-set**, one bespoke mechanism per field, because a whole-record pre-image undo would revert words a concurrently-committed writer legitimately owns. | `crates/graphus-storage/src/record.rs:114-123`; `crates/graphus-storage/src/store.rs:2507` (`write_chain_head`) and `:2541` (the label word). |
> | Rollback is **physical ARIES undo**: it reverts bytes. This is the origin of the recurring defect family rmp #220 / #172 / #239 / #301 / #578 / #772 — every one of them a case of one transaction's byte-level undo damaging another's committed state. | `RecordStore::rollback`, `crates/graphus-storage/src/store.rs:3644`. |
> | There is **no `command_id`**, so there is no statement-level isolation: a statement cannot be shown the state that preceded it within its own transaction. *(Closed by task **#972**; see `D-statement-isolation`, ratified 2026-08-05.)* | `command_id` had **zero** occurrences across `crates/graphus-txn` and `crates/graphus-storage`. |
>
> **This table is the state of the engine as it was read on 2026-08-02, and it is kept as that
> record rather than maintained.** Every finding in it has since been closed: tasks #966 to #972
> built the undo area and the chain, moved properties, labels and adjacency onto it, made rollback
> logical, retired the lock table and the deadlock detector, and delivered `command_id`. What each
> mechanism was replaced by, and in which task, is tabulated in `04-technical-design.md` §5.1.5,
> which is the authoritative and maintained list.
>
> **The four ratified decisions.**
>
> | Decision | Ratified choice | Grounding |
> | --- | --- | --- |
> | **`D-version-representation`** | **Newest version in place, one unified undo-delta chain per entity** (Memgraph / InnoDB), over append-only newest-first (PostgreSQL). One chain carries every mutation kind. | Memgraph's delta chain: `/data/refsrc/memgraph/src/storage/v2/delta.hpp:244-392` (the `Delta` record) and `delta_action.hpp:17-33` (the ten actions). The append-only contrast is PostgreSQL's heap, where an update writes a **new tuple** and links the old one to it — `/data/refsrc/postgres/src/include/access/htup_details.h:86-98` (`t_ctid` points at the replacement version) and `src/backend/access/heap/heapam.c:3808`. InnoDB's rollback segments are cited from official documentation only; **there is no InnoDB source tree in `/data/refsrc`**, so nothing about InnoDB here was read from code. |
> | **`D-write-conflict-detection`** | **Detected on the MVCC header, abort immediately, never wait.** The lock table and the wait-for-graph deadlock detector are retired. | Memgraph `PrepareForWrite`: `/data/refsrc/memgraph/src/storage/v2/mvcc.hpp:112-137`. It reads the head delta's timestamp and returns `false` — a serialization error — rather than blocking. Its call sites are the whole write surface: `vertex_accessor.cpp:191,203,265,277,425,511,580,639` and `edge_accessor.cpp:194,261,315,360`. What is retired in Graphus is `crates/graphus-txn/src/lock.rs` (`LockTable`, `find_deadlock_victim`) and its driver `crates/graphus-txn/src/manager.rs:472-552`. |
> | **`D-multi-writer`** | **N transactions write the same database in parallel.** | Enabled by the two decisions above: with no lock waits and no deadlock detector, the only interaction between two writers is a header check that either succeeds or aborts. Supersedes the single-writer facet of `D-read-parallelism`; the read-side half of that deferral was already discharged by the off-thread reader pool (rmp #336). |
> | **`D-dst-writer-scheduler`** | **A deterministic writer scheduler in DST, as a prerequisite of multi-writer certification.** | `07-dst-simulator.md` §5 already dispatches overlapping transactions from one seeded `SimScheduler`; §5.1 names the fidelity ceiling that true-parallel writer races are structurally invisible to it. Multi-writer moves a class of defect from "owned by other suites" into the centre of the engine, so the scheduler must cover it. *(The scheduler was built by task **#973**; the concurrent writers it is to order arrive with **#975**. See the "Post-ratification note (2026-08-05) — `D-dst-writer-scheduler`" below.)* |
>
> **What this replaces, and where it is specified.**
>
> The five present-day mechanisms, their single replacement, and the task in which each one
> disappears are tabulated in **`04-technical-design.md` §5.1**, which is the authoritative list. The
> delta structure, its lifecycle, its ownership by the transaction, and the commit indirection point
> are specified in the same section; the interaction with the record store and the indexes is
> `04-technical-design.md` §5.6; latching and conflict detection are §5.7; the on-disk undo-area
> format and the meaning of `undo_ptr` are `05-storage-format.md` §12.
>
> **Scope note — what these decisions do not touch.**
>
> They do not reopen `D-durability-mode` or `D-async-commit`: commit still acknowledges only after
> `fdatasync`. They do not close `04-technical-design.md` §12 item 3 (torn-write protection): the
> **doublewrite buffer stays**, with group staging (rmp #993/#994), and §4.5 is unchanged. They do not
> alter the SSI algebra of §5.4 or the read polarities of §5.3. They resolve exactly one open spike,
> `04-technical-design.md` §12 item 2.

## Ratified decision (2026-08-03) — the property path on the undo chain

> **Four decisions, ratified together on 2026-08-03, settle how properties move onto the undo chain
> in task #967.** They refine the 2026-08-02 round rather than replacing any part of it:
> `D-version-representation`, `D-write-conflict-detection`, `D-multi-writer` and
> `D-dst-writer-scheduler` are unchanged, and every one of the four inviolable requirements of
> `CLAUDE.md` stands as written. No byte of the frozen undo-area format
> (`05-storage-format.md` §12) changes.
>
> **Status: ratified (all four).**
>
> **Why now.** Task #966 built the undo area and brought `undo_ptr` to life. Task #967 is the first
> task to put a *value* on the chain, and a design pass over the code established that three
> questions had to be answered before the property path could be written down without ambiguity:
> when the conflict check arrives and at what granularity; what a property removal physically is;
> and which stamp decides what a reader may see. The fourth decision generalizes a testing
> obligation the same pass surfaced.
>
> | Decision | Ratified choice | Grounding |
> | --- | --- | --- |
> | **`D-property-write-conflict`** | **The conflict check arrives with #967, at entity granularity.** Before a property write links any delta, the writer reads the head of the entity's undo chain and aborts with a retriable serialization failure if that head belongs to another transaction that is still open. | Memgraph's `PrepareForWrite` (Source, read 2026-08-03: `/data/refsrc/memgraph/src/storage/v2/mvcc.hpp:112-137`), which every mutating accessor calls first — the property path at `vertex_accessor.cpp:425`, immediately before the delta link at `:450` and the in-place mutation at `:451`. In Graphus the Cypher seam **already imposes exactly this rule**, keyed on the node id: `RecordGraph::set_node_property` calls `note_write(node_ssi_key(node.0))` (`crates/graphus-cypher/src/record_graph.rs:5893`), and `note_write` (`:506`) surfaces a "write-write conflict … retry (serialization failure)" on a conflicting holder. So the coordinated path's behaviour does not change; what becomes newly constrained is the direct `RecordStore` callers. |
> | **`D-property-removal`** | **An empty cell in place (`type_tag = 0, value_inline = 0`), not an `xmax` tombstone.** The cell keeps its `in_use` bit and its place in the `first_prop` chain; the old value descends onto the chain in a `SetProperty` delta. | Memgraph represents removal as a `SetProperty` whose **new** value is an empty `PropertyValue`: `PropertyStore::SetProperty` (`/data/refsrc/memgraph/src/storage/v2/property_store.cpp:2829`) erases the property when `value.IsNull()` (`:2831`, `:2841`), while the delta written at `vertex_accessor.cpp:450` carries the **old** value. There is no separate removal action and no tombstone. |
> | **`D-property-visibility`** | **The undo chain is the sole visibility oracle for a property's value.** The cell's `created_ts` becomes informative; the cell's MVCC header keeps only its structural meaning (`in_use` for slot occupancy and corpse threading). | The frozen 56-byte delta (`05-storage-format.md` §12.2) has **no field for the old `created_ts`** — its `SetProperty` payload is `token`, `type_tag` and `value_inline` and nothing else. A logical undo therefore cannot restore that stamp, so it must not be load-bearing. Under this decision none needs to be. |
> | **`D-retired-mechanism-tests`** | **"All existing tests stay green" is read as "every semantic those tests protected remains asserted by a test that fails if the semantic breaks".** Each retired mechanism test is replaced by a named semantic-equivalent that is at least as strong, listed in the task's closure summary. | The project's own record of the defect class in which a test passes — or simply never runs — while the feature is broken: `VERIFICATION.md` gate 11 documents how `rmp` #960 stayed hidden because the only suite that would have caught it was never enabled, so "every gate that *does* run stayed green, start to finish". Deleting a mechanism's tests along with the mechanism reproduces that outcome by a different route. |
>
> **The consequences that are normative.**
>
> - **Exactly one owner names any `strings.store` overflow chain.** The live cell owns the current
>   value; a delta owns each historical value; the two sets are disjoint. This is what makes the
>   empty-cell representation safe to reclaim.
> - **A later `SET` of the same key reuses the empty cell**, with no allocation.
> - **`expired_ts` is never again written by a property operation**, and
>   `RecordStore::tombstone_props_for_key`
>   (`crates/graphus-storage/src/store.rs:6710-6753`) is retired.
> - **Task #970 is a rollback change only.** Because the chain is already the oracle, logical
>   rollback does not require a second rewrite of the read path.
>
> **Where this is specified.** The conflict check is `04-technical-design.md` §5.1.2 step 1 and
> §5.7; the empty-cell representation and the retirement of the tombstone pass are §5.1.5 row 1; the
> visibility oracle is §5.6; the testing rule is §11.6. The `type_tag == 0` clarification to the
> frozen delta table is `05-storage-format.md` §12.2 — prose filling a gap, not an amendment.

## Ratified decision (2026-08-05) — logical rollback

> **Three decisions, ratified together on 2026-08-05, settle how a transaction is undone once every
> mutation kind is a delta on the undo chain (task #970).** They refine the 2026-08-02 and 2026-08-03
> rounds rather than replacing any part of them: `D-version-representation`,
> `D-write-conflict-detection`, `D-multi-writer`, `D-dst-writer-scheduler`, `D-incidence-anchor` and
> the four property-path decisions are unchanged, and every one of the four inviolable requirements of
> `CLAUDE.md` stands as written. No byte of the frozen undo-area format (`05-storage-format.md` §12)
> changes.
>
> **Status: ratified (all three).**
>
> **Why now.** Tasks #966 to #969 put every mutation kind on the chain, and #971 made the entity's own
> MVCC header the engine's only conflict mechanism. Rollback was the last mechanism still working from
> bytes, and three questions had to be answered before it could be written down without ambiguity:
> which transactions the logical undo covers and what happens to the rest; what becomes of the page
> writes whose inverse is not a byte image; and when the slots an abort strands may be handed out
> again.
>
> | Decision | Ratified choice | Grounding |
> | --- | --- | --- |
> | **`D-rollback-dispatch`** | **Logical undo for a transaction that owns a commit-info slot; the ARIES physical path for one that does not.** The two kinds that own no slot are a maintenance pass and a catalog-only writer. | Memgraph's abort is the same walk over the transaction's own deltas (`/data/refsrc/memgraph/src/storage/v2/inmemory/storage.cpp:1489-1560`). The dispatch is `RecordStore::rollback` (`crates/graphus-storage/src/store.rs:5941`), over `rollback_logical` (`:5840`) and `rollback_physical` (`:6062`). |
> | **`D-chain-head-redo-only`** | **Chain-head publications and the relink of the displaced head log a redo image and an empty undo image.** The compare-and-set undo survives only where a whole-word write's inverse is the word itself. | `WalManager::log_update_redo_only` (`crates/graphus-wal/src/manager.rs:378`) and `RecordStore::write_field_redo_only` (`crates/graphus-storage/src/store.rs:3132`). The unsoundness of the compare-and-set undo was **reproduced**, not argued: the DST simulator (VOPR seed 12) drops a committed edge out of its node's incidence chain after recovery, because the restored id names a slot that had since been freed and re-used. |
> | **`D-orphan-slot-parking`** | **A slot orphaned by a logical rollback is parked until the next GC pass.** | The latest-state TEXT / FULLTEXT / SPATIAL indexes are in-memory, non-transactional and keyed by physical node id (`rmp` #467 / #756). The failure the parking prevents is reproduced by `crates/graphus-cypher/tests/text_index.rs::rmp756_constraint_rejected_insert_keeps_the_text_seek_selective`, where two constraint-rejected `CREATE`s in a row recycled one id. |
>
> **The consequences that are normative.**
>
> - **The cost of an abort is bounded by the transaction's own writes, not by the size of the store.**
>   `reload_catalog` leaves the abort path, and with it every snapshot that existed only to put back
>   what the reload had discarded: the free lists (`rmp` #578), the live-record counters (#866), the
>   physical-id and `ElementId` high-water marks (#220/#172), the token dictionary and the
>   schema-catalog superset (#534/#734). Measured over a fixed set of writes
>   (`crates/graphus-storage/tests/rollback_cost_970.rs`): **66 µs → 21 µs** on a 500-node store and
>   **1 087 µs → 25 µs** on a 16 000-node store with 4 000 interned property keys. The contract the
>   test pins is structural rather than a clock — a data transaction's rollback performs no catalog
>   reload at all.
> - **Every property write goes through the versioned path.** The raw-tag entry points
>   (`add_node_property` / `add_rel_property`) used to write an unversioned cell with no conflict check
>   and no delta. Under logical rollback that is not a shortcut but a hole: a write with no delta is a
>   write no abort can undo. They now reach the same four steps as every other property write, and the
>   raw cell primitives are private.
> - **A failed rollback still leaves its transaction OPEN.** The contract of `04-technical-design.md`
>   §4.4 is unchanged and holds on both paths: the active-set entry is released only after every
>   fallible step has succeeded, so every gate that asks "is a writer holding uncommitted state?" keeps
>   failing closed.
>
> **Where this is specified.** The dispatch and what WAL undo still decides are
> `04-technical-design.md` §4.3; the `ABORT` record and the redo-only page-update record are §4.4;
> the delta-application order, the detach and the measured cost are §5.1.2 step 5 and §5.1.5 row 4;
> the parked slots are §5.1.5. The format-side consequences are `05-storage-format.md` §7 (the
> chain-head write carries no undo image) and §12.5 (how a live abort and a crashed loser differ).

## Ratified decision (2026-08-05) — statement-level isolation

> **`D-statement-isolation` settles how a statement is isolated from its own writes, in task #972.**
> It refines the 2026-08-02, 2026-08-03 and 2026-08-04 rounds, and the logical-rollback round of the
> same day, rather than replacing any part of them:
> `D-version-representation`, `D-write-conflict-detection`, `D-multi-writer`,
> `D-dst-writer-scheduler`, `D-incidence-anchor`, the four property-path decisions and the three
> logical-rollback decisions are unchanged, and every one of the four inviolable requirements of
> `CLAUDE.md` stands as written. **No byte of the frozen undo-area format
> (`05-storage-format.md` §12) changes**: the delta's `command_id` field kept its offset and its
> width and stopped being always zero.
>
> **Status: ratified.**
>
> **Why now.** Tasks #966 to #971 put every mutation kind on the undo chain and made the entity's own
> MVCC header the engine's only conflict mechanism. `command_id` was the last field of the frozen
> delta that no write path filled in, and the guarantee it exists for — that a statement does not
> observe the rows it is itself creating — was carried entirely by the planner's eagerness barriers.
> Five questions had to be answered before the mechanism could be written down without ambiguity:
> what the rule is, including at both ends of its range; where the counter lives and who may stamp a
> delta with it; where it advances; which clause reads under which view; and what becomes of the
> eagerness barriers the new mechanism partly duplicates.
>
> | Facet | Ratified choice |
> | --- | --- |
> | The rule | **A read carries a view — `New` (the default) or `Old` — beside its snapshot, and the view decides nothing about other transactions.** It decides only whether one of the reader's **own** uncommitted deltas is undone: under `New` when the delta's command is **later** than the reader's, under `Old` when it is later **or the same**. The two views differ by one comparison operator and nothing else. |
> | The `NONE` carve-out | **A delta written outside any statement carries `command_id = 0` and is undone by no view, at any command.** Recovery, maintenance passes and the catalog write deltas without ever running a statement; such a write belongs to the transaction's **baseline**, not to a statement. Without the carve-out, `0 >= 0` makes a maintenance transaction's own `Old` read erase its own work. A transaction's first statement therefore runs at `1`, so that its `Old` view excludes every delta the transaction could have written. |
> | Where the counter lives | **In the record store, which is its single source of truth**, and it is stamped onto the delta by the store's own delta-linking path. **No caller may supply a `command_id`**, exactly as none may supply a `commit_info`: a caller that could would be able to stamp a delta with a statement that is not running. The counter **saturates** rather than wrapping, because a wrap would make a later statement's writes look older than its first. |
> | Where it advances | **Two points, and only two: when a cursor opens, and at a `WITH` that follows a write.** The `WITH` case is a dedicated operator that **drains its input before advancing**, so that no clause is split across two commands. It does **not** advance at the coordinator's per-statement graph-seam factory, which runs again on every resume of a suspended cursor, nor when a correlated sub-plan opens a seeded cursor. |
> | Polarity per clause | **`Old` for every access path, `New` for everything else.** `Old`: every node and relationship scan, every index seek of every kind, every relationship expansion, a `MATCH`'s `Filter`, `UNWIND`, and a read-only procedure `CALL`. `New`: `MERGE`'s match sub-plan, `CREATE` / `SET` / `REMOVE` / `DELETE` / `FOREACH`, the projection of `RETURN` and `WITH`, aggregation and ordering, and a writing procedure `CALL`. A seek and the scan it replaces read the **same** view, and the view filter is applied **per candidate the index returns**. |
> | The `Eager` barriers | **All retained, deliberately.** `Eager` decouples row production across a clause boundary; the view re-polarises visibility across it. Retiring the barriers in the task that introduced the views would let the two mechanisms mask each other, so their reform is separate work. |
>
> **The alternatives weighed.**
>
> - **Planner-only eagerness, as the sole mechanism.** This is Neo4j's answer to the same family:
>   `EagerWhereNeededRewriter` "insert[s] Eager only where it's needed to maintain correct semantics"
>   (Source, read 2026-08-05:
>   `/data/refsrc/neo4j/community/cypher/cypher-planner/src/main/scala/org/neo4j/cypher/internal/compiler/planner/logical/plans/rewriter/eager/EagerWhereNeededRewriter.scala:64`),
>   driven by a read/write conflict analysis (`ConflictFinder`, `WriteFinder`,
>   `ReadsAndWritesFinder` in the same package). Rejected **as the sole mechanism** on two grounds.
>   Correctness would rest on that analysis being complete, so a conflict it does not model is a
>   wrong answer with nothing beneath it to catch the miss; and a barrier costs full materialisation
>   of its input where a view costs one comparison. Not rejected **as a mechanism**: the barriers
>   stay, as the facet table records.
> - **Statement-scoped visibility on the version chain.** Chosen. Memgraph carries exactly this, as a
>   two-valued `View` beside the snapshot (Source, read 2026-08-05:
>   `/data/refsrc/memgraph/src/storage/v2/view.hpp`) that its chain walk resolves against the delta's
>   `command_id` — `View::NEW` stops on `cid <= transaction->command_id`, `View::OLD` on
>   `cid < transaction->command_id` (`src/storage/v2/mvcc.hpp:72-94`) — and it plants the `OLD`
>   polarity as the **default** on `ScanAll` and every `ScanAllBy*` variant
>   (`src/query/plan/operator.hpp:565` and twelve sibling declarations), re-verifying each index
>   candidate under that view rather than trusting the entry
>   (`src/storage/v2/inmemory/label_property_index.cpp:444`). PostgreSQL is the same rule against a
>   different representation: a tuple its own transaction inserted is invisible when
>   `HeapTupleHeaderGetCmin(tuple) >= snapshot->curcid`
>   (`/data/refsrc/postgres/src/backend/access/heap/heapam_visibility.c:965`), with `curcid` captured
>   at `GetSnapshotData` (`src/backend/storage/ipc/procarray.c:2455`) and advanced by
>   `CommandCounterIncrement` (`src/backend/access/transam/xact.c:1129-1171`). Graphus follows
>   Memgraph's placement, because Graphus's delta chain **is** Memgraph's representation, and the
>   field was already reserved for it by `05-storage-format.md` §12.2.
> - **Advancing the counter on every statement-seam call.** Rejected: that seam runs again on **every
>   resume** of a suspended cursor, so a long-running `CREATE` would advance the counter mid-flight
>   and hide from itself the rows it had already applied in earlier batches. The advance therefore
>   sits at cursor open, which is the one seam the server, the TCK harness, the CLI and the tests all
>   funnel through.
> - **Wrapping the counter at `u32::MAX`.** Rejected: a wrap makes a later statement's own writes look
>   older than its first, which is a visibility error and not an overflow. Graphus saturates;
>   PostgreSQL declines the same wrap by raising an error at the same ceiling
>   (`CommandCounterIncrement`, "cannot have more than 2^32-2 commands in a transaction").
>
> **The consequences that are normative.**
>
> - **The label creator gate is narrowed to the creating statement.** A node the writing transaction
>   created is not label-versioned, because no reader can ask what its labels were before. That
>   justification now holds only **within the creating statement**: a node created by statement 1 and
>   labelled by statement 2 is visible to statement 2's `Old` view. The gate is therefore "created by
>   this **statement**", and the bulk-create fast path (`CREATE (:L)`) is unaffected.
> - **A statement-granular read that faults fails closed.** An entity whose existence or whose value
>   cannot be resolved from the chain fails the read; it is never answered with the record header's
>   own verdict, which is the answer the chain was consulted to correct.
> - **`graphus_txn::is_visible` remains the cross-transaction answer and is complete as such.** The
>   record header names the transaction that created or expired a version and never the statement, so
>   the statement-granular answer lives one layer down, on the chain.
>
> **Where this is specified.** The rule, the carve-out, the counter's home, the two advance points,
> the per-clause polarity table and the coexistence with `Eager` are `04-technical-design.md` §5.1.4;
> the split between the cross-transaction predicate and the chain-resolved refinement is §5.3; the
> narrowed label creator gate is §5.1.5 "row 2, second consequence". The format-side clarification —
> what `command_id == 0` means and who writes the field, with no byte of the frozen layout changing —
> is `05-storage-format.md` §12.2.

## Post-ratification note (2026-08-05) — `D-dst-writer-scheduler`

> **This note records how the already-ratified `D-dst-writer-scheduler` was implemented by task #973,
> and how far it is discharged. It creates no new decision and changes no ratified outcome.** The
> ratified requirement stands exactly as written: multi-writer correctness may not be
> signed off on non-deterministic evidence alone, and the simulator must dispatch several concurrent
> writers against one database from a seeded schedule. The decision index therefore still holds 45
> decisions.
>
> **How far it is discharged.** Task #973 built the **mechanism**: a deterministic thread scheduler
> that hands a single execution token between real OS threads at declared yield points and draws the
> successor from a seeded RNG, so the global order of operations is a pure function of the seed. What
> it does **not** yet do is dispatch **several concurrent writers**, because a database still has one
> writer thread; task **#975** creates them. The four write-path yield points are installed and
> deliberately marked, in the code and in `07-dst-simulator.md` §5.2.5, as **not yet exercised**.
>
> What *is* proven is seed reproducibility over the threads that share a store today — the engine
> thread (writer and garbage collection) and an off-thread reader. The demonstrated case is `rmp`
> #811: a reader mid-property-chain-walk while GC rewrites the record it is about to read. That
> window is now entered **by construction** rather than by luck, and the suite proves it was entered
> rather than assuming it. **No claim of certified N-way parallel writing is made or implied.**
>
> **Three implementation choices are recorded here because they constrain future work.**
>
> | Choice | Why | Consequence to hold |
> | --- | --- | --- |
> | **A cargo feature (`det-sched`), not `debug_assertions`** | `graphus_core::latch` gates its tripwire on `debug_assertions` because a *correctness* tripwire costing a thread-local increment should be armed across the whole suite. A scheduler hook is *hot-path instrumentation* sitting on `with_page_fetched`, the hottest read in the engine; under `debug_assertions` it would be live in every `cargo test --workspace` and would instrument the very paths the certification gates exist to certify. | The feature is enabled by **no dependency declaration anywhere in the workspace**, because Cargo unifies features per resolve. Only `graphus-dst`'s passthrough turns it on, and only for targets declaring `required-features`. A future crate that adds `graphus-core/det-sched` to a dependency line silently arms the hook workspace-wide. |
> | **A purpose-built scheduler, not `shuttle` or `loom`** | The defect class is an interleaving race at the granularity of the **buffer-pool page latch**, not of the memory model. `loom` explores the memory model exhaustively and would deliver far more than that at prohibitive cost — and it takes ownership of the interleaving, so it cannot coexist. The existing cooperative interleaver delivers less, because its operations are atomic. A cooperative token at latch granularity is the missing rung between them. | The combinations with `loom` and with ThreadSanitizer are refused at **compile time**. The scheduler proves **interleaving** defects; the loom family and the real-OS-thread soak lane keep the **memory model**, and nothing about that ownership changed. |
> | **One invariant on the token: it is only handed over where no page latch and no page-table shard lock is held** | A thread parked holding either lock freezes the simulation rather than slowing it, since only one thread runs at a time. Frame latches are enforced against the existing `rmp` #974/#993 latch-depth tripwire rather than a new mechanism. The shard lock could not be enforced the same way, because `fetch` publishes under it *while holding a frame latch* and `select_victim` sweeps under it, so a `NoSwitchScope` suppresses the hand-off there instead. | Inside a no-hand-off region a yield point is still **recorded** — the site is provably reached — but the token stays put and no draw is consumed. Every such region narrows what a seed can explore, which is why the contended victim sweep remains on the section 5.1 table of `07-dst-simulator.md`. |
>
> **Where this is specified.** The mechanism, the determinism rules, the token invariant, the failure
> backstops, the history format, the installed yield points and the gating are `07-dst-simulator.md`
> §5.2. What the scheduler moved inside the fidelity ceiling and what remains outside it — including
> why the memory model stays outside by construction — is §5.1 of the same document. The verification
> gate is `VERIFICATION.md` gate 13.
>
> **Owner's call, if wanted.** These three choices are recorded as implementation notes under the
> ratified decision, not as decisions of their own. Should the owner prefer any of them to carry a
> decision key and a ratification date in the canonical index, that is a ratification only the owner
> can make.

## Ratified decision (2026-08-09) — chain-head publication

> **`D-chain-head-publication` settles how a chain head is made safe to publish when more than one
> writer may prepend to it, in task #1028.** It refines the earlier rounds rather than replacing any
> part of them: `D-version-representation`, `D-write-conflict-detection`, `D-multi-writer`,
> `D-dst-writer-scheduler`, `D-incidence-anchor`, the four property-path decisions, the three
> logical-rollback decisions and `D-statement-isolation` are unchanged. In particular
> **`D-chain-head-redo-only` is untouched**: the publication still carries an empty undo image. Every
> one of the four inviolable requirements of `CLAUDE.md` stands as written, and **no byte of any
> on-disk format changes** — not the record layouts, not the WAL record set, not the patch codec, not
> the format version.
>
> **Status: ratified.**
>
> **Why now.** `D-multi-writer` ratified N parallel writers, and the layers that deliver them are
> under way. Designing the acceptance criterion for one of those layers surfaced the engine's
> number-one correctness risk: the chain head was published with a plain byte write, so
> read-the-head / write-the-head was not atomic. With one writer thread that is latent; with two it
> silently loses a prepend — a committed relationship out of its node's incidence chain, a committed
> property version out of its owner's chain, a committed delta out of the undo chain that decides
> visibility. It is the `rmp` #220 defect class returning as a live hazard, and it had to be closed
> **before** the writers arrive, not after.
>
> **The alternatives weighed.**
>
> | Option | Verdict |
> | --- | --- |
> | **A — a compare-and-set on the head word alone, with no latch.** This is what the parent task asked for, and the only place in the epic where atomics rather than a latch were to be used. | **Rejected.** It cannot be reconciled with the project's own latch order. A compare-and-set needs read-compare-write under one frame latch (rank 40), while the redo record must be appended under the WAL mutex (rank 30) — and the WAL barrier already refuses, by tripwire, to run with a frame latch held. Emitting the record first and then declining the write leaves an **orphan** redo record in the log. Independently: a prepend publishes more than the head word, so a compare-and-set on that one word protects one of several words that must move together. |
> | **B — option A plus a conditional redo image, tolerating the orphan as inert.** The argument was that a compare-and-set refused at run time would be refused again at replay, so the orphan would apply nothing. | **Rejected — the premise is false as soon as a second writer exists.** Recovery replays in **LSN order**; the live system applies in **frame-latch order**; nothing couples the two. Concretely, on a head holding `H0`: writer A logs `CAS(H0→A)` at LSN 10 and releases the WAL mutex; writer B logs `CAS(H0→B)` at LSN 12, takes the frame latch, finds `H0`, succeeds, and commits durably; A then takes the frame latch, finds `B`, and declines. A crash before A retries leaves recovery to apply LSN 10 (the word is `H0`, so it **applies**) and then LSN 12 (the word is now `A`, so it no-ops). The recovered head is `A` — a loser's entry — and chain-head writes have no undo, so nothing removes it: B's committed relationship has silently left the chain. The conditional redo did not make the orphan inert, it made it **harmful**, by resurrecting a transition that never happened. A monotonic `page_lsn` does not repair this: if the page never reached disk, recovery starts from a lower `page_lsn` and replays in LSN order regardless. |
> | **C — a short publication latch that makes "peek, log, apply" one indivisible step, keeping the conditional redo for its replay properties. ★ chosen** | **Ratified.** The latch supplies the ordering invariant the conditional redo needs but cannot create: log order equals the order in which publications take effect on the page. Under it a refused publication is decided **before** anything is logged, so no orphan is ever written; and because the latch's scope is the whole publication rather than the single word, it also covers the two writes beside the head word that a prepend performs. |
>
> **The three reference implementations, read at a pinned revision.** They agree, and none of them
> uses a conditional redo record: each pays for the "log order equals apply order" invariant with a
> latch held across the LSN assignment.
>
> | Reference | What was read, and what it shows |
> | --- | --- |
> | **InnoDB** (`/data/refsrc/mysql-server`, tag `mysql-8.0.36`) | The redo record set (`mlog_id_t`, `storage/innobase/include/mtr0types.h`) contains **no conditional record type at all**: every InnoDB redo record applies unconditionally, gated only by the page LSN. The list-prepend primitive is the direct analogue of a chain-head prepend, and it demands the strongest form of the invariant: `flst_add_first` (`storage/innobase/fut/fut0lst.cc:132`) asserts that **both** the base page and the node page are X- or SX-fixed **in the same mini-transaction** (`mtr_memo_contains_page_flagged`, `:141-144`). |
> | **PostgreSQL** (`/data/refsrc/postgres`) | Modifies the page **first** and only then assigns the LSN, with both steps inside one critical section under the buffer's exclusive content lock: `heap_insert` runs `START_CRIT_SECTION()` (`src/backend/access/heap/heapam.c:2066`), `RelationPutHeapTuple` (`:2068`, which `src/backend/access/heap/hio.c:32` documents as requiring `BUFFER_LOCK_EXCLUSIVE`), then `XLogInsert` (`:2178`) and `PageSetLSN` (`:2180`) before `END_CRIT_SECTION()` (`:2186`). The consequence that matters for Graphus: **"WAL-ahead" is not "log the record before touching the page"; it is "the record is durable before the page goes home"** — which Graphus already enforces, fail-closed. Logging strictly before the page touch is therefore a local convention of one Graphus write helper, not a durability requirement, and the latch may legitimately span both. |
> | **Memgraph** (`/data/refsrc/memgraph`, commit `087bbf2`) | Gives **every vertex its own `utils::RWSpinLock`** (`src/storage/v2/vertex.hpp:47`), and `CreateEdge` takes both endpoint locks ordered by `gid` to avoid lock cycles (`src/storage/v2/inmemory/storage.cpp:130-141`, comment: "Obtain the locks by `gid` order"). Crucially it calls `PrepareForNonSequentialWrite` (`src/storage/v2/mvcc.hpp:150`) and **not** `PrepareForWrite`, deliberately, so that two open transactions may both add an edge to the same vertex without a serialization error. That is the precedent Graphus adopts: this is a **publication** latch, not write-conflict serialization. |
>
> **This latch is not the contention the sprint set out to remove.** What `D-write-conflict-detection`
> retired, and task #971 deleted, is the global lock table and the wait-for-graph deadlock detector.
> A publication latch is a physical latch in the sense of §5.7 — short, held for a memory operation
> rather than a transaction, never waited on by a transaction. Memgraph, the closest reference by
> architecture, reached the same conclusion independently: it chose the non-sequential write path
> precisely so that concurrent edge creation on one vertex is **not** a serialization conflict, while
> still guarding each vertex with its own spin lock.
>
> **The consequences that are normative.**
>
> - **Step 4 of a prepend — fixing the displaced predecessor's back-pointer — happens only after a
>   winning publication.** A writer that has read the head but not yet published owns nothing;
>   relinking first and then losing the race overwrites a pointer the winner legitimately owns. The
>   publication primitive therefore returns the head it displaced, and that value alone drives step 4.
> - **A refused publication appends no WAL record**, so the log never describes a write that did not
>   happen. This is stronger than what option B proposed, and that difference is the whole reason
>   option B was rejected.
> - **Rank 27 admits one holder per thread and is never held across I/O.** A relationship therefore
>   publishes its two endpoint heads strictly one after the other. Both obligations are checked
>   mechanically in debug builds rather than left to review.
> - **A compare-and-set is only as sound as its weakest writer**, because a single unconditional store
>   makes every other writer's comparison meaningless. Every **prepend** now passes through the one
>   primitive, and the garbage collector's corpse splice was converted to it for exactly this reason.
>   The exact scope is stated in `04-technical-design.md` §5.7.1: the *unlink*
>   paths, which remove an entry from a chain, still install a head with an unconditional whole-record
>   write. On the GC paths that is safe because a GC pass holds the store exclusively; on the logical
>   rollback of an incidence delta it is **outstanding work** that task #1028 did not deliver.
> - **An operation writes only the fields it changes.** Rewriting a whole record from a snapshot taken
>   before the write reverts whatever a concurrent writer changed in between — the #772 clobber class,
>   arriving without any new mechanism.
> - **The protocol lives in a dependency-free leaf crate so that `loom` can check it.** `--cfg loom` is
>   a global rustflag, so a protocol inside a crate that reaches `graphus-bufpool` cannot be modelled
>   at all. This is a placement constraint on model-checkable protocols, and it now has three
>   instances (`graphus-pagemap`, `graphus-groupsync`, `graphus-chainhead`).
>
> **How it is proved.** A `loom` model runs the production protocol over a modelled cell and requires
> that no prepended entry is ever lost, that a pre-existing tail is never orphaned, and that a refusal
> leaves neither a fork nor a cycle — paired with a model over a plain load-then-store cell that is
> **required to lose an entry**, so the pair also proves the atomicity is load-bearing. A DST scenario
> crashes and recovers across a scripted contended publication and requires that every committed
> prepend replays and that the refused one left no trace.
>
> **Where this is specified.** The protocol, the latch, the two ordering obligations, the writes
> beside the head word and the proof obligations are `04-technical-design.md` §5.7.1; the latch ranks
> are §3.3; the conditional redo image is §4.4; the delta-linking step that consumes the protocol is
> §5.1.2 step 3; the leaf-crate rule is §11.4. Format-side consequences — none of them a byte change —
> are `05-storage-format.md` §7, §9 and §12.5. The DST scenario and the `dst`-gated publication seam
> are `07-dst-simulator.md` §6.2 and §10.

## Ratified decision (2026-08-11) — the WAL fsync group leader

> **`D-wal-group-leader` settles how the WAL is hardened once a database engine runs more than one
> worker, in task #1040.** It refines the earlier rounds rather than replacing any part of them:
> `D-durability-mode` keeps group commit + `fdatasync` with a per-transaction synchronous mode
> available, and **`D-async-commit` is untouched** — ack-after-fsync remains unconditional, and
> nothing here defers or batches a sync in time. Every one of the four inviolable requirements of
> `CLAUDE.md` stands as written, and **no byte of any on-disk format changes** — not the WAL record
> set, not the log layout, not the format version, not a recovery step.
>
> **Status: ratified.**
>
> **Why now.** The pipelined group commit of task **#532** offloads each commit batch's `fdatasync` to
> a dedicated thread so that the durability sync of batch *K* overlaps the CPU preparation of batch
> *K+1*. Its documented invariant was **strict depth-1**: the job channel has depth one and the engine
> always waits for the outstanding job before submitting the next, so at most one batch is ever
> written-but-un-synced, and a crash tail is the tail of **one** batch. That invariant became false
> the moment the engine grew to `W` workers: each worker spawned its own fsync thread over the **one**
> `WalManager` shared behind `SharedWal`, so each was depth-1 for itself while the system reached
> depth `W`, and a crash tail could contain interleaved batches from several workers.
>
> **What was actually holding, and why that was the danger.** The ack-after-fsync rule was nevertheless
> not violated by the code as it stood — but only because of three properties of the sink that no
> contract declared:
>
> | Property | What it says | Why the coalescing needs it |
> | --- | --- | --- |
> | **1 — a job hardens whole files, not byte ranges** | The deferred job runs `full_sync_data` per file handle, so any job that runs hardens every byte written to those files before it was issued. | This is what makes out-of-order completion between workers safe: a later job's sync covers an earlier job's bytes. |
> | **2 — every `begin_harden` starts at the global durable frontier** | Writes are serialised by the single WAL mutex, and a job's range always begins at the sink's one `durable_len`, never at a per-worker frontier. | It is what makes "the newest offer subsumes the older one" true rather than merely plausible: all live jobs share a lower bound. |
> | **3 — completion is a monotone maximum, and the acknowledgement follows it** | `complete_harden` never regresses `durable_len`, and a committer is acknowledged only against a `durable_len` read **after** that advance. | It lets a waiter complete with the watermark the **group** reached instead of its own, which is the whole point of being released by someone else's sync. |
>
> **A durability guarantee that rests on three tacit properties is a guarantee by accident.** The day
> the sink moved to `sync_file_range`, to a durable frontier per worker, or to a sync per segment
> instead of per file, property 1 or 2 would die and the always-on ack gate would begin approving
> bytes that were never `fdatasync`ed — **false durability, the cardinal ACID violation**. The
> measurable cost of the shape as it stood was `W` duplicated syncs of the same interval, `W` fsync
> threads, and no coalescing whatsoever between workers.
>
> **What is ratified.**
>
> - **The three properties above become THE SINK CONTRACT**, declared normatively rather than relied
>   on tacitly, and each pinned by a test that fails if it is broken. The deferred job now carries the
>   range it hardens explicitly (`covers_from`, `target_len`) instead of only its end, so the contract
>   is **machine-checkable rather than prose**.
> - **One fsync group leader per database engine replaces the per-worker fsync thread.** Workers offer
>   their job to the shared leader; at most one `fdatasync` is in flight system-wide; a newer offer
>   **subsumes and discards** an older pending one, because by property 2 every live job starts at the
>   same global frontier and the newest therefore covers a superset of the range; and each worker is
>   released once the group's hardened watermark passes its own target.
> - **Depth-1 is restated where it is now true**: at most one `fdatasync` is in flight for the whole
>   engine, so the crash tail is again the tail of **one** un-synced interval rather than of `W`
>   interleaved ones.
> - **The discard is guarded by an always-on tripwire, not by a comment.** A job may only be discarded
>   in favour of one that leaves **no gap and no shortfall** in the range it covered, adjudicated
>   against the sink's own attested durable frontier. A per-worker frontier, or a sync narrowed to a
>   byte range, trips it.
> - **The coalescing this unlocks between workers is a prerequisite of, and is completed by, the commit
>   sequencer of task #977**, which owns total commit order and SSI validation for parallel writers.
>   This decision fixes the **durability mechanism**; #977 fixes the **ordering** on top of it.
>   **Two distinct things are called "the commit sequencer", deliberately.** Task #977's sequencer owns
>   commit **order**; the rank-20 commit sequencer of `D-published-snapshot-horizon` owns the
>   **visibility horizon** — when an already-ordered commit becomes observable. They are adjacent and they meet when
>   #977 lands, which is why the boundary is stated rather than either name changed; it is written out
>   in `04-technical-design.md` §5.2.
>
> **The reference read, at a pinned revision.** This is the shape PostgreSQL settled on, and it is
> read for the same reason Graphus needs it: a follower whose durability requirement was already met by
> another backend's flush must not issue a second one.
>
> | Reference | What was read, and what it shows |
> | --- | --- |
> | **PostgreSQL** (`/data/refsrc/postgres`, commit `0fd30e2`) | `XLogFlush` (`src/backend/access/transam/xlog.c:2800`) opens with a **quick exit if the record is already known flushed** (`:2819-2820`), and then, rather than queueing behind the write lock, calls `LWLockAcquireOrWait(WALWriteLock, LW_EXCLUSIVE)` (`:2874`) whose documented purpose is to "wait until it's released, and recheck if we still need to do the flush **or if the backend that held the lock did it for us already**. This helps to maintain a good rate of group committing when the system is bottlenecked by the speed of fsyncing" (`:2868-2871`). Having taken the lock it **rechecks once more** and breaks out without syncing if the request is by then satisfied (`:2884-2886`). The precedent Graphus adopts is exactly that: one backend's flush discharges every waiter below its watermark, and the waiter's own sync is dropped rather than performed. |
>
> This is the same **wait-and-recheck** axis the project already built for the doublewrite staging
> barrier in tasks **#993/#994**, whose leaf crate `graphus-groupsync` records the same PostgreSQL
> grounding; the WAL path had simply never been brought onto it.
>
> **How it is proved.** A multi-worker test drives 8 concurrent writers against an engine running 4
> workers over one shared leader and requires three things at once: every write is acknowledged (a
> shortfall means the leader failed to release a worker whose job it folded away); **no acknowledgement
> runs ahead of durability**, measured against the frontier an `fdatasync` has actually *completed*
> over rather than the sink's bookkeeping about it; and every acknowledged row is present after a
> restart. On top of those, the coalescing itself is asserted with a **material margin** rather than a
> strict inequality — a build that ran every folded-away job inline instead of dropping it measured
> **292 `fdatasync`s for 293 hardens** and would have passed a strict `fsyncs < hardens` test, so the
> bar is set at 0.75 syncs per harden, which refutes "no coalescing" (≈1.00 by construction under the
> per-worker thread) with room on both sides. A recorded run at 4 workers and 8 writers produced **400
> commits, 259 hardens and 155 real `fdatasync` calls** — 0.60 syncs per harden. The three sink-contract
> properties are pinned separately, including a test that fails the day `begin_harden` starts from a
> per-caller frontier.
>
> **Scope note — this decision does not lift the multi-writer gate.** `admission.engine_workers` above
> 1 remains **refused by configuration validation**, fail-closed, pending the certification measured by
> task **#1034**; multi-worker engines are reachable from tests, which is what keeps this path
> exercised. This decision removes one of the blockers behind that gate, and does not by itself open
> it.
>
> **Where this is specified.** The pipelined harden, the group leader, the restated depth-1 statement
> and the sink contract are `04-technical-design.md` §4.2; the runtime shape that places the leader off
> the async runtime is §9.1; the fsyncgate policy a failed sync follows is §4.9. The exemption of the
> leader from the deterministic scheduler is `07-dst-simulator.md` §5.2.3.

## Ratified decision (2026-08-12) — the published snapshot horizon

> **`D-published-snapshot-horizon` settles what a snapshot timestamp *means* once more than one worker
> may be committing, in task #1056.** It refines the earlier rounds rather than replacing any part of
> them: `D-version-representation`, `D-write-conflict-detection`, `D-multi-writer`,
> `D-dst-writer-scheduler`, `D-incidence-anchor`, the four property-path decisions, the three
> logical-rollback decisions, `D-statement-isolation`, `D-chain-head-publication` and
> `D-wal-group-leader` are unchanged, and `D-async-commit` is untouched — ack-after-fsync remains
> unconditional and nothing here defers a sync. Every one of the four inviolable requirements of
> `CLAUDE.md` stands as written, and **no byte of any on-disk format changes** — not the record
> layouts, not the WAL record set, not the format version, not a recovery step.
>
> **Status: ratified.**
>
> **Why now.** `D-multi-writer` ratified N parallel writers, and the layers that deliver them are under
> way. Running the multi-writer certification gate at eight engine workers produced a **lost update** —
> "the shared counters total 114 after 115 acknowledged concurrent increments" — on 4 runs in 20, and
> never at one worker. Two acknowledged increments, one applied, is the cardinal ACID violation, so it
> had to be closed before the writers are certified rather than after.
>
> **What was actually wrong, and why every backstop stood down.** The engine has always run on one
> invariant, and until this task nothing established it:
>
> > A snapshot taken at timestamp `V` sees every transaction whose commit timestamp is at or below `V`.
>
> A commit timestamp is issued at the *start* of commit; the commit publishes itself afterwards, in two
> writes in two media — the durable commit-info slot and the in-memory commit registry. `snapshot_ts()`
> returned the **issuing** clock. A worker beginning inside that window therefore took a begin timestamp
> equal to the commit timestamp of a transaction that neither oracle would yet admit was committed, read
> the pre-commit value, and — being itself a writer — overwrote it. With one writer thread nobody can
> begin inside another transaction's commit, so the window was unreachable; with eight it is a lost
> update.
>
> | Consumer of the timestamp | What it concluded | Was it wrong? |
> | --- | --- | --- |
> | `graphus_txn::visibility::is_visible` and the chain walk of `04-technical-design.md` §5.3 | a committed creator is visible iff its commit timestamp is at or below the snapshot's | **No.** That is the invariant. |
> | The write-write check of §5.7 | the chain head's holder is not an open transaction, so I may write | **No.** That was the only arm it had at the time. And the missing arm would not have saved it either: the head named a transaction that was by then genuinely committed at a timestamp **at or below** the writer's begin timestamp, so a committed-before-my-start test evaluated against that begin timestamp would also have permitted the write. |
> | `SsiTracker::are_concurrent` | `commit_ts <= begin_ts` means "committed before it began", so no rw-antidependency edge | **No** — and this is the premise that was suspected and refuted. Instrumented on the certification gate, the `commit_ts > begin_ts` shape reached the write path 100–130 times per run and survived to commit **zero times in 16 runs**: the edge did form and the pivot rule did abort it. What formed no edge was the `commit_ts == begin_ts` shape, and that reading is correct. **This function must not be "fixed" to `<`**; doing so would abort every transaction that legitimately begins at the timestamp of the commit it just read, which is the ordinary case. |
>
> All three read the timestamp correctly. The timestamp was the thing that lied.
>
> **The alternatives weighed.**
>
> | Option | Verdict |
> | --- | --- |
> | **A — make publication instantaneous**, so the window cannot exist: issue the timestamp and publish the commit inside one critical section, as Memgraph does. | **Not available in that form.** Graphus publishes a commit in **two media** — a durable `commit.store` slot and an in-memory registry — so there is no single store to make atomic. Reaching Memgraph's shape would mean holding one global engine lock across a durable write for the whole commit, which re-serialises exactly the writers `D-multi-writer` exists to run in parallel, and which the latch order forbids on its own terms (`04-technical-design.md` §3.3: the inner latches are released before any I/O, precisely so that one holder cannot convoy every writer behind a durability barrier). |
> | **B — exclude the two against each other with a lock**, taking the snapshot under the same latch a committer publishes under, as PostgreSQL's `GetSnapshotData` does under `ProcArrayLock`. | **Adopted in its guarantee, rejected in its mechanism.** It puts a latch acquisition on the **read** path, where a Graphus snapshot is a single atomic load and where every read in the engine begins. The obligation belongs on the committer, which pays it twice per commit, rather than on every reader. |
> | **C — publish a horizon derived from the set of issued-but-unpublished timestamps, and hand *that* out as the snapshot. ★ chosen** | **Ratified.** It gives option B's guarantee with option A's read cost. The horizon is the **contiguous published prefix** — the lowest pending timestamp minus one, or the whole allocation clock when nothing is pending — so a snapshot never names a commit that has not finished publishing itself, and the read path keeps a single atomic load. |
>
> **The references read, at pinned revisions.** Both engines make the same guarantee; they differ only
> in where they pay for it.
>
> | Reference | What was read, and what it shows |
> | --- | --- |
> | **PostgreSQL** (`/data/refsrc/postgres`, commit `0fd30e2`) | A snapshot and a commit's publication are mutually excluded by one lock. `GetSnapshotData` (`src/backend/storage/ipc/procarray.c:2114`) takes `ProcArrayLock` in shared mode (`:2178`); `ProcArrayEndTransaction` (`:663`) clears the committing backend's XID under the same lock in exclusive mode (`:710`), and its contract says both halves out loud: "The transaction commit/abort **must already be reported to WAL and pg_xact**", and "We must lock `ProcArrayLock` while clearing our advertised XID, **so that we do not exit the set of 'running' transactions while someone else is taking a snapshot**". Publication first, then the timestamp becomes observable — which is the rule Graphus adopts. |
> | **Memgraph** (`/data/refsrc/memgraph`, commit `087bbf2`) | The window is closed by making the whole commit one critical section. `CreateTransaction` takes `engine_lock_` and reads its start timestamp under it (`src/storage/v2/inmemory/storage.cpp:2829`, `:2840-2842`), and `Commit` acquires the same `engine_lock_` (`:1163`) *before* issuing the commit timestamp (`:1164`, `GetCommitTimestamp()` being a bare `timestamp_++` at `:4612`) and still holds it when the commit is published by one release store into `commit_info` (`:1299`). The comment at `:1178-1184` states the ordering requirement in the same terms: the WAL "must be written before actually committing the transaction (before setting the commit timestamp) **so that no other transaction can see the modifications before they are written to disk**". |
>
> **The consequences that are normative.**
>
> - **The horizon is the contiguous published prefix, not "every timestamp that has published".** With
>   `12` pending and `13` published the horizon stays `11`, because a snapshot at `13` would claim to
>   include `12`. This is conservative in a snapshot's **freshness** and never in its **consistency**.
>   It is advanced with an atomic maximum, so it is monotone whichever order two workers recompute it
>   in.
> - **A timestamp is issued and registered as pending in one indivisible step.** Split, a second worker
>   could recompute the horizon between the two, find nothing pending, and hand out a snapshot at the
>   very timestamp just issued — the same defect, reintroduced in a two-line window.
> - **An issued timestamp is released on every exit**, published once both halves of publication are
>   done and abandoned when the commit fails. A leaked timestamp **freezes the horizon permanently**:
>   one failed commit would pin every later reader in the process to a snapshot taken before it. The
>   commit path is therefore split into a timestamp-issuing wrapper and a fallible body, so that release
>   is a property of one caller instead of an obligation on every fallible step inside it. An abandoned
>   timestamp is **skipped, never reissued** — exactly as a sequence value consumed by a rolled-back
>   statement is.
> - **A transaction uses the timestamp it was handed, never a re-read of the clock.** `begin` returns
>   the horizon it captured and the commit path returns the timestamp it assigned. A second read is a
>   second instant: under `D-multi-writer` it yields a sibling worker's timestamp, or — since the
>   horizon now lags an in-flight commit — one *below* the transaction's own. Neither value is this
>   transaction's, so the write-conflict check and the SSI tracker would both be ruling on a number
>   that belongs to no transaction in front of them.
> - **The sequencer latch is rank 20** — the rank the engine's latch order already reserved for it by
>   name — entered through a **single acquisition door**, and a leaf: nothing may be acquired while it
>   is held. Two short critical sections per commit, and **nothing on the read path**.
> - **This is not the commit ordering of task #977.** The sequencer specified here owns the *visibility
>   horizon* — which issued timestamps may be seen. Task #977 owns *total commit order and SSI
>   validation* for parallel writers. The two are complementary, and neither subsumes the other.
>
> **How it is proved.** A by-seed DST scenario drives the record store directly, with **no SSI above
> it**, so the write-conflict rule is certified on its own terms rather than behind a backstop. Its
> headline oracle is the invariant itself — if `A` committed at `C` and `B` began at or after `C`, then
> `B` observed `A`'s write — and the counter oracle is kept beside it as the shape a user sees. Reaching
> the window at all required a **yield point at the snapshot itself**: without one, the first version of
> the scenario came back clean on all 32 seeds *with the fix withdrawn*, a by-seed reproduction that
> reproduced nothing. Each half of the fix was then withdrawn independently, everything else untouched:
>
> | Withdrawn | Snapshot-honesty oracle | Counter oracle |
> | --- | --- | --- |
> | The horizon — the snapshot reads the issuing clock again | **fails**, 19 seeds; **every** violation reports `commit_ts == begin_ts` | **fails**, 19 of 32 seeds |
> | The committed-before-my-start arm of the write-conflict check | passes | **fails**, all 32 seeds, 2–5 increments lost each |
> | Nothing (the shipped design) | passes | passes |
>
> That table is why **both** halves are required and neither is sufficient. With an honest horizon a
> begin timestamp never names an unpublished commit, and a writer can still overwrite a head committed
> *after* it began, which only the second arm refuses; with a dishonest horizon the arm is asked whether
> the head committed after a start timestamp that already equals the head's own, and answers no. At
> engine level the gate then ran **40 consecutive runs green at eight workers**, and the abort rate fell
> from 0.82 to about 0.70 (roughly 118 to 193 commits of 640) because a refusal now lands at the
> statement rather than at commit.
>
> **Scope note — this decision does not lift the multi-writer gate.** `admission.engine_workers` above 1
> remains **refused by configuration validation**, fail-closed, pending the certification measured by
> task **#1034**; multi-worker engines are reachable from tests, which is what keeps this path
> exercised. This decision removes one of the blockers behind that gate and does not by itself open it.
>
> **The property read path — measured, not assumed (task #1058).** This decision was recorded with a
> residual open against it: that the same allocation-versus-publication distinction had a second,
> still-live instance on the **property read path**, where a reader could observe **one leg of a
> commit that is in flight** (probed at 2 to 7 torn reads in the first ~240 reads before this
> decision landed). Task #1058 went back and measured it, and the residual is **closed by this
> decision itself** rather than by any further change.
>
> The mechanism is real and unchanged: a reader resolves each undo delta against a **live** read of
> that delta's commit slot, once per entity, so two entities written by one transaction are two slot
> reads at two instants, and a publication landing between them tears the read. What closes it is
> that the horizon never lets a reader hold a snapshot at or above a timestamp that is still
> publishing. At `C - 1` both slot reads decide the same way whichever side of the publication they
> fall on — unpublished resolves as not-yet-committed, published resolves as `Committed(C)` with
> `C > snapshot.ts` — and both undo the delta. The tear is not repaired; it is made **unreachable**.
>
> Two probes measure this and are kept as permanent regression cover.
> `graphus-storage/tests/live_snapshot_horizon_1058.rs` runs four writer threads and twelve reader
> threads against a bare `RecordStore`, every reader deriving its own snapshot through
> `RecordStore::begin` concurrently with the committers; it is clean, and with `snapshot_ts()`
> reverted to the allocation clock it fails **5 runs out of 5**, at 6583 to 6808 torn reads of about
> 29 500. `graphus-dst/tests/det_scheduler_live_snapshot_1058.rs` is its deterministic twin and
> reproduces the tear from a seed on **9 of 16 seeds**, byte-identically across runs. Both assert the
> window was genuinely sampled — the allocation clock read before the snapshot, against the horizon
> the snapshot got — rather than inferring it.
>
> **What this leaves open.** Both probes cover **node properties**. Relationship properties and labels
> reach the same `scan_polarity::delta_verdict` through different entry points and are not covered by
> them. And the scope note above still stands on its own terms: `admission.engine_workers` above 1
> remains refused by configuration validation pending task #1034.
>
> **Where this is specified.** The invariant, the horizon, the sequencer latch, the release obligation
> and the return-the-timestamp rule are `04-technical-design.md` §5.2; the latch ranks are §3.3; what
> the commit-info slot's single store does and does not settle is §5.1.3; the second arm of the
> write-conflict check and its `≤` boundary are §5.7; the lock-free inventory that now distinguishes
> reading the horizon from issuing a timestamp is §9.2. The begin-snapshot yield point that makes the
> window reachable by a seeded schedule is `07-dst-simulator.md` §5.2.5.

## Post-ratification note (2026-08-12) — `D-write-conflict-detection`

> **The second arm of the ratified rule is now implemented, and the boundary is "at or before".** The
> ratified choice names both arms in one sentence: the writer aborts unless the chain head belongs to a
> transaction that "is neither itself nor committed before its own start timestamp". Only the *in-flight
> holder* arm was ever implemented. Task **#1056** implemented the second, so a chain head whose
> transaction committed **after** the writer's start timestamp is now refused with the same retriable
> serialization failure.
>
> **The ratified wording reads as strict; the implemented comparison is `≤`, and that is not a
> deviation.** "Committed before my start" is measured against the *visibility* horizon, and a begin
> timestamp **is** that horizon (`D-published-snapshot-horizon`): the largest timestamp every one of
> whose commits has finished publishing. A version at exactly that timestamp is visible, by the same
> rule every reader in the engine already applies. A strict `<` would therefore refuse the ordinary
> sequential case — a transaction that begins after a commit, reads its value and writes on top of it,
> whose begin timestamp equals that commit's timestamp by construction — and would abort roughly every
> second write in a serial workload. The operator is `≤` **because** the horizon is honest; before the
> horizon existed neither operator was correct, which is why this arm could not have been added on its
> own.
>
> The check is skipped for a writer that holds **no recorded start timestamp** — recovery, a maintenance
> pass and a bulk import all write without ever taking a snapshot, so there is nothing to compare
> against. The ratified outcome is unchanged and nothing is re-baselined; this note records the
> completion of the rule and fixes the reading of its boundary. Design in `04-technical-design.md` §5.7.

## Ratified decision (2026-08-12) — log order equals apply order, per page

> **`D-page-write-order` settles what a logged page write must guarantee once more than one worker
> may be writing, in task #1062.** It refines the earlier rounds rather than replacing any part of
> them: `D-multi-writer`, `D-version-representation`, `D-write-conflict-detection`,
> `D-chain-head-redo-only`, `D-wal-group-leader` and `D-published-snapshot-horizon` are unchanged, and
> `D-chain-head-publication` is **absorbed as a particular case** rather than superseded. Every one of
> the four inviolable requirements of `CLAUDE.md` stands as written, and **no byte of any on-disk
> format changes** — not the record layouts, not the WAL record set, not the patch codec, not the
> format version, not a recovery step.
>
> **Status: ratified.**
>
> **The invariant, normatively.** For every page, the order in which logged writes against that page
> enter the WAL is the order in which those writes take effect on the page. Equivalently: what
> recovery rebuilds for a page is what the last logged write to that page applied.
>
> **Why now.** A logged page write is **two instants** in two media. The record enters the log under
> the WAL mutex (rank 30); the change takes effect on the cached page under the frame latch (rank 40).
> Until task #1062 nothing tied those two instants together, and `write_region` — the store's general
> page-write helper — appended and applied as two separately scheduled steps. With one writer per
> database that is latent. Once the engine gained several writers (the multi-writer layers of
> `D-multi-writer`), two writers of one page could enter the log in one order and take effect in the
> other. ARIES replays **strictly in log order** and gates each record on the page's `page_lsn`, so
> recovery then reconstructs an image the live system never held: the durable answer with no crash and
> the durable answer after a crash **differ**, and after a crash the replayed one is the one that
> survives. Neither answer is wrong on its own terms, which is exactly why no result-checking test
> catches it.
>
> **The evidence that decided it.** Measured with the deterministic simulator, on the scenario
> `det_scheduler_checkpoint_inversion_1055` — two writers, four commits each, sixteen seeds — before
> the fix:
>
> - **32 page-LSN descents across the sixteen seeds**, and **not one of them on a chain head**. The
>   pages that descended were the catalog image (`write_region`), the commit slot
>   (`patch_commit_slot_word`, which reaches the log through `write_region`), the undo area
>   (`write_undo_area_create`) and a node's label word (`write_node_labels`) — every one of them an
>   ordinary transactional write, none of them the chain-head path task #1028 had already closed.
> - The divergence in full, on seed `0x1`: a reopen recovered `[9, 5, 4]`, which is transaction 1004's
>   image, while the **last** page write in the recorded schedule was transaction 2004's `[9, 4, 5]`.
>   Recovery and the live system reached different verdicts about the same page.
> - **The positive control.** With the rank-27 section ablated to a bare call and everything else
>   identical, the invariant test fails on **13 of the 16 seeds**, 1 to 4 descents each, 30 in total,
>   while the three non-vacuity assertions of the same file continue to pass — so the zero the suite
>   asserts with the section in place is a zero the workload could have broken.
>
> **The alternatives weighed.**
>
> | Option | Verdict |
> | --- | --- |
> | **A — rely on the monotone `page_lsn` stamp.** The stamp already takes the maximum of the page's current LSN and the record's, so it never descends; the argument was that a page whose LSN never goes backwards is a page whose ordering is already safe. | **Rejected — empirically insufficient, and harmful on its own.** The stamp has taken the maximum since task **#1029**, so it was **already in the tree while the 32 descents above were measured**: a monotone stamp is therefore not the fix. It hides the divergence only if the page's *content* is monotone too, and content is not. Worse, the stamp alone is not merely inadequate but actively dangerous: redo skips every record whose LSN is at or below `page_lsn`, so a page carrying an LSN it never applied silently loses every legitimate record logged at or below it, and nothing reports the loss. Clamping the symptom would have made recovery **skip** records rather than mis-order them. |
> | **B — append the record under the frame latch, so that the LSN is assigned while the page is held.** This is what the reference engines do, and it would make the two instants one by construction. | **Rejected — it inverts the engine's latch order.** The append needs the WAL mutex (rank 30) while the frame latch is rank 40, so taking the WAL mutex under the frame latch is an out-of-rank acquisition, and the WAL barrier already refuses **by tripwire** to run with a frame latch held. This is the same rank inversion that `D-chain-head-publication` rejected in 2026-08-09, arriving for the general write path rather than for the head word. |
> | **C — hold the WAL mutex across the page apply, so that append and apply are one section under the WAL lock.** | **Rejected — it violates an absolute rule of the store.** The store MUST NOT hold its own WAL lock while calling any buffer-pool method that can trigger a write-back, because a write-back re-enters the WAL rule's durability check and would take the WAL lock again. The rule is stated as strict and absolute in `crates/graphus-storage/src/wal_rule.rs`, and it exists to prevent both a wait cycle and a non-reentrant self-deadlock. |
> | **D — re-key the existing rank-27 section from `(store kind, record id)` to the device page, and route every logged page write through it. ★ chosen** | **Ratified.** It supplies the missing coupling at the granularity the invariant actually needs, and it adds **no new latch, no new rank, no new record type and no format change** — it widens a mechanism the engine already had, already ranked, and already enforced by tripwire. |
>
> **Why the key is the page and not the record.** `page_lsn` is a property of the **page**. ARIES gates
> redo on `record.lsn > page_lsn` and replays in log order, so two writers of two *different* records
> that happen to share a page must be ordered exactly as much as two writers of one record — and the
> measurement above is precisely that case, since none of the 32 descents was on a chain head. Keying
> by page is a **strict widening** of keying by record: every writer of a record is a writer of its
> page and maps to the same shard, so the guarantee `D-chain-head-publication` ratified is preserved
> exactly rather than re-derived.
>
> **The consequences that are normative.**
>
> - **One section, four steps.** Capturing the undo pre-image, appending the record, applying the
>   post-image and stamping `page_lsn` are one indivisible section per page. The pre-image capture has
>   to be inside it: an image read outside the section can be overwritten by another writer of that
>   region before this record is appended, and the undo would then restore a state that was never this
>   writer's to restore.
> - **The page is pinned before the section is entered and unpinned after it is left.** The section is
>   never held across a page fetch that may evict, across store growth, or across a durability barrier.
> - **One door.** Every WAL append made against a page goes through the store's single logging door,
>   which asserts that the caller holds the section for that page. This is a **standing obligation on
>   future work**: a new append site that reaches the WAL by any other route reopens the defect in
>   full, and no test currently in the suite would name it as the cause.
> - **The shard count is a contention parameter only.** Correctness requires nothing beyond "one page
>   always maps to one shard". The array is sharded so that writers on unrelated pages do not wait for
>   one another; the index is derived by multiplicative (Fibonacci) hashing, which mixes the
>   low-entropy input — device page ids are dense and consecutive — instead of aliasing every *N*-th
>   page onto one shard. It is a mixing function and not a perfect distribution: two unrelated pages
>   can share a shard and then serialize needlessly, which costs throughput and never correctness.
> - **The cost accepted.** Two writers of one page now serialize where before they did not. That is a
>   deliberate widening of contention, taken because the alternative is a database whose recovered
>   state disagrees with the state it just served, and because page-level serialization is what the
>   durability model requires rather than an artefact of this implementation.
> - **The tripwires are debug-build only.** Every obligation above is checked by thread-local
>   tripwires that a release build compiles out. The mechanism itself — the latch and the single door —
>   is present in every build; what a release build gives up is the *diagnosis* of a violation, not the
>   protection.
>
> **One limitation is recorded rather than left to be discovered.** The B+-tree index layer has
> **eight WAL-append sites** (in `crates/graphus-index/src/btree.rs`) that do **not** pass through this
> door, and cannot: the section and its door are internal to the record store, and the index crate
> cannot reach them. Those eight sites satisfy the invariant today by **Rust exclusivity and by
> construction**, not by the mechanism this decision installs — every mutating `BTree` method takes
> `&mut self`, each tree owns its own single-threaded buffer pool and its own base-page range, and in
> production each tree is handed a device of its own, so no two threads can be writing one tree page
> at all. That is a sound argument for the
> engine as it stands today and **it is not the invariant this decision states**. The moment the index
> layer becomes multi-writer over one tree, the defect reappears there in full, and it will reappear
> silently: those pages are stamped outside the concurrent pool's instrumented path, so the
> page-LSN-descent oracle that measured the 32 descents does not observe them and would report zero
> while they diverged. Any task that makes an index tree writable by more than one thread MUST bring
> those sites under an equivalent mechanism first.
>
> **Where this is specified.** The invariant, the section, the single logging door, the enumerated
> append sites and the index-layer limitation are `04-technical-design.md` §5.7.2; the latch ranks and
> their obligations are §3.3; the chain-head protocol that is now a particular case is §5.7.1. The
> deterministic scenario, its non-vacuity controls and the ablation are `07-dst-simulator.md`.

## Post-ratification note (2026-08-12) — `D-chain-head-publication`

> **This note records how task #1062 changed the mechanism `D-chain-head-publication` relies on. It
> creates no new decision of its own, and it changes no ratified outcome of the 2026-08-09 round.**
> The four ordered steps of a prepend, the compare-and-publish, the rule that step 4 follows a winning
> publication, the retry a refusal demands, the rule that a refused publication appends no record, the
> redo-only status of the write and the placement of the protocol in a dependency-free leaf crate all
> stand exactly as ratified.
>
> **What changed.** The rank-27 publication latch that supplies the two ordering obligations —
> atomicity and durable order — was **re-keyed from `(store kind, record id)` to the device page**.
> Everything else about the latch is as ratified: the same rank, the same position between the
> allocation latch (25) and the WAL (30), the page pinned before the latch is taken, at most one
> holder per thread, never held across I/O, and the obligations checked mechanically in debug builds.
>
> **Why the ratified guarantee is unchanged.** The re-keying is a **strict widening**. Every writer of
> a record is a writer of the page that record lives on, and both map to the same shard, so every pair
> of writers the 2026-08-09 key ordered is still ordered by the 2026-08-12 key. Nothing that was
> serialized before is unserialized now; strictly more is serialized. The 2026-08-09 decision's own
> reasoning is therefore untouched, and its measurement of the chain-head defect class stands.
>
> **Why the widening was necessary, in one sentence.** Keying by record orders the writers of one
> chain head and leaves unordered two writers of two *different* records that share a page — and that
> is where the divergence was actually measured: of the 32 page-LSN descents task #1062 found, **not
> one was on a chain head**.
>
> **Its new standing.** `D-chain-head-publication` is a **particular case of `D-page-write-order`**,
> already absorbed by it. Both decisions remain in the canonical index with their own keys and their
> own ratification dates, because each one names a real and distinct scope: 2026-08-09 settled how a
> chain head is *published* — the compare-and-publish, the four steps, the refusal semantics — and
> 2026-08-12 settles what *every* logged page write must guarantee about order. Neither is redundant,
> and the earlier one remains a faithful record of what task #1028 ratified.
>
> Design in `04-technical-design.md` §5.7.1 (the protocol, unchanged) and §5.7.2 (the widened section).

## TCK target (pinned — closes `D-cypher-line` open question 1)

The "100% Cypher TCK" target is pinned to the **openCypher `2024.3`** tag (commit `677cbaf`,
dated 2026-03-20), the latest release on the GQL-convergent 2024.x line. **`1.0.0-M23`** is the
first-milestone snapshot.

Scenario counts. The `D-cypher-line` comparison below was made on 2026-06-05 by cloning each tag and
parsing its `features/**/*.feature`:

| Snapshot | `.feature` files | `Scenario` + `Scenario Outline` blocks | Executable scenarios (outline examples expanded) |
| --- | --- | --- | --- |
| **2024.3 (target)** | 220 | 1615 (1339 + 276) | 3880 (1339 plain + 2541 example rows) |
| 1.0.0-M23 (milestone) | 220 | 1615 (1339 + 276) | 3880 |

The two tags coincide in totals but differ in content (the scenarios were revised, not net-added,
along this path), so the 2024.x language surface (label expressions, quantified path patterns,
`SHORTEST`, element-pattern `WHERE`) is delivered behind feature flags while certifying the same
scenario budget. The pinned 2024.3 corpus is **vendored** at `crates/graphus-tck/tck/features` (221
feature files) and is the authoritative certification target: the `graphus-tck` runner executes and
passes **all 3914 executable scenarios** (1356 plain + 2558 outline example rows), asserted by the
`BASELINE` constant in `crates/graphus-tck/tests/tck.rs`. (The corpus grew by 34 scenarios — 17 plain
and 17 outline example rows — between the 2026-06-05 estimate and the vendored snapshot the harness
certifies.) "100% TCK compliant" = **all 3914 executable scenarios of the pinned, vendored corpus
pass** (correct result bag/order, correct side-effect counts, correct error type at the correct
phase).
The verbatim result/failure shapes and the error-classification table were read and frozen by
SPIKE #9 (`06-bolt-and-error-shapes.md` §2–§3; resolves open question 2 and `04-technical-design.md`
§12 item 13).

## Options and rationale (not the canonical list)

This table records the options that were weighed and the recommendation made for each decision, so
that the reasoning behind a ratified outcome stays available. It is **not** the decision list: it
predates the later decisions and does not enumerate them. The ratified outcome of every decision is
in the "Decision index (canonical)" section above, which is the only place a tool should read the
decision list from.

| ID | Decision | Options | Affects |
| --- | --- | --- | --- |
| **D-cypher-line** | Cypher version / TCK snapshot | (a) openCypher 9 (M23), frozen, smaller surface; (b) openCypher 2024.x (GQL-convergent), larger surface; ★(c) implement 2024.x but feature-gate the newest constructs and certify the M-series milestone first — **pin a specific tagged commit and count its scenarios** | Query Language |
| **D-tck-harness** | How to run the TCK from Rust | ★(a) Rust `cucumber` for CI + (b) periodic JVM `tck-api` as ground-truth oracle; (c) bespoke Rust step interpreter | Testing |
| **D-storage-arch** | Storage architecture | (a) custom record store + index-free adjacency from day one; (b) build on an embedded transactional KV engine (redb/sled/RocksDB); ★(c) **staged hybrid** — validate correctness on `redb`, then migrate the traversal hot path to a custom index-free-adjacency store. **High-impact; discuss explicitly.** | Storage Engine |
| **D-concurrency-control** | Concurrency-control scheme | (a) strict 2PL; (b) MVCC + Snapshot Isolation; ★(c) MVCC + SSI (serializable correctness at SI speed) | Transaction Manager |
| **D-isolation-level** | Default isolation level | (a) Read Committed; (b) Snapshot Isolation; ★(c) Serializable (via SSI) default, with Snapshot Isolation as an opt-in documented mode | Transaction Manager |
| **D-durability-mode** | Durability mode | (a) synchronous fsync per commit; ★(b) group commit + `fdatasync` default, per-transaction synchronous available; (c) async commit — **rejected** (breaks durability). Mandatory: torn-write protection + page checksums + PANIC-on-fsync-failure | WAL |
| **D-buffer-mgmt** | Buffer management | (a) `mmap`; ★(b) custom buffer pool (control over eviction, async I/O, torn-write protection) | Storage Engine |
| **D-runtime-model** | Async runtime / concurrency model | (a) Tokio multi-thread work-stealing; (b) thread-per-core share-nothing (glommio/monoio, Linux-only); ★(c) hybrid — Tokio baseline (runs on macOS too) + sharded write/ACID path. **Validate on a traversal-heavy benchmark.** | Architecture |
| **D-io-backend** | I/O backend | (a) epoll/kqueue only; (b) io_uring only (breaks macOS/seccomp); ★(c) portable epoll/kqueue baseline + optional io_uring on Linux with runtime fallback | Architecture |
| **D-allocator** | Memory allocator | ★(a) start with system default and benchmark; (b) mimalloc; (c) jemalloc — adopt (b)/(c) only with per-target numbers (jemalloc has historical Apple-Silicon friction) | Architecture |
| **D-target-matrix** | Target-triple matrix | (a) Linux x86_64 only; ★(b) Linux x86_64 + aarch64 + macOS aarch64 (all Rust Tier 1), 64-bit only, CI on x86 + aarch64; (c) also Intel macOS (Tier 2) + 32-bit ARM | Architecture |
| **D-wire-protocol** | UDS wire protocol | ★(a) custom binary, length-prefixed, Bolt-inspired semantics; (b) adopt Bolt directly; (c) custom + optional Bolt transport | Wire Protocol |
| **D-bolt-compat** | Bolt protocol compatibility | (a) yes, as an optional later transport (free Neo4j-driver ecosystem); ★(b) no for v1 (not part of the TCK; revisit in Phase 2) | Connectivity |
| **D-serialization** | Serialization formats | ★(a) typed JSON (Jolt-style) for REST + CBOR via negotiation; PackStream/CBOR for UDS; **fix int53 from day one**; (b) plain JSON only (lossy); (c) protobuf everywhere | Serialization |
| **D-auth-scheme** | Auth scheme per interface | ★(a) UDS = `SO_PEERCRED` + socket permissions; REST = Bearer/JWT over TLS + RBAC (optional Basic); (b) token auth on both | Auth |
| **D-v1-topology** | v1 topology | ★(a) single-node only, clustering-ready interfaces; (b) single-node + design clustering in; (c) single-node + early read replicas | Architecture |
| **D-v1-index-types** | v1 index types | ★(a) token-lookup + range/B-tree + composite; (b) + full-text; (c) + full-text + spatial + vector | Index Manager |
| **D-graph-algos** | Graph algorithms library | ★(a) native Cypher path functions only in v1; (b) small built-in set (Dijkstra, PageRank, WCC); (c) full library | Graph Algorithms |
| **D-multi-db** | Multi-database support | ★(a) single DB in v1, catalog abstraction designed in; (b) multi-database in v1 | Multi-tenancy |
| **D-vector-index** | Vector/similarity index | ★(a) out of scope for v1; (b) in v1 | Indexing & Constraints |
| **D-security-scope** | Security scope for v1 | ★(a) auth + RBAC + TLS(REST) + user/role mgmt; (b) + fine-grained access control; (c) + encryption at rest + auditing | Security |
| **D-dst-investment** | DST investment | ★(a) scaffold a deterministic simulation harness from the start; (b) add it in Phase 2 | Testing |
| **D-element-id** | Element ID scheme | (a) Neo4j-style numeric `id()` reused on delete + string `elementId`; ★ internal compact IDs + a **stable, never-reused** public ID (ULID/UUIDv7) for operational safety. **Tension to rule on:** TCK literal ID-reuse vs ACID-grade stability | Data Model |
| **D-temporal-spatial** | Temporal/spatial type scope | (a) full temporal set + full spatial in v1; ★ full temporal in v1, spatial deferred unless required at launch; (c) integers/epoch only | Data Model |
| **D-read-parallelism** | Read-query parallelism (post-ratification, sprint 19) | ★(a) **DEFER** — keep the single-writer-thread engine; accept-as-is for single-node production, schedule the parallel-reads epic as future work (rmp #146); (b) parallelize reads now — rejected for this sign-off (large/very-large, high-risk change to inviolable ACID, with an unfinished prerequisite migration) | Architecture / Transaction Manager |
| **D-perf-deferrals** | Three higher-risk efficiency optimizations (post-ratification, sprint 19) | ★(a) **DEFER all three** — accept-as-is for production, schedule as future work (rmp #159); (b) apply them now — rejected (per-commit catalog dirty-gating is a durability/identity-reuse risk, the per-row slot model is a TCK-correctness-sensitive executor rewrite, and streaming SHOW INDEXES/CONSTRAINTS has negligible benefit) | Architecture / Storage Engine / Executor |

## Cross-cutting notes

- **Inviolable and mutually reinforcing:** `D-isolation-level` (Serializable via SSI) and
  `D-durability-mode` (group commit + torn-write protection + PANIC-on-fsync-failure). Anything
  weaker contradicts "data must never be corrupted or in an invalid state."
- **Highest-risk, highest-impact:** `D-storage-arch`. It dominates cost, risk, and timeline.
- **Measurement-gated:** `D-runtime-model`, `D-io-backend`, and `D-allocator` must be confirmed by
  benchmark on a representative workload before being locked (project rule: "measure to decide").
- **Verification is a deliverable, not an afterthought:** `D-tck-harness` + `D-dst-investment` are
  how the ACID and Cypher TCK inviolable requirements are *proven empirically* rather than
  asserted; protocol-conformance and driver-interoperability tests against the official driver
  ecosystem prove the Bolt protocol and PackStream requirements the same way.

## Open questions for the owner to close before locking the spec

1. Pin the exact openCypher TCK tag and record its scenario/feature count (do not quote a number
   from memory). **Resolved** in the "TCK target" section above: pinned to openCypher `2024.3`
   (commit `677cbaf`).
2. Read the verbatim TCK result / failure shapes and lock the error-classification table.
   **Resolved (2026-06-09) by SPIKE #9 — see `06-bolt-and-error-shapes.md` §2 and §3.** The
   compile-time error-classification table is frozen with `(phase, type, detail)` triples whose
   detail strings are verbatim from `tck/features/**`, grounded in the implemented
   `crates/graphus-cypher/src/errors.rs`; the Bolt `SUCCESS`/`RECORD`/`FAILURE` result and failure
   shapes and their REST RFC 9457 equivalent are documented there. **Deferred:** the Neo4j
   two-letter Bolt status codes (a Neo4j surface, not part of the openCypher TCK triple) need the
   pinned TCK and certified driver artifacts to map verbatim and are not invented (`06` §2.4).
3. Resolve the `D-element-id` tension (TCK ID-reuse literalism vs stable never-reused IDs).
4. Decide whether spatial types ship in v1 (`D-temporal-spatial`).
5. Confirm REST read/write access-mode selection (the Bolt `BEGIN` field has no documented REST
   equivalent). **Resolved (2026-06-09) by SPIKE #9 — see `06-bolt-and-error-shapes.md` §4.** The
   REST transactional API declares access mode through an `access_mode` request member with values
   `"READ"` / `"WRITE"`, defaulting to `"WRITE"` when absent, validated as a client error otherwise,
   matching the Bolt `BEGIN` semantics.
6. Ratify `D-bulk-import-network` (see the "Ratified decision (2026-07-01)" section above and
   `08-network-bulk-import.md`). **Resolved (2026-07-01).** The owner confirmed the recommended
   REST-streaming transport and the global `Admin` RBAC gate, and selected the non-recommended
   option on database scope: both a fresh/empty database (Mode A) and an already-live database
   under concurrent traffic (Mode B) are in scope. Mode B's concurrency-safe design (`08` §7.2)
   was independently validated by `storage-systems-auditor` before being finalized; that audit
   also surfaced a prerequisite `graphus-bulk` correctness fix (`08` §7.2.2, KG Finding
   `bulk-idmap-not-abort-safe`) that must land before Mode B's automatic batch retry ships.
