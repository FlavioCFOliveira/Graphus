# 05 — Storage Format & Durability Micro-Decisions

This document records the outcome of the Phase 1 spike *"storage format and durability
micro-decisions"* (`rmp` task, Phase 1). It resolves the format choices needed before the
storage chain (`graphus-bufpool` → `graphus-wal` → `graphus-storage`) can be implemented, and
**freezes the page header and the versioned-record header**. It provisionally resolved
`04-technical-design.md` §12 items 2–5; **item 2 (the MVCC version representation) was ratified on
2026-08-02 as `D-version-representation` and is no longer provisional** — see §5, and §12 for the
on-disk undo area it unblocked.

Per the project rules, choices that genuinely require a representative workload to settle are
decided **provisionally** on the literature and **flagged for confirmation by benchmark** once
`graphus-bench` and the LDBC SNB harness exist. The one sub-decision that is cheaply measurable
today (the page checksum) was **measured**, not guessed.

---

## 1. Logical page size — **8 KiB** (provisional)

`LOGICAL_PAGE_SIZE = 8192` bytes (already in `graphus-core::constants`).

- Rationale: the long-established default for transactional B-tree engines (PostgreSQL uses 8 KiB);
  a balance between I/O granularity, internal fragmentation, and write amplification. It is a
  **logical** constant, decoupled from the OS page size, which is queried at runtime
  (`04-technical-design.md` §3.1). On a 16 KiB Apple-Silicon OS page, one OS fault covers two DB
  pages — note the read-amplification implication.
- **Measurement-gated (flag):** re-confirm 4 / 8 / 16 KiB against the LDBC SNB working set and the
  real key-size distribution (`04` §12 item 4) before 1.0.

## 2. B+-tree fanout — **derived, target ≈ 256–340** (provisional)

For an 8 KiB index page with a 24-byte page header, ~16-byte keys and 8-byte child pointers
(~24 bytes per separator entry): `(8192 − 24) / 24 ≈ 340` entries upper bound; a conservative
target fanout of **256** leaves slack for variable-length keys and split headroom.

- **Measurement-gated (flag):** finalize against the real key encoding and LDBC key sizes (`04`
  §12 item 4) when `graphus-index` is implemented.

## 3. Torn-write protection — **doublewrite buffer** (over full-page-writes)

A page write is not atomic at the device level; a crash can leave a half-old/half-new page.

- **Decision: a doublewrite buffer** (InnoDB-style). Each dirty data page is first written to a
  dedicated, contiguous doublewrite area and flushed, then written to its home location. On
  recovery, a page whose checksum (§4) fails is restored from its intact doublewrite copy.
- Rationale over **full-page-writes** (PostgreSQL-style, which logs the entire image of each page
  on its first modification after a checkpoint): full-page-writes inflate WAL volume and commit I/O,
  whereas the doublewrite area is a bounded, constant-size overhead that keeps the WAL lean
  (physiological redo). It composes cleanly with group commit (`D-durability-mode`).
- Trade-off: doublewrite roughly doubles *data-page* write I/O (not WAL); mitigated because those
  writes are sequential and batched at checkpoint, off the commit path.
- **Measurement-gated (flag):** measure write-amplification and commit latency vs full-page-writes
  per target (`04` §12 item 3) when `graphus-wal`/`graphus-bufpool` are implemented.

## 4. Page checksum — **CRC32C** (measured)

Measured on this host (`x86_64`, Rust 1.96, `--release`), hashing an 8 KiB page in a tight loop:

| Algorithm | Throughput | Per 8 KiB page |
| --- | --- | --- |
| **CRC32C** | 7.19 GB/s | 1139 ns |
| xxh3_64 | 32.22 GB/s | 254 ns |

- **Decision: CRC32C.** Although xxh3 is ~4.5× faster here, a page checksum exists for **integrity /
  corruption detection**, where CRC32C's *guaranteed* burst-error-detection properties are the right
  guarantee, and where 7.19 GB/s (≈1.1 µs/page) is far above the page I/O it protects — the checksum
  is never the bottleneck. CRC32C is hardware-accelerated (x86 SSE4.2 `crc32`, ARMv8 CRC extension)
  and is the industry choice for page integrity (e.g. InnoDB). The checksum field is 32-bit.
- xxh3 is retained as the preferred **non-integrity** in-memory hash (hash maps, plan-cache keys).
- **Flag:** re-confirm CRC32C throughput on `aarch64` (ARM CRC extension); a 3-way-pipelined CRC32C
  implementation can be adopted later if (improbably) the checksum ever shows on a profile.

## 5. MVCC version storage — **in-place latest + undo-delta chain** (ratified 2026-08-02)

- **Decision: keep the latest visible version in the home record, with older versions reconstructed
  by applying logical undo deltas backward** (Memgraph / Neumann-et-al.-style), over append-only
  newest-first. **Ratified on 2026-08-02 as `D-version-representation`**
  (`02-decision-register.md`), which closes `04` §12 item 2. This section is no longer provisional.
- Rationale: traversal-heavy graph reads overwhelmingly want the *latest* version; keeping it in the
  home record means the hot path reads the record directly with no chain walk and good cache
  locality. Older snapshots (only needed by concurrent long readers) are rebuilt by walking the undo
  deltas. GC prunes deltas older than the oldest active snapshot timestamp.
- Trade-off: a reader on an old snapshot pays a chain walk proportional to concurrent long-running
  writers; acceptable for the target workload and bounded by GC.
- **Measured ground for the delta half of the choice** (not a preference): the property path in force
  when the decision was taken tombstoned the previous version by walking the entity's whole property
  chain and then prepended the new one (`RecordStore::tombstone_props_for_key`), which is **O(M²)** in
  the number of assignments to one entity — **15.1 µs/op at M = 1000** and **97.8 µs/op at M = 8000**.
  A constant-cost delta prepend replaced that walk (task #967).
- **One chain per entity carries every mutation kind** — creation, deletion, property assignment,
  label change, and incidence-list change. The chain is anchored by the record's `undo_ptr` (§7) and
  its on-disk format is frozen in §12. The delta actions, their lifecycle, their ownership by the
  writing transaction, and the commit indirection point are specified in `04` §5.1.
- **Refined on 2026-08-03 for the property path** (task #967), without any byte changing:
  `D-property-write-conflict` (the entity-granularity conflict check arrives with #967),
  `D-property-removal` (a removal is an **empty cell in place**, not an `expired_ts` tombstone, and
  exactly one owner names any `strings.store` overflow chain), and `D-property-visibility` (the undo
  chain is the **sole** visibility oracle for a property's value, so the cell's `created_ts` is
  informative only). See §7 for how the record header reads on a property cell, §12.2 for the
  `type_tag == 0` clarification, and `04` §§5.1.2, 5.1.5, 5.6.

---

## 6. Frozen layout — page header (24 bytes)

Every page (record-store page and B+-tree page) begins with this fixed 24-byte header. Multi-byte
fields are **little-endian** (`01-needs-survey.md` FR-ST-11). The checksum covers bytes `4..PAGE_SIZE`.

| Offset | Size | Field | Notes |
| --- | --- | --- | --- |
| 0 | 4 | `checksum` | CRC32C (§4) over bytes `4..8192`. |
| 4 | 4 | `page_type` | low byte = type (record-store / btree-internal / btree-leaf / overflow / meta); high 24 bits = flags. |
| 8 | 8 | `page_lsn` | LSN of the last change to this page (ARIES `pageLSN`; idempotent redo). |
| 16 | 8 | `page_id` | self-reference; detects misdirected/torn writes. |

Payload is `8192 − 24 = 8168` bytes. Record-store pages lay records out as a fixed-size array
(record *N* at `24 + N × record_size`); B+-tree pages use a slotted directory (specified with
`graphus-index`).

## 7. Frozen layout — versioned-record header (MVCC prefix)

Node, relationship, and property records share this fixed prefix so the transaction manager can
apply MVCC visibility uniformly. Type-specific fields (label/first-rel/first-prop pointers for
nodes; endpoint/type/chain pointers for relationships; key/value for properties) are appended after
this prefix and are finalized with `graphus-storage`.

| Offset | Size | Field | Notes |
| --- | --- | --- | --- |
| 0 | 1 | `flags` | bit 0 `in_use`; bit 1 `dense` (node); remaining reserved. |
| 1 | 8 | `created_ts` | commit timestamp / `TxnId` that created this version. |
| 9 | 8 | `expired_ts` | commit timestamp that expired it; `0` = live (latest). |
| 17 | 8 | `undo_ptr` | physical id, in `undo.store` (§12), of the **head of this entity's undo-delta chain**; `0` = none. |

→ **25-byte MVCC record header.** Node and relationship records additionally carry the **16-byte
stable `ElementId`** (`D-element-id`) immediately after this prefix; property records do not.

**`undo_ptr` — its meaning.** `undo_ptr` is the **only** anchor of an entity's
version history: it holds the physical id of the newest delta on that entity's chain, each delta
carrying the id of the next-older one (§12). Reconstructing the version a given snapshot may see means
starting from the in-place record image and applying deltas from `undo_ptr` backwards until the
snapshot's visibility rule is satisfied (`04` §5.3). Without a non-zero `undo_ptr` there is no version
chain at all.

> **The field is live since task #966.** Creating or deleting a node or relationship links a delta and
> publishes it as that entity's chain head (`RecordStore::link_delta`, driven from `create_node` /
> `create_rel` / `delete_node` / `delete_rel` in `crates/graphus-storage/src/store.rs`), so `undo_ptr`
> is no longer the permanently-zero reserved word it was. The head is published with the same
> chain-head write `first_rel` / `first_prop` use, which since task **#970** carries **no undo image
> at all**: the inverse of a prepend is to unlink the entry, computed at abort time from the
> transaction's own deltas, and never the restoration of the word (`04` §4.4 and §5.1.5 row 3). Since
> task **#1028** a **prepend** publishes that head with a **compare-and-publish**: the head is
> installed only if it still holds the value the writer linked its entry to, and a refused publication
> writes nothing and logs nothing (`04` §5.7.1, which also names the unlink paths still outside that
> discipline). The word's on-disk meaning and position are untouched by the change — what changed is
> how a prepend installs it. The
> consistency checker range-checks `undo_ptr` against **`undo.store`**'s high-water and walks the
> chain below it (`Violation::UndoChain`, `crates/graphus-storage/src/check.rs`). The frozen 25-byte
> header above did **not** change: `undo_ptr` was always specified to mean this, and #966 made the
> engine honour the specification rather than the other way round.
>
> **Every mutation kind now hangs on this chain.** #966 delivered the area and the entity-lifecycle
> actions (`DeleteObject` / `RecreateObject`); property assignment (**#967**), label change
> (**#968**) and incidence change (**#969**) followed, and **#970** made the rollback that applies
> them logical. The record format did not change again when they landed, exactly as this section
> said it would not.

**How this header reads on a property record, from task #967 onward** (`D-property-visibility` and
`D-property-removal`, ratified 2026-08-03; `04` §5.6). The 25-byte prefix above is shared by node,
relationship and property records and **its bytes do not change**, but two of its fields carry less
meaning on a property cell than on an entity record, and the difference is normative:

- **`created_ts` is informative, not authoritative.** A reader never decides which value of a
  property it may see by comparing the cell's `created_ts`. It resolves visibility from the in-place
  image plus the **entity's** undo chain, which is the sole oracle for a property's value (`04`
  §5.6). The stamp remains useful for diagnostics and for the consistency checker.
- **`expired_ts` is never written by a property operation.** A property removal is an **empty cell in
  place** (`type_tag = 0, value_inline = 0`, §12.2) that keeps its `in_use` bit and its position in
  the `first_prop` chain — not a tombstone (`04` §5.1.5, row 1 in detail). `expired_ts` therefore
  stays `0` on property cells, and expiry remains meaningful only for node and relationship records.
- **`in_use` keeps its full structural meaning** on a property cell: slot occupancy and corpse
  threading are unchanged.

Entity records are unaffected: on a node or relationship, all three fields keep exactly the meaning
the table states.

---

## 8. What remains deferred (with owner-visible flags)

- Exact full record layouts (node/relationship/property type-specific fields) → **frozen in §9** by
  the `graphus-storage` task.
- B+-tree slotted-page directory format → **frozen in §10** by the `graphus-index` task.
- Undo-area layout (the delta record and the commit-info slot) → **frozen in §12** by
  `D-version-representation`; implemented by task #966.
- Page-size / fanout / torn-write **measurements** → confirmed against LDBC SNB once `graphus-bench`
  exists (this spike's choices are the working defaults until then). The **MVCC** representation is no
  longer among them: it was ratified on 2026-08-02 (§5) on the measured evidence recorded there, and
  `04` §12 item 2 is closed.
- CRC32C re-confirmation on `aarch64`.

Nothing here is silently fixed: each provisional choice is flagged for its confirming measurement.

---

## 9. Frozen layout — record store (`graphus-storage`)

The `graphus-storage` task froze the exact record layouts. All fields are little-endian. Records of
a given store are **fixed-size** and laid out as an array inside each logical page's payload (bytes
`24..8192`, after the §6 page header): record at store-slot `s` lives at byte offset
`24 + (s mod records_per_page) × RECORD_SIZE`, where `records_per_page = (8192 − 24) / RECORD_SIZE`.
Every record begins with the §7 **25-byte MVCC header**.

- **Physical id `0` is reserved as the null pointer**, so `first_rel = 0`, `first_prop = 0`,
  `next_prop = 0`, `undo_ptr = 0`, and the chain pointers all read as "none". Real records are
  allocated from id `1` upward; freed ids are reused (a per-store WAL-logged free list, §2.7),
  while the public `ElementId` is never reused.

| Store | `RECORD_SIZE` | records/page | Type-specific fields after the 25-byte MVCC header |
| --- | --- | --- | --- |
| `nodes.store` | **65** | 125 | `element_id` u128 (16) · `first_rel` u64 (8) · `first_prop` u64 (8) · `labels` u64 (8) |
| `rels.store` | **102** | 80 | `element_id` u128 (16) · `type` u32 (4) · `start_node` u64 (8) · `end_node` u64 (8) · `start_prev_rel` / `start_next_rel` / `end_prev_rel` / `end_next_rel` u64 (8 each) · `first_prop` u64 (8) · `chain_flags` u8 (1) |
| `props.store` | **46** | 177 | `key` u32 (4) · `type_tag` u8 (1) · `value_inline` u64 (8) · `next_prop` u64 (8) |

A relationship is threaded into **two** doubly-linked incidence chains (its start node's and its end
node's, §2.3); `chain_flags` marks which side is its chain's head. A self-loop
(`start_node == end_node`) is threaded into the single chain **twice** (via its start-side and
end-side pointers) and deduped by relationship id on a distinct-incidence traversal (§2.4). Parallel
edges are simply distinct relationship records (§2.4). `dense_ptr` reinterpretation of `first_rel`
(§2.5) and `value_inline`'s overflow into `strings.store` are reserved by these layouts but their
machinery lands with the dense-node and large-value tasks.

Tokens (labels / reltypes / propkeys) are bidirectional `u32 ↔ name` dictionaries, WAL-logged and
recovered (§2.6). The `ElementId → physical id` direction is rebuilt in memory on open (each record
self-describes its `ElementId`; the never-reused 128-bit counter is persisted in the metadata
catalog). All mutations are WAL-logged as intra-page `(u16 offset, bytes)` patches and are
crash-recoverable via three-phase ARIES recovery (`04-technical-design.md` §4.8). Every mutation
carries a redo patch; its undo patch is a physical pre-image, a compare-and-set, or — for a chain-head
write, whose inverse is logical (§12.5) — **empty**. A **chain-head write's redo patch is itself a
compare-and-set image** (task #1028): it carries the word's expected pre-value beside its post-value,
and both the live write and its replay install the post-value only where the word still holds the
expected one. The patch encoding did not change to accommodate this — the conditional shape already
existed for compare-and-set undo images and is reused unchanged — so neither the WAL format, the patch
codec, nor the recovery loop was altered (`04` §4.4 and §5.7.1).

---

## 10. Frozen layout — B+-tree index page (`graphus-index`)

The `graphus-index` task froze the slotted B+-tree page. An index is a file of logical pages; each
page reuses the §6 24-byte page header, then a slotted body laid out by `graphus-index`. Keys are the
**order-preserving encoding** (`04-technical-design.md` §6.2) so that page byte order equals Cypher
value order; values are 8-byte little-endian record ids.

The cross-type key order is the **openCypher orderability** (CIP2016-06-14 §Orderability, which the
TCK enforces; `04 §7.6`), ascending:
`MAP < NODE < RELATIONSHIP < LIST < PATH < {temporals} < STRING < BOOLEAN < NUMBER < NaN < null`,
where the temporal block ascends `ZonedDateTime < LocalDateTime < Date < ZonedTime < LocalTime <
Duration`, `NaN` is the largest number, and `null` is the largest value. (Note the openCypher quirk:
`STRING < BOOLEAN < NUMBER`.) `graphus-cypher`'s value ordering is derived from exactly this order, and
a 100k-pair property test cross-checks that the two agree, so indexes and `ORDER BY` never disagree.
Within a class, the byte encoding preserves order (`i64` sign-flip, IEEE-754 total order with `-0.0 <
+0.0`, UTF-8 byte order, chronological temporals). `Bytes` (a PackStream/REST extension, not an
openCypher type) is placed just above `STRING`.

| Region | Location | Contents |
| --- | --- | --- |
| Node header | bytes `24..28` | `level` u16 (0 = leaf) · `slot_count` u16 |
| Slot directory | grows down from byte `28` | fixed 8-byte slots `(cell_off u16, key_len u16, val_len u16, reserved u16)`, kept **sorted by key** (binary search) |
| Cell heap | grows up from `PAGE_SIZE − 16` | leaf cell = `key ++ value(8-byte rid)`; internal cell = `key ++ child u64` |
| Special area | last 16 bytes | `right_sibling` u64 at `−8` (B-link chain over all leaves in key order) · `leftmost_child` (`P0`) u64 at `−16` (internal nodes only) |

An internal node with `k` keys has `k + 1` children (`P0` plus one per slot). Traversal is
latch-coupled (crabbing) with B-link right-sibling retry on splits (`04 §6.1`); the discipline is
documented and the right-sibling links maintained, with the concurrent implementation deferred to the
concurrent-buffer-pool task (the single-threaded core is correct today). Every index-page mutation is
WAL-logged (redo + undo, the same intra-page patch format as the record store) and recovered by the
same three-phase ARIES machinery — there is no separate index rebuild (`04 §6.4`). Indexes are **not**
separately MVCC-versioned: a seek returns candidate record ids and visibility is resolved against each
record's MVCC header by the transaction layer (`04 §6.3`).

---

## 11. Frozen layout — offline backup artifact (`graphus-storage`)

The offline backup/restore feature (FR-BR) froze a self-describing backup artifact. It is a
**consistent snapshot**: the store is flushed (every dirty page written home under the WAL rule, the
device synced) and a clean fuzzy checkpoint (`04 §4.7`) is appended, so the captured durable image
has nothing in flight. Two integrity layers compose (`04 §4.6`): every page already carries its own
CRC32C, and the artifact adds a whole-payload digest so tampering anywhere — header, framing, or page
ids — is detected even if a per-page checksum were re-faked.

| Region | Bytes | Contents |
| --- | --- | --- |
| Header | 44 | `magic` `b"GRPHBKUP"` (8) · `format_version` u32 · `page_size` u32 · `creation_mark` u128 (the store's never-reused `ElementId`-next at snapshot) · `page_count` u64 |
| Page section | `page_count × (8 + 8192)` | per page, ascending device-page order: `page_id` u64 + the full 8192-byte page image |
| Trailer | 4 | `digest` u32 = CRC32C over every preceding byte |

`verify_backup` validates the structure + digest without restoring (catches truncation, bad magic,
wrong version/page-size, page-count mismatch, a flipped digest, and a misplaced framing `page_id`).
Restore writes the verified pages onto a fresh device and **runs the consistency checker** (§ the
checker in `graphus-storage`): a backup that frames an internally-inconsistent image (even one that
passes both integrity layers) is rejected rather than served. Online / incremental backup and
point-in-time recovery are deferred to Phase 2; this is the offline path only.

---

## 12. Frozen layout — the undo area (`D-version-representation`, task #966)

This section freezes the on-disk form of the undo-delta chain ratified as `D-version-representation`
on 2026-08-02. The behavioural model — the seven delta actions, the delta lifecycle, the transaction's
ownership of its deltas, and the commit indirection point — is `04-technical-design.md` §5.1; this
section specifies only the bytes.

> **This area exists in the engine as of task #966.** The codec is
> `crates/graphus-storage/src/undo.rs`; the two stores are `StoreKind::Undo` and `StoreKind::Commit`
> in `crates/graphus-storage/src/store.rs`, framed and recovered exactly like the four that precede
> them. All seven actions of §12.3 are encodable and decodable; the write path emits the two
> entity-lifecycle ones (`DeleteObject` on create, `RecreateObject` on delete), and tasks #967 / #968 /
> #969 add the property, label and incidence actions without changing a byte of the format below.

### 12.1 Two new stores

The undo area is **two additional fixed-record stores** in the same store directory, framed exactly
like the three that already exist (§9): an array of fixed-size records inside each logical page's
payload (bytes `24..8192`, after the §6 page header), record at store-slot `s` at byte offset
`24 + (s mod records_per_page) × RECORD_SIZE`, all fields little-endian, **physical id `0` reserved as
the null pointer**, ids allocated from `1` upward, freed ids reused through a per-store WAL-logged free
list (§2.7 of `04-technical-design.md`).

| Store | `RECORD_SIZE` | records/page | Holds |
| --- | --- | --- | --- |
| `undo.store` | **56** | 145 | one **delta** per record — the inverse of one change to one entity |
| `commit.store` | **32** | 255 | one **commit-info slot** per writing transaction — the commit indirection point |

Two stores rather than one because the §9 addressing rule requires a single record size per store. The
56-byte delta is not a coincidence: Memgraph holds its own `Delta` to the same budget
(`static_assert(sizeof(Delta) <= 56, ...)`, `/data/refsrc/memgraph/src/storage/v2/delta.hpp:408`).

### 12.2 Delta record (`undo.store`, 56 bytes)

| Offset | Size | Field | Notes |
| --- | --- | --- | --- |
| 0 | 1 | `flags` | bit 0 `in_use`; remaining reserved, must be zero. |
| 1 | 1 | `action` | one of the seven actions of §12.3. |
| 2 | 1 | `type_tag` | `SetProperty` only: the old value's type tag, encoded exactly as `props.store`'s `type_tag` (§9), including its inline-vs-overflow bit. Zero for every other action. |
| 3 | 1 | `direction` | the two incidence actions only: `1` = the **start** end of the relationship, `2` = its **end** end. Zero for every other action. |
| 4 | 4 | `command_id` | the statement counter within the writing transaction (`04` §5.1.4); `0` means the write happened outside any statement (below). |
| 8 | 8 | `commit_info` | physical id in `commit.store` of the writing transaction's slot (§12.4). Never `0` on a live delta. |
| 16 | 8 | `next` | physical id in `undo.store` of the next-older delta on this entity's chain; `0` = end of chain. |
| 24 | 4 | `token` | `SetProperty`: the property-key token. `AddLabel`/`RemoveLabel`: the label token. The two incidence actions: the relationship-type token. Zero otherwise. |
| 28 | 4 | — | reserved, must be zero. |
| 32 | 8 | `value_inline` | `SetProperty` only: the **old** value if it fits, else the `strings.store` block id, encoded exactly as `props.store`'s `value_inline` (§9). Zero for every other action. |
| 40 | 8 | `peer` | the two incidence actions only: physical id of the endpoint node at the **other** end from the one `direction` names. Zero otherwise. |
| 48 | 8 | `edge` | the two incidence actions only: physical id of the relationship record. Zero otherwise. |

A delta is **immutable once linked**: after the publication order of `04` §5.1.2 step 3, no field of it
is ever rewritten. Only its slot is reused, and only after GC has reclaimed it.

**Clarification (2026-08-03): what `type_tag == 0` means on a `SetProperty` delta.** The table above
states that `type_tag` is zero for every action other than `SetProperty`, but it did not state what a
zero means **on** a `SetProperty` delta. It means **the property did not exist before**, and applying
the delta restores its absence. This is the encoding of the "`NULL` when the property did not exist
before" payload that `04` §5.1.1 already specifies in prose. Memgraph writes the same thing for the
same case: initialising a property that was absent links a `SetProperty` delta whose old value is a
default-constructed `PropertyValue`
(`/data/refsrc/memgraph/src/storage/v2/vertex_accessor.cpp:522`).

**No byte of the frozen layout changes.** This paragraph is prose filling a gap in the table's
description, not an amendment to the format: no field moves, no field changes width, and no value
that was previously legal becomes illegal or vice versa. A reader must be able to tell the two apart,
because §12 is frozen — so it is said explicitly here.

**Why the zero is unambiguous.** The property type-tag space **starts at 1**, so no encoder can ever
emit `0` for a property that exists:

- the inline tags are `TAG_BOOL = 1`, `TAG_INT = 2`, `TAG_FLOAT = 3`
  (`crates/graphus-storage/src/propenc.rs`);
- the overflow classes are `4..=13`, always OR-ed with `OVERFLOW_BIT = 0x80`
  (`crates/graphus-storage/src/valenc.rs`), so every overflow tag is `≥ 0x84`.

The zero is therefore free to carry "absent", and it does. Two adjacent cases must not be confused
with it: `Integer(0)` and `Boolean(false)` are distinguished by their **tag** (`2` and `1`
respectively), never by the value word, so a zero `value_inline` alongside a non-zero `type_tag` is an
ordinary stored zero and not an absence. Note also that `valenc.rs`'s `TAG_LIST_EMPTY = 0` is **not**
a counter-example: it is a private `elem_tag` written **inside** a serialized empty list's body to
record that the list has no element class, and it never appears in a `type_tag` field.

**Clarification (2026-08-05): what `command_id == 0` means, and who writes the field.** Until task
**#972** no write path filled the field in and every delta carried `0`. It is now written on every
delta, and — as with the 2026-08-03 clarification above — **no byte of the frozen layout changes**:
the field keeps its offset, its width and its little-endian encoding, and no value that was
previously legal becomes illegal or vice versa. What the two paragraphs below fill in is the meaning
of the value, which the table never stated, and the rule about who is allowed to write it.

A zero means **the write happened outside any statement**, so it belongs to the writing transaction's
**baseline** rather than to one of its statements: recovery, a maintenance pass and the catalog all
write deltas without ever running a Cypher statement. A baseline write is undone by **no** view —
neither `New` nor `Old` — which is what stops a maintenance transaction's own `Old` read from erasing
its own work (`04` §5.1.4). A transaction's first statement therefore runs at `command_id == 1` and
not `0`, so that the `Old` view of that first statement excludes every delta the transaction could
possibly have written.

The field is written by `RecordStore::link_delta`, and by `RecordStore::creation_chain_head` for the
`DeleteObject` delta a creation publishes, in both cases **from the writing transaction's own
counter**. A caller may never supply it — exactly as it may never supply `commit_info` — because a
caller that could would be able to stamp a delta with a statement that is not running, and an `Old`
read would then silently resolve against it.

### 12.3 The `action` byte

The encoding is fixed, so that a stored delta is decodable by any build that reads this format
version. **A delta names the action that UNDOES the change** (`04` §5.1.1); the "Written when" column
is therefore the inverse of the action's name, and that is deliberate.

| Value | Action | Written when the transaction… | Fields it uses beyond the common ones |
| --- | --- | --- | --- |
| 1 | `DeleteObject` | creates a node or relationship | none |
| 2 | `RecreateObject` | deletes a node or relationship | none |
| 3 | `SetProperty` | sets, changes, or removes a property | `token`, `type_tag`, `value_inline` |
| 4 | `AddLabel` | removes a label from a node | `token` |
| 5 | `RemoveLabel` | adds a label to a node | `token` |
| 6 | `AddIncidentEdge` | removes one of a relationship's incidence entries | `token`, `direction`, `peer`, `edge` |
| 7 | `RemoveIncidentEdge` | adds one of a relationship's incidence entries | `token`, `direction`, `peer`, `edge` |

Value `0` is reserved and is not a valid action, so a zeroed slot never decodes as a delta.

**Action 6 is frozen but unwritten.** No write path emits `AddIncidentEdge`, because a relationship
deletion is a tombstone and never unlinks an incidence entry, so nothing exists for that action to
restore (`04` §5.1.1). It is retained in the encoding so the pair of incidence actions is complete
and so a later build that does unlink on delete needs no format change. A rollback that meets an
`AddIncidentEdge` delta on a chain treats it as corruption rather than applying it.

**The two incidence actions anchor on the RELATIONSHIP** (`D-incidence-anchor`, ratified 2026-08-04;
`04 §5.1.1`), so the entity whose chain carries them is the relationship itself and `direction` says
which of that relationship's two ends the entry is on. `edge` therefore names the owning entity and is
redundant with it by construction — which is what the consistency checker cross-validates.

Correspondence with the reference implementation: Memgraph's enumeration
(`/data/refsrc/memgraph/src/storage/v2/delta_action.hpp:17-33`) carries the same set with two
differences. It splits each incidence action by direction into four actions
(`ADD_IN_EDGE`/`ADD_OUT_EDGE`/`REMOVE_IN_EDGE`/`REMOVE_OUT_EDGE`) where Graphus uses two actions plus
the `direction` byte, and it carries one further action, `DELETE_DESERIALIZED_OBJECT`, which exists
only for its disk-backed storage mode and has no Graphus counterpart.

### 12.4 Commit-info slot (`commit.store`, 32 bytes)

| Offset | Size | Field | Notes |
| --- | --- | --- | --- |
| 0 | 1 | `flags` | bit 0 `in_use`; remaining reserved, must be zero. |
| 1 | 7 | — | reserved, must be zero. |
| 8 | 8 | `commit_ts` | **the commit indirection point.** Carries the writer's `TxnId` in the in-flight `VersionStamp` encoding while the transaction is open, and its commit timestamp once it has committed. Written exactly once, by a single store, at commit. |
| 16 | 8 | `txn_id` | the owning transaction's id, retained after commit for recovery and diagnostics. |
| 24 | 8 | `delta_count` | `0` while the transaction is open; set at commit to the number of deltas the transaction created, then decremented by GC as each one is reclaimed. |

**Why one slot and not one timestamp per delta.** A transaction that touched *k* entities commits with
**one** write, and all *k* of its deltas become committed at the same instant because each resolves its
status through this slot. This is what lets the freeze sweep be retired — the in-place rewrite of every
committed writer's stamps across `[freeze_low, high_water)`
(`RecordStore::freeze_store_headers_incremental`), a frontier that needs its own release-active audit
and whose mis-advance was a silent-data-loss defect (rmp #522). **The sweep is still present today:**
the slot removes the *need* for it, but retiring it is separate work (rmp #1069 → #1070 → #1071), and
until that lands both mechanisms are live. Memgraph publishes the same way, in one
line: `transaction_.commit_info->timestamp.store(*commit_timestamp_, std::memory_order_release)`
(`/data/refsrc/memgraph/src/storage/v2/inmemory/storage.cpp:1299`).

**Write ordering at commit, which is normative.** `delta_count` is written **before** `commit_ts`, and
`commit_ts` is the **last** write. Until `commit_ts` is published no other transaction treats this one
as committed, so the earlier write is not observable as a partial commit; publishing `commit_ts` last
is what makes a reader see either the whole transaction or none of it.

**Reclamation, and why it is a proof rather than a count** (task **#1069**). GC still decrements
`delta_count` as it reclaims each of the transaction's deltas, and the count is still cross-checked
against a full census of `undo.store` by the consistency checker — a disagreement means a delta was
lost, resurrected, or attributed to the wrong transaction. What the count no longer does is **decide
when the slot may be freed**. The invariant is that **a slot outlives its last reference**: no
delta and no MVCC record header may ever name a freed or reused slot, because what they name it for —
the writer's committed-ness — is knowable only through it.

The count cannot express that invariant, because it counts only one of the two populations that name
a slot. A record header's `created_ts` / `expired_ts` name the slot of the transaction that created or
expired the version (§7, §9), so the count would reach zero while headers still resolve through it,
and a slot freed there is reusable at once — the next transaction to take it rewrites it, and every
header still naming it silently changes which transaction it attributes the version to. Slot ids are
recycled; the `TxnId`s the header used to carry never were, which is why the count was sufficient
before and is not now.

Reclamation is therefore decided by a **census of references**: a slot is reachable when a live delta
names it in `commit_info`, **or** a record header names it, **or** it belongs to an open transaction.
Every other path — the GC's chain reclamation, a live abort, and a physical abort's cleanup — retires
a slot by clearing its `in_use` bit and arming that census, and none of them returns an id to the
allocator. An **aborting** transaction still applies and frees its own deltas itself (§12.5) and
retires its slot with them; what changed is that retiring is not freeing.

A retired slot is then **parked** rather than freed, and re-enters circulation one collection pass
later, under `D-orphan-slot-parking` — the same restraint the record stores already apply, and for a
sharper reason here: a slot id handed straight back is rewritten by the next writer, so the window
between "proved unreachable" and "reused" must not be zero.

### 12.5 Durability, recovery, and rollback

- **The undo area is ordinary storage.** Both stores are ordinary logical pages carrying the §6 page
  header, with their own CRC32C, torn-write protection (§3) and page LSN. Every mutation is WAL-logged
  as an intra-page `(u16 offset, bytes)` patch and redone by the same three-phase ARIES machinery as a
  record-store page (`04-technical-design.md` §4.8). There is no separate undo-area recovery path and
  no rebuild on open.
- **Redo stays physical; the rollback of a data transaction became logical** (task **#970**, done).
  Crash recovery still replays physical page images, so the undo area is reconstructed byte-exactly.
  What changed is transaction rollback: instead of reverting bytes, a rolling-back transaction walks
  **its own** deltas newest-first, applies each against the current state, detaches them from the
  chains they head, reclaims them with its commit slot, and ends in the log with an `ABORT` record
  carrying no compensation (`RecordStore::rollback_logical`,
  `crates/graphus-storage/src/store.rs:5986`). This is what ends the defect family rmp #220 / #172 /
  #239 / #301 / #578 / #772, all of which are cases of one transaction's byte-level undo damaging
  another's committed state. **#970 was a rollback change only.** Because the undo chain was already
  the sole visibility oracle for a property's value (`D-property-visibility`, ratified 2026-08-03;
  `04` §5.6), replacing physical undo with logical undo needed **no second rewrite of the read path**.
  Physical undo survives for a transaction that owns no commit slot — a GC or maintenance pass, or a
  catalog-only writer — whose writes name no MVCC version (`rollback_physical`, `:6062`; `04` §4.3).
- **A loser transaction after a crash is undone by the WAL, not by its deltas.** Recovery's undo
  phase follows each loser's `prev_lsn` back-chain and applies the undo image of every record it
  wrote (`04` §4.8): the in-place values revert byte for byte, and each delta the loser linked reverts
  to `!in_use` through the header-only creation undo that installed it, keeping its `next` intact. The
  chain-head publications carry no undo image (§7), so they are not reverted, and what recovery leaves
  is an entity whose `undo_ptr` names a **corpse**: a `!in_use` delta that every chain walk threads
  through and that the GC reclaims. Logical rollback is the inverse of a *live* transaction; the WAL
  is the inverse of a crashed one.
- **A publication that was refused left nothing in the log to replay** (task #1028). The word is
  compared before the redo record is appended, and both happen under one hold of the chain-head
  publication latch, so the order in which publications enter the log is the order in which they took
  effect on the page. Recovery therefore reproduces exactly the sequence of heads the live system
  installed. This is what makes the redo image's own condition safe to trust: a record that replays
  onto a page which already carries its publication declines instead of clobbering, and there is never
  a record for a publication that did not happen (`04` §5.7.1).
- **Consistency checking.** The checker's existing `undo_ptr` range guard
  (`MvccHeaderFault::UndoPtrOutOfRange`, `crates/graphus-storage/src/check.rs:1224-1229`) was written
  for this moment and needs no change in kind: it must now range-check against `undo.store`'s
  high-water mark, and gains the chain obligations that only apply once chains exist — a chain must
  terminate, every `commit_info` must address a live slot, and a **committed** slot's `delta_count` must
  equal the number of unreclaimed deltas that name it (an open transaction's slot carries `0`).

### 12.6 Format version

Adding these two stores and bringing `undo_ptr` to life is an **incompatible on-disk layout change**:
a store written by a build that has an undo area cannot be read correctly by one that does not.
`graphus_core::constants::FORMAT_VERSION` (`crates/graphus-core/src/lib.rs`, documented as "bumped
on any incompatible layout change") is therefore raised from **1 to 2** by task **#966**. A store
carrying format version 1 has no undo area and every `undo_ptr` in it reads `0`, which is a valid,
chain-free image; opening it under a version-2 build is an upgrade, and opening a version-2 store under
an older build must be refused rather than misread. The backup artifact's own `format_version`
(§11) is independent and is not affected by this bump.

**How the version is carried, and how each direction of the rule is enforced.** Before #966 the
constant was never persisted, so a store carried no version at all. #966 gives it two carriers, one
for each direction:

- **This build reading an older or a newer store.** The version lives in the durable catalog
  (`graphus_storage::Meta`), in a trailing block introduced by the magic `GRPHUNDO` and followed by the
  two undo-area store entries. The block is appended after every pre-existing block, by the same
  append-only rule every other catalog extension follows, so a version-1 image is exactly this image
  without the block: `Meta::decode` reports it as version 1 with two empty undo-area stores — a valid,
  chain-free image — and the first checkpoint rewrites the catalog at version 2. A version *newer* than
  the reading build is refused outright, never partially interpreted.
- **An older build reading this store.** A shipped build cannot be taught a new version check, so the
  refusal has to come from a validation it already performs, and it performs exactly one on the
  metadata frame: it rejects a catalog chunk whose length runs past the page. A version-2 build
  therefore sets bit 31 of the **head** metadata page's `chunk_len`, which makes a pre-#966 build fail
  that guard deterministically instead of parsing a catalog whose trailing undo-area block it would
  silently drop — which would orphan both undo stores and strand every `undo_ptr` in the record stores.
  A real chunk length is at most one page, so the bit can never collide with a genuine value; a
  version-2 build masks it off. The error an older build reports is *"metadata chunk runs past the
  page"*: a refusal, and a deterministic one, though it does not name the version.

  > **Ratified on 2026-08-03.** This tripwire is a deliberate design decision, not an accident of the
  > encoding, and it was put to the owner precisely because it carries a flag bit in a length field and
  > yields an error message that does not name the version. The trade-off was accepted as stated: **an
  > old build failing immediately on a version-2 store is worth more than one reading it wrongly and
  > then writing over it**, and the confusing message is the accepted price. Do not "clean this up" as
  > an unintentional hack — removing the bit re-opens the silent-misread path this section exists to
  > close. It is pinned by
  > `crates/graphus-storage/tests/undo_chain.rs::the_head_metadata_page_carries_the_format_tripwire`.

**Every version, and the decision taken for each.** The machinery above (the `GRPHUNDO` block that
carries the number, and the bit-31 tripwire that makes a pre-#966 build refuse) is version 2's and is
reused unchanged by every later bump. What each bump has to state is its own compatibility decision:
whether an older image is **upgraded** or **refused**, and why that is the safe answer.

| Version | Task | What changed | An older image, under this build |
| --- | --- | --- | --- |
| 1 | — | the layout before the undo area | — |
| 2 | #966 | the undo area's two stores, in the `GRPHUNDO` block | **upgraded**: a version-1 image has no chains, which is exactly what an empty undo area describes |
| 3 | #967 | **no byte moved.** A `props.store` cell's MVCC header no longer carries the property's visibility (`D-property-visibility`) | **refused, with a migration route**, if and only if the image still holds a property tombstone. That is the whole reason the number had to move: versions 2 and 3 are otherwise indistinguishable, so the gate would have had nothing to key on. A tombstone-free legacy image upgrades losslessly, which is the normal state of any store whose GC has caught up (`RecordStore::refuse_legacy_property_tombstones`) |
| 4 | #1066 | the **applied-transaction set**, in a trailing `GRPHCNTD` block: the transactions whose logged cardinality deltas (`04` §4.1) are already folded into the `Statistics` persisted beside it | **upgraded**, with an empty set |

**Why the version-4 upgrade is lossless, and why the bump was still necessary.** The set's invariant is
"these transactions are already folded into the counters beside it". For a pre-version-4 image the
empty set is not an approximation of that store's history, it *is* that history: no build below version
4 ever wrote a `COUNT-DELTA` record, so no such image's log contains one, and an empty set therefore
cannot cause anything to be applied a second time. There is nothing to convert and nothing to lose.

The refusal this version buys runs in the **other** direction, and it is the one that matters. An older
build handed a version-4 image would not merely miss the block: it would rewrite the catalogue
**without** it, discarding the record of what had already been applied, and the next version-4 build to
open that store would fold every still-retained delta in a second time. Since #866 answers `count()`
from that number and nothing recomputes it at open, the result would be a wrong query answer that
survives every restart. `Meta::decode`'s "a version newer than this build is refused outright" arm is
what stops it, and it only stops it because the number moved.

**Presence is decided by the version, in both directions.** The counters and the applied set are one
fact, so neither half may appear without the other:

- an image that declares version 4 and carries **no** set is not an older writer that stopped early —
  it is an image whose two halves disagree, and reading it would replay deltas already accounted for;
- an image that declares a version **below** 4 and still carries the set came from no writer at all,
  since no such build ever emitted the block. Taking its counters while discarding the record of what
  has been folded into them is the same drift in the opposite direction.

`Meta::decode` therefore requires the block exactly when the version says it should be there, and
refuses in both directions. Pinned by `crates/graphus-storage/tests/count_delta_wal_replay_1066.rs`.

> **The obligation this creates.** Failing closed here means that anything which *forges* an older
> image by rewriting the version word must also **cut** the trailing blocks that version does not
> define, or it produces a store no build could have written and is refused before it reaches whatever
> it meant to exercise. There is one such forgery in the tree — `rmp` #967's legacy fixture,
> `crates/graphus-storage/tests/property_undo_chain_967.rs::downgrade_catalog_to` — and its version-2
> arm truncates at the `GRPHCNTD` magic for exactly this reason. Its version-1 arm truncates at
> `GRPHUNDO`, which removes both trailing blocks at once and needed no change. Any future block
> appended to this catalog inherits the same obligation.
