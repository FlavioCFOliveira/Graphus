# 05 — Storage Format & Durability Micro-Decisions

This document records the outcome of the Phase 1 spike *"storage format and durability
micro-decisions"* (`rmp` task, Phase 1). It resolves the format choices needed before the
storage chain (`graphus-bufpool` → `graphus-wal` → `graphus-storage`) can be implemented, and
**freezes the page header and the versioned-record header**. It provisionally resolves
`04-technical-design.md` §12 items 2–5.

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

## 5. MVCC version storage — **in-place latest + undo-delta chain** (provisional)

- **Decision: keep the latest visible version in the home record, with older versions reconstructed
  by applying logical undo deltas backward** (Memgraph / Neumann-et-al.-style), over append-only
  newest-first.
- Rationale: traversal-heavy graph reads overwhelmingly want the *latest* version; keeping it in the
  home record means the hot path reads the record directly with no chain walk and good cache
  locality. Older snapshots (only needed by concurrent long readers) are rebuilt by walking the undo
  deltas. GC prunes deltas older than the oldest active snapshot timestamp.
- Trade-off: a reader on an old snapshot pays a chain walk proportional to concurrent long-running
  writers; acceptable for the target workload and bounded by GC.
- **Measurement-gated (flag):** spike both representations on a traversal-heavy workload before
  locking (`04` §12 item 2) when `graphus-txn` is implemented.

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
| 17 | 8 | `undo_ptr` | pointer into the undo area to the previous version's delta; `0` = none. |

→ **25-byte MVCC record header.** Node and relationship records additionally carry the **16-byte
stable `ElementId`** (`D-element-id`) immediately after this prefix; property records do not.

---

## 8. What remains deferred (with owner-visible flags)

- Exact full record layouts (node/relationship/property type-specific fields) → **frozen in §9** by
  the `graphus-storage` task.
- B+-tree slotted-page directory format → **frozen in §10** by the `graphus-index` task.
- Page-size / fanout / torn-write / MVCC **measurements** → confirmed against LDBC SNB once
  `graphus-bench` exists (this spike's choices are the working defaults until then).
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
catalog). All mutations are WAL-logged as intra-page `(u16 offset, bytes)` redo/undo patches and are
crash-recoverable via three-phase ARIES recovery (`04-technical-design.md` §4.8).

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
