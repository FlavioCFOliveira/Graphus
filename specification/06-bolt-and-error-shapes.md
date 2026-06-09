# 06 — Bolt Version Pin & TCK Error/Result Shapes

This document records the outcome of the Phase 1 spike *"pin Bolt version and extract TCK
error/result shapes"* (`rmp` SPIKE #9). It resolves the choices needed before the Bolt connectivity
task (`graphus-bolt`) can be implemented, and it **pins the Bolt protocol version** and **freezes
the TCK error-classification model** that `graphus-cypher` already implements in code.

It closes two open items in `02-decision-register.md`:

- **Q2** — the verbatim TCK error shapes used to lock the error-classification table
  (`04-technical-design.md` §7.3; the corresponding spike is `04` §12 item 13).
- **Q5** — the REST transactional API read/write access-mode selection
  (`04-technical-design.md` §8.2; the corresponding spike is `04` §12 item 14).

It also resolves `04-technical-design.md` §12 item 11 (the exact Bolt 5.x minor and the Manifest-v1
handshake scoping call).

Per the project rules, this document **consolidates and pins** material already specified in
`04-technical-design.md` §8.1 (Bolt wire protocol), §8.2 (REST transactional API), and §7.3 (the
compile-time vs runtime error-phase split). It references those sections rather than duplicating
their byte-level detail. The error-classification table is grounded in the implementation that
already exists in `crates/graphus-cypher/src/errors.rs`, whose detail strings are taken verbatim
from the pinned openCypher TCK feature files (`tck/features/**`).

---

## 1. Bolt version — **pin Bolt 5.4 as the v1 target**

`graphus-bolt` implements **Bolt 5.x** with **PackStream v1** as already specified in
`04-technical-design.md` §8.1. This spike pins the exact maximum minor that §8.1 left open ("exact
maximum minor is pinned in §12").

- **Decision: Bolt 5.4 is the v1 target.** The implementation provides the **5.0 baseline through
  the 5.4 message set**. Version 5.4 is the highest minor Graphus negotiates and certifies in v1.
- **Wire serialization: PackStream v1**, exactly as detailed in `04-technical-design.md` §8.1 (the
  null / boolean / integer / float64 / string / list / dictionary markers and the tagged structures
  for `Node`, `Relationship`, `UnboundRelationship`, `Path`, and the temporal types). The `Value`
  model (`04` §7.2) maps one-to-one onto PackStream structures. This document does not restate those
  markers; §8.1 is the authority.
- **Legacy 4-slot handshake is mandatory.** Graphus implements the legacy handshake regardless of
  any later option: the client sends the 4-byte magic preamble `60 60 B0 17` followed by four
  big-endian 32-bit version proposals (range-encoded since Bolt 4.3; `00 00 00 00` for unused
  slots); the server replies with the single chosen version, or `00 00 00 00` to reject. The
  byte-level detail is in `04-technical-design.md` §8.1.

### 1.1 Rationale

- **5.4 is the §8.1-stated baseline.** `04-technical-design.md` §8.1 already names "5.0 baseline
  through at least 5.4 message set" as the implementation surface; pinning 5.4 makes that the firm
  v1 ceiling rather than an open range.
- **Stable, widely supported driver target.** Bolt 5.4 is a stable protocol version supported by the
  mainstream Neo4j driver ecosystem that Graphus targets over both UDS and Bolt-over-TCP
  (`D-wire-protocol`, `D-bolt-compat`). Certifying a fixed maximum minor lets the driver
  conformance matrix be concrete (`04` §12 item 11 requires pinning against the specific driver
  versions Graphus certifies).
- **Range-encoded negotiation degrades cleanly.** Because the legacy handshake offers four
  range-encoded proposals, a Graphus server pinned to 5.4 still negotiates downward to any 5.x minor
  a driver requests within the 5.0–5.4 window, so the pin sets the ceiling without dropping older
  5.x clients.

### 1.2 Deferred to Phase 2 — Manifest-v1 handshake (5.7+)

Adopting the **Bolt 5.7+ "Manifest v1" handshake** (the client proposes `00 00 01 FF` and the
server replies with a manifest of supported version ranges, instead of the 4-slot exchange) is a
**Phase-2 scoping decision**, not part of v1. This is the same call tracked as `04` §12 item 11
(its "decide whether to implement the 5.7+ manifest handshake" half). v1 ships the legacy 4-slot
handshake only; the Manifest handshake is added later if and when the certified driver matrix
requires a Bolt minor beyond 5.4.

- **Flag:** re-confirm the maximum minor and the Manifest-handshake decision against the exact driver
  versions Graphus certifies, reading the verbatim Bolt specification for any minor adopted beyond
  5.4 (`04` §12 item 11; "never guess").

---

## 2. TCK error-classification model

The "100% Cypher TCK" requirement means every engine error must be raised with the correct TCK
**triple** at the correct execution **phase** (`02-decision-register.md` "TCK target"; `04` §7.3).
The TCK expresses an expected error in the Gherkin shape:

```text
Then a SyntaxError should be raised at compile time: UndefinedVariable
```

which decomposes into three components (openCypher TCK `tck/README.adoc`):

1. **phase** — `compile time` or `runtime`.
2. **type** (also called classification) — `SyntaxError`, `SemanticError`, and the runtime types.
3. **detail** — a fine-grained label (e.g. `UndefinedVariable`).

Graphus maps every internal error to its `(phase, type, detail)` triple through an
**error-classification table**, and a CI test asserts the phase split so it cannot silently regress
(`04` §7.3). The table for the compile-time errors is implemented in
`crates/graphus-cypher/src/errors.rs`.

### 2.1 Phase split (the load-bearing invariant)

- **Compile-time** errors are raised by **semantic analysis**, which is the *only* phase permitted
  to emit them and which runs to completion **before any side effect** (`04` §7.3). A plan that
  compiles has passed every compile-time check.
- **Runtime** errors are raised **only** by the executor, during row production.

This split is the inviolable invariant. The classification table records the phase for every error,
and the CI test asserts that every semantic-analysis error is `compile time` (never `runtime`), so a
new error variant cannot be added without classifying it.

### 2.2 Compile-time error-classification table

Semantic analysis raises exactly the errors below. Each row is a `(phase, type, detail)` triple. The
**detail** strings are taken **verbatim** from the openCypher TCK feature files (`tck/features/**`)
that assert them, and are pinned by tests in `crates/graphus-cypher/src/errors.rs`. The phase is
**compile time** for every row.

| Detail | TCK type | Phase | Meaning |
| --- | --- | --- | --- |
| `UndefinedVariable` | `SyntaxError` | compile time | A variable is referenced where it is not in scope (e.g. a name not carried through a `WITH`). |
| `VariableAlreadyBound` | `SemanticError` | compile time | A pattern re-introduces a name already bound to an entity where Cypher forbids rebinding. |
| `VariableTypeConflict` | `SemanticError` | compile time | A name is bound to two incompatible entity kinds (e.g. node vs relationship) in one scope. |
| `AmbiguousAggregationExpression` | `SemanticError` | compile time | A projection mixes aggregating and non-aggregating terms so that the grouping is ambiguous. |
| `NestedAggregation` | `SemanticError` | compile time | An aggregating function is nested inside another aggregating function. |
| `InvalidAggregation` | `SemanticError` | compile time | An aggregation appears where aggregation is forbidden (e.g. `WHERE`, a pattern predicate, a variable-length bound). |
| `NoExpressionAlias` | `SemanticError` | compile time | A non-trivial `WITH`/`RETURN` expression lacks its mandatory `AS` alias. |
| `ColumnNameConflict` | `SemanticError` | compile time | Two projected result columns share the same name. |
| `NegativeIntegerArgument` | `SemanticError` | compile time | A position requiring a non-negative integer literal received a negative one (e.g. a variable-length lower bound). |
| `NoSingleRelationshipType` | `SemanticError` | compile time | A `CREATE`/`MERGE` relationship pattern does not specify exactly one relationship type. |
| `RequiresDirectedRelationship` | `SemanticError` | compile time | A `CREATE`/`MERGE` relationship pattern is undirected, but creation requires a direction. |
| `CreatingVarLength` | `SemanticError` | compile time | A `CREATE`/`MERGE` pattern uses a variable-length relationship, which is not creatable. |
| `UnknownFunction` | `SemanticError` | compile time | A function invocation names a function the database does not provide. |
| `InvalidNumberOfArguments` | `SemanticError` | compile time | A known function is called with the wrong arity. |
| `InvalidDelete` | `SemanticError` | compile time | `DELETE` targets something that is not a deletable graph entity reference. |
| `InvalidClauseComposition` | `SemanticError` | compile time | Clauses are composed in an order Cypher forbids (e.g. a `RETURN` that is not the final clause, or an empty single query). |

**Note on `UndefinedVariable`.** It is intuitively "semantic", but the openCypher TCK raises it as a
**`SyntaxError`** at compile time (verbatim in e.g. `tck/features/clauses/return/Return1.feature`).
Graphus follows the TCK, not intuition (`CLAUDE.md`: never guess; the TCK is inviolable). Both
`SyntaxError` and `SemanticError` are compile-time types, so this type choice does not affect the
phase split — the load-bearing invariant is unchanged.

### 2.3 Runtime error classes (the executor's responsibility)

The runtime error classes are raised by the executor during row production and are **not** part of
the compile-time table above. They are modelled by the execution layer, not by semantic analysis.
The categories are:

- **Arithmetic** errors — e.g. division by zero on actual data.
- **Type** errors — e.g. a type-coercion failure on an actual runtime value.
- **Entity** errors — e.g. an entity referenced at runtime that no longer exists.
- **Constraint** errors — e.g. a uniqueness or existence constraint violation, surfaced as the
  appropriate Cypher error class at commit/validation time (`04` §6.5).

These classes carry the phase `runtime`. They exist in this document to name the boundary; their
detailed taxonomy is owned by the executor and is specified with the relevant execution tasks.

### 2.4 Deferred — Neo4j two-letter Bolt status codes

The Neo4j two-letter Bolt status codes (for example `Neo.ClientError.Statement.SyntaxError`) are a
**Neo4j surface, not part of the openCypher TCK triple**. They are therefore **deferred** and are
**not invented here**. Mapping a Graphus `(phase, type, detail)` triple to a verbatim Neo4j status
code requires the pinned TCK and the certified Bolt driver artifacts, so this mapping is locked only
once those artifacts are in hand.

- **Flag:** derive the verbatim Neo4j status-code mapping from the pinned TCK tag and the certified
  driver versions before exposing Neo4j-compatible status codes over Bolt (`02` Q2; `04` §12 item
  13). Until then, a `FAILURE` carries the engine's own classified `(phase, type, detail)` rendered
  into its `code`/`message` fields (§3.1).

---

## 3. Bolt result and failure shapes

This section fixes how a query result and an error are shaped on the Bolt wire, referencing the
message set in `04-technical-design.md` §8.1 (it does not redefine the opcodes).

### 3.1 Result shape (RUN / PULL)

A successful query over Bolt produces this sequence of server messages (`04` §8.1 message set):

1. **`SUCCESS`** in response to `RUN`, carrying the **fields metadata** (the result column names, in
   order) and a query id.
2. A stream of **`RECORD`** messages, one per result row, each a PackStream list whose entries are
   the row's `Value`s in the order declared by the fields metadata. Records are produced lazily and
   pushed in response to the client's `PULL n` demand (flow control; `04` §7.7).
3. A trailing **`SUCCESS`** carrying the **result summary** (e.g. type of query, statistics /
   side-effect counters, and a `has_more` indicator when the client `PULL`ed a bounded batch).

`DISCARD` consumes (and discards) the remaining rows and yields the trailing `SUCCESS` summary
without emitting `RECORD`s.

### 3.2 Failure shape (FAILURE)

A Cypher error is delivered as a Bolt **`FAILURE`** message carrying two fields (`04` §8.1):

- **`code`** — a structured error code string.
- **`message`** — a human-readable description.

The mapping from a Cypher error's `(phase, type, detail)` triple onto a `FAILURE` is:

- The **type** and **detail** identify the error class and render into the `FAILURE` `code` (until
  the verbatim Neo4j status-code mapping is locked per §2.4, the `code` carries the engine's own
  classified rendering of the triple).
- The human message renders into the `FAILURE` `message`, preserving the offending byte position for
  compile-time errors (`graphus-cypher` carries the AST `Span` into the message; see
  `crates/graphus-cypher/src/errors.rs`).
- The **phase** does not appear as a separate `FAILURE` field, but it is observable: a
  **compile-time** error is returned in response to `RUN` **before any `RECORD`** is produced (no
  side effect has occurred), whereas a **runtime** error may arrive **after** some `RECORD`s have
  streamed.

After a `FAILURE`, the connection enters the `FAILED` state and the server **ignores all subsequent
client requests** (replying `IGNORED`) **until the client sends `RESET`** (the mandatory
fail-then-ignore-until-`RESET` rule; `04` §8.1).

### 3.3 REST failure shape (RFC 9457 problem+json)

Over REST the same Cypher error is rendered as an **RFC 9457 Problem Details** object
(`application/problem+json`; `04` §8.2). The `(phase, type, detail)` triple maps onto the problem
object's members as follows:

- The **type/detail** identify the error class, carried in the problem's `type`/`title` and an
  error-code member.
- The human message is carried in the problem's `detail` member.
- The **phase** is again observable rather than a named field: a compile-time error fails the
  statement before any NDJSON result row is emitted; a runtime error may surface after rows have
  begun streaming.

This keeps a single error model (`04` §8.3, "one executor, one value model") behind both the Bolt
`FAILURE` and the REST problem+json renderings.

---

## 4. REST transactional API — read/write access mode

This section closes `02` Q5 / `04` §12 item 14: the Bolt `BEGIN` message carries an access-mode
field (read vs write), but `04` §8.2 left the REST equivalent open. This spike specifies it.

### 4.1 Specification

- **Field.** A transaction opened against the REST transactional API (`04` §8.2) declares its access
  mode through an **`access_mode`** member of the request body sent to `POST /db/{db}/tx` (open an
  explicit transaction) and to the `POST /db/{db}/tx/commit` single-statement auto-commit shortcut.
- **Values.** The two permitted values are **`"READ"`** and **`"WRITE"`**, matching the Bolt
  `BEGIN` access-mode semantics so the two interfaces agree (`04` §8.3).
- **Default.** When the `access_mode` member is **absent**, the transaction defaults to
  **`"WRITE"`**. A write-mode transaction may execute both read and write statements, so defaulting
  to `WRITE` is the safe, least-surprising default for a single-node server (it never rejects a
  statement that an unspecified-mode caller intended to run).
- **Validation.** An `access_mode` value other than `"READ"` or `"WRITE"` (case-sensitive) is a
  client error: the request is rejected with an RFC 9457 problem+json response (`04` §8.2) and the
  transaction is not opened.
- **Enforcement.** A transaction opened with `access_mode` `"READ"` rejects any statement that would
  produce a side effect (a write). The rejection is surfaced as the appropriate Cypher/transaction
  error rendered as problem+json (§3.3), not as a server fault.

### 4.2 Rationale

- **Parity with Bolt.** Bolt `BEGIN` already carries read/write mode; declaring the same two values
  with the same meaning on REST keeps the "one executor, one value model" guarantee (`04` §8.3) and
  means a read-only transaction behaves identically regardless of entry point.
- **Default to `WRITE` for safety against accidental rejection.** On a single-node server in v1
  (`D-v1-topology`) the access mode is primarily an intent declaration (it is most useful for read
  routing in a cluster, which is Phase 2). Defaulting an unspecified transaction to `WRITE` ensures
  no statement is wrongly rejected for a caller who did not set the field, while callers who want the
  stricter read-only guarantee opt in explicitly with `"READ"`.

- **Flag (Phase 2):** when clustering / read-replica routing is introduced (`D-v1-topology`
  "clustering-ready interfaces"), revisit whether the REST `access_mode` should also influence
  routing, consistently with how Bolt `ROUTE` is handled.

---

## 5. What this spike resolves and what remains flagged

**Resolved by this document:**

- Bolt v1 version pinned to **5.4** (5.0 baseline through the 5.4 message set), legacy 4-slot
  handshake mandatory, PackStream v1 (§1) — closes `04` §12 item 11 for v1.
- The compile-time TCK error-classification table frozen and grounded in
  `crates/graphus-cypher/src/errors.rs` (§2) — closes `02` Q2 / `04` §12 item 13 for the
  compile-time surface.
- Bolt result and failure shapes, and their REST problem+json equivalent, fixed (§3).
- REST transactional API **`access_mode`** field specified (§4) — closes `02` Q5 / `04` §12 item 14.

**Remaining flagged (deferred, owner-visible):**

- **Bolt 5.7+ Manifest-v1 handshake** — Phase-2 scoping decision; v1 is legacy-handshake-only
  (§1.2; `04` §12 item 11).
- **Neo4j two-letter Bolt status codes** — deferred; they need the pinned TCK and certified driver
  artifacts to map verbatim and are not part of the openCypher TCK triple (§2.4; `02` Q2; `04` §12
  item 13).
- **REST `access_mode` routing semantics** — revisited when clustering / read replicas arrive
  (§4.2; `D-v1-topology`).
