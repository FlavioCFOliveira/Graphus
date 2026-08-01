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

### 1.3 The negotiated minor selects the message set and the authentication flow (rmp #906)

Negotiating "down to any 5.x minor in the 5.0–5.4 window" is only honoured if the server then
**serves that minor's protocol**, not the 5.4 one. Bolt introduces messages at exact minors, and the
authentication flow itself changed inside the window, so the state machine and the message registry
are both keyed on the negotiated version.

- **Authentication.** From **5.1**, `HELLO` only negotiates and a separate `LOGON` authenticates; at
  **5.0**, `HELLO` carries the authentication token in its `extra` map and a successful `HELLO` goes
  straight to `READY` (there is no `AUTHENTICATION` state at 5.0). The Bolt server-state
  specification's "Summary of changes" states it directly — *Version 5.1*: "HELLO message no longer
  accepts authentication … LOGON message has been added … LOGOFF message has been added"; *Version
  5.0*: "No changes compared to version 4.4".
- **The 5.0 authentication token** is the whole `HELLO` `extra` map **minus** the reserved protocol
  fields `patch_bolt`, `routing`, `user_agent`, `notifications_minimum_severity` and
  `notifications_disabled_categories` — the Neo4j reference server's rule
  (`HelloMessageDecoderV41` → `AuthenticationMetadataUtils.extractAuthToken`). Note that `bolt_agent`
  is a 5.3+ field and is deliberately **not** reserved at 5.0.
- **Message availability.** `LOGON` (`0x6A`) and `LOGOFF` (`0x6B`) exist from **5.1**; `TELEMETRY`
  (`0x54`) from **5.4**; every other message spans the whole window. A message the negotiated version
  does not define is **undecodable**, not merely out of order: it is answered exactly like any other
  malformed message (`Neo.ClientError.Request.Invalid` — terminal before authentication per the
  pre-auth rule, the recoverable `FAILED` state after it). The reference server implements this by
  *unregistering* those decoders at the affected versions.
- **Security invariant.** Every authentication path — the 5.0 `HELLO` and the 5.1+ `LOGON` — resolves
  through one chokepoint, so the per-account failed-authentication throttle and the global
  concurrent-verification bound apply identically. Negotiating an older minor MUST never be a way
  around a limiter.
- **Capped window.** The `bolt_max_protocol_minor` startup option narrows the advertised window
  (`5.0..=cap`). It is honoured by **both** handshake forms — the legacy 4-slot reply and the
  Manifest-v1 exchange — so the two can never advertise different windows, and it can only ever
  narrow, never widen, what Graphus offers.

### 1.4 Slot order is the client's preference, and it binds (`rmp` #910)

The four handshake slots are **resolved in the order the client sent them**, and the first slot the
server can satisfy wins. Graphus previously took the highest supported minor found anywhere in the
four slots. That silently overrode the one mechanism the handshake gives a client to state a
preference: a driver pinned to 5.1 for a known incompatibility at 5.3 listed 5.1 first and was
answered 5.3 anyway.

Two rules apply, and they are different by design — both are the reference server's:

| scope | rule | reference |
|---|---|---|
| **across slots** | the **first** satisfiable slot wins, however low its minor | `LegacyProtocolHandshakeHandler` iterates "every suggested protocol revision (in order of occurrence)" and stops at the first it can serve |
| **within one slot** | a range proposal means "any of these", so the **highest** supported minor of the span wins | `DefaultBoltProtocolRegistry.get` takes `max(Comparator.comparing(BoltProtocol::version))` over the versions one proposal matches |

The **Manifest-v1 marker** (`00 00 01 FF`) competes for attention by slot position like any other
proposal: the reference switches to the modern handshake only on *reaching* a manifest slot, having
already stopped at any earlier legacy proposal it could serve. Every official driver puts the marker
first with legacy fallbacks behind it, so the two readings agree on real traffic; they differ only
for a client that states a legacy preference ahead of the marker, and there the client's stated
preference is the answer.

### 1.5 An illegal transition terminates the connection (`rmp` #910)

**Ratified rule: a message for which the current state defines no transition at all closes the
connection.** The `FAILURE` carries `Neo.ClientError.Request.Invalid` and the socket is closed; there
is no state in which an illegal transition is survivable.

This is a *different fault* from a message that is legal in the state and merely **fails** — a bad
query, a refused impersonation (§3.6.1), a serialization conflict. Those enter the RESET-recoverable
`FAILED` state, because the server-state tables name `FAILED` as their failure target. An
out-of-order message appears in no table entry at all, and the reference server terminates it:
`IllegalTransitionException implements ConnectionTerminating`, whose `shouldTerminateConnection()` is
`true`, carrying `Request.Invalid` — the same code Graphus sends.

* **Why it matters beyond conformance.** A recoverable illegal transition lets a peer walk every
  message against every state on a single connection, each attempt costing it one `RESET`. Closing
  the connection makes each probe cost a full handshake and authentication.
* **Uniformity.** Pre-authentication this was already terminal (`rmp` #820: a recoverable `FAILED`
  let a later `RESET` resurrect an unauthenticated connection into `READY` with a `None` — i.e.
  unrestricted — principal). The post-authentication half now matches, so the rule needs no state
  qualifier.
* **`LOGOFF`** has exactly one source state, `READY`. A `LOGOFF` anywhere else is therefore an
  illegal transition and terminates, including inside an open explicit transaction — where it must
  additionally *not* drop the session principal.
* **No transaction may leak.** The terminal path rolls back any open explicit transaction
  **unconditionally** before closing. `Flow::Stop` returns from the message loop without passing
  through the EOF arm's cleanup, so without this an illegal transition sent inside a transaction
  would leave it pinning the GC watermark and holding its intents until the executor's `Drop`
  backstop ran (`rmp` #444). The rollback is deliberately ungated: gating it is precisely how
  `rmp` #613 leaked a transaction across a `RESET`.

#### 1.5.1 Ratified deviation: pre-authentication `TELEMETRY` is `DEFUNCT`, not `FAILED`

The Bolt server-state documentation's worked example shows a `TELEMETRY` sent outside `READY`
answered with `FAILURE` into the recoverable `FAILED` state. Graphus **deviates deliberately**: when
that `TELEMETRY` arrives *before authentication* (in `NEGOTIATION` or `AUTHENTICATION`), the
connection becomes `DEFUNCT`.

The deviation is security-motivated and was ratified with `rmp` #820. `RESET` is not a valid message
before authentication, and the same document's own state tables transition `NEGOTIATION` and
`AUTHENTICATION` to `DEFUNCT` on failure — so the example and the tables disagree. Following the
example would leave an *unauthenticated* connection in a state a subsequent `RESET` could return to
`READY` with a `None` principal, which the engine seam treats as unrestricted: an authentication
bypass reachable with two messages. The tables are followed; the example is not.

The deviation costs no interoperability: `TELEMETRY` exists only from 5.4, is advisory, and no
driver sends it before authenticating. Post-authentication `TELEMETRY` outside `READY` is an ordinary
illegal transition and is governed by §1.5 like every other message. A `TELEMETRY` *in* `READY` whose
`api` value is outside `0..=3` is a different case again — a legal message with a bad argument — and
takes the recoverable `FAILED` state the message specification mandates for it.

### 1.6 PackStream decode domains (`rmp` #911)

**Ratified rule: an out-of-domain temporal field is handled at the boundary — never stored, never
re-emitted.** Graphus accepted a `Time` past midnight, a `DateTime`/`LocalDateTime` nanosecond field
up to `u32::MAX`, an unbounded `Date.days` and any `tz_offset_seconds`, then **re-emitted** them, so
the failure surfaced at the client as a corrupt server response instead of at the boundary as a
client error — and the bad value could be stored as a property in between.

The larger consequence was an **identity divergence** of the same class as `rmp` #908: the wire kept
`nanos: 1_500_000_000` while the engine normalises the same instant to `(+1 s, 500_000_000)`, and the
temporal types derive `Eq`/`Ord`/`Hash` **component-wise** — so one instant with two spellings
compared unequal and *sorted apart*, and a property indexed under one spelling could not be found by
a query written with the other.

#### 1.6.1 The rules are per-tag, and they disagree

The reference readers do **not** apply a single rule, and the differences are load-bearing. Each rule
below is taken from the reader class for that tag:

| tag | field | rule | reference |
|---|---|---|---|
| `Date` 0x44 | `days` | **reject** outside years `-999999999..=999999999` | `DateValue.epochDateRaw` → `assertValidArgument(LocalDate.ofEpochDay)` |
| `LocalTime` 0x74 | `nanoseconds` | **reject** outside one day | `LocalTimeValue.localTimeRaw` → `assertValidArgument(LocalTime.ofNanoOfDay)` |
| `Time` 0x54 | `nanoseconds` | **normalise** (wrap into the day) | `TimeValue.timeRaw` → `OffsetTime.ofInstant(Instant.ofEpochSecond(0, n), offset)` |
| `Time` / `DateTime` | `tz_offset_seconds` | **reject** beyond ±64800 s (18 h) | `zoneOffsetOfTotalSeconds` → `ZoneOffset.ofTotalSeconds` |
| `LocalDateTime` 0x64 | `nanoseconds` | **normalise** into the seconds | `LocalDateTimeValue.localDateTimeRaw` → `ofInstant(Instant.ofEpochSecond(s, n), UTC)` |
| `DateTime` 0x49, `DateTimeZoneId` 0x69 | `nanoseconds` | bound to signed 32-bit, then **normalise** | the readers' explicit `Integer` bound + `Instant.ofEpochSecond` |
| `Duration` 0x45 | `nanoseconds` | full `i64`, then **normalise** into the seconds | `DurationValue`'s constructor carries `nanos / 1e9` into `seconds` |

`Time` and `LocalTime` carry the same field name and take **opposite** rules. Three of the four
premises this rule set was drafted from were wrong when checked against the source, so the rule for
any future temporal tag MUST be read off that tag's reader rather than inferred from a neighbour.

Normalisation here is not leniency — it is what makes a wire value and its in-engine twin *the same
value*. It is applied with **Euclidean** division, so a negative field (which the readers explicitly
permit) borrows rather than producing a negative component.

#### 1.6.2 Checked arithmetic, never clamping

The UTC-to-local combination (`local = utc + offset`) and the nanosecond carry use **checked**
arithmetic and refuse on overflow. Saturating silently discards the offset at the edges of the range,
so `DateTime { seconds: i64::MAX, offset: 3600 }` decoded to a *different* instant than it named and
re-encoded to *different bytes* — a value that fails no check anywhere and is simply wrong.

For `DateTimeZoneId` the nanosecond carry is applied **before** the zone lookup: the offset a zone
resolves to is a function of the instant (`rmp` #908 localizes at the decoded instant), and a carry
can move the instant across a DST boundary.

#### 1.6.3 Structure signatures are bounded to `0..=127`

PackStream specifies a structure's signature as a single **signed** byte, so the high bit is not part
of the tag space. Graphus accepted the full `0..=255`. The two agree behaviourally today — every tag
above `0x7F` is unknown and refused either way — but the bound makes the refusal name the real fault
and stops a future tag table claiming a byte the specification does not give it.

#### 1.6.4 Ratified deviation: strict UTF-8, not lossy substitution

A PackStream string whose bytes are not valid UTF-8 is a **decode error**. The reference server
substitutes U+FFFD for the malformed sequences and carries on.

Graphus deviates deliberately. Lossy substitution silently changes the client's data: a string that
arrives malformed is stored, indexed and compared as a *different* string than the one sent, and no
party is told. That directly contradicts the property everything else in this section exists to
protect — that a value is either the client's value or an error, never a third thing. Refusing costs
no interoperability, because every official driver encodes its strings as valid UTF-8; only a
hand-rolled or corrupting client can produce the case, and such a client is better served by a clear
error than by silently mangled data.

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
2. **type** (also called classification) — `SyntaxError`, `SemanticError`, `ProcedureError`,
   `ParameterMissing`, and the runtime types.
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

Semantic analysis raises exactly the errors below — the table is **exhaustive** over the
`SemanticErrorKind` enum (28 variants mapping onto the 27 distinct details below), and a
wildcard-free `match` in `crates/graphus-cypher/src/errors.rs` fails to compile the moment a new
variant is added without classifying it. Each row is a `(phase, type, detail)` triple. The **detail**
strings are taken **verbatim** from the openCypher TCK feature files (`tck/features/**`) that assert
them (the two details marked "internal" below are for Neo4j extensions absent from the TCK corpus),
and are pinned by tests in `crates/graphus-cypher/src/errors.rs`. The phase is **compile time** for
every row.

Measured over the whole pinned corpus, the openCypher TCK classifies **almost every** compile-time
fault as a **`SyntaxError`**; the only two exceptions — both from
`tck/features/clauses/call/Call1.feature` — are an unknown procedure (`ProcedureError`) and a missing
implicit-call parameter (`ParameterMissing`). **No** compile-time error is a `SemanticError`: the only
`SemanticError` the corpus asserts is the *runtime* `MergeReadOwnWrites`, which the executor (not
semantic analysis) raises. Graphus follows the measured TCK, not intuition (`CLAUDE.md`: never guess;
the TCK is inviolable).

| Detail | TCK type | Phase | Meaning |
| --- | --- | --- | --- |
| `UndefinedVariable` | `SyntaxError` | compile time | A variable is referenced where it is not in scope (e.g. a name not carried through a `WITH`). |
| `NoVariablesInScope` | `SyntaxError` | compile time | `RETURN *` is used where no variables are in scope. |
| `VariableAlreadyBound` | `SyntaxError` | compile time | A pattern re-introduces a name already bound to an entity where Cypher forbids rebinding. |
| `VariableTypeConflict` | `SyntaxError` | compile time | A name is bound to two incompatible entity kinds (e.g. node vs relationship) in one scope. |
| `AmbiguousAggregationExpression` | `SyntaxError` | compile time | A projection mixes aggregating and non-aggregating terms so that the grouping is ambiguous. |
| `NestedAggregation` | `SyntaxError` | compile time | An aggregating function is nested inside another aggregating function. |
| `InvalidAggregation` | `SyntaxError` | compile time | An aggregation appears where aggregation is forbidden (e.g. `WHERE`, a pattern predicate, a variable-length bound). |
| `NoExpressionAlias` | `SyntaxError` | compile time | A non-trivial `WITH`/`RETURN` expression lacks its mandatory `AS` alias. |
| `ColumnNameConflict` | `SyntaxError` | compile time | Two projected result columns share the same name. |
| `NegativeIntegerArgument` | `SyntaxError` | compile time | A position requiring a non-negative integer literal received a negative one (e.g. a variable-length lower bound). |
| `NoSingleRelationshipType` | `SyntaxError` | compile time | A `CREATE`/`MERGE` relationship pattern does not specify exactly one relationship type. |
| `RequiresDirectedRelationship` | `SyntaxError` | compile time | A `CREATE`/`MERGE` relationship pattern is undirected, but creation requires a direction. |
| `CreatingVarLength` | `SyntaxError` | compile time | A `CREATE`/`MERGE` pattern uses a variable-length relationship, which is not creatable. |
| `UnknownFunction` | `SyntaxError` | compile time | A function invocation names a function the database does not provide. |
| `InvalidNumberOfArguments` | `SyntaxError` | compile time | A known function or procedure is called with the wrong arity. |
| `ProcedureNotFound` | `ProcedureError` | compile time | A `CALL` names a procedure the database does not provide (`tck/features/clauses/call/Call1.feature`). |
| `InvalidArgumentType` | `SyntaxError` | compile time | A statically-typed function or procedure argument cannot satisfy the declared input type. |
| `MissingParameter` | `ParameterMissing` | compile time | A standalone implicit procedure call needs a query parameter that was not supplied (`tck/features/clauses/call/Call1.feature`). |
| `NonConstantExpression` | `SyntaxError` | compile time | A position requiring a constant expression received a row-dependent or non-deterministic one (`SKIP n.count`, `LIMIT n.count`, `count(rand())`). |
| `InvalidDelete` | `SyntaxError` | compile time | `DELETE` targets something that is not a deletable graph entity reference. |
| `InvalidClauseComposition` | `SyntaxError` | compile time | Clauses are composed in an order Cypher forbids (e.g. a `RETURN` that is not the final clause, or an empty single query). |
| `DifferentColumnsInUnion` | `SyntaxError` | compile time | The branches of a `UNION` return different column names. |
| `InvalidLoadCsvUrl` | `SyntaxError` | compile time | A `LOAD CSV ... FROM <expr>` URL is a statically-typed non-string literal. Internal detail: `LOAD CSV` is a Neo4j extension with no TCK counterpart. |
| `InvalidShortestPath` | `SyntaxError` | compile time | A `shortestPath(...)`/`allShortestPaths(...)` wraps a pattern that is not a single variable-length relationship between two node patterns. Internal detail: no TCK counterpart. |
| `UnexpectedSyntax` | `SyntaxError` | compile time | A syntactically-formed construct appears where the grammar forbids it (e.g. a bare pattern predicate in a `RETURN`/`WITH` projection, on the right-hand side of `SET`, or as a function argument). |
| `RelationshipUniquenessViolation` | `SyntaxError` | compile time | The same relationship variable is used more than once inside a single `MATCH` pattern (relationship isomorphism forbids traversing one relationship twice). |
| `InvalidParameterUse` | `SyntaxError` | compile time | A parameter (`$p`) appears where the grammar forbids it (e.g. as the inline property predicate of a `MATCH`/`MERGE` node or relationship). |

**Note on the `SyntaxError` classification.** Several of these details are intuitively "semantic"
(e.g. `UndefinedVariable`, `NestedAggregation`), but the openCypher TCK raises them as a
**`SyntaxError`** at compile time (verbatim in e.g. `tck/features/clauses/return/Return1.feature` and
the aggregation feature files). Graphus follows the measured TCK, not intuition. Because `SyntaxError`,
`ProcedureError`, and `ParameterMissing` are all **compile-time** types, this type choice does not
affect the phase split — the load-bearing invariant is unchanged.

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
3. A trailing **`SUCCESS`** carrying the **result summary** — the query `type`, the side-effect
   `stats` (present only when non-empty), a `has_more` indicator when the client `PULL`ed a
   bounded batch, and — for a statement carrying an `EXPLAIN`/`PROFILE` prefix — the execution-plan
   metadata under `plan`/`profile` (see "Execution-plan metadata" below).

`DISCARD` consumes (and discards) the remaining rows and yields the trailing `SUCCESS` summary
without emitting `RECORD`s.

**Query `type`** is exactly one of: `r` (read-only), `w` (writes, returns no rows), `rw` (writes and
returns rows), or `s` (schema/administrative — index/constraint DDL and database/user/role commands).

**`stats`** is the map of the statement's side-effect counters, included only when non-empty (a
read-only statement carries no `stats`). Keys are kebab-case and only non-zero counters appear:

| Key | Counts |
| --- | ------ |
| `nodes-created` / `nodes-deleted` | nodes created / actually deleted |
| `relationships-created` / `relationships-deleted` | relationships created / actually deleted |
| `properties-set` | property assignments — re-setting an equal value counts; `SET null`/`REMOVE` do not |
| `labels-added` / `labels-removed` | labels actually added / removed (an idempotent add/remove counts 0) |
| `indexes-added` / `indexes-removed` | indexes created / dropped (an idempotent `IF NOT EXISTS` / `IF EXISTS` no-op counts 0 and sets no `contains-updates`) |
| `constraints-added` / `constraints-removed` | constraints created / dropped |
| `system-updates` | system-database changes (database/user/role commands) |
| `contains-updates` | `true` whenever any data or schema counter is non-zero |
| `contains-system-updates` | `true` whenever a system-database change occurred |

The counters follow Neo4j's **operation-count** model (operations *applied* by the statement),
which deliberately differs from the openCypher **TCK observability** model: `CREATE (n) DELETE n`
reports `nodes-created: 1, nodes-deleted: 1` here, whereas the TCK observes no net side effect. The
two models are kept separate by design — the TCK conformance runner uses the observability model and
is never repointed at these wire counters.

**Execution-plan metadata (`plan` / `profile`).** A statement whose text carries an `EXPLAIN` or
`PROFILE` query prefix (`04-technical-design.md` §7.8) additionally reports its execution plan in the
result summary, under exactly one key: `plan` for an `EXPLAIN`, `profile` for a `PROFILE`. The two
keys are **mutually exclusive** (never both), and **neither** key appears for an ordinary statement.
`stats` follows its own rule independently: an `EXPLAIN` executes nothing, so it reports no `stats`
(the read-only-shaped summary), whereas a `PROFILE` reports `stats` exactly as the executed statement
would. An `EXPLAIN` also produces **zero `RECORD`s**, while the `RUN` `SUCCESS` still reports the
statement's real **fields** (its column names), matching Neo4j's `ExplainExecutionResult`.

The value under `plan` / `profile` is a **plan-node tree**. On the Bolt wire each node is a
PackStream dictionary; over REST it is a plain-JSON object (not a strict-Jolt result cell — the plan
is a diagnostic document, `04-technical-design.md` §8.2). Both renderings are produced from one
protocol-neutral description built in `graphus-cypher` (`04-technical-design.md` §7.8), so the two
interfaces can never disagree. Its shape matches Neo4j 5.x's `DefaultMetadataHandler.generateExecutionPlan`
and what the official drivers parse. A node carries:

| Field | Type | Notes |
| --- | --- | --- |
| `operatorType` | String | The operator's name. Always present (drivers read it with no null check). |
| `args` | Map | The wire key is `args`, never `arguments`. Contents below. |
| `identifiers` | List of String | The variables the operator's rows bind, in introduction order. |
| `children` | List of plan nodes | The operator's sub-plans. **Omitted entirely for a leaf operator** (a leaf sends no `children` key, not an empty list). |
| `rows`, `dbHits` | Integer | **`PROFILE` only**, as **top-level** siblings of the fields above (not nested in `args`). An `EXPLAIN` omits them: nothing ran, and Graphus never fabricates a runtime counter. |

`args` always carries `Details` (the operator's own rendered detail line). A `PROFILE` adds `Rows`
and `DbHits` (PascalCase duplicates of the top-level counters) on **every** operator. The **root**
node additionally carries `EstimatedRows` (the planner's cardinality estimate for the whole plan —
Graphus has no per-operator estimate and does not invent one), `planner` (`"COST"` when statistics
drove the cost-based optimiser, `"RULE"` otherwise) and `runtime` (`"VOLCANO"`). Graphus does **not**
emit `pageCacheHits`, `pageCacheMisses`, `pageCacheHitRatio` or `time`: it does not measure them, and
it never reports a counter it did not count. All four are optional on the wire and the official
drivers default them to `0`. The measured meaning of `dbHits` is defined in `04-technical-design.md`
§7.8.

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

### 3.4 `RESET` and `GOODBYE` transaction-control semantics

`RESET` and `GOODBYE` both have to leave the server's transaction state clean. Graphus's
**single-threaded, lockstep** session loop (one request decoded, dispatched, and fully answered
before the next is read — there is no asynchronous in-flight pipeline) shapes how it realises the
two messages relative to the letter of the Bolt spec:

- **`RESET` (serial-equivalence).** The Bolt spec describes `RESET` as a message that **jumps the
  queue**: it interrupts work already in progress and any messages the client *pipelined* ahead of
  it are answered `IGNORED`, after which the connection returns to a clean `READY`
  (neo4j.com/docs/bolt/current/bolt/message/, server-state appendix `INTERRUPTED`). Graphus has no
  queue to jump and no in-flight work to interrupt: by the time it reads `RESET`, every earlier
  message (e.g. a pipelined `RUN` + `PULL`) has **already been processed to completion**. `RESET`
  therefore (a) rolls back any open explicit transaction (best-effort), (b) discards any open result
  stream and resets the per-transaction `qid` counter, (c) replies `SUCCESS`, and (d) returns to
  `READY`. For a **lockstep client** this is **observably equivalent** to the spec's queue-jumping
  `RESET` — the same `SUCCESS` and the same clean `READY` result. The only divergence is for a
  client that *pipelines* `RUN` + `PULL` + `RESET` in one burst **expecting the in-flight `RUN`/`PULL`
  to be answered `IGNORED`**: Graphus instead answers them normally (they ran before `RESET` was
  seen) and then `SUCCESS`-es the `RESET`. The official Neo4j drivers drive `RESET` synchronously
  (they do not depend on the in-flight-`IGNORED` ordering for correctness), so this is conformant for
  the driver ecosystem. The `INTERRUPTED` state and pipelined-`IGNORED` ordering are **deliberately
  not modelled** in v1; revisit if/when an asynchronous request pipeline is introduced. Pinned by the
  `reset_after_run_pull_clears_state_serial_equivalence` regression test.

- **`GOODBYE` (transaction rollback symmetry).** The Bolt spec states `GOODBYE` "interrupts the
  server current work if there is any." An open explicit transaction is *current work*, so a
  `GOODBYE` received mid-transaction **explicitly rolls it back** — symmetric with the abrupt-EOF
  path, so neither a clean client close (`GOODBYE`) nor a dropped socket (EOF) can leak a transaction
  that would pin the GC watermark and block concurrent writers. The rollback is best-effort and
  idempotent (a no-op when nothing is open); the executor's `Drop` remains the final backstop for the
  panic path. Pinned by `goodbye_mid_tx_rolls_back_open_transaction` (and its no-op counterpart
  `goodbye_with_no_open_tx_does_not_roll_back`).

### 3.5 Several result streams open at once inside a transaction (`rmp` #907)

Inside an **explicit transaction** a client may start a new statement while an earlier result is
still being streamed, so the connection can hold **several open result streams at once**, each
addressed by its own `qid`.

**Specification.** The Bolt server-state page
(neo4j.com/docs/bolt/current/bolt/server-state/) is explicit about this:

- `TX_STREAMING`'s transitions include **`RUN to TX_STREAMING or FAILED`** (Table 6, whose response
  column is `SUCCESS {"qid": id::Integer}`), so a second statement inside the transaction is a valid
  message and leaves the connection streaming.
- The `PULL` and `DISCARD` tables (7 and 8) give the post-stream state as
  **"`TX_READY` or `TX_STREAMING` if there are other streams open"**, so consuming or discarding one
  of several results does **not** return the connection to `TX_READY`.
- `qid` defaults to `-1`, "the last executed statement". Graphus resolves that to the **most recently
  opened** statement of the current transaction, matching the reference server (`TransactionImpl`
  records a `latestStatementId` at `run` and `StreamingStateTransition` resolves `-1` to it). A `qid`
  — including a resolved `-1` — that names no *live* statement is a protocol error
  (`Neo.ClientError.Request.Invalid` → `FAILED`), again matching the reference server, which throws
  when the resolved id has no open statement.

**Why it matters.** The official drivers depend on it. The Neo4j Python driver buffers the previous
result before the next `tx.run()` **only** when `connection.supports_multiple_results is False` — a
branch its own comment labels "Bolt 3 Support" — and `_bolt5.py` sets `supports_multiple_results =
True`. On Bolt 5.x the driver therefore leaves the earlier result open. A transaction whose first
result exceeds the driver's fetch size (1000 by default) answers its first `PULL` with
`has_more: true` and is still `TX_STREAMING` when the second `tx.run()` arrives; a single-stream
server rejects it and the transaction dies. Results smaller than the fetch size drain to `TX_READY`
first, which is why the defect was invisible to a suite that only used small results.

**Auto-commit `STREAMING` stays single-stream**, deliberately: `STREAMING`'s transition table lists
only `PULL` and `DISCARD`, and an auto-commit `RUN` is assigned no `qid`, so a second auto-commit
result could not be addressed even if one were opened.

**`COMMIT` / `ROLLBACK` with streams open are refused.** Neither appears among `TX_STREAMING`'s
transitions — both are listed for `TX_READY` only — and the specification states that the results
"must be fully consumed or discarded by a client before the server can transition to the `TX_READY`
state". Graphus therefore answers them with `FAILURE` → `FAILED` exactly as it does any other
out-of-order message; `RESET` recovers the connection and rolls the transaction back. This is what
the drivers already do: the Python driver's `_commit` and `_rollback` both call `_consume_results()`
first ("DISCARD pending records then do a commit"), so a conformant client never sends either here.
Note this is *stricter* than the Neo4j reference server, which merges `TX_READY` and `TX_STREAMING`
into one `IN_TRANSACTION` state and so accepts `COMMIT` with statements still open; Graphus follows
the published state machine, and no driver is affected.

**`RESET` and a failure both discard every stream.** `RESET` must return the connection to the state
it would have "as if `HELLO`/`LOGON` had just successfully completed", which has no open results at
all, so it drops **all** streams, resets the `qid` counter and rolls the transaction back (the
`rmp` #613 contract, generalised). Likewise, a `FAILURE` on any one stream drops **all** of them
before entering `FAILED`, so no stream is orphaned; `GOODBYE` and EOF roll the transaction back
exactly once however many streams were open.

**Bound.** The number of concurrently-open streams **per transaction** is capped
(`SessionConfig::max_open_streams_per_tx`, default `DEFAULT_MAX_OPEN_STREAMS_PER_TX = 64`). The
specification sets no limit and the reference server keeps an unbounded map, but on an authenticated
connection an unbounded collection is an attacker-controlled allocation: each open stream pins a
cursor, a result channel and an engine **admission permit** for its whole lifetime. The engine's
per-database admission budget is `admission.max_concurrent_queries` (256 by default), so a
per-transaction cap of a quarter of it means no single transaction can monopolise a database's
admission capacity with results nobody reads, while remaining an order of magnitude above any real
driver's usage. Exceeding it answers the offending `RUN` with `Neo.ClientError.Request.Invalid` →
`FAILED` — a *client* error, because retrying would hit the same limit and it must not look
retryable to a driver — and the refused statement is never started.

### 3.6 Transaction-initiating `extra` fields: `imp_user` and `tx_timeout` (`rmp` #909)

`BEGIN`, `RUN` and `ROUTE` carry an `extra` map that is *entirely client-controlled*. Graphus read
`mode` and `db` from it and discarded the rest. Two of the discarded fields change what the client
believes the server is doing, so silently dropping them is a conformance defect with a security
consequence, not a missing nicety.

**Ratified rule: a transaction-initiating `extra` field is either honoured or refused. It is never
accepted and ignored.** Reading the map is therefore a single validated parse (`parse_tx_extra` /
`parse_route_extra` in `graphus-bolt`'s `server.rs`), and the `mode`/`db` accessors are only reachable
through it — so a future dispatch arm cannot obtain `db` while dropping a field that matters.

#### 3.6.1 `imp_user` — refused

Graphus does not implement impersonation. Any `BEGIN`/`RUN`/`ROUTE` whose `extra` carries a
**present, non-null** `imp_user` is answered with `FAILURE`
`Neo.ClientError.Security.Forbidden` → `FAILED` (RESET-recoverable), and the statement is not run.

* **Why refuse rather than ignore.** `imp_user` *drops* privileges. Running as the connection
  principal instead is a failure to downgrade: the middle-tier multi-tenant pattern (one pooled
  connection as a service principal, impersonating the end user per request) would execute every
  tenant's request with the service principal's full rights, and the application would have no signal.
* **Why this code.** The reference server answers a rejected impersonation in the
  authentication/authorization class (`SimpleImpersonationStateTransition` wraps the realm's
  `AuthenticationException` into `AuthenticationStateTransitionException`, carrying its security
  status). `Neo.ClientError.Security.Forbidden` is documented by Neo4j as "An attempt was made to
  perform an unauthorized action". **Deliberate deviation:** Neo4j *Community* happens to raise
  `Neo.ClientError.Statement.ArgumentError` (`BasicSystemGraphRealm.impersonate` throws
  `InvalidArgumentException.unsupportedInCommunity`); that title is indistinguishable from "your
  query's arguments are wrong", and a client must be able to tell "impersonation refused" from a
  malformed statement. `Neo.ClientError.Security.Unauthorized` was also rejected: it means "your
  credentials were not accepted" and would make a driver invalidate a valid auth token.
* **Driver behaviour** (verified against the official `neo4j-driver` 6.2.0 sources): a
  non-retryable `ClientError`; not listed by the static/basic auth-token managers, so no
  credential-refresh loop; and the pooled connection provider closes the connection carrying it,
  which matches the reference server terminating a connection whose impersonation fails
  (`AuthenticationStateTransitionException implements ConnectionTerminating`).
* **Boundary cases, all ratified as refusals:** the empty string (the reference decoder does *not*
  fold `""` into "absent" the way it does for `db`); a non-string value (otherwise `imp_user: 1`
  would read as absent and be a bypass straight back to running as the connection principal); and
  the connection's **own** principal (the reference gates on `!= null` with no self-check, and a rule
  whose outcome depended on matching the session principal would make behaviour a function of a
  client-supplied name for no benefit). Only an explicit `null` means "absent".
* **No principal-existence oracle.** The refusal is unconditional and identical for every value: the
  named principal is never looked up, never compared, never echoed, so the response carries no
  signal about who exists (preserving `rmp` #812's constant-work property).
* **Connection state.** `FAILED`, not `DEFUNCT`. The Bolt server-state tables give `FAILED` as the
  failure target for `BEGIN`/`RUN` in `READY`; termination is reserved for the pre-authentication
  states (`rmp` #820). The guard sits *after* the state match, so an out-of-order message is still
  reported as an illegal transition and a pre-authentication failure stays terminal.
* **Not delivered here:** real impersonation (resolving the impersonated principal's
  `EffectivePrivileges` for the transaction, gated on an impersonation privilege). It is a separate,
  larger change; until it lands the refusal is the only correct behaviour.

#### 3.6.2 `tx_timeout` — honoured, clamped downward only

`tx_timeout` is a transaction budget in **milliseconds**.

| value | effect |
|---|---|
| absent / `null` | no client-imposed bound (unchanged behaviour) |
| `> 0` | honoured as an upper bound, clamped against the server's |
| `<= 0` | no client-imposed bound |
| non-integer | `FAILURE` `Neo.ClientError.Request.Invalid` → `FAILED` |

* **Scope.** On `BEGIN` it bounds the **transaction**: an absolute deadline is fixed at `BEGIN`, every
  statement inside is limited to what *remains*, and a `COMMIT` arriving after it is refused with the
  transaction rolled back (no half-applied state). A per-statement reading would let a client hold a
  transaction open indefinitely by running one cheap statement after another — exactly the
  GC-watermark pin `timing.max_transaction_age_ms` exists to prevent. On an auto-commit `RUN` the
  statement is the transaction, so it bounds the statement.
* **The clamp is downward only.** The effective per-statement budget is
  `min(timing.statement_timeout_ms, tx_timeout)`, computed at the single authoritative point
  (`exec::effective_statement_timeout`), and `timing.max_transaction_age_ms` still applies. A client
  can always self-limit and can never raise its own ceiling — otherwise `tx_timeout` would be a
  one-field escape from the CPU-exhaustion defence of `rmp` #476. This matches the contract the
  official drivers document for Neo4j 4.2–5.2 ("values higher than the server's configured timeout
  are ignored"); Graphus applies it at every version.
* **Non-positive values.** Neo4j documents `Duration.ZERO` as "the transaction does not have a
  timeout" (`TransactionTimeout`) and its expiry sweep gates on `timeoutNanos > 0`
  (`TransactionMonitor.checkExpiredTransaction`), so a non-positive value is neither an error nor a
  licence to run unbounded: it means the client set no bound, leaving the server's bounds in charge.
* **Expiry status code.** `Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration` — the
  reference server's title for a bound the *client* configured (`KernelImpl` selects between it and
  `TransactionTimedOut` by who supplied the value). It is a **non-retryable** `ClientError`, as in the
  reference: replaying a transaction that exhausted its own budget would exhaust it again, and a
  `TransientError` would make the drivers' managed-transaction retry burn its budget on it.
* **Overflow.** The deadline is built with `Instant::checked_add`, never `+`: `Instant + Duration`
  panics on overflow and the addend is client-chosen (`tx_timeout: i64::MAX` normalises to a
  ~292-million-year duration, whose representability depends on the platform's `Instant`). An
  unrepresentable deadline degrades to "no client bound", which raises no ceiling.
* **Interfaces.** `tx_timeout` is a Bolt `extra` field; REST carries no per-request statement budget
  and is unchanged.

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
- `RESET` serial-equivalence and `GOODBYE` transaction-rollback symmetry for the single-threaded
  lockstep session loop documented (§3.4) — closes the `RESET` queue-jump / `GOODBYE` rollback
  question for v1 (rmp #444).
- REST transactional API **`access_mode`** field specified (§4) — closes `02` Q5 / `04` §12 item 14.

**Remaining flagged (deferred, owner-visible):**

- **Bolt 5.7+ Manifest-v1 handshake** — Phase-2 scoping decision; v1 is legacy-handshake-only
  (§1.2; `04` §12 item 11).
- **Neo4j two-letter Bolt status codes** — deferred; they need the pinned TCK and certified driver
  artifacts to map verbatim and are not part of the openCypher TCK triple (§2.4; `02` Q2; `04` §12
  item 13).
- **REST `access_mode` routing semantics** — revisited when clustering / read replicas arrive
  (§4.2; `D-v1-topology`).
- **Bolt `INTERRUPTED` state / pipelined-`RESET` `IGNORED` ordering** — not modelled in v1; Graphus's
  lockstep loop makes `RESET` serial-equivalent for the driver ecosystem (§3.4). Revisit if an
  asynchronous request pipeline is introduced (rmp #444).
