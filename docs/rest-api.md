# REST WebAPI

The REST WebAPI is an HTTP/JSON interface to the same Cypher engine and transactions as
the Bolt interfaces. It is served over **TLS** (the Docker quickstart uses a self-signed
certificate, so clients pass `curl -k` / disable verification). The default database is
**`graphus`**.

- **Base URL:** `https://<host>:7474`
- **Authentication:** a Bearer JWT obtained from `POST /auth/login` (§1)
- **Content types:** request and response bodies are JSON by default; CBOR and
  (for results) NDJSON streaming are also negotiable (§6)

---

## Route summary

| Method   | Path                          | Auth          | Purpose |
| -------- | ----------------------------- | ------------- | ------- |
| `POST`   | `/auth/login`                 | none          | Exchange username + password for a Bearer JWT |
| `POST`   | `/db/{db}/tx/commit`          | Bearer        | Auto-commit: run statements in a single round-trip |
| `POST`   | `/db/{db}/tx`                 | Bearer        | Begin an explicit transaction |
| `POST`   | `/db/{db}/tx/{id}`            | Bearer        | Run statements in an open transaction (resets its timeout) |
| `POST`   | `/db/{db}/tx/{id}/commit`     | Bearer        | Run final statements and commit |
| `DELETE` | `/db/{db}/tx/{id}`            | Bearer        | Roll back an open transaction |
| `POST`   | `/db/{db}/graph`              | Bearer        | Run a read query, return a deduplicated graph projection |
| `POST`   | `/db/{db}/query/columnar`     | Bearer        | Run a read query, return an analytical columnar body |
| `GET`    | `/openapi.json`               | none          | The OpenAPI 3.1 document |
| `GET`    | `/health/live`                | none          | Liveness probe |
| `GET`    | `/health/ready`               | none          | Readiness probe |
| `GET`    | `/metrics`                    | Bearer*       | Prometheus metrics (admin Bearer or scrape token) |
| `GET`    | `/admin/status`               | Bearer (admin)| Server status + open-transaction count |
| `GET`    | `/admin/users/{name}`         | Bearer (admin)| Inspect a user's roles + password presence |
| `POST`   | `/admin/shutdown`             | Bearer (admin)| Begin a graceful shutdown |
| `POST`   | `/admin/db/{db}/bulk-import`  | Bearer (admin)| Streaming network bulk-import upload — Mode A §8.1.1, Mode B §8.1.2 |

---

## 1. Authentication — `POST /auth/login`

Exchange a username and password for a short-lived HS256 Bearer token, then send that token
as `Authorization: Bearer <token>` on every subsequent request. This is the only
unauthenticated transactional route; it is rate-limited to blunt brute-force attempts.

**Request** (`application/json`):

```json
{ "username": "graphus", "password": "graphus-local" }
```

**Response** `200 OK`:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_at_unix_secs": 1700003600
}
```

- The token is valid for 1 hour by default.
- Wrong password or unknown user → **`401`** with a uniform message (no user-exists oracle).
- Too many failed attempts → **`429`** (retriable; back off and try again).

```sh
TOKEN=$(curl -sk -X POST https://localhost:7474/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"graphus","password":"graphus-local"}' | jq -r .token)
```

> The JWT is signed with the server's `jwt_secret` (HS256). A password change immediately
> invalidates that user's outstanding tokens.

---

## 2. Running queries (auto-commit) — `POST /db/{db}/tx/commit`

The single-round-trip path: send one or more statements; they run in one transaction that
commits if they all succeed.

**Request:**

```json
{
  "statements": [
    { "statement": "CREATE (p:Person {name: $name}) RETURN p.name AS name",
      "parameters": { "name": "Ada" } }
  ],
  "access_mode": "WRITE"
}
```

**Response** `200 OK`:

```json
{
  "results": [
    {
      "fields": ["name"],
      "data": [[{ "U": "Ada" }]],
      "summary": { "type": "rw", "stats": { "nodes-created": 1 } }
    }
  ]
}
```

Result cell values are **strict-Jolt typed JSON** (`{"U":"Ada"}` is the string `"Ada"`), not
bare JSON — see §4.1.

```sh
curl -sk -X POST https://localhost:7474/db/graphus/tx/commit \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"MATCH (n) RETURN count(n) AS n"}],"access_mode":"READ"}'
```

---

## 3. Explicit transactions

For multi-request transactions, open one with `POST /db/{db}/tx`, run statements against the
returned id, then commit or roll back. A transaction is bound to the principal that opened
it (another principal targeting the same id gets a `404`).

**Begin** — `POST /db/{db}/tx` (body may set `access_mode`):

```json
{ "id": "tx-7a3b9c2e",
  "commit": "/db/graphus/tx/tx-7a3b9c2e",
  "expires_at_nanos": 1700000030000000000,
  "access_mode": "WRITE" }
```

- **Run** in the transaction: `POST /db/{db}/tx/{id}` with a `statements` body. The response
  is a `RunResponse` whose `id` and `expires_at_nanos` are refreshed (the timeout resets).
- **Commit** (optionally with final statements): `POST /db/{db}/tx/{id}/commit`.
- **Roll back**: `DELETE /db/{db}/tx/{id}` → `{ "rolled_back": true }`.

An idle open transaction is swept after a timeout, and the number a single principal may
hold open is bounded (excess `begin`s get a retriable `429`).

---

## 4. Request and response shapes

**Request** (`RunRequest`) — used by the auto-commit, run, and commit endpoints:

| Field         | Type                         | Notes |
| ------------- | ---------------------------- | ----- |
| `statements`  | array of `{statement, parameters?}` | `statement` is Cypher text; `parameters` is a JSON object or absent |
| `access_mode` | `"READ"` \| `"WRITE"`        | only meaningful on begin/auto-commit; defaults to `"WRITE"`; case-sensitive (any other value → `400`) |

**Response** (`RunResponse`):

| Field              | Type                                  | Notes |
| ------------------ | ------------------------------------- | ----- |
| `results`          | array of `{fields, data, summary}`    | one per statement, in order |
| `id`               | string (optional)                     | open-transaction id, while open |
| `expires_at_nanos` | number (optional)                     | refreshed expiry on the engine clock, while open |

Each result: `fields` is the ordered column names; `data` is the rows (each a list of cell
values in `fields` order); `summary` carries the query `type` (`r` read, `w` write, `rw`
read-write, `s` schema/admin) and `stats` — the side-effect counters as **plain JSON numbers**
(e.g. `"nodes-created": 1`, not Jolt-typed), present only when non-empty. The full counter-key list
is the Bolt result-summary contract in `specification/06-bolt-and-error-shapes.md` §3.1.

### 4.1 Value encoding (Jolt typed JSON)

Result cell values are encoded in **strict Jolt** — a typed JSON form where each scalar is a
single-key object whose key is a short type *sigil*. This is lossless (notably, 64-bit
integers survive JSON, which has no integer type): an integer comes back as
`{"Z": "<decimal>"}`, not a JSON number.

| `Value`     | Strict Jolt              | Example |
| ----------- | ------------------------ | ------- |
| null        | `null`                   | `null` |
| boolean     | `{"?": "true"\|"false"}` | `{"?": "true"}` |
| integer     | `{"Z": "<decimal>"}`     | `{"Z": "42"}` |
| float       | `{"R": "<decimal>"}`     | `{"R": "1.5"}` |
| string      | `{"U": "<text>"}`        | `{"U": "Ada"}` |
| bytes       | `{"#": "<UPPER-HEX>"}`   | `{"#": "DEADBEEF"}` |
| list        | JSON array of typed values | `[{"Z":"1"},{"U":"a"}]` |
| map         | `{"{}": { k: <typed> }}` | `{"{}": {"n": {"Z":"1"}}}` |
| temporal    | `{"T": "<ISO-8601>"}`    | `{"T": "2026-06-30"}` |
| point       | `{"@": { … }}`           | `{"@": {"srid": 4326, …}}` |

**Request parameters are more lenient:** they accept either strict Jolt **or** plain
("sparse") JSON, so you can send `{"parameters": {"name": "Ada", "age": 30}}` directly. A
sigil object always wins over the sparse reading. (Negotiating `application/cbor` carries the
same typed model in CBOR.)

---

## 5. Graph and columnar projections

- `POST /db/{db}/graph` runs a **read** query and returns a deduplicated graph projection:
  `{ "nodes": [{id, labels, properties}], "relationships": [{id, type, startNode, endNode, properties}] }`.
  Useful for visualization. It is forced to `READ`.
- `POST /db/{db}/query/columnar` runs a **read** query and returns an analytical
  **columnar** body (`Content-Type: application/x-graphus-columnar`) for large exports.

---

## 6. Content negotiation

| Direction | Header                          | Values |
| --------- | ------------------------------- | ------ |
| Request   | `Content-Type`                  | `application/json` (default), `application/cbor` |
| Response  | `Accept`                        | `application/json` (default), `application/cbor`, `application/x-ndjson` (single-statement streaming) |

With `Accept: application/x-ndjson`, a single-statement result streams incrementally — a
`fields` line, one `row` line per row, then a `summary` line — so server memory stays
bounded regardless of result size.

The request body is capped at 4 MiB (a larger body → `413`).

---

## 7. Errors (RFC 9457 problem+json)

Errors use `Content-Type: application/problem+json`:

```json
{ "type": "urn:graphus:error:compile",
  "title": "Cypher compile-time error",
  "status": 400,
  "detail": "Variable `foo` not defined",
  "code": "Neo.ClientError.Statement.SyntaxError" }
```

| HTTP  | When |
| ----- | ---- |
| `400` | Cypher syntax/argument error; malformed body; invalid `access_mode`; `/admin/db/{db}/bulk-import`: neither `phase` nor `end=true` given, an invalid `phase` value, an invalid `{db}` name, an invalid `mode`/`session` value, `mode=fresh` combined with `session=...`, or Mode B's `end=true` with no `session` |
| `401` | missing / invalid / expired Bearer token (and failed `/auth/login`) |
| `403` | valid token but the principal lacks the required privilege |
| `404` | unknown / expired transaction id (or one owned by another principal); `/admin/db/{db}/bulk-import`: unknown database |
| `406` / `415` | unacceptable `Accept` / unsupported `Content-Type` (`/admin/db/{db}/bulk-import`: an unrecognized `Content-Type` on a `phase=...` call) |
| `408` | `/admin/db/{db}/bulk-import` only: the session timeout (`bulk_import.session_timeout_ms`) elapsed |
| `409` | serialization conflict (retriable); `/admin/db/{db}/bulk-import` Mode A: the target database is already `Loading` (a concurrent session), not `Online`, or not empty; Mode B: the database is not `Online`, the named `session` is unknown/expired/busy/belongs to a different database, or a batch exhausted all automatic retries on a persistent SSI conflict |
| `413` | request body over 4 MiB (over the configured quota for `/admin/db/{db}/bulk-import`) |
| `429` | too many open transactions, or `/auth/login` rate-limited (retriable) |
| `500` | internal fault (detail redacted; logged server-side) |
| `503` | `/admin/db/{db}/bulk-import` Mode B only: the server-wide `mode_b_max_concurrent_sessions` cap is saturated |
| `507` | insufficient free disk space (`/admin/db/{db}/bulk-import` only) |

---

## 8. Health, metrics, and admin

- `GET /health/live` → `200 live` (always, while the process runs). Unauthenticated.
- `GET /health/ready` → `200 ready`, or `503` while starting/draining/degraded.
  Unauthenticated.
- `GET /metrics` → Prometheus text. **Fail-closed**: requires an admin Bearer, or
  `Authorization: Bearer <GRAPHUS_METRICS_SCRAPE_TOKEN>` if that token is configured.
- `GET /admin/status` → `{ "ready": true, "open_transactions": 3 }` (admin).
- `GET /admin/users/{name}` → `{ "user": "...", "roles": [...], "has_password": true }`
  (admin), or `404`.
- `POST /admin/shutdown` → `202 Accepted`, drain proceeds in the background (admin).

### 8.1 Network bulk import — `POST /admin/db/{db}/bulk-import`

Streams a large CSV (`neo4j-admin import` flavour) or `.gcol` (columnar) dataset into a
database over the network, for scale that ordinary parameterized Cypher cannot reach
(millions of nodes, hundreds of millions of relationships) — see
`specification/08-network-bulk-import.md` for the full design.

This endpoint supports **two modes**, declared explicitly via `?mode=` (never inferred, `08` §5):

- **Mode A** (default, `mode=fresh` or `mode` omitted): loading a **fresh, empty** database
  that is not yet serving ordinary traffic. The database is taken over exclusively (`Loading`
  state) for the session's duration.
- **Mode B** (`mode=live`, `rmp` #520): loading into an **already-live, already-serving**
  database, under ordinary concurrent Bolt/REST traffic, with **zero exclusivity** — the
  database is never taken offline. Every row is applied through the same transactional
  (SSI-checked) write path an equivalent Cypher `CREATE` would use, so it is fully
  serializable against concurrent traffic. See §8.1.2 below.

Mode A's own wire protocol, response shape, and every documented behavior below are
**unchanged** by Mode B's addition — a call with no `mode`/`session` parameter behaves
byte-for-byte as it always has.

#### 8.1.1 Mode A (default) — fresh, empty database

- **Auth:** the global `Admin` privilege — the same gate as `BACKUP`/`RESTORE`/
  `CREATE DATABASE`. Missing/invalid Bearer → `401`; valid Bearer without `Admin` → `403`.
  (Applies identically to Mode B, §8.1.2.)
- **Wire protocol — one session, several calls.** A bulk-import session is one or more
  `POST` calls against the same `{db}`, distinguished by a query parameter:
  - `?phase=nodes` / `?phase=relationships` — this call's body is **one** CSV (or `.gcol`)
    file. The **first** such call against a given `{db}` implicitly **begins** the session
    (moving the database to the `Loading` state, `08` §5.2); every subsequent call against
    the same, already-`Loading` database **continues** it. Response: `200 OK`,
    `Content-Type: application/json`, body `{"nodes":N,"relationships":M,"properties":P}` —
    the session's **cumulative** stats — once this call's whole file has been durably
    ingested (batch-by-batch, so the engine thread is never blocked for the whole upload).
  - `?end=true` — ends the session: durably deletes the internal checkpoint sentinel node,
    moves the database from `Loading` to `Offline` (never straight back to `Online` — the
    operator issues `START DATABASE` once satisfied with the load), and returns the same
    JSON shape with the final cumulative stats. Empty body, no `Content-Type` required.
    **Idempotent:** calling it when no session is active (never begun, or already ended) is
    a `200` no-op reporting `{"nodes":0,"relationships":0,"properties":0}`, never an error.
  - A request naming neither a recognized `phase` nor `end=true` → `400`.
- **`Content-Type`** (on `phase=...` calls): `text/csv` or `application/vnd.graphus.gcol` (a
  `;charset=...` parameter is ignored; matching is case-insensitive). Anything else → `415`.
  Node and relationship files are sent as **separate calls** — nodes must fully land before
  relationships that reference them.
- **Empty-database precondition:** checked only on the call that begins the session (the
  first call against a not-yet-`Loading` database): the database must contain zero nodes, or
  the call is rejected with `409` (pointing at Mode B, `rmp` #520, as the option for a
  non-empty database). A subsequent call against an already-`Loading` database skips this
  check (the database is by then non-empty by design).
- **Streaming, not buffered:** the body is read incrementally and is exempt from the
  general 4 MiB `DefaultBodyLimit` — it has its own configurable byte quota
  (`bulk_import.max_bytes_per_session`, default 8 GiB), enforced **per call** as bytes
  arrive. Exceeding it aborts the upload with `413` without ever holding the excess in
  memory. (`.gcol`'s CRC-framing makes it structurally impossible to decode incrementally,
  so a `.gcol` body is buffered whole — still byte-quota-bounded — before being transcoded
  to the same CSV shape the streaming path uses.)
- **Disk-space guard:** before accepting each call's upload, and periodically while
  streaming, the server checks free space on the target database's volume against
  `bulk_import.min_free_disk_bytes` (default 1 GiB). Insufficient space → `507`. `0`
  disables the check.
- **Session timeout:** `bulk_import.session_timeout_ms` (default 2 hours) bounds each
  individual call's wall-clock duration; exceeding it aborts that call with `408`.
- **Target database:** the `{db}` path segment; an unknown database → `404`.
- **Dropped-connection / retry contract:** if the connection drops mid-file, the in-flight
  batch is rolled back and the database **stays `Loading`** — a mid-file failure never
  forecloses resuming. Retry with the **same** `phase=...` call, resending the header plus
  every row not yet reflected in the last successful response's cumulative counts (rows from
  earlier, already-committed batches of the same call are safe and must not be resent, as
  long as the server process itself has not restarted). A client resuming after a **full
  server restart** must resume from the last **fully durable file boundary** (never
  mid-file) — this endpoint does not track byte offsets beyond the per-file resume above.
- **Status codes:**

  | HTTP | When |
  | ---- | ---- |
  | `200` | a `phase=...` batch was durably ingested, or `?end=true` completed (or was a no-op) — cumulative stats in the body |
  | `400` | neither `phase` nor `end=true` given; invalid `phase` value; invalid `{db}` name |
  | `401` | missing/invalid/expired Bearer token |
  | `403` | valid Bearer without the `Admin` privilege |
  | `404` | unknown database |
  | `409` | the database is not empty (Mode A's precondition — see Mode B, `rmp` #520), or is not currently online (offline, or another session is already `Loading` it) |
  | `413` | this call's upload crossed `bulk_import.max_bytes_per_session` |
  | `415` | unrecognized `Content-Type` on a `phase=...` call |
  | `408` | this call exceeded `bulk_import.session_timeout_ms` |
  | `507` | insufficient free disk space on the target database's volume |
  | `500` | a header/value-parse/storage error, or an internal fault (detail redacted where sensitive; logged server-side) |

Every session-lifecycle event (begin, each accepted batch, end, and every rejection) is
recorded in the security audit log (`security.md`).

```sh
# 1. Create an empty database for the load.
curl -sk -X POST $BASE/db/graphus/tx/commit \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"CREATE DATABASE loadtest"}]}'

# 2. Stream the node file (begins the session; the database moves to Loading).
curl -sk -X POST "$BASE/admin/db/loadtest/bulk-import?phase=nodes" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: text/csv" \
  --data-binary @nodes.csv

# 3. Stream the relationship file (nodes must already be fully landed).
curl -sk -X POST "$BASE/admin/db/loadtest/bulk-import?phase=relationships" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: text/csv" \
  --data-binary @rels.csv

# 4. End the session (Loading -> Offline) and start the database for ordinary traffic.
curl -sk -X POST "$BASE/admin/db/loadtest/bulk-import?end=true" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
curl -sk -X POST $BASE/db/graphus/tx/commit \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"START DATABASE loadtest"}]}'

# 5. The loaded data is now visible to ordinary queries.
curl -sk -X POST $BASE/db/loadtest/tx/commit \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"MATCH (n) RETURN count(n) AS c"}]}'
```

#### 8.1.2 Mode B (`mode=live`) — already-live database, concurrent, no exclusivity

`rmp` #520. Loads into a database that is **already `Online` and stays `Online`** for the
whole session — it is never taken offline, never moved to `Loading`, and continues serving
ordinary Bolt/REST reads and writes from other clients throughout the import. Every row is
applied through the same transactional (SSI-checked) write path an equivalent Cypher
`CREATE` would use, so the import is fully serializable against concurrent traffic (`08`
§7.2) — this is *why* it is safe to run without exclusivity, not a shortcut around safety.

- **Precondition:** the target database exists and is `Online`. Unlike Mode A, Mode B does
  **not** require the database to be empty — it is explicitly designed for incremental load
  into an already-populated, live graph. A database that is offline, `Loading`, or does not
  exist → `409` (offline/not-found cases already covered by the `404`/`409` rows in §8.1.1's
  status table — a non-existent database is still `404`, checked before `mode`/`session`
  parsing even runs).
- **Wire protocol — mode + session.** Every call adds two optional query parameters on top
  of Mode A's `phase=...`/`end=true`:
  - `?mode=live` — declares this call Mode B (required explicitly, or see the shorthand
    below — never inferred from anything else about the request). `?mode=fresh` (or
    omitting `mode` entirely) is Mode A, unchanged.
  - `?session=<uuid>` — the Mode B session id. **Omitted** on the call that **opens** a new
    session; **present** on every call that **continues** or **ends** an existing one. A
    present `session` with `mode` omitted is treated as `mode=live` (a convenience
    shorthand for "continue my session" — still an explicit declaration via `session`'s
    presence, never an inferred one). `mode=fresh` together with a `session` parameter is
    rejected with `400` (a session id is a Mode B concept only).
  - `phase=nodes` / `phase=relationships` with `mode=live` and **no** `session` → opens a
    **new** Mode B session against `{db}` (subject to the concurrent-session cap below) and
    streams this call's file into it. Response adds one field to the usual JSON body:
    `{"nodes":N,"relationships":M,"properties":P,"session":"<uuid>"}` — the newly-minted
    session id, to be reused on every subsequent call.
  - `phase=...` with `mode=live` (or the shorthand above) and a `session=<uuid>` naming a
    still-open session → continues it, streaming this call's file into it. Same response
    shape, echoing the same `session` id.
  - `?end=true&mode=live&session=<uuid>` → ends the session: removes it from the server's
    open-session registry and returns its final cumulative stats. **Idempotent**, mirroring
    Mode A's `End` contract exactly: an unknown, already-ended, or idle-reaped session id is
    a `200` no-op reporting zero stats, never an error. `?end=true&mode=live` **without** a
    `session` → `400` (a session id is required to know which session to end — Mode A's
    `end=true` has no such requirement since it is per-database, not per-session).
  - A `session=<uuid>` naming a session that is unknown, expired (idle-reaped), or currently
    busy (already driven by another in-flight call — a Mode B session is driven by **one**
    call at a time) → `409`. A `session=<uuid>` naming a session that exists but belongs to a
    **different** database than `{db}` → `409` (cross-database continuation is refused; the
    session remains usable against its own database).
- **No empty-database check, no `Loading` transition.** Everything else about the file
  format, `Content-Type` detection, streaming/quota/disk-space/timeout guards, and the
  target-database resolution is **identical** to Mode A (§8.1.1) — Mode B reuses the exact
  same streaming/CSV/`.gcol`/quota/disk-space/timeout machinery, branching only in how each
  batch is committed.
- **Server-wide concurrent-session cap** (`bulk_import.mode_b_max_concurrent_sessions`,
  default `8`, across *all* databases): opening a new session past the cap → `503`
  (`Retry-After`-style: "retry once another session ends"). Already-open sessions are
  unaffected by a rejected open attempt.
- **Batch size, chunking, and automatic retry** (server-side, not client-visible beyond the
  eventual response): each call's rows are grouped into **batches**
  (`bulk_import.mode_b_batch_rows`, default `2,000` — measured empirically, see the
  field's doc comment in `config.rs` for the abort-rate-vs-batch-size table this default is
  chosen from) and each batch into **chunks** (`bulk_import.mode_b_chunk_rows`, default
  `25`) dispatched as separate engine commands so the single engine thread is never
  monopolized by one Mode B session for more than a chunk's worth of work at a time (`08`
  §7.2.6/§8 — the fairness/DoS requirement). A batch that aborts on a genuine SSI conflict
  (the dominant, *correct* source of Mode B contention: a concurrent transaction that scans
  or counts the exact relationship type/rows being imported — `08` §7.2.1) is retried
  automatically up to `bulk_import.mode_b_max_batch_retries` times (default `5`, exponential
  backoff starting at `bulk_import.mode_b_retry_backoff_ms` = 20 ms, capped at 2 s); once
  exhausted, the call fails with `409` naming the exceeded retry count.
- **Crash / process-restart behavior — read this before relying on Mode B across a restart.**
  Every batch that committed before a crash is durable via ordinary WAL/ARIES recovery (`08`
  §7.2.5: no special mechanism is needed). An **in-process** HTTP reconnect (the server
  process itself never restarted) resumes a session for free — it is still parked, live, in
  the server's session registry. A full **server process restart** loses **every** in-memory
  Mode B session (there is no durable checkpoint sentinel for Mode B, unlike Mode A — see
  `crates/graphus-server/src/bulk_import_mode_b.rs`'s module doc for the full reasoning: a
  bookkeeping node would be visible to ordinary Cypher queries on a *live* database, an
  acceptable trade-off for Mode A's offline `Loading` database but not for Mode B's). The
  operator must open a **new** Mode B session after a restart and re-supply data from the
  last file boundary they tracked client-side. **This has a real, honest consequence:**
  Mode B does **not** deduplicate against external ids — a re-sent, already-committed row
  after a restart simply creates a **second** node/relationship with the same properties,
  exactly as an ordinary Cypher client re-running a `CREATE` after a crash would. This is not
  a defect; it is the correct consequence of "no exclusivity, ordinary transactional
  semantics" (`08` §5.3).
- **Status codes** (in addition to Mode A's table in §8.1.1, which still applies unchanged
  for `mode=fresh`/omitted):

  | HTTP | When |
  | ---- | ---- |
  | `200` | a `phase=...` batch was durably ingested, or `?end=true` completed (or was an idempotent no-op) — cumulative stats + `session` in the body |
  | `400` | `mode=fresh` combined with `session=...`; `?end=true&mode=live` with no `session`; an invalid `mode` value (anything other than absent/`fresh`/`live`); an invalid `session` value (not a UUID) |
  | `404` | unknown database (checked before `mode`/`session` parsing) |
  | `409` | the database is not `Online` (offline, or does not exist as `Online`); the named `session` is unknown/expired/busy; the named `session` belongs to a different database; a batch exhausted all automatic retries on a persistent SSI conflict |
  | `503` | the server-wide `mode_b_max_concurrent_sessions` cap is already saturated |

Every session-lifecycle event (open, continue, end, and every rejection) is recorded in the
security audit log (`security.md`), naming the mode and session id.

```sh
# 1. The target database is ALREADY live and serving traffic — no CREATE/STOP needed.
#    (Seed a little existing data to make the point concrete.)
curl -sk -X POST $BASE/db/livedb/tx/commit \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"CREATE (:Seed {x: 1})"}]}'

# 2. Open a Mode B session (no `session` param — a new one is minted) and stream the node file.
SESSION=$(curl -sk -X POST "$BASE/admin/db/livedb/bulk-import?phase=nodes&mode=live" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: text/csv" \
  --data-binary @nodes.csv | jq -r '.session')

# 3. The database is STILL live: an ordinary concurrent read succeeds right now.
curl -sk -X POST $BASE/db/livedb/tx/commit \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"MATCH (n) RETURN count(n) AS c"}]}'

# 4. Continue the SAME session for the relationship file, naming it explicitly.
curl -sk -X POST "$BASE/admin/db/livedb/bulk-import?phase=relationships&mode=live&session=$SESSION" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: text/csv" \
  --data-binary @rels.csv

# 5. End the session — the database was NEVER taken offline; no START DATABASE step needed.
curl -sk -X POST "$BASE/admin/db/livedb/bulk-import?end=true&mode=live&session=$SESSION" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

#### 8.1.3 Performance notes (Mode A)

Empirically measured (`rmp` #521, a ~65,000-user/~37.7M-relationship social-graph dataset with
the `huge` profile's friend-degree density, streamed over loopback HTTPS on an x86_64
workstation — see the project memory for the full write-up and numbers): the **node** phase is
very fast (a single hash-map insertion per row, no lookups); **relationship**-phase throughput
is markedly lower and dominated by the per-batch commit/dispatch cost over the network and the
single engine thread, not by raw store-write speed — expect low-thousands to low-tens-of-
thousands of relationship rows per second rather than the offline `graphus-bulk` importer's
`O(E)` in-process rate, and budget accordingly for very large transfers against
`bulk_import.session_timeout_ms`.

A background maintenance cadence (`rmp` #305) periodically pauses ingest for a full-store GC
pass. Its cost scales with the *current total store size*, not with bytes written since the
last pass — an insert-only workload like Mode A reclaims almost nothing on each pass, so a
naive fixed interval makes total maintenance overhead grow roughly quadratically with dataset
size over a long session. To keep this practical, a `Loading` database uses a **much wider**
maintenance interval than ordinary online traffic (`rmp` #521/#522) — a stopgap that
substantially reduces, but does not eliminate, this cost; a general fix (skip the reclaim scan
entirely when nothing has died since the last pass) is tracked as a follow-up (`rmp` #522).

User, role, and database administration is done by sending the administrative statements
(`CREATE USER`, `GRANT`, `CREATE DATABASE`, …) to the transactional endpoint as an
administrator — see [security.md](security.md).

---

## 9. End-to-end with curl

```sh
BASE=https://localhost:7474

# 1. Log in.
TOKEN=$(curl -sk -X POST $BASE/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"graphus","password":"graphus-local"}' | jq -r .token)

# 2. Write + read in one auto-commit call.
curl -sk -X POST $BASE/db/graphus/tx/commit \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"statements":[
        {"statement":"CREATE (:Person {name:$n})","parameters":{"n":"Ada"}},
        {"statement":"MATCH (p:Person) RETURN p.name AS name"}
      ]}'

# 3. Explicit transaction.
TX=$(curl -sk -X POST $BASE/db/graphus/tx \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"access_mode":"WRITE"}' | jq -r .id)
curl -sk -X POST $BASE/db/graphus/tx/$TX/commit \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"CREATE (:Person {name:\"Bob\"})"}]}'
```

A runnable Go version of this flow is in
[`examples/clients-go/rest`](../examples/clients-go/rest).

See also: [getting-started.md](getting-started.md) · [security.md](security.md) ·
[bolt.md](bolt.md) · [configuration.md](configuration.md).
