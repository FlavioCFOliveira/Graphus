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
| `POST`   | `/admin/db/{db}/bulk-import`  | Bearer (admin)| Streaming network bulk-import upload (§8.1) |

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
| `400` | Cypher syntax/argument error; malformed body; invalid `access_mode`; `/admin/db/{db}/bulk-import`: neither `phase` nor `end=true` given, an invalid `phase` value, or an invalid `{db}` name |
| `401` | missing / invalid / expired Bearer token (and failed `/auth/login`) |
| `403` | valid token but the principal lacks the required privilege |
| `404` | unknown / expired transaction id (or one owned by another principal) |
| `406` / `415` | unacceptable `Accept` / unsupported `Content-Type` (`/admin/db/{db}/bulk-import`: an unrecognized `Content-Type` on a `phase=...` call) |
| `408` | `/admin/db/{db}/bulk-import` only: the session timeout (`bulk_import.session_timeout_ms`) elapsed |
| `409` | serialization conflict (retriable); `/admin/db/{db}/bulk-import`: the target database is already `Loading` (a concurrent session), not `Online`, or not empty (Mode A's precondition — see §8.1) |
| `413` | request body over 4 MiB (over the configured quota for `/admin/db/{db}/bulk-import`) |
| `429` | too many open transactions, or `/auth/login` rate-limited (retriable) |
| `500` | internal fault (detail redacted; logged server-side) |
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

This endpoint implements **Mode A**: loading a **fresh, empty** database that is not yet
serving ordinary traffic. **Mode B** — bulk-importing into an already-live, already-serving,
non-empty database under concurrent Bolt/REST traffic — is `rmp` #520 and is **not yet
implemented**; this endpoint `409`s cleanly (see the status table below) if attempted
against a non-empty database rather than attempting it.

- **Auth:** the global `Admin` privilege — the same gate as `BACKUP`/`RESTORE`/
  `CREATE DATABASE`. Missing/invalid Bearer → `401`; valid Bearer without `Admin` → `403`.
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
