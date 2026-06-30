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
| `400` | Cypher syntax/argument error; malformed body; invalid `access_mode` |
| `401` | missing / invalid / expired Bearer token (and failed `/auth/login`) |
| `403` | valid token but the principal lacks the required privilege |
| `404` | unknown / expired transaction id (or one owned by another principal) |
| `406` / `415` | unacceptable `Accept` / unsupported `Content-Type` |
| `409` | serialization conflict (retriable) |
| `413` | request body over 4 MiB |
| `429` | too many open transactions, or `/auth/login` rate-limited (retriable) |
| `500` | internal fault (detail redacted; logged server-side) |

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
