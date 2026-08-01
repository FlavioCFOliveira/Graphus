# Bolt interfaces (UDS and TCP)

Graphus speaks the **Bolt 5.x** protocol (versions 5.0–5.4) with **PackStream v1**
serialization, exposed over two transports that share the same Cypher engine and the same
security catalog:

| Transport         | Use case                          | TLS         | Authentication                         |
| ----------------- | --------------------------------- | ----------- | -------------------------------------- |
| **Bolt over UDS** | local inter-process comms (IPC)   | none (local)| OS peer-credential **and** `LOGON`     |
| **Bolt over TCP** | network access, Neo4j drivers     | **required**| Bolt `LOGON` (username + password)     |

Because Graphus implements standards-compliant Bolt + PackStream, the entire **Neo4j
driver ecosystem** (Python, Go, Java, JavaScript, .NET, …) connects over TCP without
modification.

---

## Bolt over TCP

The networked transport, for drivers and remote clients.

- **Address:** `bolt_tcp_addr` (the Docker image publishes `0.0.0.0:7687`).
- **TLS is mandatory.** If `bolt_tcp_addr` is set without a TLS certificate, the server
  refuses to start. Configure the certificate with `GRAPHUS_TLS_CERT_PATH` /
  `GRAPHUS_TLS_KEY_PATH` (see [configuration.md](configuration.md)). The Docker entrypoint
  provisions a self-signed pair on first boot.
- **Authentication:** the driver sends `HELLO` then `LOGON` with the `basic` scheme; the
  password is verified against the stored Argon2id hash.

### Connection URI schemes

A Neo4j driver selects TLS behaviour through the URI scheme:

| Scheme        | Meaning                                              | When to use                         |
| ------------- | ---------------------------------------------------- | ----------------------------------- |
| `bolt+s://`   | TLS, certificate **verified** against a trusted CA   | production, CA-issued certificate   |
| `bolt+ssc://` | TLS, **self-signed** certificate accepted (no CA)    | the Docker quickstart's self-signed cert |
| `bolt://`     | plaintext (no TLS) — **rejected on TCP by Graphus**  | not usable over TCP                 |

### Example (Go, official driver)

The official Neo4j Go driver works directly. See
[`examples/clients-go/bolt-tcp`](../examples/clients-go/bolt-tcp):

```go
driver, _ := neo4j.NewDriverWithContext(
    "bolt+ssc://localhost:7687",
    neo4j.BasicAuth("graphus", "graphus-local", ""),
)
defer driver.Close(ctx)
res, _ := neo4j.ExecuteQuery(ctx, driver,
    "MATCH (n) RETURN count(n) AS n", nil,
    neo4j.EagerResultTransformer,
    neo4j.ExecuteQueryWithDatabase("graphus"))
```

```sh
go run ./bolt-tcp -uri bolt+ssc://localhost:7687 \
    -user graphus -password graphus-local -database graphus
```

The Python driver example is in the [README](../README.md#connecting).

---

## Bolt over UDS

The local **inter-process** transport — a Unix domain socket. It avoids the network stack
entirely, so it is the fastest path for a client on the same host.

- **Socket path:** `uds_path` (the Docker image uses `/data/graphus.sock`).
- **No TLS** — UDS is a kernel-protected local trust domain, gated by peer credentials
  instead.
- **Two authentication gates, both required:**
  1. **Peer-credential gate.** At accept time the server reads the connecting process's OS
     uid and resolves it to a Graphus user. An **unmapped uid is refused before any Bolt
     bytes flow** — the socket is simply closed. Map the OS uid that is allowed to connect
     with `admin_uid` in `[auth]`:

     ```toml
     [auth]
     admin_uid = 1000     # this OS uid may open the socket, mapped to admin_user
     ```

  2. **Bolt `LOGON`.** After admission, the session authenticates with username + password,
     exactly as over TCP.

### Stock drivers cannot dial a Unix socket

The official Neo4j drivers connect to `host:port` and do **not** expose Unix-socket
dialing. To use UDS you therefore speak Bolt directly over the socket. Two options:

- **The `graphus-cli` tool** — an interactive Bolt shell over UDS:

  ```sh
  graphus-cli --uds /data/graphus.sock --user graphus --password graphus-local
  ```

- **A raw Bolt client.** [`examples/clients-go/bolt-uds`](../examples/clients-go/bolt-uds)
  is a complete, dependency-free Go client that implements the handshake, HELLO, LOGON,
  RUN, PULL, GOODBYE, and a PackStream decoder — a faithful, readable reference for the
  wire protocol:

  ```sh
  go run ./bolt-uds -socket /data/graphus.sock \
      -user graphus -password graphus-local
  ```

---

## Protocol details

- **Handshake, and your slot order is honoured.** The client opens with the 4-byte magic preamble
  `60 60 B0 17` followed by four 32-bit version proposals. Graphus reads them **in the order you sent
  them** and answers the first it can serve within the 5.0–5.4 window, replying with that 4-byte
  version (or `00 00 00 00` to reject). So listing `5.1` ahead of `5.3` gets you 5.1 — the slot order
  is how the handshake lets a client state a preference, and it is binding. Within a *single*
  range-encoded proposal (which offers a span of minors) the highest supported minor of that span is
  chosen, since a range means "any of these". The modern Manifest-v1 handshake is also supported, and
  its marker slot competes by position on the same terms: a legacy proposal listed ahead of it wins.
  The top of the window can be capped with the `bolt_max_protocol_minor` startup option (both
  handshake forms honour the same cap); see
  [configuration.md](configuration.md#bolt-protocol-version-cap).
- **Authentication depends on the negotiated version.** From Bolt **5.1** the `HELLO` only
  negotiates and a separate `LOGON` authenticates. At Bolt **5.0** the `HELLO` does both: the
  authentication token (`scheme`, `principal`, `credentials`) travels in the `HELLO` `extra`
  map and a successful `HELLO` lands directly in `READY`. Graphus serves both flows, and the
  official drivers pick the right one automatically from the negotiated version.
- **Per-version message set.** Older minors define fewer messages, and Graphus rejects a
  message the negotiated version does not define (a `Neo.ClientError.Request.Invalid`
  `FAILURE`, like any other undecodable message) rather than acting on it: `LOGON` and
  `LOGOFF` exist from **5.1**, `TELEMETRY` from **5.4**; every other message spans the whole
  5.0–5.4 window.
- **Server agent.** The `HELLO` reply's `SUCCESS` carries a `server` agent string. Graphus announces
  `Graphus/<version>` by default — 100% Bolt-conformant and accepted by every modern Neo4j driver
  (which treat it as informational). For strict/legacy clients that demand the literal `Neo4j`, set
  the `bolt_server_agent` startup option (e.g. `neo4j-compat` → `Neo4j/5.13.0`); see
  [configuration.md](configuration.md#bolt-server-agent-legacy-driver-compatibility). This never
  affects conformance or negotiated capabilities.
- **Messages.** Each Bolt message is a PackStream structure framed in chunks (a 2-byte
  big-endian length per chunk, terminated by `00 00`). The request set used by a client is
  `HELLO`, `LOGON`, `RUN`, `PULL`/`DISCARD`, `BEGIN`/`COMMIT`/`ROLLBACK`, `RESET`,
  `GOODBYE` (and `ROUTE`/`TELEMETRY`); the server replies with `SUCCESS`, `RECORD`,
  `FAILURE`, `IGNORED`.
- **Errors.** A server-side problem arrives as a Bolt `FAILURE` carrying a Neo4j-style
  `code` and a human-readable `message`, after which the connection is `FAILED` until a
  `RESET`.
- **An out-of-order message closes the connection.** A message the current state defines no
  transition for at all — `COMMIT` with no open transaction, `LOGOFF` outside `READY`, `COMMIT` or
  `ROLLBACK` while a result is still streaming — is answered with
  `FAILURE {code: "Neo.ClientError.Request.Invalid"}` and the connection is then **closed**. It is
  not recoverable with `RESET`, matching the reference server, which treats an illegal transition as
  connection-terminating. Any open explicit transaction is rolled back first, so nothing is left
  half-applied or pinned. This is a different case from a message that is *legal* here and simply
  fails (a bad query, a refused impersonation): those leave the connection `FAILED` and a `RESET`
  recovers it as usual. The official drivers already avoid out-of-order messages — the Python
  driver's `_commit` consumes pending results before committing — so a conformant client never
  reaches this.
- **Impersonation (`imp_user`) is refused, never ignored.** `BEGIN`, `RUN` and `ROUTE` may carry an
  `imp_user` field naming the principal the client wants the server to act as. Graphus does **not**
  implement impersonation, so it **refuses** any message that carries one, with
  `FAILURE {code: "Neo.ClientError.Security.Forbidden"}`, and does not run the statement. It is
  refused rather than ignored because `imp_user` *drops* privileges: a server that accepted the field
  and ran as the connection's own principal would hand a middle-tier application (one pooled
  connection as a service principal, impersonating its end user per request) the service principal's
  full rights while the application believed it was scoped to one tenant.
  The refusal is unconditional and identical for every value — the named principal is never looked
  up, so the response reveals nothing about who exists. Any present, non-null value counts, including
  the empty string, a non-string value, and the connection's own principal; only an explicit `null`
  means "no impersonation requested". The connection enters `FAILED` and recovers with `RESET` like
  any other statement failure. Applications needing per-request identity should open a connection per
  principal, or authenticate the end user with `LOGON` (Bolt 5.1+ re-authentication).
- **Transaction timeout (`tx_timeout`) is honoured, and clamped downward only.** `BEGIN` and an
  auto-commit `RUN` may carry `tx_timeout`, a transaction budget **in milliseconds**. Graphus applies
  it as follows:
  - A **positive** value is honoured as an upper bound. On `BEGIN` it bounds the **whole**
    transaction, not each statement: every statement in it is limited to what remains of the budget,
    and a `COMMIT` arriving after the budget has run out is refused and the transaction rolled back —
    so a timed-out transaction never leaves half-applied state. On an auto-commit `RUN`, where the
    statement *is* the transaction, it bounds that statement.
  - The clamp is **downward only**. The effective per-statement budget is the *smaller* of the
    client's value and the server's configured `timing.statement_timeout_ms` (2 minutes by default);
    a client asking for more than the server allows gets the server's bound. The server's
    `timing.max_transaction_age_ms` sweep likewise still applies. A client can therefore always
    self-limit, and never buy itself more time than the operator allows.
  - **Zero or negative** means "the client sets no bound of its own", matching the reference server
    (which documents a zero duration as "the transaction does not have a timeout" and skips expiry
    for any non-positive value). The server's own bounds still apply, so this is not a way to run
    unbounded. The official drivers reject a negative value client-side.
  - A **non-integer** `tx_timeout` is refused with
    `FAILURE {code: "Neo.ClientError.Request.Invalid"}` rather than silently dropped.
  - When the budget expires, the failure carries
    `Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration` — the reference server's
    title for a bound the *client* configured. It is a non-retryable `ClientError`, because replaying
    a transaction that exhausted its own budget would simply exhaust it again. A statement cancelled
    mid-execution by the deadline currently surfaces the generic cancellation failure
    (`Neo.ClientError.Statement.ArgumentError`, message `query cancelled`) — the same non-retryable
    classification, with a less specific title.
- **Result summary.** After a query's records, the trailing `SUCCESS` carries the summary:
  `type` — the query type (`r` read, `w` write, `rw` read-write, `s` schema/admin) — and
  `stats`, the side-effect counters (`nodes-created`/`-deleted`, `relationships-created`/`-deleted`,
  `properties-set`, `labels-added`/`-removed`, `indexes-added`/`-removed`,
  `constraints-added`/`-removed`, `system-updates`, `contains-updates`, and
  `contains-system-updates`), present only when non-empty. The official driver surfaces these as `summary().query_type` and
  `summary().counters.*`. The counters use Neo4j's operation-count model; the full contract is
  `specification/06-bolt-and-error-shapes.md` §3.1.
- **Query plan (`EXPLAIN` / `PROFILE`).** A statement sent with the `EXPLAIN` prefix carries its plan in
  the trailing `SUCCESS` under `plan`; one sent with `PROFILE` carries it under `profile`, annotated with
  each operator's measured `rows` and `dbHits`. Exactly one of the two keys is ever sent (never both), and
  neither appears for an ordinary statement. Each plan node is a dictionary with `operatorType`, `args`,
  `identifiers` and — for a non-leaf — `children`, which is the shape the official drivers parse
  (`summary().plan` / `summary().profile`). See [cypher.md](cypher.md#query-prefixes--explain-and-profile).

For the exact wire encoding, the authoritative reference is the `graphus-bolt` crate
(`handshake.rs`, `framing.rs`, `message.rs`, `packstream.rs`) — and the Go UDS example,
which transcribes it.

See also: [getting-started.md](getting-started.md) · [security.md](security.md) ·
[rest-api.md](rest-api.md) · [configuration.md](configuration.md).
