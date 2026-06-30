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

- **Handshake.** The client opens with the 4-byte magic preamble `60 60 B0 17` followed by
  four 32-bit version proposals. Graphus negotiates the highest mutually supported minor in
  the 5.0–5.4 window and replies with the chosen 4-byte version (or `00 00 00 00` to
  reject). The modern Manifest-v1 handshake is also supported.
- **Messages.** Each Bolt message is a PackStream structure framed in chunks (a 2-byte
  big-endian length per chunk, terminated by `00 00`). The request set used by a client is
  `HELLO`, `LOGON`, `RUN`, `PULL`/`DISCARD`, `BEGIN`/`COMMIT`/`ROLLBACK`, `RESET`,
  `GOODBYE` (and `ROUTE`/`TELEMETRY`); the server replies with `SUCCESS`, `RECORD`,
  `FAILURE`, `IGNORED`.
- **Errors.** A server-side problem arrives as a Bolt `FAILURE` carrying a Neo4j-style
  `code` and a human-readable `message`, after which the connection is `FAILED` until a
  `RESET`.
- **Result summary.** After a query's records, the trailing `SUCCESS` carries the summary:
  `type` — the query type (`r` read, `w` write, `rw` read-write, `s` schema/admin) — and
  `stats`, the side-effect counters (`nodes-created`/`-deleted`, `relationships-created`/`-deleted`,
  `properties-set`, `labels-added`/`-removed`, `indexes-added`/`-removed`,
  `constraints-added`/`-removed`, `system-updates`, `contains-updates`, and
  `contains-system-updates`), present only when non-empty. The official driver surfaces these as `summary().query_type` and
  `summary().counters.*`. The counters use Neo4j's operation-count model; the full contract is
  `specification/06-bolt-and-error-shapes.md` §3.1.

For the exact wire encoding, the authoritative reference is the `graphus-bolt` crate
(`handshake.rs`, `framing.rs`, `message.rs`, `packstream.rs`) — and the Go UDS example,
which transcribes it.

See also: [getting-started.md](getting-started.md) · [security.md](security.md) ·
[rest-api.md](rest-api.md) · [configuration.md](configuration.md).
