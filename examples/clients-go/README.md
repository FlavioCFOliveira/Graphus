# Graphus Go client examples

Runnable Go programs showing how to connect to Graphus over each of its three interfaces
and perform an authenticated round-trip (create → read → aggregate → clean up). Each lives
in its own directory and is a standalone `main` program in one Go module.

| Directory                | Interface          | Library                                   |
| ------------------------ | ------------------ | ----------------------------------------- |
| [`rest/`](rest)          | REST WebAPI (HTTP) | standard library (`net/http`, `crypto/tls`) |
| [`bolt-tcp/`](bolt-tcp)  | Bolt over TCP      | official `github.com/neo4j/neo4j-go-driver/v5` |
| [`bolt-uds/`](bolt-uds)  | Bolt over UDS      | a hand-rolled, dependency-free Bolt client |

Why a hand-rolled client for UDS? The official Neo4j driver only dials `host:port`, so it
cannot reach a Unix domain socket. `bolt-uds/bolt.go` implements just enough of Bolt 5.x +
PackStream v1 — faithfully transcribed from Graphus's own `graphus-bolt` crate — to speak
the protocol directly over the socket.

## Prerequisites

- **Go 1.23+**.
- A **running Graphus server** with the interface you want to exercise enabled, and a user
  you can authenticate as.

The quickest server to try them against is the Docker image (REST + Bolt-TCP):

```sh
docker run -d --name graphus -p 7687:7687 -p 7474:7474 -v graphus-data:/data graphus:latest
```

That publishes REST on `:7474` and Bolt-TCP on `:7687` with a self-signed certificate, and
the default administrator `graphus` / `graphus-local`. (UDS is a host-local socket; to try
the UDS example, run the server natively — see below.)

## Run

```sh
cd examples/clients-go
go mod download            # fetch the Neo4j Go driver (bolt-tcp only)

# REST WebAPI (login -> JWT -> query); -insecure accepts the self-signed cert:
go run ./rest      -url https://localhost:7474 -user graphus -password graphus-local -database graphus

# Bolt over TCP via the official driver; bolt+ssc:// accepts the self-signed cert:
go run ./bolt-tcp  -uri bolt+ssc://localhost:7687 -user graphus -password graphus-local -database graphus

# Bolt over UDS (see the dual-gate note below):
go run ./bolt-uds  -socket /data/graphus.sock -user graphus -password graphus-local
```

Each program also reads environment variables (`GRAPHUS_REST_URL`, `GRAPHUS_BOLT_URI`,
`GRAPHUS_UDS_SOCKET`, `GRAPHUS_USER`, `GRAPHUS_PASSWORD`, `GRAPHUS_DATABASE`).

### UDS has two authentication gates

The Unix-socket interface admits a connection only if **both** hold:

1. the connecting process's **OS uid is mapped** to a Graphus user (set `admin_uid` in the
   server's `[auth]` config to your uid — `id -u`); and
2. the Bolt **`LOGON`** (username + password) succeeds.

A minimal native server for the UDS example:

```toml
# graphus.toml
store_path = "./graphus-data"
rest_addr  = ""                 # disable network listeners for a pure-UDS demo
bolt_tcp_addr = ""
uds_path   = "./graphus.sock"

[auth]
admin_user     = "graphus"
admin_password = "graphus-local"
admin_uid      = 1000           # <-- set to your `id -u`
```

```sh
cargo run --release -p graphus-server -- graphus.toml &
go run ./bolt-uds -socket ./graphus.sock -user graphus -password graphus-local
```

## What they demonstrate

All three perform the same authenticated workload so you can compare the interfaces
directly: authenticate, `CREATE` a node with parameters, `MATCH` it back, run an aggregate
(`count`), and `DETACH DELETE` to stay idempotent. The `bolt-tcp` example additionally
shows an explicit managed-write transaction.

See the usage guides: [REST](../../docs/rest-api.md) · [Bolt](../../docs/bolt.md) ·
[Security](../../docs/security.md).
