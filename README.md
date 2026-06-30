# Graphus

Graphus is a **Label Property Graph (LPG) database server** written in Rust, designed to
operate exemplarily under extreme load and concurrency. It is built to be **100% ACID
compliant** and **100% Cypher TCK compliant**, with a **multigraph** model by default.

It exposes three connection interfaces — **Bolt over UDS**, **Bolt over TCP** (`bolt://`),
and a **Web REST API** — and targets Linux, macOS, and Raspberry Pi OS on x86_64 and
aarch64 (including Apple Silicon and Raspberry Pi 5+).

## Status

Released — **v0.0.2** (see the [CHANGELOG](CHANGELOG.md) and
[releases](https://github.com/FlavioCFOliveira/Graphus/releases)). The single-node
correctness core is complete and production-hardened: the four inviolable guarantees —
**100% ACID**, **100% openCypher TCK** (pinned `2024.3`), **100% Bolt protocol**, and
**100% PackStream** — hold, validated by an extensive test suite including a deterministic
simulation tester (DST/VOPR). A production-grade, multi-architecture Docker image is
published. The complete **specification** lives in [`specification/`](specification/).

## Documentation

Usage documentation is in **[`docs/`](docs/)** — start with
[`docs/getting-started.md`](docs/getting-started.md):

| Guide | Covers |
| --- | --- |
| [getting-started](docs/getting-started.md) | Install with Docker, credentials, first query per interface |
| [rest-api](docs/rest-api.md) | REST WebAPI: login/JWT, queries, transactions, errors, health |
| [bolt](docs/bolt.md) | Bolt over TCP (Neo4j drivers) and UDS (local IPC) |
| [security](docs/security.md) | Credentials, users, roles, and access control (RBAC) |
| [configuration](docs/configuration.md) | Every config key and `GRAPHUS_*` environment variable |

Runnable **Go client examples** for all three interfaces are in
[`examples/clients-go/`](examples/clients-go).

## Repository layout

| Path | Contents |
| --- | --- |
| `specification/` | The functional + technical specification (the single source of truth for *what* and *how*). |
| `crates/` | The Cargo workspace (see below). |
| `CLAUDE.md` | Operating instructions for the AI agent working on the project. |

## Workspace

A single Cargo workspace (Rust edition 2024). Crates follow the layered architecture in
`specification/04-technical-design.md`:

| Crate | Responsibility |
| --- | --- |
| `graphus-core` | Shared IDs, the Cypher value model, errors, capability traits, constants. |
| `graphus-sim` | Deterministic + production capability implementations for DST. |
| `graphus-io` | Async file/socket I/O (epoll/kqueue + optional io_uring); fsync threads. |
| `graphus-wal` | ARIES write-ahead log, group commit, checkpoints, recovery. |
| `graphus-bufpool` | Self-managed buffer pool, page format, checksums. |
| `graphus-storage` | Record store with index-free adjacency, tokens, element-ID map. |
| `graphus-index` | B+-tree, token-lookup, composite and relationship-property indexes; constraints. |
| `graphus-txn` | MVCC + Serializable Snapshot Isolation transaction manager. |
| `graphus-cypher` | Cypher parse → plan → execute pipeline (targets 100% TCK). |
| `graphus-gds` | In-memory CSR graph projection + a library of graph data science algorithms. |
| `graphus-bolt` | Bolt protocol + PackStream over UDS and TCP. |
| `graphus-rest` | HTTP transactional API (typed JSON / CBOR, NDJSON streaming). |
| `graphus-auth` | Peer-credential, JWT/Bearer auth and RBAC, shared across listeners. |
| `graphus-crypto` | Authenticated encryption at rest (AES-256-GCM page encryption + HKDF keyring). |
| `graphus-bulk` | Offline high-throughput CSV bulk import and whole-graph export. |
| `graphus-server` | The server process: wiring, admission control, observability. |
| `graphus-cli` | Interactive shell and admin client. |
| `graphus-tck` | openCypher TCK harness. |
| `graphus-dst` | Deterministic simulation scenarios and fault injection. |
| `graphus-bench` | Criterion micro-benchmarks and the LDBC SNB macro harness. |
| `graphus-elle` | Isolation-anomaly (Elle/Jepsen-style) checking. |

## Building

```sh
cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

## Running with Docker

Graphus ships a production-grade, **multi-architecture** container image of the
`graphus-server`. A single image runs without problems on **x86 / amd64**,
**aarch64 / arm64**, **Raspberry Pi 5**, and **Apple Silicon** (M1–M5, via Docker's
Linux/arm64 runtime). All persistent state lives under **`/data`** — mount a volume
there and your databases survive container restarts and recreation.

> ⚠️ **Local quickstart defaults.** On first boot the entrypoint provisions a
> **self-signed** TLS certificate and a random JWT secret (persisted under `/data`),
> so Bolt + REST run **encrypted** out of the box — but the certificate is *not*
> CA-trusted, and the image ships a well-known admin password. Clients must opt out
> of verification (`bolt+ssc://…`, `curl -k`). **Do not use these defaults beyond a
> local sandbox.** See [Production / TLS](#production--tls) to harden it.

### Quick start

```sh
# Build the multi-arch-capable image from this repository (native arch):
docker build -t graphus:latest .

# Run it with a named volume for durable persistence and both listeners published:
docker run -d --name graphus \
  -p 7687:7687 \         # Bolt over TCP (Neo4j drivers)
  -p 7474:7474 \         # Web REST API
  -v graphus-data:/data \  # databases persist here
  graphus:latest

# Liveness check (unauthenticated; -k because the cert is self-signed):
curl -k https://localhost:7474/health/live      # -> live
```

The default credentials for the local quickstart are user **`graphus`** /
password **`graphus-local`**.

### Using Docker Compose

```sh
docker compose up --build      # build + run (foreground)
docker compose down            # stop; the named volume keeps your data
docker compose down -v         # stop AND delete the data volume
```

See [`docker-compose.yml`](docker-compose.yml).

### Connecting

**Bolt** — point any Neo4j-ecosystem driver at `bolt+ssc://localhost:7687`. The
`+ssc` scheme means *encrypted, self-signed certificate* (no CA verification),
which matches the quickstart's self-signed cert. Example with the Python driver:

```python
from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt+ssc://localhost:7687",
                              auth=("graphus", "graphus-local"))
with driver.session() as s:
    s.run("CREATE (:Person {name: 'Ada'})")
    print(s.run("MATCH (p:Person) RETURN p.name AS name").single()["name"])  # -> Ada
driver.close()
```

(With a CA-trusted certificate, use `bolt+s://` instead.)

**REST** — the API is served over TLS on port `7474`. The OpenAPI document is at
`https://localhost:7474/openapi.json`, and `GET /health/live` / `GET /health/ready`
report liveness/readiness. Use `curl -k` while the certificate is self-signed. The
transactional `/db/<name>/tx*` routes require an `Authorization: Bearer <JWT>` token
(HS256, signed with the server's `jwt_secret`).

### Persistence

Everything durable lives under `/data` (the record store at `/data/graphus-data`,
the Unix socket at `/data/graphus.sock`, the audit log, the auto-generated JWT
secret, and the self-signed certificate under `/data/tls`). Mount any of:

```sh
-v graphus-data:/data            # a Docker named volume (recommended)
-v /srv/graphus:/data            # a host bind mount (an absolute host path)
```

The entrypoint runs the server as the unprivileged `graphus` user (uid 10001) and
makes the mounted directory writable on startup.

### Configuration

The container reads [`docker/graphus.toml`](docker/graphus.toml) by default. Override
it by mounting your own file over `/etc/graphus/graphus.toml`, by pointing
`GRAPHUS_CONFIG` at another path, or by setting individual `GRAPHUS_*` environment
variables (`GRAPHUS_STORE_PATH`, `GRAPHUS_BOLT_TCP_ADDR`, `GRAPHUS_REST_ADDR`,
`GRAPHUS_UDS_PATH`, `GRAPHUS_JWT_SECRET`, `GRAPHUS_TLS_CERT_PATH`,
`GRAPHUS_TLS_KEY_PATH`, …).

### Production / TLS

The quickstart uses a self-signed certificate. For anything beyond a local
sandbox, supply a **CA-issued** certificate and your own secrets, so clients can
verify the server (`bolt+s://`, plain `https://`):

* set `GRAPHUS_TLS_CERT_PATH` / `GRAPHUS_TLS_KEY_PATH` (PEM) to your real cert+key
  — this overrides the auto-generated self-signed pair;
* set a strong `[auth] admin_password` and a real `GRAPHUS_JWT_SECRET`;

```sh
docker run -d --name graphus \
  -p 7687:7687 -p 7474:7474 \
  -v graphus-data:/data \
  -v /srv/graphus/tls:/etc/graphus/tls:ro \
  -e GRAPHUS_TLS_CERT_PATH=/etc/graphus/tls/fullchain.pem \
  -e GRAPHUS_TLS_KEY_PATH=/etc/graphus/tls/privkey.pem \
  -e GRAPHUS_JWT_SECRET="$(openssl rand -hex 32)" \
  graphus:latest
```

### Multi-architecture builds

To build and publish a manifest covering every supported architecture:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  -t ghcr.io/flaviocfoliveira/graphus:latest --push .
```

CI builds both architectures on every change and publishes on tags — see
[`.github/workflows/docker.yml`](.github/workflows/docker.yml).

## License

See [`LICENSE`](LICENSE).
