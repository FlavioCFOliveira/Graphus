# Graphus

**An ACID, Cypher- and Bolt-compatible Label Property Graph (LPG) database server, written in Rust.**

![License: MIT](https://img.shields.io/badge/license-MIT-blue)
![Architectures](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-informational)
![Protocol](https://img.shields.io/badge/wire-Bolt%20%2B%20PackStream-success)

Graphus is a **multigraph** LPG database built to run exemplarily under extreme load and
concurrency. It holds four inviolable guarantees — **100% ACID**, **100% openCypher TCK**,
**100% Bolt protocol**, and **100% PackStream** — so the standard Neo4j driver ecosystem
talks to it unchanged. It is a single self-contained server process, with no external
dependency to run.

## Quick reference

- **Source & Dockerfile:** [github.com/FlavioCFOliveira/Graphus](https://github.com/FlavioCFOliveira/Graphus)
- **Documentation:** [`docs/`](https://github.com/FlavioCFOliveira/Graphus/tree/main/docs) — getting started, REST, Bolt, security, configuration
- **File issues / get help:** [GitHub issues](https://github.com/FlavioCFOliveira/Graphus/issues)
- **Maintained by:** Flávio CF Oliveira
- **Supported architectures:** `linux/amd64`, `linux/arm64` (x86-64, Apple Silicon M1–M5, Raspberry Pi 5+)

## Supported tags

- **`latest`** — the most recent final (non-prerelease) release.
- **`vX.Y.Z`** — a specific, immutable release (e.g. `v0.0.2`).

Every tag is a multi-architecture manifest (amd64 + arm64), so `docker pull` selects the
right image for your platform automatically.

## What is Graphus?

Graphus stores a **Label Property Graph** — nodes and relationships, each with
labels/types and properties, in a multigraph by default — and you query it with
**Cypher**. You can reach it through three interfaces:

- **Bolt over TCP** (`bolt://`) — the wire protocol of the Neo4j driver ecosystem (TLS).
- **Bolt over UDS** — the same protocol over a local Unix domain socket, for in-host,
  low-overhead access.
- **Web REST API** — an HTTP/JSON transactional API with Bearer-token authentication.

## How to use this image

```sh
docker run -d --name graphus \
  -p 7687:7687 \      # Bolt over TCP (Neo4j drivers)
  -p 7474:7474 \      # Web REST API
  -v graphus-data:/data \
  flaviocfo/graphus:latest

# Liveness probe (unauthenticated; -k because the default cert is self-signed):
curl -k https://localhost:7474/health/live      # -> live
```

> ⚠️ **Local-quickstart defaults.** On first boot the entrypoint provisions a
> **self-signed** TLS certificate and a random JWT secret (persisted under `/data`), so
> Bolt and REST run **encrypted** out of the box — but the certificate is *not* CA-trusted
> and the image ships a **well-known admin password** (`graphus` / `graphus-local`).
> Clients must opt out of verification (`bolt+ssc://…`, `curl -k`). **Do not use these
> defaults beyond a local sandbox** — see *Production hardening* below.

### Connect with a Neo4j driver (Bolt)

Point any Neo4j-ecosystem driver at `bolt+ssc://localhost:7687` (`+ssc` = encrypted,
self-signed, no CA verification). The default database is named **`graphus`**.

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

### Connect over REST

REST is served over TLS on port `7474`. Exchange credentials for a JWT, then send Cypher:

```sh
# 1) Log in -> short-lived Bearer JWT
TOKEN=$(curl -sk -X POST https://localhost:7474/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"graphus","password":"graphus-local"}' | jq -r .token)

# 2) Run a query in an auto-commit transaction against the default database
curl -sk -X POST https://localhost:7474/db/graphus/tx/commit \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"RETURN 1 AS one"}]}'
```

The OpenAPI document is at `https://localhost:7474/openapi.json`; `GET /health/live` and
`GET /health/ready` report liveness/readiness.

### Docker Compose

```yaml
services:
  graphus:
    image: flaviocfo/graphus:latest
    container_name: graphus
    restart: unless-stopped
    ports:
      - "7687:7687"   # Bolt over TCP
      - "7474:7474"   # Web REST API
    volumes:
      - graphus-data:/data
    healthcheck:
      test: ["CMD", "curl", "-fsSk", "https://127.0.0.1:7474/health/live"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 15s

volumes:
  graphus-data:
```

## Persistence

All durable state lives under **`/data`** — the record store (`/data/graphus-data`), the
Unix socket (`/data/graphus.sock`), the audit log, the auto-generated JWT secret, and the
self-signed certificate (`/data/tls`). Mount a volume there so your databases survive
container restarts and recreation:

```sh
-v graphus-data:/data       # a Docker named volume (recommended)
-v /srv/graphus:/data       # a host bind mount (absolute host path)
```

The server runs as the unprivileged `graphus` user (uid 10001).

## Configuration

The container reads `/etc/graphus/graphus.toml` by default. Override it by mounting your
own file over that path, by pointing `GRAPHUS_CONFIG` at another file, or by setting
individual environment variables:

| Variable | Purpose (default) |
| --- | --- |
| `GRAPHUS_CONFIG` | Path to the TOML config file (`/etc/graphus/graphus.toml`). |
| `GRAPHUS_STORE_PATH` | Record-store directory (`/data/graphus-data`). |
| `GRAPHUS_BOLT_TCP_ADDR` | Bolt-over-TCP listen address (`0.0.0.0:7687`). |
| `GRAPHUS_REST_ADDR` | REST listen address (`0.0.0.0:7474`). |
| `GRAPHUS_UDS_PATH` | Unix-domain-socket path (`/data/graphus.sock`). |
| `GRAPHUS_JWT_SECRET` | HS256 signing secret for REST Bearer tokens (auto-generated on first boot if unset). |
| `GRAPHUS_TLS_CERT_PATH` / `GRAPHUS_TLS_KEY_PATH` | PEM cert + key; set both to use a CA-issued certificate instead of the auto self-signed pair. |
| `GRAPHUS_DATA_DIR` | Base data directory the entrypoint prepares (`/data`). |

**Ports:** `7687` (Bolt over TCP, always TLS) and `7474` (Web REST API, TLS).
Full reference: [`docs/configuration.md`](https://github.com/FlavioCFOliveira/Graphus/blob/main/docs/configuration.md).

## Production hardening

The quickstart defaults are for a local sandbox only. For real deployments, supply a
**CA-issued** certificate and your own secrets so clients can verify the server
(`bolt+s://`, plain `https://`):

```sh
docker run -d --name graphus \
  -p 7687:7687 -p 7474:7474 \
  -v graphus-data:/data \
  -v /srv/graphus/tls:/etc/graphus/tls:ro \
  -e GRAPHUS_TLS_CERT_PATH=/etc/graphus/tls/fullchain.pem \
  -e GRAPHUS_TLS_KEY_PATH=/etc/graphus/tls/privkey.pem \
  -e GRAPHUS_JWT_SECRET="$(openssl rand -hex 32)" \
  flaviocfo/graphus:latest
```

Also set a strong `[auth] admin_password` in your mounted config. See
[`docs/security.md`](https://github.com/FlavioCFOliveira/Graphus/blob/main/docs/security.md).

## License

[MIT](https://github.com/FlavioCFOliveira/Graphus/blob/main/LICENSE) © Flávio CF Oliveira
