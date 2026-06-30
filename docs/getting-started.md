# Getting started

Graphus is a Label Property Graph database server. It speaks three interfaces, all backed
by the same Cypher engine, transactions, and security catalog:

- **REST WebAPI** (HTTP/JSON) — see [rest-api.md](rest-api.md)
- **Bolt over TCP** (Neo4j drivers) — see [bolt.md](bolt.md)
- **Bolt over UDS** (local IPC) — see [bolt.md](bolt.md)

This page gets you from nothing to a first authenticated query.

---

## 1. Run the server (Docker)

```sh
# Pull the published multi-arch image from Docker Hub
# (to build locally instead: `docker build -t graphus:latest .`, then use graphus:latest):
docker run -d --name graphus \
  -p 7687:7687 \           # Bolt over TCP
  -p 7474:7474 \           # REST WebAPI
  -v graphus-data:/data \  # all durable state lives under /data
  flaviocfo/graphus:latest

# Liveness check (-k because the quickstart certificate is self-signed):
curl -k https://localhost:7474/health/live      # -> live
```

On first boot the entrypoint provisions a **self-signed TLS certificate** and a **random
JWT secret** under `/data`, so both REST and Bolt run encrypted out of the box. See the
[README](../README.md#running-with-docker) for Compose, persistence, and multi-arch
details.

> Building from source instead? `cargo build --release -p graphus-server` produces the
> `graphus-server` binary; run it with a config file (see [configuration.md](configuration.md)).

## 2. Credentials

The quickstart ships with administrator **`graphus`** / password **`graphus-local`**.

> ⚠️ These are **local-sandbox defaults**. Before any real use, set a strong
> `admin_password`, a real `GRAPHUS_JWT_SECRET`, and a CA-issued TLS certificate. See
> [security.md](security.md#7-checklist-for-production).

The default database is **`graphus`**.

## 3. First query, per interface

### REST

REST authenticates with a Bearer JWT obtained from `POST /auth/login`:

```sh
# 1. Log in to obtain a token.
TOKEN=$(curl -sk -X POST https://localhost:7474/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"graphus","password":"graphus-local"}' | jq -r .token)

# 2. Run a query (auto-commit) against the default database.
curl -sk -X POST https://localhost:7474/db/graphus/tx/commit \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"RETURN 1 AS one"}]}'
```

Full route reference: [rest-api.md](rest-api.md).

### Bolt over TCP (any Neo4j driver)

```python
from neo4j import GraphDatabase
driver = GraphDatabase.driver("bolt+ssc://localhost:7687",
                              auth=("graphus", "graphus-local"))
with driver.session(database="graphus") as s:
    print(s.run("RETURN 1 AS one").single()["one"])   # -> 1
driver.close()
```

Details and the Go driver example: [bolt.md](bolt.md).

### Bolt over UDS (local IPC)

```sh
graphus-cli --uds /data/graphus.sock --user graphus --password graphus-local
```

UDS requires the connecting process's OS uid to be mapped (`admin_uid`) **and** a `LOGON`.
See [bolt.md](bolt.md#bolt-over-uds).

## 4. Go client examples

Runnable Go programs for all three interfaces are under
[`examples/clients-go`](../examples/clients-go): `rest`, `bolt-tcp`, and `bolt-uds`.

## 5. Where to go next

| You want to…                                  | Read |
| --------------------------------------------- | ---- |
| Run authenticated REST queries + transactions | [rest-api.md](rest-api.md) |
| Connect a Bolt driver / use UDS               | [bolt.md](bolt.md) |
| Create users, roles, and grant access (RBAC)  | [security.md](security.md) |
| Tune addresses, TLS, limits, env vars         | [configuration.md](configuration.md) |
