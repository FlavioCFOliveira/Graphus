# Graphus documentation

Usage documentation for operating the Graphus graph database server. Start here, then dive
into the guide for the interface you need.

| Guide | What it covers |
| ----- | -------------- |
| **[getting-started.md](getting-started.md)** | Install with Docker, default credentials, and a first authenticated query over each interface. |
| **[transactions.md](transactions.md)** | The transaction model: autocommit by default (MySQL/MariaDB/SQL-Server semantics), explicit transactions, lock-free reads, and the per-work isolation levels (Snapshot for standalone reads, Serializable for writes and explicit transactions). |
| **[cypher.md](cypher.md)** | Cypher language support: the function library (math, scalar/id, conversion, string, spatial, aggregation, `reduce`), map projection, type predicates, `CALL`/`COUNT`/`COLLECT` subqueries, label expressions, quantified path patterns, `USE`, administrative `SHOW`/constraint/security DDL and `dbms.*`/GDS procedures — with runnable examples and an honest "not yet supported" list. |
| **[indexes.md](indexes.md)** | Node-property indexes: named `CREATE INDEX`, `IF NOT EXISTS` / `IF EXISTS` idempotency, `DROP INDEX` by name or target, and `SHOW INDEXES` with the Neo4j column shape. |
| **[rest-api.md](rest-api.md)** | The REST WebAPI: `POST /auth/login`, running queries and transactions, result and error shapes, health and metrics, with `curl` examples. |
| **[bolt.md](bolt.md)** | The Bolt interfaces over TCP (Neo4j drivers) and UDS (local IPC): addresses, TLS, URI schemes, and authentication. |
| **[security.md](security.md)** | Credentials, creating users, roles and privileges (RBAC), per-interface authentication, and multi-database scoping. |
| **[configuration.md](configuration.md)** | Every configuration key and `GRAPHUS_*` environment variable, with defaults, and hardware auto-tuning. |
| **[docker.md](docker.md)** | Container deployment: Docker Compose recipes for each configuration (quickstart, UDS-only, `Neo4j`-compat, custom ports, bind-mount persistence, production CA-TLS). |

## Runnable examples

- **[examples/clients-go](../examples/clients-go)** — Go client programs for all three
  interfaces (`rest`, `bolt-tcp`, `bolt-uds`).
- **[examples/](../examples)** — end-to-end Rust scenario demonstrations (social network,
  fraud OLTP, GDS analytics, knowledge graph over REST, and more), each instrumented to
  collect CPU/RAM/storage evidence.

## The four guarantees

Graphus holds four inviolable guarantees: **100% ACID**, **100% openCypher TCK**, **100%
Bolt protocol**, and **100% PackStream**. Any Cypher query, any Bolt driver, and any
PackStream value behaves exactly as the respective specification mandates.

See also the top-level [README](../README.md) and the design [`specification/`](../specification).
