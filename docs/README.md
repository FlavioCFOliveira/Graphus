# Graphus documentation

Usage documentation for operating the Graphus graph database server. Start here, then dive
into the guide for the interface you need.

| Guide | What it covers |
| ----- | -------------- |
| **[getting-started.md](getting-started.md)** | Install with Docker, default credentials, and a first authenticated query over each interface. |
| **[rest-api.md](rest-api.md)** | The REST WebAPI: `POST /auth/login`, running queries and transactions, result and error shapes, health and metrics, with `curl` examples. |
| **[bolt.md](bolt.md)** | The Bolt interfaces over TCP (Neo4j drivers) and UDS (local IPC): addresses, TLS, URI schemes, and authentication. |
| **[security.md](security.md)** | Credentials, creating users, roles and privileges (RBAC), per-interface authentication, and multi-database scoping. |
| **[configuration.md](configuration.md)** | Every configuration key and `GRAPHUS_*` environment variable, with defaults. |

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
