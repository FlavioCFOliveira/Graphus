# Social network over UDS — Graphus MVP demonstration

This example proves, end to end, that Graphus is already usable as a **Minimum Viable Product**:
a real client talks to a real server over a **Unix Domain Socket (Bolt/UDS)**, stores and queries a
social graph, and keeps every committed change across a restart — including a simulated crash.

It is both a runnable **demonstration** and an executable **E2E test**: every step asserts its
expected result and the script exits non-zero if any assertion fails.

## What it demonstrates

| # | Capability | How it is shown |
|---|------------|-----------------|
| 1 | **Accepts UDS connections** | Boots `graphus-server` with a UDS-only config; the real `graphus-cli` connects over the socket (peer-cred + password auth) and runs queries. |
| 2 | **Inserts nodes and relationships** | Builds the classic social model: `Person` nodes with `FRIEND`, `FOLLOWS`, and `POSTED` relationships, all carrying properties. |
| 3 | **Searches and traverses** | Direct friends, **friend-of-friend recommendations**, most-followed person (aggregation + ordering), city filters. |
| 4 | **Manipulates data** | `SET` (Alice moves city), `MERGE` (new friendship), `DELETE` (unfriend), `DETACH DELETE` (remove a post). |
| 5 | **Survives a graceful restart** | `SIGTERM` → clean shutdown → reboot from the same store; counts and properties are unchanged. |
| 6 | **Survives a crash (durability / ACID)** | `SIGKILL` mid-life (a power-failure simulation) → reboot → the WAL is replayed and **all committed mutations are intact**. |

## Running it

```bash
# From the repository root. Builds the binaries if they are not already present.
examples/social-network-uds/run.sh
```

Use pre-built binaries from a custom location with `GRAPHUS_BIN_DIR`:

```bash
cargo build --release -p graphus-server -p graphus-cli
GRAPHUS_BIN_DIR=target/release examples/social-network-uds/run.sh
```

A successful run ends with:

```
25 checks run, 0 failures.
MVP DEMONSTRATION PASSED — ...
```

## How it works

The script is fully self-contained. It:

1. Creates a private temp directory holding the store, a generated UDS-only `graphus.toml`, and the
   socket — all removed on exit.
2. Configures an admin user bound to the current OS uid, so the UDS `SO_PEERCRED` gate admits the
   script's own connections.
3. Starts the server as a **separate process** (no in-process shortcuts), waits for the socket to be
   bound, and drives it exclusively through the `graphus-cli` binary — exactly as an operator would.
4. Restarts the server twice from the same on-disk store: once gracefully (`SIGTERM`) and once via a
   hard kill (`SIGKILL`), asserting the data is intact after each.

Because it speaks only the public CLI/UDS surface and a real on-disk store, a passing run is direct
evidence that the server, its Bolt/UDS transport, its Cypher engine, and its durable storage all
work together.

## CI coverage

The same scenario also runs under `cargo test` as a Rust integration test
(`crates/graphus-server/tests/mvp_social_network_uds.rs`), so the MVP guarantees are protected
against regression on every build.
