# Configuration reference

Graphus is configured by a **TOML file** and/or **environment variables**. The server is
started with the config-file path as its argument:

```sh
graphus-server /etc/graphus/graphus.toml
```

The Docker image reads [`docker/graphus.toml`](../docker/graphus.toml) by default; override
it by mounting your own file over `/etc/graphus/graphus.toml` or by pointing
`GRAPHUS_CONFIG` at another path.

**Precedence:** the file is read first, then environment variables override individual
fields. Environment variables cover the deployment-relevant subset (addresses, paths, TLS,
the JWT secret, and the most-tuned admission/timing knobs); the file is the place for the
full surface. For a listener address env var, an **empty value disables** that listener
(e.g. `GRAPHUS_BOLT_TCP_ADDR=""`).

---

## Paths and database

| TOML key            | Env var                     | Default         | Meaning |
| ------------------- | --------------------------- | --------------- | ------- |
| `store_path`        | `GRAPHUS_STORE_PATH`        | `graphus-data`  | Directory for the record store, WAL, `security.toml`, audit log. (Docker: `/data/graphus-data`.) |
| `default_database`  | `GRAPHUS_DEFAULT_DATABASE`  | `graphus`       | The always-online default database; name rule `[a-z][a-z0-9_-]{0,62}`. |
| `buffer_pool_pages` | —                           | `4096`          | Buffer-pool capacity in pages. |

## Listeners

| TOML key                  | Env var                            | Default            | Meaning |
| ------------------------- | ---------------------------------- | ------------------ | ------- |
| `rest_addr`               | `GRAPHUS_REST_ADDR`                | `127.0.0.1:7474`   | REST listen address; `None`/empty disables. TLS required (unless `allow_insecure_network`). |
| `bolt_tcp_addr`           | `GRAPHUS_BOLT_TCP_ADDR`            | disabled           | Bolt-over-TCP listen address. TLS required when set. (Docker: `0.0.0.0:7687`.) |
| `uds_path`                | `GRAPHUS_UDS_PATH`                 | `graphus.sock`     | Bolt-over-UDS socket path; `None`/empty disables. (Docker: `/data/graphus.sock`.) |
| `advertised_bolt_address` | `GRAPHUS_ADVERTISED_BOLT_ADDRESS`  | = `bolt_tcp_addr`  | Address advertised to routing (`neo4j://`) drivers when reachable via a different name/port (LB/NAT). |

## TLS

| TOML key (`[tls]`)        | Env var                   | Default | Meaning |
| ------------------------- | ------------------------- | ------- | ------- |
| `cert_path`               | `GRAPHUS_TLS_CERT_PATH`   | unset   | PEM certificate chain. Both cert and key, or neither. |
| `key_path`                | `GRAPHUS_TLS_KEY_PATH`    | unset   | PEM private key. |

By default, every **network** listener (REST, Bolt-TCP) requires TLS. UDS never uses TLS
(it is a local, peer-credential-gated trust domain).

| TOML key                  | Env var | Default | Meaning |
| ------------------------- | ------- | ------- | ------- |
| `allow_insecure_network`  | —       | `false` | **Escape hatch.** Allow REST/Bolt-TCP to run **without** TLS (loopback test harnesses / trusted dev only). Deliberately named to discourage production use. |

## Authentication and security

| TOML key                          | Env var                          | Default            | Meaning |
| --------------------------------- | -------------------------------- | ------------------ | ------- |
| `jwt_secret`                      | `GRAPHUS_JWT_SECRET`             | insecure generated | HS256 secret for REST Bearer tokens. **Must** be overridden (≥ 32 bytes) when a network listener is on, or startup is rejected. |
| `[auth] admin_user`               | —                                | `admin`            | Bootstrap administrator username (Docker: `graphus`). |
| `[auth] admin_password`           | —                                | empty (disabled)   | Bootstrap administrator password (Docker: `graphus-local`). |
| `[auth] admin_uid`                | —                                | unset              | OS uid mapped to the admin user for UDS peer-credential auth. |
| `[[auth.users]]`                  | —                                | none               | Extra bootstrap users (granted READ + WRITE). |
| `metrics_scrape_token`            | `GRAPHUS_METRICS_SCRAPE_TOKEN`   | unset (fail-closed)| Shared bearer for `/metrics`; unset ⇒ an admin Bearer is required. An empty value is rejected. |

The `[auth]` bootstrap seeds the catalog only on a **fresh** store; thereafter
`<store_path>/security.toml` is authoritative. See [security.md](security.md).

## Admission control and parallelism

| TOML key (`[admission]`)    | Env var                            | Default | Meaning |
| --------------------------- | ---------------------------------- | ------- | ------- |
| `max_concurrent_queries`    | `GRAPHUS_MAX_CONCURRENT_QUERIES`   | `256`   | Concurrent query admission ceiling. |
| `max_connections`           | `GRAPHUS_MAX_CONNECTIONS`          | `1024`  | Process-wide connection cap (load-shed beyond it). |
| `max_connections_per_ip`    | `GRAPHUS_MAX_CONNECTIONS_PER_IP`   | `256`   | Per-source-IP connection cap (`0` disables). |
| `max_open_transactions`     | `GRAPHUS_MAX_OPEN_TRANSACTIONS`    | bounded | Per-principal open-transaction cap (REST `429` beyond it). |
| `reader_threads`            | `GRAPHUS_READER_THREADS`           | `0`     | Off-thread read pool size (`0` = auto). |
| `morsel_parallelism`        | `GRAPHUS_MORSEL_PARALLELISM`       | `0`     | Intra-query morsel parallelism (`0` = auto). |
| `csr_adjacency`             | `GRAPHUS_CSR_ADJACENCY`            | `false` | Opt-in CSR adjacency accelerator (`true/false/1/0/yes/no/on/off`). |

## Timing and limits

| TOML key (`[timing]`)       | Env var                            | Default     | Meaning |
| --------------------------- | ---------------------------------- | ----------- | ------- |
| `statement_timeout_ms`      | `GRAPHUS_STATEMENT_TIMEOUT_MS`     | `120000` (2 min) | Per-statement execution timeout. |
| `max_transaction_age_ms`    | `GRAPHUS_MAX_TRANSACTION_AGE_MS`   | `3600000` (1 h)  | Per-transaction maximum age (bounds GC-watermark pinning). |
| `slow_query_threshold_ms`   | `GRAPHUS_SLOW_QUERY_THRESHOLD_MS`  | `500`       | Logs queries slower than this. |
| `handshake_timeout_ms`      | `GRAPHUS_HANDSHAKE_TIMEOUT_MS`     | `10000`     | TLS-handshake + Bolt pre-auth read deadline (slow-loris guard). |
| `header_read_timeout_ms`    | `GRAPHUS_HEADER_READ_TIMEOUT_MS`   | `15000`     | REST request-header read deadline. |
| `idle_timeout_ms`           | `GRAPHUS_IDLE_TIMEOUT_MS`          | `0` (off)   | Idle authenticated-session reaper (`0` = disabled). |

(`transaction_idle_timeout_ms` defaults to `60000` — the REST open-transaction idle
sweep.)

## Encryption at rest and audit logging

| TOML key                       | Env var                        | Default     | Meaning |
| ------------------------------ | ------------------------------ | ----------- | ------- |
| `[encryption] key_path`        | `GRAPHUS_ENCRYPTION_KEY_PATH`  | unset (plaintext) | AES-256-GCM master key for store pages, WAL frames, backups. |
| `[audit]` (see source)         | —                              | disabled    | Crash-safe append-only JSONL security audit log at `<store_path>/audit.log`. |

---

## A minimal production-style file

```toml
store_path     = "/var/lib/graphus"
default_database = "graphus"

rest_addr      = "0.0.0.0:7474"
bolt_tcp_addr  = "0.0.0.0:7687"
uds_path       = "/var/run/graphus.sock"

jwt_secret     = "REPLACE-with-32+-bytes-of-high-entropy"

[tls]
cert_path = "/etc/graphus/tls/fullchain.pem"
key_path  = "/etc/graphus/tls/privkey.pem"

[auth]
admin_user     = "graphus"
admin_password = "REPLACE-with-a-strong-password"
admin_uid      = 1000           # the OS uid allowed to connect over UDS
```

The canonical, commented example shipped with the project is
[`docker/graphus.toml`](../docker/graphus.toml).

See also: [getting-started.md](getting-started.md) · [security.md](security.md) ·
[rest-api.md](rest-api.md) · [bolt.md](bolt.md).
