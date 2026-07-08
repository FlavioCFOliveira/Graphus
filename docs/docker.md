# Docker deployment

Graphus ships a production-grade, **multi-architecture** container image of `graphus-server`
(`flaviocfo/graphus`), running unchanged on **x86-64 / amd64**, **aarch64 / arm64**, **Raspberry
Pi 5**, and **Apple Silicon**. This guide collects **Docker Compose recipes** for the configurations
you are most likely to need — copy the one that matches your deployment and adjust.

For the full list of configuration keys and environment variables, see
[configuration.md](configuration.md); for connecting once it is up, see
[getting-started.md](getting-started.md).

## How configuration works in the container

- All persistent state lives under **`/data`** (the record store, the Unix socket, the audit log,
  the auto-provisioned JWT secret, and the self-signed TLS material under `/data/tls`). Mount a
  volume there so your databases survive `docker compose down` and container recreation.
- The image reads a baked config at **`/etc/graphus/graphus.toml`** (`GRAPHUS_CONFIG` points at it).
  You customise a deployment in one of two ways, **in this precedence order**:
  1. **Environment variables** (`GRAPHUS_*`) — override individual keys without touching the file.
     This is the simplest approach and is what most recipes below use.
  2. **Mount your own config file** over `/etc/graphus/graphus.toml` — for settings that have **no**
     environment variable, notably **`[auth] admin_password`** and the full `[admission]` / `[timing]`
     surface. A mounted file *replaces* the baked one, so include every key you need.
- On **first boot** the entrypoint provisions a **self-signed TLS certificate** and a **random JWT
  secret** (both persisted under `/data`) unless you supply your own (`GRAPHUS_TLS_CERT_PATH` /
  `GRAPHUS_TLS_KEY_PATH`, `GRAPHUS_JWT_SECRET`). Bolt-over-TCP is always TLS; this lets the image run
  encrypted with zero configuration.
- The server runs as the unprivileged **`graphus`** user (uid `10001`); the entrypoint makes the
  mounted `/data` writable on startup.

> ⚠️ **Local quickstart defaults.** The self-signed certificate is *not* CA-trusted and the image
> ships a well-known admin password (`graphus` / `graphus-local`). Clients must opt out of
> verification (`bolt+ssc://…`, `curl -k`). **Do not use these defaults beyond a local sandbox** —
> see [Recipe 6](#recipe-6--production-ca-issued-tls--secrets) to harden it.

Every recipe below is validated with `docker compose -f <file> config`.

---

## Recipe 1 — Quickstart (default)

Bolt-TCP + REST over self-signed TLS, published on the standard ports, with a named volume for
persistence. This is the canonical [`docker-compose.yml`](../docker-compose.yml) at the repo root.

```yaml
services:
  graphus:
    image: flaviocfo/graphus:latest
    container_name: graphus
    restart: unless-stopped
    ports:
      - "7687:7687"   # Bolt over TCP (Neo4j drivers)
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

```sh
docker compose up -d
curl -k https://localhost:7474/health/live          # -> live
# Bolt: bolt+ssc://localhost:7687  (user graphus / graphus-local)
```

---

## Recipe 2 — Custom host ports

Keep the container listening on `7687`/`7474` but publish them on different **host** ports (e.g. to
avoid a clash with a local Neo4j). Only the left-hand side of each `ports` mapping changes.

```yaml
services:
  graphus:
    image: flaviocfo/graphus:latest
    container_name: graphus
    restart: unless-stopped
    ports:
      - "17687:7687"   # host 17687 -> container Bolt 7687
      - "17474:7474"   # host 17474 -> container REST 7474
    environment:
      # If routing (`neo4j://`) drivers must reconnect through the remapped host port, advertise the
      # externally-reachable address (otherwise the bind address 0.0.0.0:7687 is not a usable target).
      GRAPHUS_ADVERTISED_BOLT_ADDRESS: "localhost:17687"
    volumes:
      - graphus-data:/data

volumes:
  graphus-data:
```

To change the **container** ports instead, set `GRAPHUS_BOLT_TCP_ADDR=0.0.0.0:<port>` /
`GRAPHUS_REST_ADDR=0.0.0.0:<port>` and update the mappings and the healthcheck accordingly.

---

## Recipe 3 — UDS-only (no network exposure)

Disable **both** network listeners and serve **only** Bolt-over-UDS (Unix domain socket). Nothing is
published to the network; clients connect over the shared socket at `/data/graphus.sock`, gated by
kernel peer-credential authentication. This is the most locked-down profile — ideal when the client
runs on the same host / in a sidecar.

```yaml
services:
  graphus:
    image: flaviocfo/graphus:latest
    container_name: graphus
    restart: unless-stopped
    environment:
      # Empty string disables a listener. With both network listeners off, only UDS remains — so no
      # ports are published and TLS is not needed on the wire.
      GRAPHUS_BOLT_TCP_ADDR: ""
      GRAPHUS_REST_ADDR: ""
      GRAPHUS_UDS_PATH: "/data/graphus.sock"
    volumes:
      - graphus-sock:/data
    healthcheck:
      # REST is off, so probe the socket file instead of the REST health endpoint.
      test: ["CMD-SHELL", "test -S /data/graphus.sock"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 15s

  # Your application connects over the shared socket — no TCP, no TLS, no exposed port.
  app:
    image: your-app:latest        # replace with your client image (mount uses the same volume)
    depends_on:
      graphus:
        condition: service_healthy
    environment:
      GRAPHUS_UDS_PATH: "/data/graphus.sock"
    volumes:
      - graphus-sock:/data:ro     # read-only mount is enough to reach the socket

volumes:
  graphus-sock:
```

> Peer-credential auth maps the connecting OS uid to a Graphus user. Set `[auth] admin_uid` (via a
> mounted config) to the uid your `app` container runs as if you want it admitted as the admin
> identity — see [security.md](security.md).

---

## Recipe 4 — `Neo4j`-compatible Bolt agent

Some strict/legacy Neo4j drivers verify the `server` agent string in the Bolt `HELLO` reply and
reject anything that is not the literal `Neo4j`. Opt in so `HELLO` reports **`Neo4j/5.13.0`**. This
changes **only** the advertised string — Bolt/PackStream conformance and capabilities are unchanged
(drivers gate features on the negotiated Bolt version, never on this string).

```yaml
services:
  graphus:
    image: flaviocfo/graphus:latest
    container_name: graphus
    restart: unless-stopped
    ports:
      - "7687:7687"
      - "7474:7474"
    environment:
      # `neo4j-compat` -> the vetted "Neo4j/5.13.0"; or set any literal, e.g. "Neo4j/5.13.0-graphus".
      GRAPHUS_BOLT_SERVER_AGENT: "neo4j-compat"
    volumes:
      - graphus-data:/data

volumes:
  graphus-data:
```

Verify: the startup log shows the resolved agent, and a driver's `SUCCESS` metadata reports
`server: "Neo4j/5.13.0"`. See [bolt.md](bolt.md) for the full compatibility notes.

---

## Recipe 5 — Bind-mount persistence (host directory)

Instead of a Docker **named volume**, persist to an absolute **host path** (easier to back up or
inspect from the host). The entrypoint chowns the mount to uid `10001` on startup.

```yaml
services:
  graphus:
    image: flaviocfo/graphus:latest
    container_name: graphus
    restart: unless-stopped
    ports:
      - "7687:7687"
      - "7474:7474"
    volumes:
      - /srv/graphus:/data        # host directory <- absolute path
```

Named volume vs bind mount is purely the `volumes` line:
`- graphus-data:/data` (named, recommended) versus `- /srv/graphus:/data` (host path). Remove a named
volume's data with `docker compose down -v`; a bind mount's data is deleted by you on the host.

---

## Recipe 6 — Production (CA-issued TLS + secrets)

Harden every quickstart default: a **CA-issued** certificate (so clients verify the server with
`bolt+s://` / `https://`), a strong **JWT secret**, and a strong **admin password**. The admin
password has **no** environment variable, so supply it through a **mounted config file**.

`graphus.prod.toml` (mounted over the baked config):

```toml
store_path    = "/data/graphus-data"
uds_path      = "/data/graphus.sock"
bolt_tcp_addr = "0.0.0.0:7687"
rest_addr     = "0.0.0.0:7474"

[auth]
admin_user     = "graphus"
admin_password = "a-strong-password-you-set"   # or seed via your secrets manager
```

`docker-compose.yml`:

```yaml
services:
  graphus:
    image: flaviocfo/graphus:latest
    container_name: graphus
    restart: unless-stopped
    ports:
      - "7687:7687"
      - "7474:7474"
    environment:
      GRAPHUS_TLS_CERT_PATH: "/etc/graphus/tls/fullchain.pem"
      GRAPHUS_TLS_KEY_PATH: "/etc/graphus/tls/privkey.pem"
      GRAPHUS_JWT_SECRET: "${GRAPHUS_JWT_SECRET:?set a strong secret, e.g. openssl rand -hex 32}"
    volumes:
      - graphus-data:/data
      - ./graphus.prod.toml:/etc/graphus/graphus.toml:ro
      - /srv/graphus/tls:/etc/graphus/tls:ro    # your CA-issued cert + key (PEM)

volumes:
  graphus-data:
```

```sh
export GRAPHUS_JWT_SECRET="$(openssl rand -hex 32)"
docker compose up -d
# Now the cert is CA-trusted: use bolt+s://your-host:7687 and https://your-host:7474 (no -k).
```

Optional production tuning (all have environment variables — see [configuration.md](configuration.md)):
pin `GRAPHUS_BUFFER_POOL_PAGES` instead of the RAM-derived auto-size, cap connections with
`GRAPHUS_MAX_CONNECTIONS` / `GRAPHUS_MAX_CONNECTIONS_PER_IP`, and gate `/metrics` with
`GRAPHUS_METRICS_SCRAPE_TOKEN`.

---

## Connecting

| Interface | Quickstart (self-signed) | Production (CA-trusted) |
| --------- | ------------------------ | ----------------------- |
| Bolt (TCP) | `bolt+ssc://host:7687` | `bolt+s://host:7687` |
| REST | `curl -k https://host:7474/…` | `curl https://host:7474/…` |
| Bolt (UDS) | connect to `/data/graphus.sock` (peer-cred auth) | same |

Health/metrics: `GET /health/live`, `GET /health/ready`, and `GET /metrics` (Prometheus). The OpenAPI
document is at `/openapi.json`. See [rest-api.md](rest-api.md) and [bolt.md](bolt.md).
