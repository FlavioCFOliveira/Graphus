# syntax=docker/dockerfile:1
#
# Graphus — production-grade, multi-architecture container image.
#
# Builds the `graphus-server` binary natively for the target architecture
# (linux/amd64 and linux/arm64) so a single `docker buildx` invocation yields a
# manifest that runs without problems on x86/amd64, aarch64, Raspberry Pi 5 and
# Apple Silicon (M1–M5) — the latter via Docker's Linux/arm64 runtime.
#
#   docker buildx build --platform linux/amd64,linux/arm64 -t graphus:latest .
#
# Building per-architecture (under QEMU emulation for the non-native arch)
# favours correctness over cross-compilation complexity for a database server.

# ---------------------------------------------------------------------------
# Stage 1 — builder
# ---------------------------------------------------------------------------
# Pinned to the workspace MSRV (rust-version = 1.85, edition 2024).
FROM rust:1.85-slim-bookworm AS builder

# Build dependencies for the aws-lc-rs / ring TLS backends used by rustls:
#   * cmake + build-essential — compile the vendored AWS-LC C library
#   * perl                    — AWS-LC assembly generation
# `--locked` guarantees the build matches the committed Cargo.lock.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        perl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# BuildKit cache mounts keep the cargo registry and target tree warm across
# builds. The release binary is copied OUT of the cache-mounted target dir
# inside the same RUN, because the mount does not persist to the next layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo build --release --locked -p graphus-server \
    && cp /app/target/release/graphus-server /usr/local/bin/graphus-server

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
# debian-slim gives us glibc (the gnu target the binary links against), a shell
# for the entrypoint, and a small footprint. Multi-arch by construction.
FROM debian:bookworm-slim AS runtime

# Runtime dependencies only:
#   * ca-certificates — TLS trust roots
#   * curl            — HEALTHCHECK probe against the REST /health/live endpoint
#   * openssl         — first-boot self-signed certificate generation (entrypoint)
#   * gosu            — drop privileges from root to the graphus user at startup
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        openssl \
        gosu \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 graphus \
    && useradd --system --uid 10001 --gid graphus --home-dir /data --shell /usr/sbin/nologin graphus \
    && mkdir -p /data /etc/graphus \
    && chown -R graphus:graphus /data

COPY --from=builder /usr/local/bin/graphus-server /usr/local/bin/graphus-server
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/graphus.toml  /etc/graphus/graphus.toml
RUN chmod +x /usr/local/bin/entrypoint.sh

# The default container config (overridable by mounting your own and/or by the
# GRAPHUS_* environment variables). See docker/graphus.toml for the security note.
ENV GRAPHUS_CONFIG=/etc/graphus/graphus.toml

# Durable state. Mount a host volume or named volume here for persistence.
VOLUME ["/data"]

# 7687 — Bolt over TCP   |   7474 — Web REST API
EXPOSE 7687 7474

# Liveness probe via the unauthenticated REST endpoint. REST is served over TLS
# (the entrypoint provisions a self-signed certificate), so the probe uses
# https + -k (the cert is self-signed). Override with GRAPHUS_HEALTHCHECK_URL.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsSk "${GRAPHUS_HEALTHCHECK_URL:-https://127.0.0.1:7474/health/live}" || exit 1

# OCI image metadata.
LABEL org.opencontainers.image.title="Graphus" \
      org.opencontainers.image.description="Graphus — an ACID, Cypher- and Bolt-compatible Label Property Graph database server." \
      org.opencontainers.image.source="https://github.com/FlavioCFOliveira/Graphus" \
      org.opencontainers.image.licenses="See LICENSE" \
      org.opencontainers.image.vendor="Flavio CF Oliveira"

# The entrypoint starts as root only long enough to prepare /data and provision
# the JWT secret, then drops to uid 10001 (graphus) via gosu before exec'ing.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["graphus-server"]
