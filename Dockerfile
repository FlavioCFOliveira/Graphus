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
# Stage 1 — builder (cross-compiling)
# ---------------------------------------------------------------------------
# Pinned to `--platform=$BUILDPLATFORM`, so the builder always runs on the BUILD
# machine's architecture (e.g. x86_64) and CROSS-COMPILES `graphus-server` for the
# requested TARGET architecture. This lets a fast x86 runner produce the arm64
# (Raspberry Pi 5 / Apple Silicon) binary natively — the heavy Rust compile is never
# emulated; only the tiny runtime stage below runs under QEMU. Pinned to the workspace
# MSRV (rust-version = 1.85, edition 2024).
FROM --platform=$BUILDPLATFORM rust:1.85-slim-bookworm AS builder
ARG TARGETARCH

# Build dependencies for the aws-lc-rs / ring TLS backends used by rustls:
#   * cmake + build-essential — compile the vendored AWS-LC C library
#   * perl                    — AWS-LC assembly generation
# Plus, when the target differs from the build arch, the aarch64 cross toolchain
# (gcc/g++ + the Rust std for the target). `TARGETARCH` is set automatically by buildx.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential cmake perl ca-certificates; \
    case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-gnu > /rust-target ;; \
      arm64) apt-get install -y --no-install-recommends \
               gcc-aarch64-linux-gnu g++-aarch64-linux-gnu; \
             echo aarch64-unknown-linux-gnu > /rust-target ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac; \
    rm -rf /var/lib/apt/lists/*; \
    rustup target add "$(cat /rust-target)"

WORKDIR /app
COPY . .

# Cross-compile for the target triple. The `CC_*`/`CXX_*`/`AR_*`/linker env vars point
# the `cc` and `cmake` crates (which build aws-lc-sys) and the Rust linker at the aarch64
# cross toolchain; they are harmless no-ops for a native amd64 build. BuildKit cache
# mounts keep the cargo registry and target tree warm; the binary is copied OUT of the
# cache-mounted target dir in the same RUN. `--locked` matches the committed Cargo.lock.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    set -eux; \
    RUST_TARGET="$(cat /rust-target)"; \
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
           CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
           CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
           AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar; \
    cargo build --release --locked -p graphus-server --target "$RUST_TARGET"; \
    cp "target/$RUST_TARGET/release/graphus-server" /usr/local/bin/graphus-server

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
