# Changelog

All notable changes to **Graphus** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.1] - 2026-06-15

First tagged release of Graphus, a Label Property Graph (LPG) database server written
in Rust. This release packages the single-node correctness core together with a
production-grade, multi-architecture container image, giving adopters a reproducible way
to build, run, and evaluate the server.

### Added

- **Single-node correctness core.** ACID transactions backed by MVCC with Serializable
  Snapshot Isolation, an ARIES-style write-ahead log with group commit and checkpoints,
  and crash recovery. Storage uses a record store with index-free adjacency; indexing
  provides B+-tree, token-lookup, composite, and relationship-property indexes plus
  constraints.
- **Cypher query engine** targeting 100% openCypher TCK compliance (pinned target
  `2024.3`), covering the parse → plan → execute pipeline.
- **Bolt protocol over UDS and TCP.** Bolt 5.x with PackStream serialization, exposed both
  over Unix Domain Sockets (IPC) and over TCP (`bolt://`) for the standard Neo4j driver
  ecosystem. TCP transport is secured with TLS.
- **Web REST API.** HTTP transactional interface with an OpenAPI document, liveness and
  readiness endpoints, and Bearer (JWT, HS256) authentication on transactional routes.
- **Authentication and RBAC.** Peer-credential, JWT/Bearer authentication and fine-grained
  role-based access control, shared across all listeners with a durable, crash-safe
  security catalogue.
- **Encryption at rest.** AES-256-GCM for store pages, WAL frames, and backup envelopes,
  with crash-safe key rotation.
- **Observability.** Metrics and an audit log built into the server process, alongside
  admission control.
- **Deterministic Simulation Testing (DST).** A VOPR-style deterministic simulator with a
  scenario battery, fault injection, and Elle/Adya isolation checking, used to reproduce
  realistic production situations and verify correctness and durability guarantees.
- **Multi-architecture Docker deployment.** A production-grade container image of
  `graphus-server` for `linux/amd64` and `linux/arm64` (Raspberry Pi 5 and Apple Silicon
  included via Docker's Linux/arm64 runtime). Includes a `Dockerfile`, a
  `docker-compose.yml`, and an entrypoint that, on first boot, provisions a self-signed TLS
  certificate and a random JWT secret under `/data` so that Bolt and REST run encrypted out
  of the box. All durable state lives under `/data`.
- **GHCR multi-arch CI.** A GitHub Actions workflow (`.github/workflows/docker.yml`) that
  builds both architectures on every change and publishes a multi-architecture manifest to
  the GitHub Container Registry on `v*` tags, with provenance and SBOM attestations.

### Security

- The container quickstart ships **local-sandbox defaults only**: a self-signed
  certificate and a well-known admin password. These are not suitable for production.
  Supply a CA-issued certificate, a strong admin password, and a real JWT secret before
  any non-sandbox use. See the README "Production / TLS" section.

[Unreleased]: https://github.com/FlavioCFOliveira/Graphus/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/FlavioCFOliveira/Graphus/releases/tag/v0.0.1
