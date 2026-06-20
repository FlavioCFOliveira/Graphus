# Graphus — Functional Specification

This directory is the single source of truth for the **functional specification** of
**Graphus**, a Label Property Graph (LPG) database server written in Rust.

The specification is built **Specify → Implement → Test → Document**. This baseline
covers the **Specify** stage: a global survey of every need derived from the project
definition, the non-functional/quality requirements, the open design decisions, and the
phased scope. It is grounded in authoritative sources (see `03-sources.md`) and mirrored
in the project Knowledge Graph (`rmp` roadmap `graphus`).

## Documents

| File | Purpose |
| --- | --- |
| `00-overview.md` | Project definition, goals, scope boundaries, glossary, non-functional requirements, phased roadmap, traceability. |
| `01-needs-survey.md` | **The global needs survey** — every functional need, organized by the 15 domains, each tagged `[CORE]` or `[ADV]`. |
| `02-decision-register.md` | The 24 design decisions, each with options and a recommendation. **All ratified on 2026-06-05** — see the "Ratified outcomes" section; the chosen option is recorded on each KG `Decision` node. Tracks the open questions and which spikes close them. Also records two post-ratification sprint-19 deferrals (`D-read-parallelism`, rmp #146; `D-perf-deferrals`, rmp #159). |
| `03-sources.md` | Authoritative references (standards, papers, vendor docs) backing every requirement. |
| `04-technical-design.md` | The implementation-design layer (the "HOW"): crate boundaries, on-disk layouts, byte-level formats, algorithms, and control/data flow. Collects the remaining measurement-gated spikes in §12. §6.7 documents the full-text index (advanced; delivered ahead of Phase 2, rmp #72). |
| `05-storage-format.md` | Phase 1 spike: storage-format and durability micro-decisions. Freezes the page header, the versioned-record header, the record-store and B+-tree page layouts, and the offline backup artifact. |
| `06-bolt-and-error-shapes.md` | Phase 1 spike: pins the Bolt version (5.4), freezes the TCK error-classification table and the Bolt/REST result and failure shapes, and specifies the REST transactional access-mode field. Closes decision-register open questions 2 and 5. |
| `07-dst-simulator.md` | The external **deterministic simulator** (VOPR, decision `D-vopr`): determinism model, architecture, the three real wire clients, workloads, the cooperative interleaver of overlapping transactions, the seeded fault models (disk, clock, transport, crash + ARIES) and unified fault scheduler, the live-device `dst` fault seam, the oracles (incl. the strong reference model and the Elle isolation checker), the safety/liveness/swarm certification modes, replay artifacts + config shrinker, the hyper-speed fuzzer, the CLI and CI gates, the scenario catalogue, and the engine gaps it surfaced (`rmp` #171/#172/#220). |

## How to read this

1. Start with `00-overview.md` for the project frame and the four inviolable requirements.
2. Read `01-needs-survey.md` for the complete enumeration of what Graphus must do.
3. Review `02-decision-register.md` and ratify each decision; ratified decisions unblock
   the detailed, per-domain functional specification (one document per domain) and the
   implementation sprints in `rmp`.

## Requirement identifiers

Functional needs are identified as `FR-<DOMAIN>-<n>` (e.g. `FR-DM-1`).
Non-functional requirements are `NFR-<n>`. Decisions are `D-<slug>`.
These identifiers are stable and used for traceability across `rmp` tasks and the
Knowledge Graph.

## Status

- **Stage:** Specify (baseline complete; all 24 design decisions ratified).
- **Next:** per-domain detailed functional specification (one document per domain), consistent
  with the ratified decisions; then Phase 1 implementation planning in `rmp`.
- **Roadmap / KG:** `rmp` roadmap `graphus` (the queryable project map; updated on every commit).
- **Inviolable requirements:** 100% ACID compliant, 100% Cypher TCK compliant,
  100% Bolt protocol compliant, 100% PackStream compliant.
- **Interfaces:** Bolt over UDS, Bolt over TCP, and the Web REST API (three; the Bolt-over-TCP
  interface is an owner-ratified extension of the project definition).
