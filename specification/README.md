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
| `02-decision-register.md` | All open design decisions, each with options and a recommendation. **These require the project owner's ratification before the detailed per-domain functional spec is written.** |
| `03-sources.md` | Authoritative references (standards, papers, vendor docs) backing every requirement. |

## How to read this

1. Start with `00-overview.md` for the project frame and the two inviolable requirements.
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

- **Stage:** Specify (baseline).
- **Roadmap / KG:** `rmp` roadmap `graphus` (89 nodes, 113 edges at baseline).
- **Inviolable requirements:** 100% ACID compliant, 100% Cypher TCK compliant.
