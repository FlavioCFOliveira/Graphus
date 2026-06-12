# CLAUDE.md

Operating instructions for the AI agent working on **Graphus**, a Label Property Graph written in Rust.

These rules are mandatory. Read them in full before starting any task and follow them at all times.

## Roadmap

**Name:** graphus

## Project definition

Graphus is an **LPG (Label Property Graph) database server**. The server is built to operate **exemplarily and without failure** under extreme load and concurrency (highly demanding environments). By default, the graph uses a **multigraph** architecture.

The server implements, in an exemplary manner, all official software-development standards, specifications, and conventions in order to guarantee that it is:

1. **100% ACID COMPLIANT** — guarantees full reliability and safety when processing transactions, even in the event of power failures, errors, or system faults; that is, it guarantees that the data will never become corrupted or left in an invalid state after an operation.
2. **100% CYPHER TCK COMPLIANT** — fully compliant with the official specifications of the **Cypher** language; that is, it guarantees that any query written in Cypher will behave exactly as expected, with no unexpected behavior or syntax failures.

**These two requirements (100% ACID COMPLIANT and 100% CYPHER TCK COMPLIANT) MUST be considered absolutely inviolable.**

The Graphus server is developed with a focus on maximizing performance without leaving out any functionality, taking advantage of the available hardware capabilities (from the most basic to the most advanced).

### Connections

Three types of connection are available to access and use the server. Two of them speak the **Bolt** protocol (with **PackStream** serialization), and one speaks HTTP:

- **UDS (Bolt)** — **Unix Domain Sockets** (also known as **IPC sockets**, Inter-Process Communication): a highly efficient method that allows direct data exchange and communication between processes (programs) running **on the same operating system**. Over UDS, the server speaks the Bolt protocol.
- **Bolt over TCP** (`bolt://`) — the Bolt protocol exposed over the network (secured with TLS) so that the standard Neo4j driver ecosystem can connect to Graphus directly.
- **Web REST API** — an interface that enables communication between different systems over the internet using the HTTP protocol. It acts as a "translator", allowing applications (such as websites or mobile apps) to talk to servers and databases in a standardized, fast, and secure way.

In all cases, the implementations strictly follow the official, industry-reference standards and specifications of software development.

> Note: the original definition listed two connections (UDS + REST). The third interface (Bolt over TCP) and the adoption of Bolt as the UDS protocol were ratified as design decisions `D-wire-protocol` and `D-bolt-compat` (see `specification/02-decision-register.md`).

### Systems and architectures

The Graphus server can run on Linux, macOS, and Raspberry Pi OS, on the x86 / amd64, arm64, and aarch64 architectures. It must run without failure on Apple Silicon, x86 processors, and Raspberry Pi 5 or higher.

The highest performance is observable across all of these architectures and operating systems.

### Tests

The project contains an extensive test suite to guarantee that the server behaves as expected — not only as a whole, but also each of its modules and components. Several types of tests are implemented, such as:

1. **Unit tests** — All features are properly tested.
2. **E2E (end-to-end) tests** — Realistic tests that prove the server's readiness for use in different scenarios.
3. **Stress and load tests** — Realistic tests that prove the server's readiness for use in environments of **EXTREME CONCURRENCY AND LOAD**.

## Core rules

1. **You are NOT authorized to make decisions on your own.** Whenever the instructions are insufficient, unclear, non-specific, non-concrete, or whenever there are contradictions or ambiguities, you MUST ALWAYS ASK the user how to proceed. When asking the user:
   - Provide multiple options (a, b, c, ...) and clearly state which one is your recommendation.
   - When there are multiple questions (clarifications needed), ask them to the user **sequentially, one at a time**.
2. **All project documentation (including CLAUDE.md and other operational documents) MUST be written in English** — flawless English, free of spelling, grammar, and syntax errors. Use clear, simple, unambiguous technical language intended for human readers.
3. **Documentation MUST be accurate and faithful to the code.**
4. **The workflow MUST always follow these steps:** Specify → Implement → Test → Document.

## Self-contained development policy

Every development cycle MUST be self-contained. You must NEVER do only part of a task; each development cycle must produce a tangible result.

When new needs that were not previously foreseen are discovered during a task, those new needs MUST be resolved (as immediately as possible) within the same development cycle — add the new tasks and develop them as quickly as possible.

All code and development MUST, as a rule, be **full-fledged**. Tests MUST NOT be created with skip.

Whenever you find pre-existing bugs, you MUST fix them on the spot and then continue the work you were doing when you found the bug.

## Production-oriented

Throughout the entire work cycle (analysis → planning → development → testing), the goal MUST be that the produced result is **production-grade**. Apply not only your maximum knowledge but also your maximum diligence to ensure that you only ever work toward code that is ready to be used in production.

## Task planning and execution

To plan and coordinate execution, you MUST use the `rmp` tool (a CLI available on the system for roadmap management). Treat this tool as the **single source of truth** for planning and executing this project's tasks; no other means must be used for this purpose.

Use the **Knowledge Graph** to better understand the project, its components, and how they relate, so that it is easier to identify the scope and impact of each task on the project.

### Planning

Carefully examine the scope of the work proposed by the user and determine, first and foremost, whether it makes sense to have several development phases in order to properly accommodate the tasks. Consider that each phase must accommodate a solid deliverable.

Every task must have a very clear and objective definition of its goals, functional requirements, and technical requirements, and must also contain the acceptance criteria that confirm a task can be considered complete (that its goal has been met). Whenever a task is completed, it must be closed with a short summary describing what was done.

Phases must be modeled as **Sprints** in the `rmp` tool, which serve to group tasks.

If the work being planned requires several phases (or sprints), then the planning must comprise two distinct stages: first, define which phases (or sprints) are needed and the scope (goal) of each sprint; only then, go sprint by sprint to determine which tasks belong to each sprint. Always using the `rmp` tool as the single source of truth.

Use the **Knowledge Graph** to help identify which tasks bring the most gains and the extent of each task's impact. Use the KG (Knowledge Graph) to help determine which tasks are foundational and highest-gain, in order to optimize the best path for executing the tasks.

High-gain tasks (those with the greatest gain or the greatest impact on the project), tasks that unblock other tasks or features, and foundational tasks MUST always take priority. By default, you must always seek to work from the highest-gain tasks down to the least essential ones.

When the work for a task is substantially large (too much for a single task to be developed by an AI agent such as Claude Code), that task MUST be subdivided into parts, respecting the operating principles already established (for example, the self-contained-task principle).

### Task execution

Task execution is the natural continuation (the next step) of planning. You MUST always use the `rmp` tool to determine:

1. Whether there is an open task that is not yet complete, in order to continue it;
2. Identify which is the next task;
3. Identify and understand the goal of the task to be started, based on its description and its functional and technical requirements;
4. Determine which subagent is most appropriate and delegate the task's execution to it;
5. Always validate that the acceptance criteria are met before closing the task;
6. Ensure the task is closed with a short summary of what was done;
7. After the task is closed and before moving on to the next one, make a git commit following best practices, explaining what was done;
8. Update the Knowledge Graph.

Whenever possible, you MUST adapt the model and the model's effort level to the requirements of each task's individual operations.

Task and sprint execution should preferably be carried out sequentially. Sprints MUST only be executed sequentially; tasks may run in parallel if there is justification for it.

## Knowledge Graph

You MUST use the "Graph" features of `rmp` (Groadmap) to create, maintain (update), and query a knowledge graph of the project. This graph **MUST CONTAIN EVERYTHING** that proves useful to know about the project (examples: which features it has; where they are specified; where they are implemented; which tests exist and what they test; which components exist and how they relate; the dependencies between them; in which git commit a feature was specified, implemented, and tested; the rmp tasks; the component tasks; ...) among other information worth mapping.

This knowledge graph **MUST ALWAYS BE UPDATED** on every git commit, indicating the changes to the graph's objects. When updating nodes and relationships, it must be recorded which commit and date they correspond to.

**This graph is intended to provide the absolute truth about the project.** You MUST diligently and attentively keep it as up to date as possible, so that before having to read files, you can query the graph and learn what you need.

You may create whatever nodes and edges make the most sense for the project and your activity. Use the graph together with tasks and sprints to coordinate the project's work.

## Never guess

All interactions in the project MUST be based EXCLUSIVELY on the knowledge you already have, and you must never try to guess the intended answers. When the information you have is insufficient, you must look for answers on the internet in official or authoritative sources, papers, books, or specialist authors, in order to determine the best result.

Use the **Knowledge Graph** (KG) as the primary source of information — both as a means of consultation and as a means of storing the relationships you discover.

## Measure to decide

Whenever it is necessary to evaluate performance, completeness (whether something is complete), or correctness (whether something is right), you MUST ALWAYS gather evidence from the project to determine the needs. You MUST ALWAYS decide empirically.

## Regression prevention

Whenever a bug is identified, the necessary regression tests MUST be created to ensure that the same bugs do not recur as a consequence of future development.

## Separation of responsibilities

Every package, component, and function MUST follow a strict separation-of-responsibilities pattern in order to maximize code reuse.

## Memory

Use the KG as the memory of the project, of the agents, and of the skills. You MUST take advantage of the relational capabilities (of the graph database) to optimize how you read and write your memories. You MUST use this method to save the token cost of reading files.

**WHENEVER** the project files are changed, you MUST update the KG so that you preserve your ability to understand the project.
