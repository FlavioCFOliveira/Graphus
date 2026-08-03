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
3. **100% BOLT PROTOCOL COMPLIANT** — fully compliant with the official specifications of the **Bolt** protocol (handshake and version negotiation, message types, connection states, transaction semantics, and error handling); that is, it guarantees that any Bolt client — including the official Neo4j driver ecosystem — can communicate with the server exactly as the specification mandates, with no deviations or unexpected behavior.
4. **100% PACKSTREAM COMPLIANT** — fully compliant with the official specifications of **PackStream**, the binary serialization format used by the Bolt protocol; that is, it guarantees that every value and structure is encoded and decoded byte-for-byte exactly as the specification mandates, ensuring full wire-level interoperability with the official driver ecosystem.

**These four requirements (100% ACID COMPLIANT, 100% CYPHER TCK COMPLIANT, 100% BOLT PROTOCOL COMPLIANT, and 100% PACKSTREAM COMPLIANT) MUST be considered absolutely inviolable.**

The Graphus server is developed with a focus on maximizing performance without leaving out any functionality, taking advantage of the available hardware capabilities (from the most basic to the most advanced).

**Parallelism is a foundational design principle.** Graphus is engineered, from its very foundations, to exploit the multi-core / multi-thread architectures of modern processors, with the explicit objective of maximizing performance. Concurrency is designed into the system from the component level upward rather than bolted on afterwards: **both the write path and the read path are highly optimized to execute in parallel**, and the server is built to scale its work across **all available CPU cores** so that it extracts the fullest possible throughput from the hardware it runs on.

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

You MUST use the **DST (Deterministic Simulation Testing) simulator** of the project as a support tool for designing test scenarios and for reproducing (replicating) real-world situations. The DST simulator MUST be used to:

1. **Simulate real-world cases** — model and replicate realistic production situations deterministically, so that any issue can be reproduced reliably and verified against the project's correctness and durability guarantees.
2. **E2E (end-to-end) tests** — every E2E test that can be expressed as a deterministic scenario MUST be driven through the DST simulator, so that realistic, end-to-end behavior is exercised reproducibly rather than relying on non-deterministic ad-hoc setups.
3. **Wherever else it is needed** — any other test, validation, or investigation that benefits from deterministic, reproducible execution (especially those involving concurrency, faults, crashes, and recovery) MUST leverage the DST simulator.

Whenever you author, exercise, or validate test scenarios — especially those involving concurrency, faults, crashes, and recovery — you MUST leverage the DST simulator to model and replicate those real situations deterministically, so that issues can be reproduced reliably and verified against the project's correctness and durability guarantees.

## Core rules

1. **You are NOT authorized to make decisions on your own.** Whenever the instructions are insufficient, unclear, non-specific, non-concrete, or whenever there are contradictions or ambiguities, you MUST ALWAYS ASK the user how to proceed. When asking the user:
   - Provide multiple options (a, b, c, ...) and clearly state which one is your recommendation.
   - When there are multiple questions (clarifications needed), ask them to the user **sequentially, one at a time**.
   - **Boundary between acting and asking.** Obvious, low-risk corrections proceed immediately — for example, a pre-existing bug whose fix is unambiguous (see "Self-contained development policy"). Any decision that changes the scope, the expected behavior, the architecture, or the requirements MUST be put to the user before you act on it.
2. **All project documentation (including CLAUDE.md and other operational documents) MUST be written in English** — flawless English, free of spelling, grammar, and syntax errors. Use clear, simple, unambiguous technical language intended for human readers.
3. **Documentation MUST be accurate and faithful to the code.**
4. **The workflow MUST always follow these steps:** Specify → Implement → Test → Document.
5. **Open-source inspired.** For every component of the project you MUST look for inspiration in the open-source projects that implement that same component in an exemplary manner. Whenever possible, rely on **more than one** reference project, so that the strengths and the weaknesses of each approach can be compared. Whenever it is necessary, the reference project's **source code** MUST be used as the ultimate source of truth. The mandatory protocol is defined in "Open-source inspiration policy".

## Decision framework

To decide what the project expects as a result — whether during evaluations and audits, or during development (code implementation) — you MUST follow these guidelines, and you MUST apply them in this exact order (**correct → safe → fast**):

1. **Is it correct?** — Ask whether the result (of an evaluation or of a task) meets the stated goal, complies with the project's specification, and conforms to the applicable specifications, RFCs, or other authoritative sources.
2. **Is it safe?** — Ask whether the decision to be made, or the task to be developed, contains no characteristic or behavior that could compromise the safe use of the deliverable in question.
3. **Is it fast?** — Ask whether the decision to be made, or the task to be developed, is the fastest that can be achieved without compromising the correctness (exactness / precision / assertiveness) or the safety of the requirements; and ask what can be done so that the deliverable reaches the highest possible performance.

If there are conflicts between these steps, or difficulty in following them, you MUST immediately ask the user how to proceed, presenting the possible options.

## Self-contained development policy

Every development cycle MUST be self-contained. You must NEVER do only part of a task; each development cycle must produce a tangible result.

When new needs that were not previously foreseen are discovered during a task, those new needs MUST be resolved (as immediately as possible) within the same development cycle — add the new tasks and develop them as quickly as possible.

All code and development MUST, as a rule, be **full-fledged**. Tests MUST NOT be created with skip.

Whenever you find pre-existing bugs, you MUST fix them on the spot and then continue the work you were doing when you found the bug.

## Production-oriented

**EVERY action you take MUST be held to production-grade standards** — development, bug fixes, evaluations, analyses, audits, and anything else. There is no category of work that is exempt.

Throughout the entire work cycle (analysis → planning → development → testing), the goal MUST be that the produced result is **production-grade**. Apply not only your maximum knowledge but also your maximum diligence to ensure that you only ever work toward code that is ready to be used in production.

### Exemplary components

Every component of the project MUST be a piece that performs, in an **exemplary** manner, the purpose it was built for.

Every piece MUST have its responsibility defined clearly and explicitly, so that the boundaries of what it does — and of what it is accountable for — are unambiguous.

To **design, implement, and evaluate** each component, you MUST search for the open-source projects that implement each of those features in an exemplary manner, and take those implementations as a source of inspiration for this project. You may use several open-source projects for the same feature or component. The protocol to follow is defined in "Open-source inspiration policy".

### Sound architecture

The general architecture of the project — and the specific architecture of each of its components — MUST be based on the best practices that best suit the project's purpose. You MUST also seek inspiration in other open-source projects, in order to guarantee that the intended results are reached in an assertive and deliberate way.

## Subagent team

Graphus is built by a **team**, not by a lone generalist. In addition to your own work, you have a roster of **specialized subagents** defined both at the **user level** (`~/.claude/agents/`) and at the **project level** (`.claude/agents/`). You MUST treat these subagents as **members of the working team** and actively put them to work.

1. **Know your team.** You MUST be aware of which subagents are available (user-level and project-level) and what each one specializes in. The roster includes deep specialists across the project's domains — for example, and non-exhaustively: the Bolt protocol, PackStream, storage engines, concurrency and parallelism, Rust engineering and profiling, columnar / NoSQL / graph-theory knowledge, security research, specification management, and releases.

2. **They act and intervene whenever their specialty is useful.** A specialist MUST act and intervene **whenever its expertise adds value to the work at hand — not only when explicitly asked**. Delegate proactively: route each piece of work to the subagent best suited to it, and call in the relevant specialist to design, review, audit, or certify anything that touches their domain (for example: a storage change reviewed by the storage auditor; security-sensitive code vetted by the security researcher; Bolt / PackStream work validated by the respective protocol experts) — including proactively, before a task is closed.

3. **Maximum effort, every time.** Each subagent MUST behave like a **top professional hired to give their absolute best** on every task they take part in. Partial, careless, or mediocre contributions are not acceptable; each specialist is accountable for the quality of the work in their area of expertise.

4. **Work as a team, toward a better version.** The subagents MUST collaborate as a team — combining their perspectives, challenging one another's work, and building on each other's contributions — with a single shared objective: to guarantee that **every development produces a better, more evolved version** of Graphus than the one before it. Their combined judgment MUST continuously raise the bar on correctness, safety, performance, and conformance.

This complements — and does not replace — the task-execution rule that you MUST determine and delegate to the most appropriate subagent for each task (see "Task execution", step 4).

## Task planning and execution

**For any operation that involves Tasks or Sprints, you MUST use the `roadmap-manager` skill.** That skill is the interface through which the roadmap is planned, queried, and updated; do not drive the roadmap by any other means.

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

**Task and sprint execution MUST be carried out sequentially.** Sprints MUST be executed sequentially, and tasks MUST be executed sequentially. Tasks MUST NEVER be run in parallel, regardless of any perceived justification: exactly one task may be in progress at any given moment, and it MUST be closed before the next one is started.

This rule governs the execution of **tasks** (the units of work tracked in `rmp`). It does not restrict the internal execution of the single task that is currently in progress: within that one task you may still engage several subagents at the same time (see "Subagent team"), because subagents are not roadmap tasks.

**Evaluations and audits may be run in parallel, but ONLY when the user has explicitly authorized it, and ONLY when they are not roadmap tasks.** This covers investigative work such as running several auditor subagents at once inside the single open task, or an ad-hoc evaluation that is not tracked in `rmp`. It NEVER authorizes running two `rmp` tasks concurrently: the "exactly one task in progress" invariant holds without exception, including for tasks whose subject is an audit or an evaluation.

**Even when parallel execution has been authorized, you MUST NEVER run more than 2 (two) evaluations or audits at the same time.** Plan every evaluation and audit that is needed, but execute them in waves of at most two: as soon as one finishes, start the next one, always keeping the limit of two running in parallel.

## Knowledge Graph

**The Knowledge Graph MUST be managed with the help of the `knowledge-authority` skill.** That skill is the empirical source of truth about this project's own contents: use it to bootstrap, query, refresh, and synchronize the graph, and to update it after every commit.

You MUST use the "Graph" features of `rmp` (Groadmap) to create, maintain (update), and query a knowledge graph of the project. This graph **MUST CONTAIN EVERYTHING** that proves useful to know about the project (examples: which features it has; where they are specified; where they are implemented; which tests exist and what they test; which components exist and how they relate; the dependencies between them; in which git commit a feature was specified, implemented, and tested; the rmp tasks; the component tasks; ...) among other information worth mapping.

This knowledge graph **MUST ALWAYS BE UPDATED** on every git commit, indicating the changes to the graph's objects. When updating nodes and relationships, it must be recorded which commit and date they correspond to.

**This graph is intended to provide the absolute truth about the project.** You MUST diligently and attentively keep it as up to date as possible, so that before having to read files, you can query the graph and learn what you need.

You may create whatever nodes and edges make the most sense for the project and your activity. Use the graph together with tasks and sprints to coordinate the project's work.

## Never guess

All interactions in the project MUST be based EXCLUSIVELY on **verified knowledge**, and you must never try to guess the intended answers. When the information you have is insufficient, you must look for answers in official or authoritative sources — specifications, RFCs, papers, books, or specialist authors — in order to determine the best result.

Use the **Knowledge Graph** (KG) as the primary source of information — both as a means of consultation and as a means of storing the relationships you discover.

When the KG does not hold the answer, the **reference projects** listed in the next section are an authoritative source you MUST exploit.

## Reference projects

For reference and inspiration, you MUST use every open-source project that contains (implements or solves) functionality that is the same as, or similar to, the functionality of the **Graphus** server. Whenever it is necessary, you can and MUST go to the source code of those projects — the ultimate source of truth — in order to evaluate their technical approaches and the impact those approaches have on this project.

The baseline references are:

- **Neo4j** and **Memgraph** — they implement solutions that are identical to Graphus both from an architectural perspective and in the purpose of the project as a graph database (LPG approach).
- **ClickHouse** and **DuckDB** — references for the **columnar** component.
- **MariaDB** and **PostgreSQL** — databases that are very well known and widely used by the community.

You can and MUST research and use other reference projects as well, provided that they solve some technical functionality that exists in the Graphus server, and provided that they are open-source projects whose code you can go and consult in order to verify the implementation details empirically.

All of these reference projects MUST provide precious information about the technical and architectural aspects that are used by the open-source community. The insights obtained from them MUST contribute to making the Graphus server an exemplary implementation in terms of **Performance**, **Efficiency**, **Correctness**, and **Security**, and they MUST point the way toward objective and assertive decisions.

Reference projects are consulted for **understanding**, never for copy-and-paste: their code is read in order to learn the approach, the trade-offs, and the measured consequences of a design. The implementation that lands in Graphus MUST be Graphus's own, and the licences of the consulted projects MUST always be respected.

Whatever you learn from a reference project MUST be recorded in the **Knowledge Graph**, so that the insight — and the decision it supports — is preserved and can be consulted again without re-reading external sources.

The way reference projects MUST be selected, studied, and turned into decisions for Graphus is defined in the next section.

## Open-source inspiration policy

### Principle

Before designing or implementing any component, **identify clearly and objectively what that component is meant to do**. Only then — and always as a function of that objective, the macro objective first — study how the most successful or most authoritative open-source projects solved the same problem, and use that knowledge to take better-informed decisions for **this** project.

Reference projects are treated as **good practice to be analysed**, never as a solution to be adopted automatically. What is extracted from them is **understanding** (the structure, the algorithm, the reason behind the decision, the trade-offs accepted), never code to transcribe.

### Protocol

Follow this sequence for each component:

1. **Define the component's macro objective.** Which problem it solves, which role it plays in the project, which guarantees it must offer, and under which constraints (correctness, safety, performance, durability, concurrency). Written down explicitly and without ambiguity.
2. **Define the micro objectives.** The concrete features and behaviors: inputs and outputs, invariants, edge cases, quality and performance requirements, and acceptance criteria (see "Planning").
3. **Record the objectives and the decisions in the Knowledge Graph** (see "Knowledge Graph"), so that they remain consultable and traceable.
4. **Identify the reference projects.** Select the open-source projects that solve the same class of problem with recognized success. Selection criteria: maturity and real-world adoption, active maintenance, demonstrable engineering quality, documented design, and production use — **not** popularity on its own. The identification MUST be verified, never presumed (see "Never guess").
5. **Study the approach in the primary sources.** The source code at a concrete version or tag, the official documentation, design documents, ADRs, papers, and issue/PR discussions — rather than secondary sources. The goal is to understand **why** the decision was taken, and not merely what it was. To study a repository, apply the "Token-economy policy" (a local clone instead of many remote queries).
6. **Analyse the favorable AND the unfavorable aspects.** For each approach, enumerate explicitly:
   - what serves this component's objective, and why;
   - what does **not** serve it, and which problems it would bring here;
   - which trade-offs the approach accepts;
   - which premises and context the reference project had (scale, language, concurrency model, durability requirements, runtime environment), and **whether those premises hold in this project**;
   - what the reference project **abandoned** over time, and for what reason — negative evidence is frequently the most valuable.
7. **Decide for this project.** The decision follows from the objectives defined in steps 1 and 2 and from the "Decision framework" (correct → safe → fast). The decision is expected to be an **adaptation or a synthesis**: it may combine ideas from several references, or reject all of them, as long as it is justified.
8. **Document the decision.** Record the decision taken, the alternatives considered, the sources consulted, and the reasoning, in a form that can be audited and revisited.
9. **Validate empirically.** When the approach has a measurable impact, measure it in this project instead of trusting the reference's claims (see "Measure to decide").

### Direct copying is forbidden

- **Copying code directly from open-source projects into this project is FORBIDDEN**: whole files, blocks of code, or line-by-line transcription or translation into another language.
- The implementation MUST be **original**, idiomatic for the language and for this project's conventions, and designed for the objectives defined in the protocol above.
- **Copying a decision without understanding it is equally forbidden.** Adopting an approach merely because a reference project uses it is a form of guessing (see "Never guess"). If you cannot explain why it is appropriate for this component, do not adopt it.
- **Licences and legal obligations.** Inspiration does not remove the obligation to respect the licence of the originating project. Never incorporate third-party code without checking its licence and **without the user's explicit authorization**. If you conclude that reusing code or adopting a dependency is the best route, **ask the user first** (see "Core rules", rule 1), presenting the options and identifying the licence of each one.
- **Attribution.** Record in the Knowledge Graph and in the documentation which source inspired each decision — for traceability and credit, never as a way of legitimizing a copy.

### Safeguards

- **"That is how project X does it" is never, on its own, a justification.** The justification is always this component's objective. Popularity is not suitability.
- **A different context invalidates the conclusions.** Compare the premises before comparing the solutions: an approach that is excellent in its own context may be inadequate here.
- **Approaches evolve.** Study a concrete version, and check whether the approach is still in force in the reference project.
- If a reference approach conflicts with this project's specification or objectives, **ask the user** how to proceed (see "Core rules", rule 1), presenting the possible options.

## Measure to decide

Whenever it is necessary to evaluate performance, completeness (whether something is complete), or correctness (whether something is right), you MUST ALWAYS gather evidence from the project to determine the needs. You MUST ALWAYS decide empirically.

## Token-economy policy

### Principle

**Before performing any operation, always consider its cost in tokens and choose the cheapest alternative that produces the same result.** When two or more ways of obtaining the same information (or the same effect) are available, the cheapest one is mandatory.

**Choosing the cheap route MUST NOT AFFECT THE RESULT OF THE OPERATION IN ANY WAY.** The saving applies **exclusively to the means** used to reach the result, **never to the result itself**. The result obtained through the cheap route MUST be **identical** to the one the expensive route would have produced — not "close enough", not "approximate", not "probably the same": **identical**.

**Mandatory condition (equivalence test).** You may only choose the cheaper alternative when you are certain that the result is equivalent. Before choosing, verify:

- Does it return exactly the same information, with the same accuracy and the same level of detail?
- Does it cover exactly the same scope (the same files, the same cases, the same data)?
- Does it produce exactly the same effect on the project?

If the answer to any of these questions is "no" or "I don't know", the cheap alternative is **excluded** and you use the route that guarantees the result. **Whenever the equivalence is in doubt, always choose the more reliable route, even if it is more expensive.** Economy is only the tie-breaker between options that are proven to be equivalent — never a criterion for deciding the result itself.

**To save tokens, NEVER reduce:** the scope of the task, the depth of the analysis, the number of files or cases examined when all of them are relevant, the tests to run, the evidence to gather, the verification against authoritative sources, the validation of the acceptance criteria, or the quality of the deliverable. Saving tokens is **not** doing less: it is doing the same thing by a shorter route.

**Limit of this principle (precedence):** token economy **NEVER** justifies compromising correctness, safety, completeness, or the gathering of evidence. If the cheaper route produces a different, incomplete, or uncertain result, then it is **not** the same operation — in that case "Never guess", "Measure to decide", and the "Decision framework" prevail. Saving tokens must never lead you to guess or to assume.

### Concrete examples

**Preference for the local CLI (general rule)**

- **If an operation can be performed locally through a CLI, it MUST be performed through the CLI and by no other means.** The local CLI is systematically the cheapest option, so, where an equivalent command exists, no other way of obtaining the same result is acceptable.
- This applies to every more expensive alternative: web queries, browser tooling, navigating graphical interfaces, or any remote service that returns what a local command already returns.
- Examples:
  - `git log`, `git show`, `git diff`, `git blame` locally, instead of consulting the repository's web interface;
  - `gh issue view`, `gh pr view`, `gh api` (the GitHub CLI), instead of opening the corresponding web pages;
  - `rmp` for everything concerning tasks, sprints, and the Knowledge Graph (see "Task planning and execution" and "Knowledge Graph"), which is moreover the single source of truth;
  - `--help`, `man`, or the command's own documentation, instead of searching for that same documentation online;
  - filtering and aggregating data locally (for example with `grep`, `jq`, `sort`, `wc`) instead of pulling the full result set into the context.
- Reserve the more expensive routes (web, browser, remote services) for the cases where **no** local command can produce the same result.
- This preference is equally subject to the equivalence test above: if the CLI does not return the same information, with the same scope and accuracy, use the route that guarantees the result.

**Obtaining external information**

- If a repository can be cloned (preferably `git clone --depth 1`) and its files consulted locally, **avoid** using `WebFetch` to obtain the same content — above all when several files from the same repository are needed.
- To consult the documentation of a dependency, prefer the documentation already available locally (the project's own files, the dependency's source code, `cargo doc`, the command's `--help`) over an internet search.
- When a web search really is necessary, run **one targeted, specific search** instead of several generic searches followed by reading irrelevant pages.

**Consulting this project**

- Consult the **Knowledge Graph first** (see "Knowledge Graph"). Reading the graph is cheaper than reading files or walking the code in search of the same answer. That is exactly what the graph exists for.
- Use targeted searches (`grep` / `glob` with precise patterns) instead of reading whole files in search of a single reference.
- When reading a large file, read only the range of lines you need instead of the complete file.
- For wide searches (sweeping many files or directories), **delegate to a subagent** that returns only the conclusion, instead of pulling the content of every file into the main context.

**Do not repeat work already done**

- Do not re-read files you have already read in this session, and do not re-confirm an edit that was applied successfully.
- Do not re-derive facts already established in the conversation, and do not reopen decisions the user has already taken.
- Do not launch the same search twice (for example, delegating a search to a subagent and also running it yourself). Delegate **or** execute, never both.

**Commands and output**

- Limit command output to what is needed: use `git log --oneline`, `git diff --stat` before the full diff, `git status --short`, `--name-only`, the `-q` / `--quiet` flags, or otherwise restrict the result (for example with `head`).
- Avoid dumping large files into the context or into the answer. Reference `path:line` instead of reproducing the content.
- Prefer reading text (or a page's accessibility tree) over capturing images or screenshots, which are substantially more expensive, whenever the text is sufficient.

**Tests and validation**

- While iterating, run the specific test or crate that is at stake; reserve the full suite for the task's final validation.
- Do not run the full suite repeatedly to check changes that only affect one isolated component.

**Model, effort, and parallelism**

- Adapt the model and the effort level to the real difficulty of each operation (see "Task execution"): simple, mechanical operations do not justify the most expensive model or the highest effort level.
- Group into a single message the tool calls that are independent of one another, instead of issuing them one at a time.
- Respect the limit of 2 evaluations or audits in parallel (see "Task execution"): excessive parallelism multiplies the cost without accelerating the result.

### Safeguard

Every example above is subject to the equivalence test. They are shortcuts on the **route**, not cuts in the **result**.

If, during execution, you find that the cheap route you chose is not producing the same result — it returned insufficient information, left part of the scope out, or raised doubt — **abandon it immediately and redo the operation by the complete route**. The cost already spent is never a justification for accepting an inferior result.

## Regression prevention

Whenever a bug is identified, the necessary regression tests MUST be created to ensure that the same bugs do not recur as a consequence of future development.

## Separation of responsibilities

Every package, component, and function MUST follow a strict separation-of-responsibilities pattern in order to maximize code reuse.

## Memory

Use the KG as the memory of the project, of the agents, and of the skills. You MUST take advantage of the relational capabilities (of the graph database) to optimize how you read and write your memories. You MUST use this method to save the token cost of reading files.

**WHENEVER** the project files are changed, you MUST update the KG so that you preserve your ability to understand the project.
