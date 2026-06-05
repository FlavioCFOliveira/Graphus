# CLAUDE.md

Operating instructions for the AI agent working on **Graphus**, a Label Property Graph written in Rust.

These rules are mandatory. Read them in full before starting any task and follow them at all times.

## Core rules

1. **You are NOT authorized to make decisions on your own.** Whenever the instructions are insufficient, unclear, non-specific, non-concrete, or whenever there are contradictions or ambiguities, you MUST ALWAYS ASK the user how to proceed. When asking the user:
   - Provide multiple options (a, b, c, ...) and clearly state which one is your recommendation.
   - When there are multiple questions (clarifications needed), ask them to the user **sequentially, one at a time**.
2. **All project documentation MUST be written in English** — flawless English, free of spelling, grammar, and syntax errors. Use clear, simple, unambiguous technical language intended for human readers.
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

### Task execution

Task execution is the natural continuation (the next step) of planning. You MUST always use the `rmp` tool to determine:

1. Whether there is an open task that is not yet complete, in order to continue it;
2. Identify which is the next task;
3. Identify and understand the goal of the task to be started, based on its description and its functional and technical requirements;
4. Always validate that the acceptance criteria are met before closing the task;
5. Ensure the task is closed with a short summary of what was done;
6. After the task is closed and before moving on to the next one, make a git commit following best practices, explaining what was done;
7. Update the Knowledge Graph.

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
