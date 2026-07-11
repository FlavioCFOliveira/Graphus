# Examples — operating rules

Guidance for the project's demonstrative examples. This file loads only when working with files under `examples/`.

The repository MUST organize the project's demonstrative examples inside this `examples/*` folder at the root of the project. Each example MUST be contained in its own dedicated sub-folder, used exclusively for that example. Examples are NOT an integral part of the server; they are instruments used to exercise the server and its functionalities.

The project's examples MUST **always** be **REALISTIC E2E demonstrations** of how Graphus is used. Every example MUST always fulfill the following objectives:

1. **Demonstration** — a didactic purpose, showing how Graphus can be used for a given scenario or goal.
2. **Exercise** — the example MUST always exercise the functionalities most appropriate to its scenario or overall objective. The server MUST be exercised not only in its most basic functionalities, but also in its most advanced ones, as well as in the combination of multiple functionalities with one another and of the server as a whole.
3. **Evidence** — each example MUST allow the objective and explicit collection of evidence while its functionalities are exercised, in order to clearly evaluate ALL of Graphus's performance vectors (memory usage, CPU, storage).

Examples MUST be able to act as simulations of real-world scenarios that, when run, allow observing Graphus's behavior in order to better understand its performance, as well as the opportunities for improvement in the usage of CPU, RAM, and storage.

To perform the proper measurements, collect the evidence, and interpret it, you MUST use the tools most appropriate to the technology stack — tools that allow each behavior to be observed in detail so that sound conclusions can be drawn from the resulting data.

**Evidence that is subtly wrong is worse than no evidence, because it is believed.** The
evidence-honesty rules in the "Evidence-honesty rules (non-negotiable)" section of `examples/README.md`
are MANDATORY and MUST be followed by every example: measure it or omit it (never a zero placeholder);
`total_millis` is the workload's wall-time, not the report's emission time; every field carries the
quantity its name promises (never overload an amplification field to smuggle a per-element cost);
sample the SERVER, not the driver, whenever the goal is server evidence; classify the WAL by PATH (it
is a *directory*) and decompose the on-disk footprint; and NEVER run a stale binary (build through
`harness_build`). Each of those rules exists because the opposite was actually done here and produced
a report that lied.

Run `examples/run-all.sh` to exercise the whole suite (locally or against a running instance) — an
example that is never run cannot expose anything, and every one of the rules above was violated
undetected precisely because nothing ran the suite.

Every example MUST also be runnable against an **already-running Graphus instance** — local or remote — not only a self-booted one. Use the shared external-target seam in `_harness/harness.sh` (the `GRAPHUS_TARGET_*` contract): when a target is set, the example skips booting a server, isolates its work in a dedicated run-scoped database, and collects server-side evidence from the target's Prometheus `/metrics` (the process CPU/RSS and on-disk storage vectors are N/A remotely and a baseline is captured only from a local run). Durability/crash-recovery examples that must inject a crash and own the server lifecycle are the documented local-only exception. See the "Running against an external target" section of `examples/README.md`.
