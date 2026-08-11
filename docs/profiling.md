# Profiling Graphus

How to extract, measure, observe and profile the server's execution with the Rust ecosystem's
tooling. This is a **contributor** guide, not an operations one: nothing here is needed to run
Graphus, and none of it is compiled into a shipped build.

It exists because this project decides empirically (`CLAUDE.md`, "Measure to decide" and "Empirical
measurement"): a performance claim is worth exactly the measurement behind it.

## Which tool answers which question

Reach for the tool that answers the question you actually have. They are not interchangeable, and
running the wrong one produces a confident answer to a question nobody asked.

| Question | Tool | Kind |
| -------- | ---- | ---- |
| Where does the CPU time go? | `cargo-flamegraph` | External binary |
| Where does the CPU time go, interactively, with the call tree and stacks explorable? | `samply` | External binary |
| Which hardware events explain it (cache misses, branch misses, IPC, cycles)? | `perf` | External binary |
| Where is the heap allocated, how many times, and how much is wasted? | `dhat` | Cargo feature |
| How does memory grow over time, and where does it peak or leak? | `heaptrack` | External binary |
| What is each thread doing, millisecond by millisecond, live? | `tracy` | Cargo feature |

The **external binaries** observe an ordinary build from outside the process — no source change, no
feature flag. The **Cargo features** are compiled in, are OFF by default, and change what the program
does, so they never reach a release.

## The `profiling` build profile

The sampling profilers (`cargo-flamegraph`, `samply`, `perf`) attribute samples through the binary's
debug information. A release build of this workspace carries the same 4897 Graphus symbols in
`.symtab` but **zero debug sections**, so it resolves function names and nothing else — no
`file:line`, and every frame that `lto` and `codegen-units = 1` inlined is folded into its caller,
which is precisely where the hot paths are. A `--dev` build has the debug information but measures
unoptimised code no one ships. The `profiling` profile is the combination that answers the real
question: the same code generation as release, plus the line tables needed to attribute it.

```bash
cargo build --profile profiling -p graphus-server
# → target/profiling/graphus-server
```

It inherits `codegen-units = 1` and `lto = "thin"` from release deliberately. Loosening either would
build faster and measure a different program — inlining is precisely what decides where a release
build spends its time. Frames that were inlined away are still attributed, because
`debug = "line-tables-only"` keeps the inline records.

## CPU and general performance

### cargo-flamegraph

The quickest path from "it is slow" to a picture of why. Wraps `perf` (Linux) or `dtrace` (macOS)
and renders an interactive SVG.

```bash
cargo install flamegraph
cargo flamegraph --profile profiling -p graphus-bench --bin ldbc_snb -- --medium
# → flamegraph.svg
```

Read it by **width**, never by height: width is time spent, height is only call depth. A wide plateau
is the cost; a tall spike is just a deep call chain.

### samply

A sampling profiler with a far better viewer: it serves a local web UI where the call tree, the
inverted ("heaviest stack") view and per-thread timelines are all explorable. Preferred over a raw
flamegraph whenever the answer is not obvious at a glance, and the better tool for anything
multi-threaded — which, in this server, is most things.

```bash
cargo install --locked samply
cargo build --profile profiling -p graphus-server
samply record ./target/profiling/graphus-server config.toml
```

### perf

The native Linux tool underneath the other two, and the only one that reads hardware counters. Use it
when the flamegraph shows *where* the time goes but not *why* — a hot loop with a poor
instructions-per-cycle ratio is a memory problem, not a compute one, and only the counters say so.

```bash
perf stat -e cycles,instructions,cache-misses,branch-misses ./target/profiling/graphus-server config.toml
perf record --call-graph dwarf ./target/profiling/graphus-server config.toml
perf report
```

Two environment notes:

- **`perf_event_paranoid`** gates unprivileged profiling. Check it with
  `cat /proc/sys/kernel/perf_event_paranoid`; values above `1` block call-graph collection for a
  normal user. Lower it for the session with `sudo sysctl -w kernel.perf_event_paranoid=1`. Some
  distributions patch in values above upstream's range — the reference workstation for this project
  reports `4` out of the box, so expect to set it before the first run.
- **Call graphs** need either DWARF unwinding (`--call-graph dwarf`, slower but works with this
  profile as built) or frame pointers, which you can force with
  `RUSTFLAGS="-C force-frame-pointers=yes" cargo build --profile profiling -p graphus-server`.

## Memory: allocation and heaps

### dhat

The heap profiler, compiled in behind a feature. It records every allocation with its call stack and
writes `dhat-heap.json` on a clean exit; open that file in the
[DHAT viewer](https://nnethercote.github.io/dh_view/dh_view.html).

```bash
# The server
cargo run --profile profiling -p graphus-server --features dhat-heap -- config.toml

# The LDBC-SNB macro harness
cargo run --profile profiling -p graphus-bench --features dhat-heap --bin ldbc_snb -- --medium
```

Three things to know before trusting the output:

- **The report is written by a destructor.** A graceful shutdown produces the file; `SIGKILL` — or
  any exit through `std::process::exit` — produces nothing.
- **Timings under this feature are fiction.** Every allocation captures a backtrace. Use this build
  to learn *where the heap goes*, and an ordinary build to learn *how fast it is*.
- **It is the global allocator.** It cannot be combined in one binary with the counting allocators
  some test targets install (for example `graphus-storage/tests/commit_path_bench.rs`), because a
  process has exactly one.

### heaptrack

Where `dhat` answers "which call stacks allocate", `heaptrack` answers "how did memory grow, and when
did it peak". It traces allocations and deallocations of an **unmodified binary** — no feature, no
rebuild — and charts consumption over time, which is what you want for leak hunting and for peak-RSS
questions.

```bash
sudo apt install heaptrack heaptrack-gui        # Debian / Ubuntu
cargo build --profile profiling -p graphus-server
heaptrack ./target/profiling/graphus-server config.toml
heaptrack_gui heaptrack.graphus-server.*.zst
```

## Real-time tracing and instrumentation

### tracy

A real-time profiler that shows thread execution millisecond by millisecond. The `tracy` feature adds
a `TracyLayer` to the server's existing `tracing` subscriber, so **every span the server already
emits** becomes a timeline event — no new instrumentation needed to get started.

```bash
cargo run --profile profiling -p graphus-server --features tracy -- config.toml
```

Then start the Tracy GUI (a separate program — build it from
[wolfpld/tracy](https://github.com/wolfpld/tracy) at a tag matching the `tracy-client` version the
`tracing-tracy` pin resolves to) and connect to the running process.

`RUST_LOG` filters what reaches Tracy exactly as it filters what reaches the log. Spans emitted
before the GUI attaches are buffered by the client, so there is no start-up race to win.

**The feature is off by default and must stay off in production**: the Tracy client opens a listening
socket and broadcasts, which a database server must never do unasked.

## Measurement hygiene

The tooling is the easy part. These are the rules that decide whether the number means anything:

1. **One measurement at a time, on an idle host.** Two profiling runs in parallel measure each
   other's interference. Nothing else heavy may share the machine.
2. **Establish the baseline first, and re-measure it.** A comparison against a number recorded weeks
   ago compares against a different tree. Measure both sides in the same session.
3. **Instrumented and uninstrumented runs are not comparable.** See the `dhat` caveat above; the same
   applies to any counter-bearing feature such as `graphus-storage/read-probe`.
4. **Watch the disk.** A full `/data` makes the build fail in ways that read as code faults. Check
   `df -h` before diagnosing anything strange, and clear `target/debug/incremental` when it grows.
5. **Record the evidence where it survives.** Findings belong in the roadmap task and the Knowledge
   Graph, not only in a terminal scrollback.
