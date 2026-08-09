# 07 — External Deterministic Simulator (VOPR)

This chapter specifies the **external deterministic simulator** for Graphus: a TigerBeetle-VOPR-style
tool that drives the **real** server interfaces and engine under **seeded, fully reproducible**
workloads, faults, and adversarial clients, and certifies behaviour with a set of oracles. It
realizes decision `D-dst-investment` at the *connectivity/protocol* layer (the pre-existing
`graphus-dst` storage harness realizes it at the storage layer).

It is implemented across `graphus-dst` (the simulator core, interleaver, fault scheduler, oracles,
repro/shrink and fuzzer), `graphus-sim` (the deterministic substrate, including the clock- and
transport-fault models), `graphus-io` (the simulated disk and its fault model), `graphus-elle` (the
isolation checker), and small public seams added to `graphus-server`/`graphus-bolt`/`graphus-rest`. A
`dst` cargo feature (off by default, zero-cost in production) exposes a live-device fault seam through
`graphus-server`/`graphus-cypher`/`graphus-storage`/`graphus-bufpool` (section 6.2).

## 1. Determinism model — "external" over a simulated transport

The owner ratified **total determinism** (TigerBeetle's principle): a run is a pure function of its
seed. That is reconciled with "connect by every method" as follows:

> **External** means the simulator speaks the **real wire protocols with no backdoor** — the genuine
> Bolt state machine + PackStream codec and the genuine REST request core — but over an **in-memory,
> simulated transport**, against the **real engine** built on a **simulated disk + clock**. It does
> **not** mean real OS sockets, which would reintroduce non-determinism.

Everything random is drawn from one seeded PRNG (`graphus_sim::SimRng`); everything timed advances one
logical clock (`graphus_sim::SharedClock`, set from the scheduler). There is no wall clock and no
thread scheduling in the driven path.

The fault, workload, and (swarm) environment choices are each drawn from their **own** seeded PRNG,
derived from the one master seed by mixing in a domain-separation tag (the workload uses `seed`, the
fault scheduler `seed ^ FAULT_TAG`, the swarm config `seed ^ SWARM_TAG`). These streams compose
deterministically: a single seed reproduces all of them bit-for-bit, yet adding a fault or swarming the
environment never silently reshapes an existing seed's workload, because no stream consumes another's
draws.

## 2. Architecture

| Component | Crate | Role |
| --- | --- | --- |
| `LocalEngine` | `graphus-server` (`engine::local`) | Drives the **real** `TxnCoordinator`/storage/WAL **inline, single-threaded**, reusing the production command-dispatch path verbatim. Unbounded result egress so a single thread cannot deadlock. Time flows through an injected `Clock`. |
| `SimScheduler<P>` | `graphus-sim` | Deterministic discrete-event scheduler: one logical clock + one `SimRng`; events ordered by `(due, rng-priority, seq)`. |
| `SimNet` / `SimEndpoint` | `graphus-sim` | Deterministic in-memory network; endpoints implement `graphus_bolt::Transport`. Reliable, ordered, delayable, breakable (latency / partition / reset / close). Byte reorder/drop/dup are deliberately **not** modelled (a reliable TCP stream does not exhibit them). |
| `SharedClock` | `graphus-sim` | Atomic clock the simulator sets from scheduler time; read by the engine — logical time in lockstep. |
| `FaultyClock` | `graphus-sim` (`clock_fault`) | Wraps a `Clock` and perturbs it from a seeded `ClockFaultPlan` (skew, forward jumps, regressions) — see section 6. |
| `MemBlockDevice` + `FaultPlan` | `graphus-io` (`mem`) | The simulated disk; a seeded `FaultPlan` arms the full disk-corruption model (bit-rot, misdirected I/O, latent sector error, ENOSPC, write reordering) — see section 6. |
| `SimNet` + `TransportFaultPlan` | `graphus-sim` (`net`) | Deterministic in-memory network with a seeded transport-fault model (mid-message drop, truncate-then-stall, slow consumer) — see section 6. |
| VOPR core | `graphus-dst` (`vopr`) | Builds the world, runs the seed-driven **cooperative interleaver** of overlapping explicit transactions, records a canonical FNV-1a event trace + state hash, and runs the oracles. CLI: `graphus-dst vopr --seed B --seeds K`. |
| Thread-scheduling seam | `graphus-core` (`sched`) | The yield points at which a **real OS thread** offers the execution token back: page-latch acquisition and release, thread spawn/exit, both halves of commit publication, snapshot acquisition, free-list push, and each GC phase. Behind the `det-sched` cargo feature, off by default — see section 5.2. |
| `DetScheduler` | `graphus-dst` (`detsched`) | The seeded policy behind that seam: one execution token, an ordered runnable set, a `SimRng`-drawn successor, park/release on contended resources, deadlock and stall detection, a bounded step budget, and a byte-comparable `SchedHistory`. Driven by `run_scheduled` — see section 5.2. |
| Fault scheduler | `graphus-dst` (`vopr_fault`) | Schedules disk/clock/transport/crash faults on the VOPR timeline under a bounded `FaultBudget`, folded into the canonical trace — see section 6. |
| Reference-model oracle | `graphus-dst` (`vopr_oracle`) | A deterministic shadow LPG compared cell-by-cell against the engine on every commit — see section 8. |
| Repro + shrink | `graphus-dst` (`vopr_repro`) | Persisted JSON replay artifacts and a deterministic config shrinker — see section 11. |
| Fuzzer | `graphus-dst` (`vopr_fuzz`) | A continuous, time-budgeted, multi-core seed sweep — see section 12. |

## 3. Connection methods (all three, real protocols)

- **Bolt over UDS** and **Bolt over TCP** share one Bolt state machine; only the transport differs, so
  the simulator's `SimNet`-backed `BoltSession` covers both. `dst::wire::run_scripted_bolt_session`
  drives a real handshake + `RUN`/`PULL`/`BEGIN`/`COMMIT`/… via a `LocalBoltExecutor`
  (`graphus_bolt::BoltExecutor` over `LocalEngine`). Result cells are mapped with the **same**
  `graphus_server::engine::bolt_values` mapping the production seam uses (byte-identical PackStream).
- **REST** is driven through the **real** request core: `graphus_rest::router::execute_autocommit`
  runs `run_statements_buffered` (statement binding, tx lifecycle, wire serialization, RFC 9457
  errors) over a `SimRestEngine` (`graphus_rest::RestEngine` over `LocalEngine`), bypassing only the
  generic axum/hyper socket layer. This required relaxing `RestEngine`'s `Send + Sync` supertrait onto
  the `router` function so a single-threaded (`!Send`) engine can implement it.

Because `BoltSession::run` is a blocking loop, clients are **byte-scripted** (a fixed request stream),
which is also the natural shape for misbehaved clients.

## 4. Workloads

`dst::mix` is the single workload source: `WorkloadOp` (`to_cypher` runs the same op over direct
engine / Bolt / REST), `MixProfile` presets (`write_heavy` / `read_heavy` / `oltp_light` / `mixed`),
and `LoadProfile` arrival shapes (`steady` / `ramp` / `spike`). All seed-reproducible.

## 5. The cooperative interleaver

The VOPR main loop is a **deterministic cooperative interleaver** of **overlapping explicit
transactions** (`vopr.rs`). Each virtual client is a small state machine (`ClientState`) that is either
`Idle` or `Open` — holding an open transaction ticket and the next scripted step. A client's
transaction is scripted as `[BEGIN, stmt, …, COMMIT | ROLLBACK]`, and the single `SimScheduler`
dispatches each client's **next step** as its own event, ordered by the canonical
`(due, rng-priority, seq)` key. Because each step is a separate event, **multiple clients can have a
transaction open at the same scheduler instant** — real overlap, not serialized batches.

The interleaver runs **single-threaded**. All randomness comes from the scheduler's seeded RNG, so the
entire interleaving is a pure function of the seed.

**It is not the simulator's only deterministic scheduler, and the two are not interchangeable.** The
cooperative interleaver orders **transaction lifetimes** on one OS thread, with each Cypher statement
atomic. The **deterministic thread scheduler** of section 5.2 orders **real OS threads**, at the
granularity of a declared yield point *inside* a statement. They answer different questions — a
transaction-ordering anomaly against an intra-operation interleaving race — and they coexist: the
interleaver is always on, the thread scheduler is installed only by a run that asks for it.

- **`advance_client`** advances exactly one client's state machine by one step, executes it against the
  engine, folds the `(client, step kind, outcome)` into the canonical trace in dispatch order, and
  schedules the client's following step.
- The loop folds three artifacts into one **canonical FNV-1a trace**: the workload steps (in dispatch
  order), every fault decision (section 6), and every crash event (section 6.5). It also computes a
  **state hash** — an ordered snapshot of all `:Person` nodes and `:KNOWS` relationships read back
  through real queries — so a run is fully described by `(trace_hash, state_hash)`.
- **Determinism gate.** Every seed is run **twice** and the two `VoprReport`s compared field-for-field
  (trace, state, counts, oracle). Any mismatch is a determinism failure — the simulator's own core
  invariant — counted and listed for one-line reproduction.

### 5.1 Concurrency-fidelity ceiling — what DST does **not** cover, and who owns it (rmp #460, #973)

The cooperative interleaver's "concurrency" is **overlapping transaction lifetimes on one cooperative
OS thread**, with **each Cypher statement executed atomically to completion** before the next client's
step begins. On its own that leaves a precise, named **fidelity ceiling**: a class of **true-parallel
races is invisible to it** and is therefore **owned by other suites, not by the interleaver**.
Reviewers must not attribute a parallel-memory property to "DST-proven".

The deterministic thread scheduler of section 5.2 **narrows that ceiling. It does not remove it.**
What moved and what did not is stated exactly below, and the distinction is load-bearing.

What DST genuinely covers: transaction-overlap / SSI logical races (e.g. `#171`/`#172`/`#220`),
durability and atomicity across ARIES crash-restart, determinism, single-thread disk/clock fault
recovery, the backup/restore/key-rotation crash windows (section 10), and the property-value /
secondary-index oracle (section 8).

**What the thread scheduler moved inside the ceiling.** **Garbage collection racing an off-thread
reader, at the granularity of the buffer-pool page latch, is now reproducible deterministically from a
seed.** The demonstrated case is `rmp` #811: the reader is placed mid-property-chain-walk — it has
captured the record id of the next link and has not yet read it — while the engine thread runs GC
phase D and rewrites that record in place. `graphus-dst/tests/det_scheduler_gc_reader_811.rs` enters
that window **by construction** in 24 GC cycles, and **proves** it entered it by locating the phase-D
step between two of the reader's record-read steps in the recorded history. `graphus-storage`'s own
`offthread_reader_never_loses_live_property_across_gc_811` remains the probabilistic owner of the same
window: it hammers 20 000 cycles hoping the OS scheduler cooperates, and nothing in it can say whether
the window was ever entered. Two real threads sharing one store — the engine thread (writer and GC)
and an off-thread reader — therefore now produce a **byte-identical history for a given seed**.

**What that claim does not extend to.** It is reproducibility of an *interleaving*, over the threads
that share a store today. It is **not** a certification of N parallel writers: this simulator creates
none. The N-writer scenarios that `D-dst-writer-scheduler` requires arrive with `rmp` #975, and the
four write-path yield points (`WriteReadMvcc`, `WriteConflictCheck`, `WriteChainHeadUnheld`,
`WriteLinkDelta`) are installed but **not yet exercised** — with one writer thread per database there
is nothing to interleave at them. The code says so at each of them, and so does this specification.
Task **#1028** moved two of them: the undo chain's head-read (`WriteLinkDelta`) and head-publish
(`UndoChainHeadPublish`) now sit **inside** the publication retry loop, so every attempt — not only the
first — has its own read half and publication half for a future schedule to interleave.

What remains **outside** the ceiling, with its real owner:

| Parallel-race class (still invisible to DST) | Owning suite(s) — the authoritative proof |
| --- | --- |
| The server's off-thread reader **pool** (`#336`). DST drives `LocalEngine`, whose dispatch is a hardcoded `ReadDispatch::Inline`; the pool's workers are marked `sched::exempt` because they block in `recv()` on a bounded channel, and a thread that parks in `recv()` holding the execution token freezes the simulation. Bringing them under the scheduler requires the channel to become a scheduled resource. *(A single off-thread reader **thread** against GC is covered — see above. The **pool** is not.)* | `graphus-server/tests/concurrent_read_scaling.rs`, `concurrent_reader_serializability.rs` |
| Intra-query **morsel** fan-out (`#339`): DST never sets `morsel_threads > 1`, so it runs fully serial (degree 1). The rayon workers are marked `sched::exempt` for a different reason of their own — rayon owns its work-stealing scheduler, and two schedulers cannot both decide which thread runs | `concurrent_read_scaling.rs` (real reader pool + morsel threads) |
| `ConcurrentBufferPool` contended victim sweep / the `#359` fetch livelock; concurrent evictors. The scheduler **records** `select_victim` but cannot hand the token over there: the sweep runs under the page-table shard lock (section 5.2) | `graphus-bufpool/tests/loom_bufpool.rs`, `loom_eviction_storm.rs`, `loom_freeze_vs_reader.rs` |
| Doublewrite-buffer (DWB) eviction ring (`#411`/`#412`) | `graphus-bufpool/tests/loom_dwb_ring.rs`, `graphus-storage/tests/dwb_concurrent_eviction_411.rs` |
| SSI commit-path interleavings at the memory level | `graphus-txn/tests/loom_ssi.rs` |
| Real-OS-thread supernode write contention (the true-parallel pair to the DST `#220` logical guard) | `graphus-dst/tests/real_thread_supernode_stress.rs` |
| Two writers **prepending onto one chain head** at the same instant (`#1028`). DST cannot open this window: a database has one writer thread and `RecordStore`'s write methods take `&mut self`, so the scenario catalogued in section 10 scripts the interleaving through a `dst`-gated seam instead of racing it | `graphus-chainhead/tests/loom_chainhead.rs` (the concurrent half: both entries end up in the chain, no fork, no cycle, and a naive publication is required to lose one) |
| Engine-thread panic isolation; blocking-thread budget under load. The server's engine thread is `sched::exempt`: bringing it under the scheduler needs its blocking command/reply channels handled first | `graphus-server/tests/panic_isolation.rs`, `blocking_thread_budget.rs`, `connection_stress.rs`, `slow_consumer_no_head_of_line_block.rs` |

**The memory model stays outside, by construction and by refusal.** This is a limitation, not a
detail. The scheduler creates a *happens-before* edge between every pair of consecutive steps, so a
program running underneath it is **totally ordered**: ThreadSanitizer would observe no concurrent
access at all and report **zero** races — hiding precisely what the `scripts/tsan-soak.sh` lane exists
to find. The combination is therefore refused at **compile time** (`compile_error!` in
`graphus_core::sched`), as is the combination with `--cfg loom`, because loom takes ownership of the
interleaving itself and two schedulers cannot both own it. **The deterministic thread scheduler proves
interleaving defects, not memory-model defects.** Everything that already belonged to the loom family
and to the real-OS-thread family still belongs to them.

These owners fall in two families: **loom** suites (exhaustive interleaving of the atomic-level memory
operations) and **real-OS-thread** tests (genuine parallelism across threads). Both are **non-determin­istic
by nature**, so they are run as a **soak lane** (section 13, `scripts/tsan-soak.sh`) under
ThreadSanitizer — and that lane **must never feed the deterministic seed-replay gate**, whose
byte-identical contract requires the interleaving to be **seed-driven**, which OS scheduling is not.
Single-threaded execution was the original way of meeting that contract; since `rmp` #973 it is one
way of meeting it, and no longer the only one.

A second, narrower caveat (**F-DST-2**): the `#220` "concurrent writers" guard expresses K concurrency
as **K overlapping tickets executed sequentially** (commutative-overlap-at-commit), which is narrower
than the word "concurrent" suggests. Its true-parallel counterpart is the real-OS-thread supernode
stress named above.

### 5.2 The deterministic thread scheduler (rmp #973)

`D-dst-writer-scheduler` requires that multi-writer correctness be certified from a **seeded
schedule** rather than from an unreproducible race. The mechanism that carries that requirement is a
second deterministic scheduler, distinct from the cooperative interleaver of section 5 and working at
a different granularity. The two coexist.

| | Cooperative interleaver (section 5) | Deterministic thread scheduler (this section) |
| --- | --- | --- |
| What it orders | Transaction **lifetimes** | Real **OS threads** |
| Granularity | One scripted step per event; each Cypher statement runs atomically to completion | One declared **yield point**, inside a statement |
| Threads | One | N registered threads, exactly one running at a time |
| Source of the order | The `SimScheduler` event key `(due, rng-priority, seq)` | A seeded draw taken at each yield point |
| Recorded as | The canonical FNV-1a trace + state hash | A fixed-width byte history (`SchedHistory`) |
| Availability | Always | Only with the `det-sched` cargo feature |

#### 5.2.1 The mechanism

An installed scheduler owns a **single execution token**. Only the thread holding it runs; every other
registered thread is parked. At each yield point the running thread offers the token back, and the
scheduler draws the successor from a seeded `SimRng`. The global order of operations is therefore a
pure function of the seed.

Four rules make that a property of the design rather than a hope, and each is enforced in one place:

1. **No address ever enters a decision or the history.** `ResourceId` is a newtype over a
   class-tagged `u64` — a frame index, a page id, a store slot, a transaction id, a logical thread —
   and it has **no constructor from a pointer**. An address would differ between two runs of the same
   seed under ASLR, and the replay would diverge for a reason that has nothing to do with the
   schedule.
2. **No `std::thread::ThreadId`.** Logical thread ids are minted by the scheduler in registration
   order, and they are minted **by the parent while it holds the token**, before the child runs. Were
   children to register themselves on arrival, the registration order would itself be a race and
   determinism would be lost at birth.
3. **The runnable set is ordered** (a `BTreeSet`, never a `HashSet`), because its iteration order is
   an input to the RNG-indexed choice.
4. **No wall clock on a decision path.** Every draw comes from the `SimRng`. The only clock reads are
   the stall and hang backstops, which influence no schedule and fire only on a run that has already
   stopped making progress.

**Amortisation is seeded, never timed.** A hand-off at every visit to `with_page_fetched`, the hottest
read in the engine, would mean tens of millions of context switches, so each yield point draws once
and switches only with probability `switch_permille / 1000` (default 250; `DetSchedConfig::exhaustive`
raises it to 1000, which is what a scenario whose window is a handful of record reads wide requires).
This stays deterministic precisely *because* the token serialises the draws into one global stream. A
counter keyed on **time** would not, which is why there is none.

#### 5.2.2 The invariant: where the token may change hands

**The token is only ever handed over at a point where the yielding thread holds no buffer-pool frame
latch and no page-table shard lock.** A thread parked while holding either one freezes the simulation
rather than slowing it: only one thread runs at a time, so every other thread's blocking acquisition
of that lock waits for a holder that can never be scheduled. The invariant is enforced twice, by two
different mechanisms, because the two locks fail differently:

- **Frame latches** — `YieldSite::requires_no_frame_latch` classifies every latch-class site, and
  reaching one with a latch held trips the `rmp` #974/#993 latch-depth tripwire
  (`graphus_core::latch`) with a loud assertion. Reusing that tripwire is deliberate rather than
  inventing a second mechanism for the same property, and it inherits the tripwire's documented
  scope: exact in the debug profile every DST scenario runs under, vacuous in release. The
  yield is therefore placed **before** the latched region opens, never inside it, and the matching
  **release** is announced through `ReleaseOnDrop` / `ReleaseAllOnDrop` guards declared so that
  reverse drop order reopens the blocked set only once the latch is genuinely free.
- **The page-table shard lock** — this one cannot be forbidden, because the buffer pool genuinely
  takes it *around* work that reaches yield points: `select_victim` runs its entire CLOCK sweep under
  it, and `fetch` publishes its `Ready` entry under it **while still holding the freshly loaded
  victim's frame latch**. Handing the token over anywhere in there would park a thread holding both.
  A `NoSwitchScope` therefore suppresses the **hand-off** for the duration of the region. Inside such
  a region a yield point is still **recorded** — the site is provably reached, and the history stays a
  complete account of the run — but the token stays put, and no coin is drawn, so a suppressed
  hand-off never consumes the RNG stream.

`NoSwitchScope` was added to the design because of `fetch` and `select_victim`; it is not a general
escape hatch, and every use of it narrows what a seed can explore. That is the price of the invariant,
and it is why the contended victim sweep remains an entry in the section 5.1 table.

#### 5.2.3 Failure is a finding, never a hang

A thread that cannot take a contended resource parks on it and the token moves on; a release reopens
the set. Four backstops turn every way that can go wrong into a reported failure carrying the history:

- **Deadlock** — the runnable set empties while threads are parked. Reported with a dump of who is
  runnable and who is parked on what, never left to hang.
- **Stall** — the token holder stops making progress for `stall_timeout`, which means it is blocked
  inside a lock the scheduler does not mediate: a yield point placed inside a latched region, or an
  unscheduled thread holding a resource a scheduled thread needs.
- **Step budget** — a bounded `max_steps` fails a run that spins through yield points without
  converging.
- **Watchdog** — a separate, deliberately exempt thread aborts with a diagnostic in the one case the
  in-condvar stall check cannot observe: **every** scheduled thread wedged, so no thread is left to
  report it.

An unregistered, non-exempt thread that reaches a yield point **panics**. A thread the scheduler does
not control runs freely and would destroy the determinism of the whole run in silence, so a thread
that is deliberately outside the simulation must say so explicitly by calling `sched::exempt()`, at
the point where it is created and for a reason recorded there. Today that covers the reader-pool
workers and both WAL fsync offloads, which block in a channel `recv()`; the rayon analytics workers,
because rayon owns its own work-stealing scheduler; the server's engine thread, whose blocking
command and reply channels must become scheduled resources first; and the scheduler's own watchdog.

#### 5.2.4 The history

One scheduling decision is one `Step`, serialised into exactly **24 little-endian bytes** — sequence
number, logical thread, site code, a `switched` flag, an explicit pad byte, and the resource. Fixed
width and explicitly padded, so two histories compare as `Vec<u8> == Vec<u8>`, byte for byte, with
nothing to parse and nothing to normalise: a divergence is **located**, not merely detected. The
`YieldSite` discriminants are `#[repr(u16)]` and **append-only**; renumbering an existing site would
invalidate every recorded history, and two codes retired during design stay retired rather than being
recycled.

`SchedHistory` also carries the run's **non-vacuity numbers**: the count of steps at which the token
actually moved to a different thread, and the number of distinct threads that appear. A run in which
only one thread ever ran is perfectly deterministic and perfectly useless, so every suite asserts on
these before it asserts on the invariant it is really testing.

The digest is folded through the **same** FNV-1a hasher the VOPR already uses for its trace and state
digests, and `VoprReport` carries a `sched_history_hash` field so a schedule divergence would fail the
existing determinism gate without that gate being touched. **That field is `0` for every VOPR run
today, and honestly so**: the wire/engine VOPR drives the engine inline on one thread with no
scheduler installed, so there is no interleaving to digest, and the field records the absence rather
than inventing a number. It becomes live when a VOPR run first drives real concurrent writers
(`rmp` #975).

#### 5.2.5 Installed yield points

| Group | Sites |
| --- | --- |
| Buffer-pool frame latches | Every acquisition path (`with_page`, `try_with_page`, `with_page_fetched`, `fetch`, `with_page_mut`, `with_page_mut_lsn`, `flush`, `flush_unlogged`, `select_victim`, the batch flush) **and** the matching release |
| Thread lifecycle | Spawn, start, exit, join |
| Commit publication | The **durable** slot publication, the **in-memory** registry record, and the settling of the active-set entry — three sites, not one, because the window in which a commit is durable but not yet visible is exactly what a scheduled reader must be able to observe |
| Snapshot acquisition | The reclamation floor every GC watermark derives from, and the snapshot an off-thread read task carries away |
| Storage | Free-list push (a slot becomes reusable), undo-chain-head publication |
| Garbage collection | Phases A, B, C, B2, F, D and E **individually** — not the pass as a whole. The pass is the coarsest possible grain and would make every reclamation atomic with respect to a reader, which is exactly the interleaving the `rmp` #811 class lives inside |
| Write-path header reads | `read_mvcc`, the write-write conflict check, the chain-head ownership check, and the chain-head read in `link_delta`. **Installed but not yet exercised**: their writer-versus-writer value arrives only with `rmp` #975 |

#### 5.2.6 Cost, gating, and what runs it

**The cost in production is zero.** With `det-sched` off, `yield_at` is an empty
`#[inline(always)] const fn`, the release announcements are zero-sized types with empty `Drop` bodies,
`acquire` reduces to calling its blocking closure, and `spawn` is `std::thread::spawn`. There is no
branch to predict and no code to eliminate. The installation API — the `Scheduler` trait, `install`,
`Installed` — does **not exist** without the feature, so a test that installs a scheduler fails to
compile in the default build rather than silently running unscheduled and asserting a determinism
property it never exercised. `scripts/verify.sh` proves the claim mechanically rather than arguing it:
it builds the release server the way the shipped binary is built
(`cargo build --release --locked -p graphus-server`) and requires **zero** scheduler symbols in the
result. A `-p graphus-server` resolve cannot reach the feature, so every scheduler symbol must be
absent.

**The gate is a cargo feature, deliberately not `debug_assertions`.** `graphus_core::latch` chose
`debug_assertions` for its tripwire, and rightly: a *correctness* tripwire costing a thread-local
increment should be armed across the whole suite. A scheduler hook is *hot-path instrumentation* — it
sits on `with_page_fetched` — and under `debug_assertions` it would be live in every
`cargo test --workspace`, instrumenting the very paths the other gates exist to certify. The feature
is enabled by **no dependency declaration anywhere in the workspace**; only `graphus-dst`'s own
passthrough turns it on, and only for the two test targets that declare
`required-features = ["det-sched"]`. That isolation is the point: Cargo unifies features per resolve,
so a crate that merely *declared* the dependency would arm the hook in every build that transitively
reaches `graphus-core`, which is every crate in the workspace.

Because those targets are outside the default resolve, `cargo test --workspace` does not even compile
them. A suite behind an opt-in feature that no automated gate ever enables is a defect class this
project has already been bitten by, so `scripts/verify.sh` invokes all three — the scheduler's own
unit tests and both scenario suites — explicitly, at step 5, together with the symbol-absence check
above. It is gate 13 of `VERIFICATION.md`.

#### 5.2.7 What the suites prove

| Suite | Claim |
| --- | --- |
| `graphus-dst/src/detsched.rs` unit tests | The mechanism itself: byte-identical replay, distinct interleavings across seeds, fixed-width records, and an unreleasable park reported as a deadlock |
| `graphus-dst/tests/det_scheduler_gc_reader_811.rs` | Over the **real two-thread engine**: the same seed replays byte-identically, different seeds explore, the `rmp` #811 window is entered by construction and provably so, and the installed yield points are actually reached |
| `graphus-dst/tests/det_scheduler_elle_oracle.rs` | The isolation oracle still rules on what the scheduler produces — on a genuinely two-threaded scheduled history, and on the existing VOPR safety run with a scheduler installed over it, whose report must stay identical |

The two headline claims — that one seed replays byte-identically and that different seeds explore
different interleavings — are asserted **over the engine scenario**, not over the scheduler's own
self-test. A self-test of the mechanism is a legitimate unit test of the mechanism, but it cannot
stand in for those claims: it would let them pass without the engine ever having been scheduled.

## 6. Fault models

Sprints 22–25 added a composable, fully seeded fault library. Every fault is a pure function of its
plan's seed (no wall clock, no OS entropy on any path) and every fault is designed to be **detectable
or survivable** — corrupt data is never silently served as valid, and the chaos stays bounded so the
engine can still recover.

### 6.1 Disk faults — `graphus_io::FaultPlan` on `MemBlockDevice`

A seed-driven `FaultPlan`, armed via `MemBlockDevice::arm_fault_plan`, drives an in-file SplitMix64 PRNG
(no external RNG crate) to model the disk pathologies the storage spine must recover from:

- **Bit-rot** — flips a seeded, bounded set of bytes when a target page is *read*, forcing each flip to
  actually change a byte, so the page no longer matches its checksum.
- **Misdirected read** — reading page `from` returns the bytes of a different page `to` (whose header
  carries the wrong id, so the caller's page-id/checksum check must reject it).
- **Misdirected write** — writing `from` persists to page `to` instead; `from` keeps its old contents
  and `to` is silently overwritten.
- **Latent sector error** — a page is marked unreadable, so a later read hard-fails instead of serving
  bytes.
- **ENOSPC** — `extend` past a seeded capacity cap fails, modelling a full disk (the failure is sticky,
  not one-shot, and a failed extend grows nothing).
- **Write reordering** — a sync persists only a seeded subset (a configured percentage) of the pending
  page cache and leaves the rest cached, so a subsequent crash loses that pre-sync subset, modelling a
  non-atomic, reordered flush. This resolves the formerly deferred `WriteReordering` fault: it is now a
  real injected fault.

An empty (default) plan is inert: arming it changes nothing.

### 6.2 The live-engine fault seam (`dst` cargo feature)

To arm a disk fault on a **running** store mid-workload (rather than only on a device the harness owned
before construction), the engine exposes a fault seam gated behind the `dst` cargo feature:

- `RecordStore::device_mut()` and `LocalEngine::with_device_mut(f)` borrow the engine's live block
  device so the harness can arm a `FaultPlan` (or the one-shot I/O-error / torn-write seams) during
  interleaved transactions. `LocalEngine::with_device_mut` returns `None` on an already-shut-down
  engine, so a caller can never panic on a spent engine.
- `RecordStore::dst_publish_node_first_rel(node, expect, entry, txn)` (task #1028) publishes a node's
  `first_rel` chain head through the ordinary publication primitive, reporting whether the
  compare-and-publish was accepted. It exists so a scenario can **script** the interleaving a second
  writer would produce — read the head, let another transaction publish onto it, then replay the first
  writer's now-stale publication — which is the same window a race would open. Gated with the rest of
  the seam and therefore never compiled into a production build, so it adds no writer of a chain head
  to a shipped binary.
- The feature forwards down the crate chain (`graphus-server/dst` → `graphus-cypher/dst` →
  `graphus-storage/dst` → `graphus-bufpool/dst`) and is **off by default**, so the production build
  never compiles the seam — the device stays encapsulated and the cost is exactly zero (the method does
  not exist on the production path).

This seam resolved the former `WriteIoErrorFullEngine` deferral: a write I/O error plus a later read
corruption can now be armed through the **full** engine (not just the buffer-pool layer), and the engine
must surface the error and never serve or commit corrupt data.

### 6.3 Clock faults — `graphus_sim::FaultyClock`

`FaultyClock` wraps any `Clock` and perturbs it from a seeded `ClockFaultPlan`:

- **Bounded skew** — a fixed signed offset (drawn once from the seed, within `±bound` ns) added to
  every reading; models a clock that runs a constant amount fast or slow.
- **Forward jumps** — a seeded, bounded forward leap on some reads (an NTP step, a VM resume); each read
  jumps with a per-mille probability.
- **Non-monotonic regressions** — a seeded, bounded step *backward* on some reads (a wrong-way clock
  correction), so two successive reads can go down.

The clock exposes a documented **tolerance contract** with two read paths:

- `now_nanos()` (the tolerant `Clock` read) serves the full hostile reading, including regressions.
  Timestamping and latency paths use it and already compute durations with `saturating_sub`, so a
  backward read yields a clamped (never negative) duration rather than a panic.
- `now_nanos_monotone()` is used where a non-decreasing source is a correctness precondition (lease /
  lock expiry, keep-alive deadlines). It passes readings through a high-water mark so a faulted reading
  below the previous one is saturated up to it and the value never regresses; skew and forward jumps
  still pass through.

The four guarantees the model upholds: every reading is **bounded** (a hostile clock can never reach
infinity or zero), **durations are never negative**, **monotone reads never regress**, and the whole
sequence is **deterministic** for a given seed.

### 6.4 Transport faults — `graphus_sim::TransportFaultPlan` on `SimNet`

A seeded `TransportFaultPlan`, armed on a `SimNet` link direction, models the pathologies a reliable
transport genuinely exhibits, expressed at **byte-offset precision** so they can land *inside* a
`RUN` / `PULL` / `COMMIT` message, not only at a message boundary:

- **Drop in message** — the link is reset the instant cumulative delivery first reaches a seeded byte
  offset; bytes delivered before the offset stay readable, every read/write afterwards errors.
- **Truncate-then-stall** — only the first seeded prefix of bytes is delivered, then the direction
  half-closes (the reader sees the prefix, then EOF) and the rest is discarded; the reader still
  terminates rather than hanging.
- **Slow consumer** — delivery is throttled to a seeded byte budget per network step (backpressure);
  all bytes still arrive in order, only the rate is capped, so the exchange still reaches quiescence.

The faults **preserve the reliable-stream invariant otherwise**: the bytes that *are* delivered stay
ordered and uncorrupted, and every fault drives the reader to a terminal state (a reset error or an
EOF), so a blocking `BoltSession::run` read always returns rather than blocking forever.

### 6.5 Crash + ARIES restart woven into the interleave

A seeded **crash + ARIES restart** fault can fire *during* the interleave (`CrashSplit`, in `vopr.rs`).
At the firing step the simulator snapshots the durable WAL prefix, drops the live engine (the crash),
and rebuilds a fresh engine purely from that WAL via `LocalEngine::crash_restart` (ARIES recovery),
reusing the same swappable faulty clock so time and clock faults stay continuous across the restart.
The workload then continues on the recovered engine.

The crash fires at the most dangerous durability moment: acknowledged commits and still-open
(in-flight) transactions coexist. Each crash records a `CrashSplit` tracking the acked-vs-in-flight
counts and the post-recovery state hash. Every acknowledged commit must survive the restart (ARIES
redo); every transaction still open at the crash must not (ARIES undo / no-redo). After recovery, all
clients are reset to `Idle` so none reuses a ticket from the dead engine; remaining op budget is
untouched, so the run continues.

### 6.6 The unified fault scheduler and seeded budget

`FaultScheduler` (`vopr_fault.rs`) does not reinvent any fault model; it **schedules** the models above
on the interleaver's single timeline. It decides, up front from a **dedicated** fault RNG
(`master_seed ^ FAULT_TAG`) under a bounded `FaultBudget`, which dispatched-step ordinals fire which
fault, and folds every decision into the canonical trace, so the fault schedule is part of the
reproducible run and does not consume draws from the workload stream.

The `FaultBudget` caps both the **rate** (`max_faults` over the run; `max_crashes` separately) and the
**intensity** (`disk_max_pages`, `disk_page_span`, `clock_max_ns`), and weights which kinds are eligible
(`disk_weight`, `clock_weight`, `transport_weight`). Crashes are off by default (`max_crashes == 0`), so
a standard run never crashes and replays bit-for-bit; the caps keep the chaos recoverable, never a
guaranteed wipe.

**Honest transport status.** Disk and clock faults are physically injected: disk via the `dst`-gated
live-device seam (section 6.2), clock by intensifying the engine's `FaultyClock` plan. Transport faults
are **scheduled, budgeted and folded into the trace** so the budget and reproducibility cover them. The
main in-process VOPR loop calls `LocalEngine` directly (no `SimNet` byte stream to reset), but the
scheduled transport plan **is physically applied** through the `SimNet`-backed Bolt driver
(`wire::run_bolt_session_with_scheduled_transport_fault`, rmp #462, closing F-DST-4): it pulls the very
plan the scheduler folded into the trace via `FaultScheduler::take_transport_plan` and arms it on the
real Bolt session's link, so a mid-message-severed `RUN`/`PULL`/`COMMIT` byte stream is exercised against
the genuine Bolt state machine. The recovery oracle asserts the state machine never panics or hangs
(`run()` always returns) and that a severed transaction is atomic (it never half-commits). The same
seeded `TransportFaultPlan` also drives the REST request core
(`wire::run_rest_with_transport_fault`). The simulator never fakes a transport fault it cannot physically
apply.

## 7. Adversarial and environment coverage

- **Misbehaved clients** (`dst::misbehave`, via `wire::drive_raw_bolt`): garbage after handshake,
  truncated/oversized chunk headers, `RUN` before `LOGON`, bad credentials, unsupported version. The
  real Bolt stack must never panic/hang and must return the correct protocol error or close cleanly.
- **Environment faults** (`dst::faults`): network partition/reset/delay; the disk, clock, transport and
  crash fault models of section 6; and **crash + restart** (`LocalEngine::crash_restart` rebuilds from
  the durable WAL via ARIES recovery).
- **Load/stress** (`vopr` + `LoadProfile`): high-concurrency runs with liveness (monotone progress, no
  hang) and consistency (`created == persisted`) checks.

## 8. Oracles

1. **Strong reference model** (`vopr_oracle.rs`) — a deterministic in-memory **shadow LPG**
   (`ShadowGraph`) applies exactly the *committed* workload operations and is compared **cell-by-cell**
   against the engine queried back: the multiset of node ids, the multiset of relationships keyed by
   stable `(src_id, dst_id)` property keys, and the `count(n)` / neighbour read-backs. The comparison
   keys on the workload's own `id` property (the model cannot predict the engine's internal record
   numbers), uses **multiset semantics** (a duplicate id is a second node; an edge is a Cartesian
   product over its endpoint matches), and is applied **only on COMMIT** — rolled-back, SSI-aborted, or
   crash-lost transactions are discarded, never applied, mirroring the durability contract. A divergence
   surfaces as a precise `OracleError` naming the offending id or edge. The oracle's read-backs run in
   their own auto-commit read transactions and are not folded into the trace, so wiring it in does not
   perturb `trace_hash`.
   - **Property values + secondary index (rmp #461).** The model additionally tracks each id's `rank`
     property and, on every commit, the oracle cross-checks three things the structural multisets are
     blind to: (a) each id's `rank` value (catching a wrong property left by a concurrency bug — e.g. an
     SSI rollback restoring a stale pre-image over a committed `SET`); (b) an **indexed** `rank` seek
     (`MATCH (n:Person {rank: $v})`) against the model; and (c) the indexed seek against a **forced full
     scan** (`MATCH (n:Person) WITH n WHERE n.rank = $v`) — a disagreement is a secondary-index-vs-base
     divergence (the surface of #313/#316). This check is driven by the dedicated **`property_index_oracle`**
     scenario (section 10), which exercises `SET`/`DELETE` churn over a declared `(Person, rank)` index;
     it runs **only** when `rank` data is present, so the default workload's `trace_hash` is unchanged. The
     contended workload vocabulary `WorkloadOp` is extended with `SetProperty` and `DeleteNode`, generated
     only by that scenario's driver — never by the default `WorkloadGen`, so the seed-replay gate stays
     byte-identical.
2. **Isolation / serializability** — `graphus-elle`: an Elle/Adya dependency-graph checker over the
   list-append model (`ww`/`wr`/`rw` edges, cycle detection). `dst::isolation` drives interleaved
   real transactions and feeds the recovered history to it.
3. **Invariants / liveness** — no panic/hang under misbehaved and stress workloads; correct error
   taxonomy.
4. **Durability under crash/restart** — acked commits survive `crash_restart`; uncommitted work does
   not.

## 9. Certification modes — safety, liveness, swarm

The VOPR core can run in three certification modes, each a thin wrapper over the same cooperative
interleaver and selected from the CLI (section 13).

### 9.1 Safety mode (`run_safety` → `SafetyReport`)

Safety mode bundles **four** properties that must all hold simultaneously, under fault injection, on a
contended interleave (overlapping explicit transactions under a write-heavy mix, with faults and crashes
firing during concurrent work):

- **Serializability** — the recovered history is acyclic and order-consistent (the `graphus-elle`
  checker).
- **Durability** — every acknowledged commit from before a crash survives the ARIES restart.
- **Atomicity** — no in-flight or rolled-back effect persisted.
- **Reference-model equivalence** — the shadow model (section 8) agrees with the engine cell-by-cell.

The `SafetyReport` records `safe` (true iff no property was violated), the number of checked
transactions, every `SafetyViolation` (each naming the broken `SafetyProperty` and a detail string), and
the underlying deterministic `VoprReport`.

### 9.2 Liveness mode (`run_liveness` → `LivenessReport`)

Liveness mode asserts the engine makes progress and recovers availability, under a bounded, recoverable
fault window:

- **Progress watchdog** — tracks the longest run of consecutive dispatched scheduler steps during which
  no client advanced its state machine. If that run reaches a generous, client-scaled stall threshold
  (`8 * clients + 32`) — or the run trips the hard step cap on a non-empty queue — the engine is judged
  wedged (deadlock / livelock / hang). The watchdog is **bounded by the same hard step cap as the
  workload**, so a real engine hang becomes a returned `LivenessReport { live: false, .. }`, never an
  actual infinite loop or CI hang.
- **Fault-then-heal recovery** — after the workload drains and every fault and crash has healed, a
  fresh deterministic post-heal workload batch must fully commit *and* read back correctly (the
  reference model agrees), proving the engine resumed serving correct results.

The `LivenessReport` records `live`, any `LivenessFailure` (`ProgressStalled` or
`DidNotRecoverAfterHeal`), the worst stall length and where it occurred, a bounded ring of the recent
schedule for debugging, and the post-heal recovery counts.

### 9.3 Swarm testing (`VoprConfig::swarm(seed)`)

Swarm testing derives the **entire** configuration — environment (clients, ops-per-client, pool pages),
workload mix, load profile, transaction shape, and fault budget — deterministically from the master seed
within sane, documented, bounded ranges, using a dedicated swarm RNG (`seed ^ SWARM_TAG`). Because the
swarm stream is domain-separated from the workload (`seed`) and fault (`seed ^ FAULT_TAG`) streams,
swarming the environment chooses the knobs without perturbing the workload or fault draws; the three
streams compose deterministically from the one seed. The bounds keep every swarmed run recoverable: at
least two clients (so transactions overlap), pools small enough to induce eviction but never zero,
faults and crashes capped so no swarmed config can guarantee a wipe.

## 10. Scenario catalogue

`dst::scenarios` is a named catalogue of known graph-DB usage patterns. Each scenario is a pure
`fn(seed) -> ScenarioOutcome` that drives the **real** engine (inline, deterministic) and checks an
oracle appropriate to it. The workload scenarios reuse the `vopr` runner + `dst::mix`; the structural
ones drive a `LocalEngine` directly. `run_sweep(seeds)` runs every scenario across a seed range and is
the CI-friendly entry point. The in-crate battery is deliberately sized to stay fast in a debug build;
raw scale is delegated to the `vopr` CLI seed-sweep.

The catalogue holds **21 scenarios**, grouped by the production-readiness dimensions a graph database
must satisfy under extreme concurrency and load. Each entry below names the scenario, the production
concern it certifies, and its oracle.

### OLTP / ingest / serving

- `oltp_mixed` — a balanced read/write mix runs cleanly. *Oracle:* `created == persisted`, the run
  replays identically (determinism), and no spurious errors occur.
- `bulk_ingest` — a write-heavy ingest workload. *Oracle:* every acked create persists
  (`created == persisted`, no errors).
- `read_serving` — a read-heavy serving workload. *Oracle:* the run is deterministic and produces no
  spurious errors.

### Traversal / structural

- `deep_traversal` — a variable-length chain is traversed end to end. *Oracle:* the variable-length
  traversal reaches the tail.
- `supernode_fanout` — one hub with a large sequential fan-out. *Oracle:* counting the hub's out-edges
  returns exactly the fan-out.
- `large_result_stream` — a single query streams 200 rows. *Oracle:* exactly 200 rows are returned.
- `cyclic_traversal` — a directed cycle is traversed variable-length. *Oracle:* the traversal
  terminates (no hang) by way of Cypher relationship-uniqueness and reaches every node in the cycle —
  liveness on cyclic graphs.

### Lookup / aggregation

- `point_lookup` — exact property-equality lookups. *Oracle:* each hit returns exactly one row and a
  miss returns zero rows.
- `aggregation_analytics` — a global `count(n)` over the full dataset. *Oracle:* the aggregate is
  exact.

### Isolation / concurrency

- `contended_writes` — two writers update an existing node concurrently. *Oracle:* SSI must not let
  both transactions commit.
- `concurrent_supernode` — two concurrent writers each create an edge on the **same** hub. *Oracle:*
  both commit and both edges persist (`fan-out == committed`). The scenario asserts only the safe
  two-writer boundary; see finding rmp #220 in section 14.
- `snapshot_isolation` — a read transaction's snapshot must stay stable while a concurrent writer
  commits. *Oracle:* the reader observes the same count twice within its transaction (repeatable read),
  and a fresh read afterward then sees the new row.

### Property / secondary index

- `property_index_oracle` (rmp #461) — a contended `CREATE`/`SET rank`/`CREATE edge`/`DETACH DELETE`
  workload over a declared `(Person, rank)` secondary index. *Oracle:* on every commit the extended
  reference model (section 8) cross-checks **property values**, the **indexed `rank` seek vs the model**,
  and the **indexed seek vs a forced full scan** (index-vs-base-store). Closes the oracle's former
  blindness to property values, secondary indexes, and delete churn.

### Atomicity / churn

- `transaction_rollback` — a write inside a rolled-back transaction. *Oracle:* the rollback leaves no
  trace (atomicity).
- `churn_create_delete` — create N nodes, `DETACH DELETE` all of them, then create N again. *Oracle:*
  the count returns to the baseline at each step (delete is honoured and storage is reused via the
  free-list).

### Durability / crash recovery

- `crash_recovery_durability` — drives `LocalEngine::crash_restart` (ARIES recovery from the durable
  WAL). *Oracle:* an acked commit survives the crash and uncommitted work does not.
- `chain_head_publication_recovery_1028` (rmp #1028) — 200 seeds of prepends onto one hub node's
  `first_rel` chain head, crashed by both shapes (steal: dirty pages already written home; no-force:
  only the durable WAL prefix survives) and recovered through ARIES. Each seed also **scripts** the
  interleaving a second writer would produce, through the `dst`-gated `dst_publish_node_first_rel`
  seam (section 6.2): it reads the head, lets another transaction publish onto it, and then replays the
  first writer's now-stale publication. *Oracle:* the stale publication is **refused**; and after
  recovery the hub's incidence chain still holds **every** committed relationship — a conditional redo
  that declined at replay would leave the head naming an older entry and silently drop every edge
  published after it. Non-vacuity is asserted, not assumed: each seed must have committed at least
  four prepends onto the one head, and the sweep must have exercised **both** crash shapes. The pool is
  deliberately small (16 frames) so eviction and the WAL-before-data rule are live throughout rather
  than everything staying resident until the crash.
- `backup_restore_crash` (rmp #440) — drives the genuine backup → seal → file → restore /
  key-rotation pipeline on **real temp files** and injects a crash at each of its four atomicity windows
  (after `seal_artifact` / before the backup rename; mid `write_file_atomic`; mid
  `restore_chain_file_atomic` temp write; after the device temp-rename / before the WAL + DWB reset).
  *Oracle:* at every window the database opens to a **committed-only, consistent** state **under exactly
  the expected key** (a wrong key fails closed). Reconstructs the pipeline at the public-API level
  (`LocalEngine::backup`, `graphus_crypto::seal_backup`/`open_backup`, `atomic_replace_file`,
  `restore_chain_file_atomic`, `verify_on_open`), since the server's `dbcatalog` orchestration is
  private.

### Network bulk import

- `network_bulk_ingest_mode_a` (rmp #519) — drives `LocalEngine::bulk_import_batch` against a fresh
  database: seed-varying node/relationship batches with cumulative-stats assertions, an
  aborted-batch (duplicate `:ID` under the Strict policy) retry proven idempotent, and a crash
  mid-session. *Oracle:* every committed batch's cumulative stats are exact; the doomed batch leaves
  no trace; after `crash_restart`, all previously committed nodes/relationships and the durable
  checkpoint sentinel node (`batch_seq`/`nodes`/`relationships`/`properties`) survive intact; `End`
  deletes the sentinel and reports the final stats on an uninterrupted session (the documented no-op
  behavior of `End` immediately after a crash-restart, before the `LoadingSession` is re-established,
  is asserted explicitly — see `crates/graphus-server/src/engine/bulk_load.rs`'s module doc on the
  resumability contract). Reconstructs the ingestion path at the public-API level (`LocalEngine`),
  the same convention `backup_restore_crash` established, since `08-network-bulk-import.md`'s
  HTTP-transport and `DatabaseCatalog`/`Loading`-state layers are DST's structural non-goals
  (covered instead by `dbcatalog.rs`'s `mod tests` and `graphus-server/tests/bulk_import_endpoint.rs`).
- `network_bulk_ingest_mode_b` (rmp #520) — Mode A's concurrent, higher-risk sibling: drives
  `LocalEngine::begin`/`bulk_import_mode_b_chunk`/`commit` against an already-**live** database (no
  `Loading` exclusivity), through a synchronous, DST-local mirror of
  `graphus_server::bulk_import_mode_b::drive_mode_b_batch`'s retry-loop shape (`drive_mode_b_batch_sync`
  — the real async driver cannot run against a synchronous `LocalEngine`; its own real-`EngineHandle`
  tests live in `graphus-server/src/bulk_import_mode_b.rs`). Covers, in order: (1) **joint
  serializability** — a Mode B node batch interleaved with an ordinary concurrent read-then-append
  Cypher transaction on a shared key, checked via the Elle list-append model (`graphus_elle::check`),
  the same convention `isolation.rs` establishes; (2) a **seeded, genuine SSI pivot abort** (the exact
  `graphus_txn::ssi::SsiTracker::add_edge` eager committed-pivot-break rw-edge sequence, not a mock) of
  an in-progress batch under `max_retries=0` (surfaces immediately, atomically, `GraphusError::
  Transaction`-classified) and again under retries enabled (the real retry loop converges to exactly
  the retry's own contribution — no duplication, no stale bindings); (3) **concurrent readers at
  different snapshot begin timestamps** observe exactly "everything committed strictly before my
  snapshot began," proven precisely (exact counts), never inferred; (4) a **dense/hot pre-existing
  node** targeted by both a concurrent ordinary writer and a Mode B batch — fan-out exactly matches
  what committed (the #220 invariant, Mode B as one of the two writers); (5) the **chunking mechanism**
  genuinely bounds a single `bulk_import_mode_b_chunk` dispatch's row count (a direct assertion on
  dispatched chunk sizes — real wall-clock engine-thread-yielding latency is DST's structural
  non-goal here, covered instead by `graphus-server/tests/bulk_import_mode_b_fairness.rs`, the same
  DST/integration split this section already uses for Mode A's transport layer); (6) a **crash
  mid-batch** while unrelated ordinary transactions concurrently commit — recovery reconciles the
  interleaved WAL exactly (every actually-committed row present, the never-committed in-flight batch
  absent, nothing torn). *Oracle:* every bullet above is asserted precisely (exact counts/classes),
  not just "no crash"; `network_bulk_ingest_mode_b_holds_across_seeds` (`scenarios.rs`) pins a 20-seed
  deterministic-replay + always-holds gate independent of the whole-catalogue sweep.

### Load shapes

- `spike_load` — a thundering-herd arrival shape (`LoadProfile::Spike`). *Oracle:* the run stays live
  and consistent (deterministic, no spurious errors, `created == persisted`).
- `ramp_load` — an accelerating arrival shape (`LoadProfile::Ramp`). *Oracle:* the run stays live and
  consistent (same checks as `spike_load`).
- `sustained_high_concurrency` — 16 interleaved clients under heavy load. *Oracle:* liveness (every
  scheduled op runs, monotone progress), `created == persisted`, deterministic replay, and no spurious
  errors.

## 11. Shrink and replay (`vopr_repro.rs`)

Every failing run can be persisted and reproduced exactly:

- A **`ReplayArtifact`** is a self-contained JSON reproducer holding the run's `mode`, the full
  `VoprConfig`, the expected `trace_hash` and `state_hash`, and a failure summary. Because the run is a
  pure function of its config, loading the artifact and re-running reproduces the **exact** failure.
- **`vopr-repro --replay <file>`** loads an artifact, re-runs the recorded mode and config, and
  certifies a byte-identical reproduction: the reproduced `trace_hash` / `state_hash` must equal the
  recorded hashes (the determinism gate) **and** the run must still be a failure. The `ReplayOutcome`
  distinguishes the three cases — faithfully reproduced, hash mismatch, or no longer failing.
- **`vopr-repro --shrink <seed>`** runs a deterministic, bounded greedy shrinker: it reduces one config
  knob at a time, accepting a candidate only if it still fails, keeping the config monotonically
  smaller. Knobs are tried in a fixed order (most impactful first); the search is reproducible and
  bounded by a candidate cap, and the emitted artifact is always a real, still-failing — and minimal —
  reproducer.

## 12. Hyper-speed fuzzer (`vopr_fuzz.rs`)

The fuzzer turns "a run is a pure function of its config" into a continuous, wall-clock-time-budgeted,
**parallel multi-core** seed sweep:

- It enumerates a contiguous range of seeds (optionally swarming each seed's full environment, section
  9.3) across `jobs` worker threads, each building its own engine. The wall clock is read **only** in
  the orchestrator — to bound the soak (`--secs`) and measure throughput — never inside a per-seed run.
- Each seed's `SeedVerdict` (`failed`, `trace_hash`, `state_hash`, ops, simulated time) is a pure
  function of `(mode, config, predicate)` — independent of which worker ran it or of thread timing — so
  the **parallel sweep's verdict set is provably equal to a serial sweep's** over the same range, sorted
  by seed.
- The `FuzzReport` reports the verdict set plus throughput: seeds-per-second, ops-per-second, total
  simulated time, and elapsed wall-clock. The verdict set is the determinism contract; the throughput
  metrics vary run to run and are explicitly *not* part of it.
- On any failing seed the fuzzer emits its section 11 `ReplayArtifact` (planted-seed artifact emission),
  so a nightly failure ships a self-contained reproducer.

## 13. CLI and CI integration

The `graphus-dst` binary exposes the VOPR modes as subcommands:

- `graphus-dst vopr --seed B --seeds K` — the serial determinism + reference-model sweep.
- `graphus-dst vopr safety --seed B --seeds K` — the safety bundle (section 9.1).
- `graphus-dst vopr liveness --seed B --seeds K` — the liveness checks (section 9.2).
- `graphus-dst vopr fuzz --mode <m> [--swarm] [--secs T] [--max-seeds N] [--jobs N] …` — the
  time-budgeted soak fuzzer (section 12).
- `graphus-dst vopr-repro --replay <file>` / `--shrink <seed>` — replay and shrink (section 11).

A non-zero exit status signals at least one failing seed, listed for one-line reproduction.

**PR CI gate** (`.github/workflows/ci.yml`). A dedicated `dst` job on the x86_64 Linux runner runs a
fast, bounded VOPR sweep that fails on any violation, non-determinism, or oracle divergence:

- `vopr safety --seed 1 --seeds 256`
- `vopr liveness --seed 1 --seeds 256`
- `vopr --seed 1 --seeds 256` (determinism + reference-model)

The gate is bounded to 256 seeds per mode so it stays a quick check, and lives in its own job (separate
from the `test` matrix) so it runs once on a single runner. It fires on pull requests, on pushes to
`main`, on version tags, and on manual dispatch — but, because `push` is scoped to `main` + tags, it
never runs on an ordinary feature-branch push (those reach CI only through their pull request). The
release-optimised crash-recovery soaks (`selfloop_churn_recovery`, `property_churn_recovery`,
`double_crash_recovery`) run in the same `dst` job.

**Nightly soak** (`.github/workflows/nightly-fuzz.yml`). A scheduled job runs the swarmed,
time-budgeted fuzzer once per mode (`safety`, `liveness`, `standard`) — `vopr fuzz --mode <m> --swarm
--secs <budget> --keep-going --write-artifacts <dir>` — and, on any failing seed, uploads the emitted
replay artifacts so the exact failure can be reproduced locally via `vopr-repro --replay`.

**Threaded concurrency soak under ThreadSanitizer** (`scripts/tsan-soak.sh`, rmp #460). A separate,
**non-deterministic, soak-only** lane runs the **real-OS-thread** owners of the parallel-race class
(section 5.1) under ThreadSanitizer (`-Z sanitizer=thread`, nightly toolchain): the
`graphus-server/tests` concurrency tests (`concurrent_read_scaling`, `concurrent_reader_serializability`,
`panic_isolation`, `blocking_thread_budget`, `connection_stress`,
`slow_consumer_no_head_of_line_block`), the `graphus-storage` DWB real-thread test
(`dwb_concurrent_eviction_411`), and the `graphus-dst` real-thread supernode stress
(`real_thread_supernode_stress`). This lane is the **named owner** of the true-parallel races that remain
outside the section 5.1 ceiling; it asserts the absence of **data races**, which no byte-identical
seed-replay run can detect — including a scheduled one, whose steps are totally ordered. It is
**deliberately excluded from the deterministic seed-replay gate** — its thread interleaving
is OS-scheduled, not seed-driven, so feeding it into the byte-identical gate would be a category error.
The loom suites (`graphus-bufpool/tests/loom_*`, `graphus-txn/tests/loom_ssi`) are the exhaustive-interleaving
complement and run on their own (`RUSTFLAGS=--cfg loom`).

This lane must also **never be combined with the deterministic thread scheduler** of section 5.2, and
the combination is refused at compile time rather than left to discipline: the scheduler totally
orders the program, so ThreadSanitizer running underneath it would observe no concurrent access and
report zero races — a vacuously clean soak. The same refusal applies to `--cfg loom`.

**Deterministic thread-scheduler suites** (`scripts/verify.sh` gate 5; `VERIFICATION.md` gate 13). The
scheduler's own unit tests and the two scenario suites of section 5.2.7 are run with
`--features det-sched` explicitly, because `required-features` keeps them out of the default
`cargo test --workspace` resolve entirely. A companion step rebuilds the release server and requires
**zero** scheduler symbols in the binary, which is how the zero-production-cost claim is verified
rather than asserted.

## 14. Findings (engine gaps surfaced by the simulator)

The simulator did its job and surfaced three real serializability/durability gaps (filed in `rmp`,
pinned by tests so they cannot silently regress). All three (**#171**, **#172** and **#220**) are now
**FIXED** in the engine and their pins were flipped into regression **guards**:

- **rmp #171 (FIXED) — phantom write-skew / lost-update.** Two transactions that each read a predicate
  returning nothing and then insert a row matching the other's predicate previously **both committed**
  (non-serializable), because per-record SIREAD markers only close an rw-antidependency when a writer
  overwrites a record the reader already saw, never on a phantom insert. *Fix:* SSI now also maintains
  **predicate SIREAD markers** — a reader registers the predicate footprint it depends on, and a
  concurrent writer whose insert / relabel / `SET` makes a node newly match that predicate (its
  predicate *write* footprint) forms the missing `reader --rw--> writer` edge, feeding the unchanged
  Cahill dangerous-structure detector so exactly one transaction aborts. Relationship phantoms (read
  "no `:T` edges", concurrent create of a `:T` edge) are covered by a predicate marker keyed by the
  relationship-type token. Guarded by `phantom_insert_into_equality_predicate_still_aborts` and
  `same_key_equality_scan_write_skew_still_aborts_one` in
  `crates/graphus-cypher/tests/ssi_scan_filter_eq.rs`.
- **rmp #172 (FIXED) — concurrent same-node write–write durability.** The conflict is detected (SSI
  aborts exactly one), and the surviving committed transaction's update now **persists** — the value
  reflects exactly one increment, never reverting to the pre-image. *Root cause:* the SSI loser's
  rollback restored a stale `first_prop` chain-head pre-image over the survivor's committed value.
  *Fix:* the chain-head update logs a **compare-and-set logical undo** (unlink only if still the head)
  and a record creation logs a **header-only undo** (revert the slot to not-in-use while preserving
  its forward chain pointers), so an abort never reverts another transaction's committed structure.
  Guarded by `isolation::tests::write_write_conflict_is_detected`.
- **rmp #220 (FIXED) — supernode high-concurrency lost edges.** With **three or more** concurrently-open
  write transactions each creating an edge on the **same** node, every edge that **commits** now
  survives — `fan-out == committed`, at every concurrency degree (previously it collapsed to **0**, an
  Atomicity + Durability violation). *Root cause:* an SSI loser's rollback clobbered the shared
  `first_rel` chain head, severed the freshly-created records below it, and — at the catalog level —
  lowered the id high-water / token dictionary that concurrently-committed records depended on. *Fix:*
  the same chain-head compare-and-set + header-only creation undo, plus a **monotonic catalog floor on
  rollback** (an aborting transaction never lowers the shared physical-id high-water, token dictionary,
  or `ElementId` allocator below what a concurrent open transaction has already advanced them to).
  Guarded by `scenarios::tests::supernode_high_concurrency_keeps_committed_edges_guards_220`, swept
  across K ∈ {2,3,4,6,8,12,16,24}.

## 15. Features beyond the original brief

Added because they materially improve realistic testing, though not enumerated in the request: the
seed-double-run **determinism gate** (the CLI fails on any non-reproducible seed); the **crash-restart
durability oracle over the wire**; the **Elle isolation checker**; network **partition/reset/delay**
fault injection; the **misbehaved-client catalogue**; and reusable public value-mapping seams
(`engine::bolt_values` / `engine::rest_values`) so the simulator packs results byte-identically to the
server.
