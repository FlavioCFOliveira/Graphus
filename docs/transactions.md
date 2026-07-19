# Transactions & isolation

How Graphus groups statements into transactions, and the isolation guarantee each one gets.

The model is deliberately the one you already know from **MySQL / MariaDB / SQL Server**:
**a transaction exists only when you open one.** Anything you send outside an explicit
transaction runs in *autocommit* mode — it is its own transaction, committed the moment it
finishes.

## Autocommit by default

Every statement you send *without* first opening a transaction is an independent, atomic unit
of work:

- It commits automatically when it completes successfully.
- If it fails, it leaves no partial effect.
- Two statements sent back-to-back in autocommit mode are **two separate transactions** — the
  second does not see a half-applied first, and neither can roll the other back.

You never have to open a transaction to run a query or a single write. This is exactly MySQL /
MariaDB / SQL Server autocommit behaviour.

| Interface | Autocommit statement |
| --------- | -------------------- |
| **Bolt** (TCP or UDS) | a `RUN` (+ `PULL`) sent while no explicit transaction is open |
| **REST** | a `POST /db/{db}/tx/commit` (statements run and commit in one round-trip) |

## Explicit transactions

A transaction spans **more than one statement** only when you open it yourself. Every statement
you then run belongs to that transaction until you `COMMIT` (durably applies all of them) or
`ROLLBACK` (discards all of them).

| Interface | Open | Commit | Roll back |
| --------- | ---- | ------ | --------- |
| **Bolt** | `BEGIN` | `COMMIT` | `ROLLBACK` (or `RESET`) |
| **REST** | `POST /db/{db}/tx` | `POST /db/{db}/tx/{id}/commit` | `DELETE /db/{db}/tx/{id}` |

Use an explicit transaction when you need several statements to succeed or fail together, or to
read-modify-write under the strongest isolation (see below).

## Reads never lock

A read-only query **takes no locks** and **never blocks a writer** (and no writer blocks a
reader). Reads run against a consistent MVCC snapshot, so concurrency is limited only by CPU and
memory — not by lock contention. Concurrent read-only queries are dispatched across a pool of
reader threads, so read throughput scales with the number of cores rather than serialising on a
single thread.

## Isolation levels

Graphus is **100% ACID**. ACID's *Isolation* property means every transaction is isolated at a
well-defined level — not that every transaction must be *serializable*. Graphus applies the
level that fits the work, exactly as MySQL / MariaDB / SQL Server do (whose defaults are *not*
serializable either):

| Work | Isolation | What it means |
| ---- | --------- | ------------- |
| **Standalone read** (autocommit, read-only) | **Snapshot Isolation** | Reads a single consistent MVCC snapshot taken when the statement starts. Takes no locks, tracks no conflicts: it can never be aborted and can never cause another transaction to abort. This is the MySQL/InnoDB read-only model. |
| **Standalone write** (autocommit) | **Serializable** | Full Serializable Snapshot Isolation (SSI): the write commits atomically and durably, and conflicting concurrent writers are resolved so the outcome is equivalent to some serial order. |
| **Explicit transaction** (`BEGIN … COMMIT`) | **Serializable** | Every statement in the transaction — reads *and* writes — runs under full SSI. Use this when a read-modify-write must be serializable. |

### What a snapshot covers

A snapshot covers **every** observable part of a node or relationship, not just its properties:

| State | Snapshot-isolated |
| ----- | ----------------- |
| Node / relationship existence (create, delete) | yes |
| Property values (`SET n.p = ...`, `REMOVE n.p`) | yes |
| **Node labels** (`SET n:L`, `REMOVE n:L`) | **yes** |
| Relationship type | yes (a relationship's type is fixed at creation) |

This matters because labels are stored differently from properties — a property is a separately
versioned record, whereas a label set is a bitmap written in place inside the node record. Until
recently that difference leaked into the observable semantics: a label read returned the
*current* bitmap, so a committed `REMOVE n:Person` became visible to a reader whose snapshot
predated it (a non-repeatable read), and an *uncommitted* one was visible to any concurrent reader
(a dirty read). Both are anomalies that Snapshot Isolation excludes, so this was an isolation
defect, not a documented trade-off. Older label versions are now retained and every label read is
resolved against the reader's own snapshot, exactly as a property read already was.

### What Snapshot Isolation for standalone reads implies

Because a standalone read does not participate in serializability validation, it can observe the
classic *snapshot-isolation read-only anomaly*: a state that is consistent in itself, but that no
single serial ordering of the concurrent **writers** would have produced. This is the same
trade-off MySQL / MariaDB / SQL Server make for an ordinary `SELECT`, and it is what lets reads
be lock-free, abort-free, and horizontally scalable across cores.

If you need a read to be **serializable** with respect to concurrent writers (for example, a
read whose result you will use to decide a subsequent write), run it inside an **explicit
transaction** — every statement in an explicit transaction is serializable.

Writers are always serializable among themselves, whether or not any reader is running: a
concurrent write–write conflict is always resolved (one side commits, the other gets a
retriable serialization failure), and no committed write is ever lost.

## Retrying a serialization failure

A statement or transaction under **Serializable** isolation (a write, or anything inside an
explicit transaction) may be aborted with a retriable *serialization failure* to preserve
serializability. This is normal and expected under contention: catch the error and retry the
transaction. Standalone reads are never aborted this way.
