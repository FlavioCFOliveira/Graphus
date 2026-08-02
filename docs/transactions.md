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

### Administrative termination

An administrator can stop an open transaction with `TERMINATE TRANSACTIONS '<id>'` (the id comes
from `SHOW TRANSACTIONS` — see [cypher.md](cypher.md)). A terminated transaction **cannot commit on
any interface**: the next thing the client does with it — run a statement, refresh it, or commit —
rolls it back and fails with

```
the transaction has been terminated by an administrator (TERMINATE TRANSACTIONS)
```

as a **non-retryable** client error (Bolt `Neo.ClientError.Statement.ArgumentError`; REST `400`
problem+json carrying the same code and the same message). A driver must not auto-retry it: the
transaction was deliberately killed, not aborted by a serialization conflict.

Rolling a terminated transaction back (`ROLLBACK` on Bolt, `DELETE /db/{db}/tx/{id}` on REST)
**succeeds**: it is exactly what the termination asked for, so a client is never denied the ability
to discard a transaction it has been told is dead.

Termination reaches a **client** transaction at its next interaction, not mid-statement: a statement
that is already executing runs to completion, and the transaction is stopped immediately afterwards.
Server-internal schema work (a validating `CREATE CONSTRAINT`) *is* interrupted while it runs.

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

### Which failures a driver retries, and which it must not

The official Neo4j drivers decide whether to replay a managed transaction
(`session.executeRead` / `executeWrite`, `session.execute_read` / `execute_write`) from the
**classification** of the status code Graphus sends: a `TransientError` is replayed with backoff for
up to `maxTransactionRetryTime` (30 seconds by default), and anything else fails the call at once.

Graphus is deliberate about which side of that line each failure falls on, so a client can always
tell "try again" from "this can never work":

| What happened | Status code | Retried? | REST |
| --- | --- | --- | --- |
| Serialization failure (the case above) | `Neo.TransientError.Transaction.Outdated` | **yes** | `409` |
| The database is unavailable (server shutting down) | `Neo.TransientError.General.DatabaseUnavailable` | **yes** | `503` |
| A write statement inside a `READ` transaction | `Neo.ClientError.Statement.AccessMode` | no | `400` |
| The transaction does not exist — never opened, or already committed / rolled back | `Neo.ClientError.Transaction.TransactionNotFound` | no | `404` |
| A message that is illegal for the transaction's current state | `Neo.ClientError.Request.Invalid` | no | `400` |
| The server's `timing.max_transaction_age_ms` elapsed | `Neo.ClientError.Transaction.TransactionTimedOut` | no | `400` |
| The `tx_timeout` you set at `BEGIN` elapsed | `Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration` | no | `400` |
| An administrator ran `TERMINATE TRANSACTIONS` | `Neo.ClientError.Statement.ArgumentError` | no | `400` |

The practical consequence: `session.executeRead(tx => tx.run("CREATE (n)"))` fails **immediately**
with `Neo.ClientError.Statement.AccessMode`. It does not spend the retry budget first, because no
number of replays makes a write legal in a read transaction — use `executeWrite` instead.

You rarely need to write the retry loop yourself: the drivers' managed-transaction helpers already
implement exactly this rule.

### A transaction the server reaped for age

The server rolls back any explicit transaction that has been open longer than
`timing.max_transaction_age_ms` (it pins the MVCC garbage-collection watermark, so an
indefinitely-held transaction would stop reclamation). The next statement or `COMMIT` on that
transaction reports **`Neo.ClientError.Transaction.TransactionTimedOut`**, naming the setting that
stopped it.

That is deliberately a *different* code from `TransactionNotFound`. Both are permanent and
non-retriable, so a driver behaves identically either way — but they are different facts, and only one
of them is a diagnosis. "Does not exist" would send you looking for a transaction-lifecycle bug when
the real cause is a configuration bound; `TransactionTimedOut` tells you to look at
`timing.max_transaction_age_ms` (or to stop holding the transaction open). `TransactionNotFound` stays
reserved for an id that was never issued or is already spent.

Graphus emits the same pair the reference server does, split by *who configured the bound*:

| Bound | Code |
| --- | --- |
| the server's `timing.max_transaction_age_ms` | `Neo.ClientError.Transaction.TransactionTimedOut` |
| the client's Bolt `tx_timeout`, sent on `BEGIN` | `Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration` |

Recovering means opening a **new** transaction and doing the work again. That is not something the
driver may do silently on your behalf: the reaped transaction's earlier statements were rolled back,
so the application has to know.
