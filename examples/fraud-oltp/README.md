# Fraud-detection OLTP over Bolt/TCP — Graphus demonstration

This example demonstrates Graphus as an **OLTP fraud-detection store** driven over **Bolt secured with
TLS**, using the **official `neo4j-driver`** — the exact wire path the Neo4j driver ecosystem speaks.
It plants a **known, enumerable** set of fraud structures (rings, mule chains, and **shared-device/IP
collusion clusters**) into a deterministic, seeded graph, proves the detection workload finds
**exactly** them, runs a **blended point-lookup OLTP mix**, then drives a **production-shaped OLTP
client** — managed, **retried** double-entry ledger transfers — under **extreme Serializable Snapshot
Isolation (SSI) contention on the REAL mule supernodes**, and collects standardized **performance
evidence**, including **server-side `/metrics` deltas**, across the run.

It runs in **two modes**: a **LOCAL** self-boot (a real `graphus-server` with process CPU/RSS +
on-disk store/WAL metering and a committed-baseline gate) and an **EXTERNAL attach** mode against an
**already-running instance** — local or remote — into a dedicated, isolated database.
See [Running against an external target](#running-against-an-external-target).

It is both a runnable **demonstration** and an executable **E2E test**: every step asserts its
expected result, the script prints a `N checks run, M failures` summary and the evidence-report path,
and it exits non-zero if any assertion fails.

## What it demonstrates

| # | Capability | How it is shown |
|---|------------|-----------------|
| 1 | **Deterministic, seeded generation** | `graphus-fraud-gen` emits a byte-identical graph + ground truth per profile (fast / large), including the shared-device/IP collusion signal. |
| 2 | **Bolt + TLS, local OR remote** | LOCAL: boots `graphus-server` with a self-signed cert; the official driver connects with `bolt+ssc://`. EXTERNAL: attaches to a running instance and isolates its work in a dedicated database (session `{database}` routing). |
| 3 | **Version-adaptive production schema** | A `NODE KEY`, a node `UNIQUE`, a **`RELATIONSHIP KEY`** on `TRANSFER.tx_id`, two **relationship** property constraints on `TRANSFER.amount`, node/relationship `RANGE` indexes, and a `TEXT` index on `Customer.name` — loaded **best-effort**: a target whose version does not support a form records it as unsupported and skips it (the essential node constraints are created everywhere), and the negative tests + `SHOW`-assertions adapt to what was actually created. |
| 4 | **Schema DDL + bulk load + detection** | Over Bolt via the official `neo4j-driver`; asserts the detection finds **exactly** the planted fraud (0 FP, 0 FN). |
| 5 | **Shared-device/IP collusion detection** | The generated `device`/`ip` fields carry a planted signal (every fraud cluster shares one device+IP; benign transfers have unique devices), re-identified by a group-by-device query — asserted **exactly** against ground truth. |
| 6 | **Blended point-lookup OLTP mix** | `account-by-id` (a NODE KEY point read) and a `recent-transfers` statement-of-account read, timed alongside the analytical detection. |
| 7 | **Constraint enforcement (negative tests)** | The driver observes that a duplicate `Account.id`, a null-`amount` `TRANSFER`, and both a duplicate and a missing `TRANSFER.tx_id` are **rejected** — gated on which constraints the target actually created. |
| 8 | **A PRODUCTION OLTP client under extreme contention** | Every unit of business work is a **double-entry ledger transfer**, driven as a **managed transaction** (`executeWrite`) so the official driver **retries** an SSI abort with bounded exponential backoff until it commits. Reports **both layers of truth** (engine abort rate *and* application commit rate / retries-per-commit / retry-inclusive p50-p999), and asserts the **ledger reconciles** (conserved; nothing lost, nothing double-applied). |
| 9 | **The driver's retry classification (rmp #612 regression gate)** | A deterministic probe forces a real SSI abort and asserts the **official driver's own classifier** (`neo4j.Neo4jError.isRetriable`) deems it **retryable**. A poison title (`…Transaction.Terminated`) silently breaks `execute_write` for every driver application — this example now **fails** if that regresses. |
| 10 | **Standardized performance + server-side evidence** | Meters the live server (CPU/RSS + on-disk store/WAL, LOCAL only), throughput + latency + abort rate, AND the **server-side `/metrics` deltas** (committed/aborted/abort_rate/slow-queries/**force-detached**/panics) → `report.json` + `report.md` + `schema.txt`; LOCAL also gates a fresh run against a committed baseline. |
| 11 | **Per-TRANSFER insert cost curve** | Per-edge insert latency vs cumulative edge count, surfacing the scan-based `RELATIONSHIP KEY` O(E) cost (rmp #683) where the target enforces it. |
| 12 | **Deterministic SSI repro** | The in-process `dst_contention` binary reproduces the contention byte-identically for a fixed seed (the DST discipline). |

## The data model (Label Property Graph)

| Element | Shape |
|---------|-------|
| `(:Customer {id, name, country})` | the account holder; **`id` is `UNIQUE`**, **`name` has a `TEXT` index** |
| `(:Account {id, holder, balance, risk_score, opened_ts, country})` | a financial account; **`id` is a `NODE KEY`** (present + unique) |
| `(:Customer)-[:OWNS]->(:Account)` | ownership |
| `(:Account)-[:TRANSFER {tx_id, amount, ts, device, ip}]->(:Account)` | a money transfer (the edge detection traverses); **`tx_id` is a `RELATIONSHIP KEY`** (present + unique — every transfer has a globally-unique id), **`amount` is `NOT NULL` + `IS :: INTEGER` + `RANGE`-indexed**; **`device`/`ip` carry the collusion signal** (see below) |

### Injected ground truth

Two fraud archetypes are planted on top of a benign background of legitimate transfers, plus a
digital-forensics collusion signal on every fraud edge. The exact planted set is emitted as
`ground_truth.json`:

- **Transaction rings / cycles** `A → B → C → A`: a closed `TRANSFER` cycle (the layering pattern).
  Every account in a ring is fraudulent.
- **Mule fan-in / fan-out chains**: a central *mule* account that fans **in** from many sources and
  **out** to many destinations (smurfing / structuring). The mule account is fraudulent.
- **Shared-device / shared-IP collusion clusters**: every `TRANSFER` in a given ring or mule chain is
  minted from **one shared `device` fingerprint and one shared `ip`** (the operator's digital
  fingerprint). Every **benign** transfer instead carries a **unique** `device` and a random `10.x.y.z`
  `ip`, while the fraud clusters use the disjoint `172.16/172.17` space — so a `count(*) >= 2`
  group-by-device query returns **exactly** the planted clusters. The clusters are emitted in
  `ground_truth.collusion` (device, ip, kind, edge_count, accounts).

The discriminator that separates planted fraud from benign noise is the **transfer amount**: benign
transfers are `≤ 900`, ring edges are `≥ 9000`, mule edges are `≥ 2000`. The detection queries apply
these amount floors (and the shared-device grouping for collusion), so on the seeded dataset they
yield **zero false positives and zero false negatives**.

## Schema / DDL the workload loads

Graphus accepts schema DDL as raw statements over Bolt (intercepted by the server's admin matcher,
**not** the Cypher parser — they must run as auto-commit statements, never inside an explicit
transaction). The example declares a **production-realistic** schema that exercises several index and
constraint kinds — node and relationship, RANGE and TEXT — over exactly the properties the risk model
reasons about:

```cypher
-- Node constraints: Account.id is a NODE KEY (present + unique); Customer.id is UNIQUE.
CREATE CONSTRAINT account_id_key        FOR (a:Account)  REQUIRE a.id IS NODE KEY;
CREATE CONSTRAINT customer_id_unique    FOR (c:Customer) REQUIRE c.id IS UNIQUE;
-- Relationship constraints on the money: every TRANSFER must carry an INTEGER amount.
CREATE CONSTRAINT transfer_amount_exists  FOR ()-[t:TRANSFER]-() REQUIRE t.amount IS NOT NULL;
CREATE CONSTRAINT transfer_amount_integer FOR ()-[t:TRANSFER]-() REQUIRE t.amount IS :: INTEGER;
-- Every money transfer carries a globally-unique id — a RELATIONSHIP KEY (present + unique) on tx_id.
CREATE CONSTRAINT transfer_tx_id_key      FOR ()-[t:TRANSFER]-() REQUIRE t.tx_id IS RELATIONSHIP KEY;
-- Node RANGE indexes on the properties the risk model filters / sorts on.
CREATE INDEX account_risk_score_range   FOR (a:Account)  ON (a.risk_score);
CREATE INDEX customer_country_range     FOR (c:Customer) ON (c.country);
-- Relationship RANGE index on the amount the detection queries filter on.
CREATE INDEX transfer_amount_range      FOR ()-[t:TRANSFER]-() ON (t.amount);
-- TEXT (trigram) index accelerating investigator CONTAINS / STARTS WITH / ENDS WITH by name.
CREATE TEXT INDEX customer_name_text    FOR (c:Customer) ON (c.name);
```

Note that `t.amount` is an **INTEGER** in the model (an `i64`), so its property-type constraint is
`IS :: INTEGER` — never `FLOAT`. The seed data conforms to every constraint, so a schema-first load
succeeds; the schema is loaded before the data over the live Bolt path (each statement auto-commit).

> **Version-adaptive, best-effort loading.** The schema is loaded **best-effort**: `data/detect.js`
> attempts every DDL statement and, if the target's version rejects a form as a `SyntaxError` (an older
> Graphus that predates relationship constraints / named indexes / `TEXT` indexes), records it as
> *unsupported by target* and continues — the data load and detection do not depend on it. The
> essential node constraints (`NODE KEY`, `UNIQUE`) are creatable on every supported target. The
> negative tests and the `SHOW`-based assertions then adapt to what was actually created, so the same
> example runs against a current LOCAL server (full schema) and an older remote target (a subset)
> without a false failure. Which forms were created vs skipped is reported in the run output and the
> `GRAPHUS_SCHEMA` line.

> **Cypher parser vs admin path.** Graphus's **Cypher parser** does not accept `CREATE CONSTRAINT` /
> `CREATE INDEX` as query clauses; the **server's admin path** does, over Bolt. This is the supported,
> tested surface (see `crates/graphus-server/tests/db_admin_surface.rs`). The example uses exactly
> these forms — no invented syntax. The schema is a performance/integrity layer, not a detection
> precondition: the data-only hermetic mirror (`fraud_oltp_detection.rs`) loads the CREATEs only and
> still finds the same fraud.

### What the relationship RANGE index actually optimises (measured)

The detection queries filter transfers by amount with **range** predicates (`t.amount >= 9000`,
`>= 2000`). We verified empirically (in `fraud_oltp_schema.rs`, against Graphus's real planner) what
the relationship `RANGE` index on `TRANSFER.amount` serves:

- an **equality** predicate on a relationship property (`t.amount = 9000`) **is** served from the
  index — it lowers to a `RelIndexSeek`;
- a **range** predicate (`t.amount >= 9000`) is **not** served — a relationship index seek is
  equality-only, so the range predicate stays a full traversal + residual `Filter`.

So the index is genuinely built and `ONLINE` (an equality seek returns the seeded rows), but the
detection queries — being all `>=` — scan and filter rather than seek. We assert this **honestly**:
the example does not claim range-seek utilisation the engine does not provide. (Node RANGE indexes do
serve range predicates; the relationship-index seek path is equality-only.)

## Detection queries + OLTP mix

The three analytical detections use only Cypher features verified against the real engine (explicit
multi-hop cycle patterns, amount-filtered fan-in/fan-out aggregation, two-stage `WITH`). They are kept
**byte-identical** between the official-driver path (`data/detect.js`) and the hermetic cargo mirror
(`crates/graphus-server/tests/fraud_oltp_detection.rs`), so both front doors assert the same thing:

- **Rings**: explicit 3-hop closed cycle `(a)-[r1]->(b)-[r2]->(c)-[r3]->(a)` with every
  `amount ≥ 9000` and distinct nodes. Returns `DISTINCT a.id`.
- **Mules**: `count(DISTINCT src) ≥ 6` fanning in **and** `count(DISTINCT dst) ≥ 6` fanning out, each
  over transfers `≥ 2000` (two-stage `WITH`).
- **Velocity** (structuring): accounts emitting `≥ 6` large (`≥ 2000`) outgoing transfers, ordered by
  volume — independently re-identifies the mules.

The detector asserts the union of ring + mule findings equals the planted `fraud_accounts` set.

Beyond the analytical detections, `data/detect.js` also runs:

- **Shared-device / shared-IP collusion** — `MATCH ()-[t:TRANSFER]->() WITH t.device AS device,
  count(*) AS edges WHERE edges >= 2 RETURN device, edges`. Because every benign transfer has a unique
  device, this returns exactly the fraud clusters; the result is asserted **equal to**
  `ground_truth.collusion` (device + edge_count), corroborated by the count of distinct `172.x` fraud
  IPs. This is the exercise of the previously-unused `device`/`ip` fields.
- **Blended point-lookup OLTP** — `account-by-id` (`MATCH (a:Account {id: $id}) …`, a NODE KEY point
  read, asserted to return 1 row for an existing id and 0 for an absent one) and `recent-transfers`
  (`MATCH (a:Account {id: $mule})-[t:TRANSFER]->(b) … ORDER BY t.ts DESC LIMIT 10`, a
  statement-of-account read). Their latency is reported separately (`point_lookup_p99_ms`).

## A production OLTP client under extreme contention (`rmp #715`)

`data/concurrency.js` contends on the **actual mule `:Account` supernodes** of the loaded graph (the
highest-degree fan-in/fan-out hubs — read from `ground_truth.mules`), **not** synthetic `:Hot` nodes.

### The unit of work is a double-entry ledger transfer

One business transaction moves `amount` from the writer's own funded settlement account to a mule, as a
genuine **double-entry** move, atomically in one transaction:

```
read src.balance, read mule.balance     ← the read-modify-write SSI must serialize
check sufficient funds                  ← the business rule
SET src.balance  -= amount              ← the debit
SET mule.balance += amount              ← the credit (the contended write)
CREATE (src)-[:TRANSFER {tx_id:'CONC-<client>-<op>', amount, …}]->(mule)   ← the journal entry
```

Because every committed transfer debits exactly what it credits, **the ledger must reconcile**. `tx_id`
is keyed to the **business unit** (client+op), never to the attempt, so a transfer the engine wrongly
committed twice shows up as a duplicate journal entry. (This example previously credited the mule out of
thin air and never debited any source — so it *could not* detect money being created.)

### Two modes — the default is the retrying client

| Mode | What it does | Why |
|------|--------------|-----|
| **`FRAUD_RETRY=1` (default)** | Every transfer is a **managed transaction** through the official driver's `session.executeWrite()`, so a serialization failure is **retried** with the driver's own bounded exponential backoff until it commits or its declared budget (`maxTransactionRetryTime`, 30 s) is exhausted. | This is what **every** official Neo4j driver does. The application-visible outcome of contention is **"slower", not "lost"**. It is also the *only* configuration that exercises the driver's **retry classifier** — the path `rmp #612` broke. |
| **`FRAUD_RETRY=0`** | One explicit, single-shot transaction per transfer; no retry, so the **raw** engine abort rate is observed directly. | A legitimate **pure-contention isolation** — and how this example used to run. But it is *not* what a production client does, so it is no longer the default. |

### Two layers of truth — never conflated

Measured on this host (9 writers, 2 mule supernodes, 30 transfers each — the **identical** workload and
the **identical** transaction shape; the *only* difference is whether the client retries):

| | engine abort rate | application commit rate | phase wall | retry-inclusive p99 |
|---|---|---|---|---|
| **`FRAUD_RETRY=0`** (isolation) | **0.907** | **0.093** — 91% of the business work is **LOST** | 0.64 s | 127 ms |
| **`FRAUD_RETRY=1`** (default) | **0.049** | **1.000** — nothing is lost | 4.6 s | 1 154 ms |

Both rows are true, and reporting either one alone misleads:

- The **engine** layer (`throughput.abort_rate` = aborts / attempts) is the **contention evidence**, and
  it is kept — SSI genuinely fires, hard. But a raw abort rate is *not* an application outcome.
- The **application** layer (transfers committed, retries per commit, **retry-inclusive** p50/p99/p999,
  retry-budget exhaustion) is what a real system experiences.

**A high engine abort rate with a 100 % application commit rate is a healthy system under contention.**
The striking result is that a retrying client does not merely *survive* contention, it largely
**dissolves** it: backing off after an abort spreads the writers out in time, so the per-attempt conflict
rate collapses **~18×** (0.907 → 0.049). The cost is paid in **latency** — a ~4 ms median against a
~1.2 s p99 and a ~3–7 s p999 — never in lost work. The **tail is the whole story**, which is exactly why
the no-retry client's headline abort rate is a misleading measure of a real system.

### What it asserts

- **Ledger reconciliation.** The **sum of all balances is conserved** across the contention phase
  (delta must be 0 — money neither created nor destroyed); every mule's credit and every settlement
  account's debit equals the sum of its committed journal entries; and the journal holds **exactly one
  entry per committed transfer**, with all `tx_id`s distinct (**nothing lost, nothing double-applied**).
- **Progress.** Under the retrying client **every** business transfer must commit (0 budget-exhausted);
  work that never commits under an honest, bounded retry budget is a **write-liveness defect**, not an
  acceptable outcome.
- **`rmp #612` cannot regress unnoticed.** A deterministic probe forces a **real** SSI abort (two
  overlapping read-modify-writes on one account) and asserts the **official driver's own public
  classifier**, `neo4j.Neo4jError.isRetriable()` — the very function `executeWrite` consults — deems it
  **retryable**. Graphus must return `Neo.TransientError.Transaction.Outdated`; a poison title such as
  `…Transaction.Terminated` is **explicitly excluded from retry** by every official driver, which
  silently turns `execute_write` into a hard failure and makes contention mean **LOST** instead of
  slower. The probe exists because `executeWrite` *absorbs* the aborts it retries, so a managed-only run
  never sees the abort code — the probe is where it becomes visible, and its result is reported as
  `probe_abort_code` / `probe_driver_retriable`.
- **The engine abort-rate band** stays a first-class, two-sided, absolute signal:
  `FRAUD_ABORT_FLOOR ≤ engine abort rate ≤ FRAUD_ABORT_CEIL`. The floor proves SSI genuinely fired; the
  ceiling proves the engine still progressed. The two modes sit at genuinely different points, so they
  carry **different defaults** — `0.01 … 0.60` when retrying (5× headroom below the measured ~0.05, 12×
  above), `0.40 … 0.995` in the no-retry isolation. Both are overridable for a differently-sized target.
- The server-side **force-detached** and **panic** counters must be 0.

## Schema exercise, investigator query, and negative tests

After detection, `data/detect.js` also exercises the schema itself (adapting to what the target
supports):

- **Investigator substring query** — `MATCH (c:Customer) WHERE c.name CONTAINS 'customer-1' RETURN
  c.id`. Customer ids are `0..acctCount-1`, so the expected match set is derived deterministically and
  asserted exactly. It uses the `TEXT` index where the target has one, and the scan path otherwise.
- **Negative integrity tests (gated)** — the driver attempts a **duplicate `Account.id`** (rejected by
  the `NODE KEY`), a **null-`amount` `TRANSFER`** (rejected by the relationship existence constraint),
  and a **duplicate** + **missing** `TRANSFER.tx_id` (rejected by the `RELATIONSHIP KEY`) — but **only**
  for the constraints the target actually created, so an older target that cannot create the
  relationship constraints skips those negatives (reported explicitly) rather than false-failing. Each
  rejection surfaces as `Neo.ClientError.Schema.ConstraintValidationFailed`.
- **Schema evidence** — it captures `SHOW INDEXES` / `SHOW CONSTRAINTS` (tolerating the differing column
  sets across versions), writes the listing to `evidence/schema.txt`, and cross-checks the kind of each
  object **that was created**.

The hermetic cargo mirror `crates/graphus-server/tests/fraud_oltp_schema.rs` asserts the **full** schema
in-process against a current engine (the relationship `RANGE` index, the `TEXT` index, the `NODE KEY`,
the relationship constraints incl. the `RELATIONSHIP KEY` present + unique halves, a non-integer
`amount` rejection, and the empirical planner utilisation of the relationship RANGE index).

## Running it

```bash
# From the repository root. Builds the binaries if needed, then runs.
examples/fraud-oltp/run.sh

# Use pre-built release binaries from a custom location:
cargo build --release -p graphus-server -p graphus-fraud-gen
GRAPHUS_BIN_DIR=target/release examples/fraud-oltp/run.sh

# Evidence-scale dataset (an order of magnitude larger graph):
FRAUD_PROFILE=large examples/fraud-oltp/run.sh

# The PURE-CONTENTION isolation: single-shot transactions, no retry, so the RAW engine abort
# rate is observed directly (~0.91 — and 91% of the business work is lost, which is exactly why
# this is an experiment and not the default):
FRAUD_RETRY=0 examples/fraud-oltp/run.sh

# Skip the official-driver (Node) steps — the hermetic generator + DST repro still run:
RUN_DRIVER=0 examples/fraud-oltp/run.sh
```

| Env var | Meaning | Default |
|---------|---------|---------|
| `FRAUD_RETRY` | `1` = production client (managed, retried transactions). `0` = pure-contention isolation (no retry). | `1` |
| `FRAUD_RETRY_BUDGET_MS` | The application's declared retry budget per transfer (`maxTransactionRetryTime`). | `30000` |
| `FRAUD_ABORT_FLOOR` / `FRAUD_ABORT_CEIL` | The two-sided **engine** abort-rate band. Mode-dependent defaults. | `0.01`/`0.60` retrying; `0.40`/`0.995` no-retry |
| `FRAUD_PROFILE` | `fast` (default) or `large`. | `fast` |
| `RUN_DRIVER` | `0` skips the Node/official-driver steps. | auto |

### Running against an external target

Set any of `GRAPHUS_TARGET_{BOLT,REST,UDS}` to attach to an **already-running** instance instead of
self-booting. The run then carves out a dedicated, **isolated database** (session `{database}`
routing), loads + detects + runs concurrency there, scrapes the target's `/metrics` before + after,
emits an **EXTERNAL-mode** `report.json` (server-side deltas + client throughput/latency; process
CPU/RSS + storage are N/A remotely and no baseline is gated), and **DROPS the isolated database on
exit** — never touching the target's own data.

```bash
# Attach to a remote instance over Bolt+TLS + REST, into an isolated DB:
GRAPHUS_TARGET_BOLT=bolt+ssc://graphus.example.com:7687 \
GRAPHUS_TARGET_REST=https://graphus.example.com:7474 \
GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=graphus-local \
GRAPHUS_TARGET_TLS_INSECURE=1 \
  examples/fraud-oltp/run.sh
```

This uses the shared external-target seam in `examples/_harness/harness.sh` (the `GRAPHUS_TARGET_*`
contract — see `examples/README.md`). Setting `GRAPHUS_TARGET_DB` instead pins an **operator-owned**
database the harness never creates or drops (it then only clears its own `:Account`/`:Customer`
footprint on exit). Because a target may run an **older** Graphus, the schema loads best-effort and the
negative/`SHOW` assertions adapt (see *Version-adaptive, best-effort loading* above).

A successful run ends with:

```
11 checks run, 0 failures.  (mode: external)
evidence: .../examples/fraud-oltp/evidence {report.json, report.md, schema.txt}
FRAUD-OLTP DEMONSTRATION PASSED (external mode) — ...
```

(The hermetic `RUN_DRIVER=0` path runs a subset — the official-driver load/detect, concurrency, and
evidence steps are skipped.)

The official-driver steps (2–5) require `node`, `npm`, and network access for `npm install
neo4j-driver` (LOCAL mode also needs `openssl` for the self-signed cert); they are opt-in
(auto-enabled when `node`/`npm` are present, via `RUN_DRIVER`). The generator (step 1) and the
deterministic SSI repro (step 6) are fully hermetic and always run. The script is self-contained: it
works inside a private temp directory that a cleanup `trap` removes on exit, and in EXTERNAL mode it
drops the isolated database it created — a passing or failing run leaves **no residual server
processes, no temp files, and no leftover database on the target**.

### Profiles

| Profile | Accounts | Transfers | Purpose |
|---------|----------|-----------|---------|
| `fast` (default) | ~155 | ~430 | CI/E2E assertions + the committed evidence baseline; runs in a few seconds. |
| `large` | ~2 000 | ~12 000 | Evidence collection at volume (storage/CPU/RAM footprint). Plants the same fraud kinds, so the detection queries are identical. The `large` report is for inspection; the committed regression **baseline** is the `fast` profile (the gate runs on `fast` only). |

## Reading the evidence

Each run writes the standardized, schema-versioned evidence into the git-ignored `evidence/`
directory: a machine-readable `report.json` and a human-readable `report.md`. Both follow the shared
`graphus-examples-harness` schema (`SCHEMA_VERSION`), the same one every `examples/*` uses:

| Section | Captures |
|---------|----------|
| `metadata` | scenario id, dataset scale, and the workload knobs — including **both layers**: the application (`oltp_committed`, `oltp_commit_rate`, `oltp_retries_per_commit`, `oltp_max_retries`, `oltp_retry_budget_exhausted`, `oltp_mode`) and the engine (`engine_txn_attempts`, `engine_txn_aborts`, `engine_abort_rate`), plus the separately-named serial phase (`detect_operations`, `detect_p50/p99/p999_ms`, `point_lookup_p99_ms`) |
| `measurement_mode` | `local` (co-located metering) or `external` (attach — CPU/RSS/storage are N/A) |
| `host` | os, arch, cpu cores, hostname, rustc version, timestamp |
| `cpu` | server user / system CPU seconds, mean core utilisation *(LOCAL only)* |
| `memory` | peak / final server RSS (bytes) *(LOCAL only)* |
| `storage` | store / WAL bytes + pages, bytes fsynced, write- & space-amplification *(LOCAL only)*. The per-element costs `bytes_per_node` / `bytes_per_relationship` are deliberately **ABSENT** — see below. |
| `throughput` | **the OLTP contention phase, and ONLY it** — see the warning below. `operations` = business transfers **committed** (work *done*), `ops_per_sec` = the rate they committed at, `p50/p99/p999` = their **retry-inclusive** latency, `abort_rate` = the **engine's** abort rate over the **very same** transactions. |
| `phases` | `load+detect+oltp-mix` and `oltp-contention`, each with its real wall-clock |
| `server_metrics` | **server-side `/metrics` before→after deltas** for the run's database: committed / aborted / **abort_rate** / slow_queries / query-duration percentiles, and the health invariants **statement_panics / engine_recovery_panics / engine_force_detached** (which MUST be 0), plus the SSI-tracked gauge |

> **The `throughput` section used to describe two disjoint sets of transactions (`rmp #715`).**
> `operations` / `ops_per_sec` / the latency percentiles came from the **serial detect phase** (914
> load + detection + lookup queries, which never abort), while `abort_rate` came from the **270
> transactions of the concurrency phase**, which appeared nowhere in `operations`. A reader seeing
> `operations: 914, abort_rate: 0.878` could only conclude *"802 of my 914 operations failed"* — false
> in both directions, and a textbook breach of evidence-honesty rule 3 (*every field carries the
> quantity its name promises*). Every field in `throughput` now describes **one** coherent set of
> transactions; the detect-phase figures are kept, explicitly named, in `metadata.workload`.
>
> Note that `throughput.abort_rate` (aborts / **attempts in the contention phase**) and
> `server_metrics.abort_rate` (aborted / **all transactions in the database**, the server's own counter)
> have **different denominators** on purpose: the first is the contention experiment, the second is the
> whole run's server-side health. Both are correct; they are not interchangeable.

How the figures are sourced (and their honest caveats):

- **CPU + RSS** are read from the *live* server process (`/proc/<pid>/{stat,statm}` on Linux, a `ps`
  fallback elsewhere) by the dev-only `measure_server` harness binary while the server is still up.
- **`storage.bytes_per_node` / `bytes_per_relationship` are deliberately ABSENT** (`rmp #711`), and
  their baseline gates are reported as *skipped*. A per-element durable cost is only honest if its two
  inputs describe the **same graph**: here `--nodes`/`--rels` are the *generator's* seeded counts, while
  the extreme-concurrency phase CREATEs additional `CONC-`tagged `TRANSFER` relationships into the very
  store being metered. Dividing the measured store image by the seed counts would be real arithmetic
  over a graph the store no longer holds — a figure wrong in a way no reader could see. In external
  (attach) mode the whole `storage` / `cpu` / `memory` vectors are likewise absent, not zeroed: the
  server is not co-located, so there is nothing to measure.
- **Storage** is the real on-disk footprint of `<store>/graphus.store` and the `<store>/graphus.wal/`
  segment directory, measured after the workload. `bytes_fsynced` is the WAL byte count (a faithful
  proxy: every committed WAL byte is fsynced before acknowledgement). `space_amplification` and
  `write_amplification` are those durable bytes over the **logical dataset the generator actually
  emitted** (`wc -c graph.cypher`).

  > **Evidence honesty (`rmp #699`).** The denominator used to be an *invented* `nodes*256 +
  > rels*128` formula — a fabricated logical size, which made the published ratio a fabrication — and
  > `write_amplification` was left at a `0.0` placeholder. Both are now real.
- **`throughput`'s latency percentiles** are the **retry-inclusive** wall-time of a *business transfer*,
  measured client-side by `concurrency.js`: the clock starts before the first attempt and stops when the
  transfer finally **commits**, so it includes every retry and every backoff the driver slept through.
  That is what the application actually waited, and under contention the **tail is the whole story**
  (a ~4 ms median against a ~1.2 s p99). The serial detect phase's own percentiles are reported
  separately as `detect_p50/p99/p999_ms` (plus `point_lookup_p99_ms`), because they measure a different,
  non-contended workload.
- **`throughput.ops_per_sec`** is the **committed** business transfers over the **contention phase's**
  wall-clock (`phase_secs`, emitted by `concurrency.js`) — a rate of **work done**. It counts only
  transfers that actually committed: a throughput figure that counted failures would not be a number a
  reader could use.
- **`total_millis`** is the workload's real wall-clock. `measure_server` runs *after* the workload, so
  it is passed in explicitly via `--total-millis`; an unbracketed report timed only its own emission
  (the old committed baseline read `total_millis: 0.044` — 44 microseconds for a multi-second run).
- **`server_metrics`** are the server's own Prometheus counters, scraped from `/metrics` **before and
  after** the workload and diffed by `measure_target` (EXTERNAL) or folded in by `inject_server_metrics`
  (LOCAL, `rmp #689`); attributed to the run's database via the per-database `graphus_db_*` series where
  present. This is the only vector available for a **remote** target where `/proc` and the store files
  cannot be read, and it carries the authoritative **server-side abort rate** and the **force-detached /
  panic** health invariants.
- **`GRAPHUS_TXCURVE`** records per-TRANSFER insert latency vs cumulative edge count (rmp #683): where
  the target enforces the scan-based `RELATIONSHIP KEY`, later inserts get dearer (O(E)); where it does
  not, the curve is flat — the report shows the contrast honestly.
- **This is a contention experiment, not a saturating benchmark.** `ops_per_sec` is the rate at which
  9 deliberately-over-contending writers got their transfers committed against 2 supernodes; it is a
  measure of behaviour **under conflict**, and it is not Graphus's write throughput.

### Variance and the regression baseline (LOCAL only)

A committed reference run lives at `baseline.json` (a `fast`-profile `report.json`). On a **LOCAL**
`fast` run the script compares the fresh report against it with `baseline_cmp`, which gates **only
stable structural metrics** and ignores the machine-variant ones (in EXTERNAL mode there is no baseline
— `measure_target --assert` gates the host-independent health invariants instead):

| Metric family | Tolerance | Why |
|---------------|-----------|-----|
| storage bytes / pages, amplification | **15%** | deterministic for a fixed seed+profile; a real footprint regression. |
| abort / conflict rate | **+200% rise** | a **livelock-drift guard** over a scheduling-variant rate — see below. The PRIMARY abort gate is the two-sided **absolute** band asserted first-class in `concurrency.js` (`FRAUD_ABORT_FLOOR..CEIL`). |
| throughput, latency p50/p99/p999, CPU, peak RSS | ignored (∞) | vary with machine speed, allocator, OS, scheduling — flaky to gate across machines. |

**The baseline was re-captured for `rmp #715` by *running* the example** (never by editing numbers).
Two things moved, both honestly and for the same reason — the client now **retries**:

- **`storage.store_bytes` +27.8 % (442 368 → 565 248) and `wal_bytes` +28.3 % (3 982 455 → 5 107 876).**
  Not a storage regression: it is **more committed work**. The old no-retry client durably wrote only
  the 13–33 transfers that happened to survive contention; the retrying client commits **all 270**, so
  270 journal entries plus 540 balance updates plus the settlement-account funding now reach disk.
- **`throughput.abort_rate` 0.952 → 0.053.** Not an isolation regression: it is the *engine* abort rate
  of a *retrying* client, and backoff de-synchronises the writers (see the table above).

This also made the **storage gate stronger**. Under the old default the number of transfers that
survived contention varied run to run (13, then 25, then 33 of 270 — a 2.5× swing), and every surviving
transfer is durable bytes, so the footprint the 15 % gate compared **swung with it**. Now exactly
270 of 270 commit on every run, so the dominant term is fixed; only the handful of retried attempts
varies (13–15 across runs), moving the store image ~1.5 % — comfortably inside the band, where the old
2.5× swing in committed work was not.

Conversely the **abort-rate gate had to be loosened**, and that is a real trade, stated plainly: at
~0.9 the rate was structurally saturated and a **+10 %** rise was a meaningful livelock guard (it fired
past ~0.99). At ~0.05 it is small and **scheduling-variant** — consecutive runs measured 0.046 / 0.049 /
0.053 / 0.059, a ±12 % spread that a +10 % gate would have failed **on an unchanged codebase**. So the
guard is now **+200 %** (fires past ~0.15, i.e. a tripling — a retrying client that lost the
de-synchronising benefit of backoff), and the *real* two-sided assertion lives in `concurrency.js`.

This keeps the gate meaningful (it fails a genuine storage-footprint regression or a write-liveness
collapse) without being flaky across the developer/CI machines a single committed baseline is shared
between. The gate prints `GRAPHUS_BASELINE_OK` on success.

## CI coverage (hermetic, default `cargo test`)

The official-driver path needs Node; CI's default `cargo test` does not. Two npm-free counterparts run
in the default test run (no Bolt, no Node, no network — both in-process via `LocalEngine`):

- `crates/graphus-server/tests/fraud_oltp_detection.rs` — the **detection mirror**: generates the
  **same** fast-profile graph + ground truth, loads the data, runs the **same** detection queries, and
  asserts the **same** exact ground-truth match.
- `crates/graphus-server/tests/fraud_oltp_schema.rs` — the **schema mirror** (`rmp` #673): drives the
  generator's DDL block through the real admin path (`parse_admin_statement` →
  `LocalEngine::{index_ddl, constraint_ddl}`), loads the graph **schema-first**, and asserts the new
  index/constraint kinds are `ONLINE` (`SHOW INDEXES` / `SHOW CONSTRAINTS`, including the `RELATIONSHIP
  KEY` on `TRANSFER.tx_id`), constraint enforcement (duplicate id, null amount, non-integer amount,
  duplicate tx_id, missing tx_id all rejected), the empirical rel-index utilisation (equality served,
  range not), and the `TEXT` `CONTAINS` path.

The official-driver E2E stays feature-gated (`RUN_DRIVER` for the shell, `neo4j-interop` for the Rust
interop test).

## Where the pieces live

- **Generator + ground truth + DST repro + baseline gate**: `crates/graphus-fraud-gen` (a dev-only
  leaf crate; `graphus-server` does **not** depend on it in the production graph, so the shipped
  binary is unaffected).
  - `gen` binary → `graph.cypher` + `ground_truth.json` (hermetic; includes the shared-device/IP
    collusion clusters).
  - `dst_contention` binary (feature `dst-repro`) → deterministic in-process SSI contention.
  - `baseline_cmp` binary → the structural regression gate (hermetic; harness only).
  - `inject_server_metrics` binary → folds the LOCAL `/metrics` before/after delta into the
    `measure_server` report (hermetic; harness API only), so the LOCAL report carries the same
    `server_metrics` section EXTERNAL mode gets from `measure_target`.
  - determinism + the collusion invariants are guarded by `crates/graphus-fraud-gen/tests/`
    (`determinism.rs`) and the crate's unit tests.
- **Detection + concurrency Node scripts**: `data/detect.js`, `data/concurrency.js` (official driver;
  both take `<uri> <database> …` so they run against a self-booted server or an attached instance, and
  both emit machine-readable `GRAPHUS_STATS {…}` lines the harness consumes).
- **Hermetic cargo mirrors** (default test run): `crates/graphus-server/tests/fraud_oltp_detection.rs`
  (detection) and `crates/graphus-server/tests/fraud_oltp_schema.rs` (schema: indexes, constraints,
  enforcement, planner utilisation, TEXT path) — both against a current in-process engine.
- **Evidence harness**: `crates/graphus-examples-harness` (`measure_server` for LOCAL, `measure_target`
  for EXTERNAL, the report schema, the `compare_to_baseline` regression diff, the `/metrics` scrape).
- **External-target seam**: `examples/_harness/harness.sh` (isolated-DB create/drop, `/metrics` scrape,
  the `GRAPHUS_TARGET_*` contract).
- **Evidence output**: `report.json` + `report.md` + `schema.txt` in `evidence/` (git-ignored). The
  committed LOCAL reference run is `baseline.json`.
