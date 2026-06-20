# Fraud-detection OLTP over Bolt/TCP — Graphus demonstration

> Status: this README is a **stub** delivered with `rmp #250`–`#252` (scenario, generator, detection
> workload, concurrency + DST repro). `rmp #256` finalizes the prose, the evidence walkthrough, and
> the performance vectors.

This example demonstrates Graphus as an **OLTP fraud-detection store** driven over **Bolt-over-TCP
secured with TLS**, using the **official `neo4j-driver`** — the exact wire path the Neo4j driver
ecosystem speaks. It plants a **known, enumerable** set of fraud structures into a deterministic,
seeded graph and proves the detection workload finds **exactly** them, then stresses the engine with
**extreme concurrency** to exercise Serializable Snapshot Isolation (SSI).

## The data model (Label Property Graph)

| Element | Shape |
|---------|-------|
| `(:Customer {id, name, country})` | the account holder |
| `(:Account {id, holder, balance, risk_score, opened_ts, country})` | a financial account; **`id` is unique** |
| `(:Customer)-[:OWNS]->(:Account)` | ownership |
| `(:Account)-[:TRANSFER {amount, ts, device, ip}]->(:Account)` | a money transfer (the edge detection traverses) |

### Injected ground truth

Two fraud archetypes are planted on top of a benign background of legitimate transfers, and the exact
planted set is emitted as `ground_truth.json`:

- **Transaction rings / cycles** `A → B → C → A`: a closed `TRANSFER` cycle (the layering pattern).
  Every account in a ring is fraudulent.
- **Mule fan-in / fan-out chains**: a central *mule* account that fans **in** from many sources and
  **out** to many destinations (smurfing / structuring). The mule account is fraudulent.

The discriminator that separates planted fraud from benign noise is the **transfer amount**: benign
transfers are `< 900`, ring edges are `≥ 9000`, mule edges are `≥ 2000`. The detection queries apply
these amount floors, so on the seeded dataset they yield **zero false positives and zero false
negatives**.

## Schema / DDL the workload loads

Graphus accepts schema DDL as raw statements over Bolt (intercepted by the server's admin matcher,
**not** the Cypher parser — they must run as auto-commit statements, never inside an explicit
transaction). The verified, supported forms this example uses:

```cypher
CREATE CONSTRAINT account_id_unique  FOR (a:Account)  REQUIRE a.id IS UNIQUE;
CREATE CONSTRAINT customer_id_unique FOR (c:Customer) REQUIRE c.id IS UNIQUE;
CREATE INDEX FOR (a:Account)  ON (a.risk_score);
CREATE INDEX FOR (c:Customer) ON (c.country);
```

> Note: Graphus's **Cypher parser** does not (yet) accept `CREATE CONSTRAINT` / `CREATE INDEX` as
> query clauses; the **server's admin path** does, over Bolt. This is the supported, tested surface
> (see `crates/graphus-server/tests/db_admin_surface.rs`). The example uses exactly these forms — no
> invented syntax.

## Detection queries

All three use only Cypher features verified against the real engine (explicit multi-hop cycle
patterns, amount-filtered fan-in/fan-out aggregation, two-stage `WITH`):

- **Rings**: explicit 3-hop closed cycle `(a)-[r1]->(b)-[r2]->(c)-[r3]->(a)` with every
  `amount ≥ 9000` and distinct nodes.
- **Mules**: `count(DISTINCT src) ≥ 6` fanning in **and** `count(DISTINCT dst) ≥ 6` fanning out, each
  over transfers `≥ 2000`.
- **Velocity** (structuring): accounts emitting `≥ 6` large (`≥ 2000`) outgoing transfers, ordered by
  volume — independently re-identifies the mules.

The detector loads `ground_truth.json` and asserts the union of its findings equals the planted set.

## Running it

```bash
# From the repository root. Builds the binaries if needed, then runs.
examples/fraud-oltp/run.sh

# Evidence-scale dataset (larger graph):
FRAUD_PROFILE=large examples/fraud-oltp/run.sh

# Skip the official-driver (Node) steps — the hermetic generator + DST repro still run:
RUN_DRIVER=0 examples/fraud-oltp/run.sh
```

The official-driver steps (3 + 4) require `node`, `npm`, and network access for
`npm install neo4j-driver`; they are opt-in (auto-enabled when `node`/`npm` are present). The
generator (step 1) and the deterministic SSI repro (step 5) are fully hermetic and always run.

## What it exercises

| Step | Capability |
|------|------------|
| 1 | **Deterministic, seeded generation** — byte-identical graph + ground truth per profile (fast / large). |
| 2 | **Bolt-over-TCP + TLS** — a self-signed cert; the official driver connects with `bolt+ssc://`. |
| 3 | **Schema DDL + bulk load + detection** over Bolt via the official driver; asserts **exact** ground-truth match. |
| 4 | **Extreme-concurrency SSI** — overlapping writer/reader transactions on hot accounts; reports commit/abort tallies; proves **no lost update**. |
| 5 | **Deterministic SSI repro** — the in-process `dst_contention` binary reproduces the contention byte-identically for a fixed seed (the DST discipline). |

## Where the pieces live

- **Generator + ground truth + DST repro**: `crates/graphus-fraud-gen` (a dev-only leaf crate;
  `graphus-server` does **not** depend on it, so the production build is unaffected).
  - `gen` binary → `graph.cypher` + `ground_truth.json` (hermetic).
  - `dst_contention` binary (feature `dst-repro`) → deterministic in-process SSI contention.
  - determinism is guarded by `crates/graphus-fraud-gen/tests/determinism.rs`.
- **Detection + concurrency Node scripts**: `data/detect.js`, `data/concurrency.js` (official driver).
- **Evidence**: written at run time into `evidence/` (git-ignored). Wired by `rmp #253`–`#256`.
