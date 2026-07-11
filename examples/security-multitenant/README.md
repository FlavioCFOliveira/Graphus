# security-multitenant

A realistic, end-to-end demonstration of **fine-grained, multi-tenant security** on Graphus. It
provisions **isolated tenant databases** plus a set of **roles / users / grants / DENYs** at runtime,
then drives a complete **authorization surface** — the allow/deny matrix, a **fine-grained DENY**
(property-scope + label-scope), and **broadened cross-tenant no-leak** probes — against a live server
from **two** wire protocols: the **REST** API (HTTPS + a Bearer obtained from `POST /auth/login`, a
pure-stdlib `python3` client) and **Bolt-over-TCP** (TLS, the **official Neo4j driver**), asserting
every cell over both. It runs in **two modes**:

- **LOCAL (default)** — boots a real, **encrypted-at-rest** `graphus-server` (AES-256-GCM), drives the
  full surface, measures the encryption overhead against a cleartext twin, runs a **hermetic in-process
  verifier** of the encryption-at-rest guarantees (ciphertext on disk, offline key rotation, encrypted
  backup roundtrip), and collects the full evidence set (server CPU/RSS, on-disk **tenant** store/WAL
  footprint, a committed-baseline regression gate) plus a server-side `/metrics` delta.
- **EXTERNAL / ATTACH** — when any of `GRAPHUS_TARGET_{BOLT,REST,UDS}` is set, it does **not** boot a
  server: it attaches to an **already-running** instance (local or remote, e.g. `pi516`) via the shared
  external-target seam, authenticates with `POST /auth/login`, provisions an **isolated, namespaced**
  set of tenants/roles/users (idempotent, `IF NOT EXISTS`), drives the RBAC + cross-tenant + DENY
  (feature-detected) wire legs, scrapes the target's `/metrics` (incl. the auth-failure signal) via
  `measure_target` (`measurement_mode=external`), then **tears everything down** (`DROP` database/role/
  user) on exit so the target is left exactly as it was found.

It doubles as an executable E2E test: `run.sh` exits non-zero the moment any assertion fails.

## What it demonstrates

| Capability | How |
| --- | --- |
| Tenant isolation | one Graphus **database per tenant** (`CREATE DATABASE` at runtime — a hard isolation boundary) |
| Fine-grained RBAC | `GRANT <action> ON <scope>` with graded actions (Traverse ⊂ Read ⊂ Write) and the containment model (Database ⊇ Graph(db) ⊇ {Label, RelType, Property}) |
| **Negative privilege (DENY)** | `DENY READ ON PROPERTY db.Label.prop` (property reads back **NULL**) and `DENY TRAVERSE ON LABEL db.Label` (node **invisible**), layered over a GRANT with **deny-precedence** — incl. the multi-label `#645` regression guard |
| Authorization matrix | read/write/admin × {tenant_a, tenant_b} × {allow, deny}, plus unauthenticated, asserted per cell over both protocols |
| **Cross-tenant no-leak** | as a tenant_a user against tenant_b, `Patient.ssn` / `Record.secret_token` / all nodes / `count(n)` each return **no data** — over REST **and** Bolt |
| Two wire protocols | the **same** surface driven over **REST** (HTTPS + JWT via `/auth/login`) and **Bolt** (TLS + official driver), from one manifest |
| Remote-capable | the RBAC/DENY/cross-tenant/auth wire legs run against an **already-running** instance (`--base-url` / a Bolt URI), isolated + torn down |
| Encryption at rest *(LOCAL-only)* | AES-256-GCM page + WAL encryption; ciphertext-on-disk proof; offline key rotation; encrypted backup roundtrip; encryption overhead |
| /metrics auth-failure signal | scrapes `graphus_auth_failures_total` before→after and asserts it moved (with the confirmed REST-parity finding) |

## The sensitive multi-tenant model

Each tenant lives in its **own database** — a hard isolation boundary. Within a tenant the graph models
sensitive healthcare PII:

| Node label | Meaning |
| --- | --- |
| `(:Patient {id, name, ssn, country})` | a patient holding sensitive PII (`ssn` is a pseudo-SSN) |
| `(:Record {id, patient, diagnosis, secret_token})` | a clinical record; `secret_token` is a per-record secret |
| `(:Secret {name})` | one canary per tenant (`A_SECRET` / `B_SECRET`) — the exact probe the RBAC matrix reads |
| `(:Secret:Confidential {name})` *(DENY demo)* | a **multi-label** node (`A_CONFIDENTIAL`) the `#645` deny-precedence guard keys on |

| Relationship | Direction | Meaning |
| --- | --- | --- |
| `:HAS_RECORD` | `(:Patient)→(:Record)` | a patient owns a clinical record |

## The RBAC model (roles · users · grants · DENYs)

| Role | Grant | Meaning |
| --- | --- | --- |
| `reader_a` | `READ ON GRAPH tenant_a` | read-only, tenant_a only |
| `writer_a` | `WRITE ON GRAPH tenant_a` | write **⊇** read (graded), tenant_a only |
| `analyst` | `READ ON DATABASE` | **server-wide** read across **all** tenants |

| User | Role | |
| --- | --- | --- |
| `alice` | `reader_a` | additionally **DENY**-ed `Patient.ssn` (property) and `Confidential` (label) |
| `wendy` | `writer_a` | |
| `ana` | `analyst` | |
| `neo4j`/target admin | — (bootstrap) | holds the global **Admin** privilege; provisions everything; read/write any tenant |

### The allow/deny matrix (asserted on every run, over both protocols)

| User | tenant_a READ | tenant_a WRITE | tenant_b READ | tenant_b WRITE |
| --- | --- | --- | --- | --- |
| `alice` (reader_a) | **allow** | deny | deny *(cross-tenant)* | deny |
| `wendy` (writer_a) | allow *(write⊇read)* | **allow** | deny | deny |
| `ana` (analyst) | allow | deny | **allow** *(server-wide)* | deny |
| admin | allow | **allow** | allow | **allow** |
| _unauthenticated_ | **401** | — | — | — |

`allow` ⇒ HTTP 200 / no Bolt error; a denied **write** ⇒ HTTP 403 (`Neo.ClientError.Security.Forbidden`)
/ Bolt Forbidden throw; a denied **read** ⇒ 403 (REST coarse gate) **or** zero rows (Bolt value-level
filter) — **no leak either way**; unauthenticated ⇒ HTTP 401 (`Neo.ClientError.Security.Unauthorized`).

### Fine-grained DENY (property + label scope; the `#645` regression guard)

Layered over `reader_a`'s `GRANT READ ON GRAPH tenant_a`:

```cypher
DENY READ ON PROPERTY tenant_a.Patient.ssn TO reader_a;
DENY TRAVERSE ON LABEL tenant_a.Confidential TO reader_a;
```

With **deny-precedence**, the workloads assert (as `alice`, and re-checked as the admin to prove the
data exists and only the DENY hides it):

- **property NULL** — `MATCH (p:Patient) RETURN p.ssn` returns rows, but every `ssn` reads back **NULL**
  for `alice` (non-NULL for the admin);
- **node invisible** — `MATCH (c:Confidential) RETURN c` returns **zero rows** for `alice` (≥1 for the
  admin);
- **`#645` multi-label precedence** — `MATCH (s:Secret) WHERE s.name = 'A_CONFIDENTIAL' RETURN s`
  returns **zero rows** for `alice`: the node stays hidden **even when queried via its *other*
  (`:Secret`) label**. This is the exact regression guard for the `rmp #645` bug where an OR-union of
  labels dropped DENY-precedence on multi-label nodes.

**Version tolerance.** `DENY` is a newer part of the security grammar. The wire legs **feature-detect**
it: if the target rejects `DENY` (an older build answers a `400` SyntaxError on the leading `DENY`), the
demo **records the version gap** and skips the DENY assertions rather than failing — while still
asserting the full GRANT-scoped RBAC and cross-tenant isolation. The full modern DENY coverage (incl.
the `#645` guard) is asserted against a **current** server (LOCAL mode). See "Confirmed findings".

### Broadened cross-tenant no-leak probes

As `alice` (tenant_a-scoped) against **tenant_b**, over **both** protocols, the demo asserts that none
of the following ever returns any of the other tenant's data:

```cypher
MATCH (p:Patient) RETURN p.ssn        -- no cross-tenant PII
MATCH (r:Record)  RETURN r.secret_token
MATCH (n)         RETURN n            -- no cross-tenant node at all
MATCH (n)         RETURN count(n)     -- the cross-tenant count is 0
```

Over **REST** the coarse up-front gate answers **403**; over **Bolt** the value-level RBAC filter
answers **zero rows / count 0**. Either way **no sensitive datum crosses the tenant boundary** — a
broadening of the original single `:Secret`-canary check to the full PII surface.

## Encryption at rest (LOCAL-only)

The live LOCAL server is booted **encrypted** (`[encryption] key_path = <32-byte master key>`), deriving
per-purpose AES-256-GCM subkeys via an HKDF keyring for every store page and WAL frame. These legs read
**raw store bytes** and therefore **cannot** target a remote server; in EXTERNAL mode they are skipped
with a clear note.

- **Ciphertext on disk** — a known sensitive token (`TENANT_A_SECRET_TOKEN`) is **absent** from the raw
  encrypted store and **present** in a cleartext store built identically.
- **Offline key rotation** — `rotate_master_key` re-keys the database; data intact across, **old key
  fails closed** (KCV `Security` error, never a silent misread).
- **Encrypted backup roundtrip** — `backup_store` → `seal_backup` (no plaintext in the sealed bytes) →
  `open_backup` → `restore` (lossless); a wrong key fails closed.
- **Encryption overhead** — the **same** seeded dataset is loaded into an **isolated** database on
  **both** the encrypted server (`overhead_enc`) and a cleartext twin (`overhead_clear`), and **only
  those two db stores** are compared (see "Evidence fixes"), so the store-byte delta is purely the
  bounded per-page GCM tag/nonce cost.

## Confirmed findings (server)

Two confirmed server behaviours are documented and exercised here (both **outside** this example's
edit scope — reported for fixing, not fixed here):

1. **REST auth-failure metric parity gap** — `graphus_auth_failures_total` is incremented **only** by
   Bolt authentication failures (`listeners/bolt.rs`) and by a bad Bearer on the `/metrics` endpoint
   itself (`listeners/extra_routes.rs`). A REST **data-plane** 401 (missing/invalid Bearer on
   `/db/*/tx/commit`) and a `/auth/login` failure do **not** bump it — they only emit an audit record
   via `RestAuthObserver::on_auth_failure` (`engine/seam_rest.rs`). **Repro (pi516, verified this
   session):** counter `4` → bad-Bearer `GET /metrics` → `5`; a data-plane `POST /db/graphus/tx/commit`
   with no Bearer (401) and a `POST /auth/login` with bad creds (401) both leave it at `5`. The demo
   therefore moves the counter with a deliberate bad-Bearer `GET /metrics` (and, when the Bolt leg
   runs, the unauthenticated Bolt connection), and asserts the before→after delta ≥ 1.
2. **`verify_password` unknown-user timing oracle (`rmp #500`)** — a login for an **unknown** user
   skips the Argon2 verification a wrong-password-for-an-existing-user performs, so response-time
   differs (a user-enumeration side-channel). The REST `/auth/login` path already returns a **uniform**
   401 body for both cases (no user-exists oracle in the response), and throttles per account, but the
   **timing** oracle in `verify_password` remains. (Not exercised as a hard assertion — timing
   assertions are flaky across hosts — but documented with its `rmp` id.)

3. **DENY grammar version gap (observed on pi516)** — the pinned pi516 build predates the `DENY`
   security DDL and rejects it with a `400` SyntaxError; the demo records this and validates the full
   modern DENY coverage against a current server.

## Evidence fixes (`rmp #696`)

Two methodology defects in the prior evidence were corrected:

- **(a) storage measured the wrong store.** The prior run metered the empty default `graphus` database.
  It now meters a **real tenant database store** (`databases/tenant_a/graphus.store`) as the primary
  storage vector, and reports the **all-tenants** store/WAL **sum** as `tenant_store_bytes` /
  `tenant_wal_bytes` params (`measure_server` walks a single path per vector). The committed
  `baseline.json` was regenerated against the tenant store.
- **(b) encryption overhead was apples-to-oranges.** The prior comparison measured the whole encrypted
  tree (two seeded tenants) against a nearly-empty cleartext tree. It now seeds the **identical**
  `tenant_a` dataset into an **isolated** database on each side (`overhead_enc` / `overhead_clear`) and
  compares **only those two db stores**, so the delta is purely encryption overhead.

## A hermetic mirror in the default `cargo test` run

The example is also mirrored by an in-process integration test in the ordinary, dependency-free
`cargo test` — `crates/graphus-server/tests/security_multitenant.rs`. It generates the *same*
deterministic fast-profile scenario, boots the real `graphus_rest` axum router over a real engine, and
drives **every base matrix cell** through `tower::oneshot` (no TLS, no socket, no python, no Node),
asserting `allow ⇒ 200` / `deny ⇒ 403` / `unauth ⇒ 401`; it also drives the same crypto stack the
verifier proves. The generator's additive DENY / cross-tenant sections are consumed only by the wire
clients and leave this mirror's base matrix (7 allow / 7 deny / 1 unauth) unchanged.

## The deterministic generator — `crates/graphus-security-gen`

A **dev-only leaf crate** (`publish = false`, depended upon by nothing in the production build). It
emits, for a `(profile[, namespace])`:

- `provision.cypher` — the admin RBAC DDL (databases, roles, grants, users; all `IF NOT EXISTS`);
- `deny.cypher` — the fine-grained DENY grants;
- `teardown.cypher` — the idempotent `DROP` of every database/role/user (`STOP` then `DROP DATABASE`);
- `<database>.cypher` — each tenant's canary `:Secret` + sensitive patient/record PII;
- `manifest.json` — the tenants, users (with passwords), roles, grants, the allow/deny matrix, the DENY
  grants + seed + checks, and the cross-tenant probes the workloads drive and assert from.

`--namespace <ns>` prefixes every tenant-database / role / user name (the bootstrap admin is never
namespaced) so a **shared** external target hosts collision-free, cleanly torn-down provisioning.
Generation is a pure function of `(seed, profile, namespace)` — with **no** namespace the output is
byte-identical to the historical generator (`cargo test -p graphus-security-gen` proves determinism).

| Profile | Patients / tenant | Use |
| --- | --- | --- |
| `fast` (default) | 40 | CI + the live matrix E2E assertions |
| `large` | 1500 | evidence-scale (bigger store footprint) |

## Running it

From the repository root:

```bash
# LOCAL — boots an encrypted server, runs everything, collects evidence + baseline gate:
examples/security-multitenant/run.sh

# Reuse pre-built binaries / tune the profile:
GRAPHUS_BIN_DIR=target/release SEC_PROFILE=large examples/security-multitenant/run.sh

# EXTERNAL / ATTACH — against an already-running instance (e.g. pi516), isolated + torn down:
GRAPHUS_TARGET_REST=https://100.89.148.30:7474 \
  GRAPHUS_TARGET_BOLT=bolt+ssc://100.89.148.30:7687 \
  GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=graphus-local \
  GRAPHUS_TARGET_TLS_INSECURE=1 examples/security-multitenant/run.sh
```

| Env var | Default | Meaning |
| --- | --- | --- |
| `GRAPHUS_BIN_DIR` | `target/release` | where to find `graphus-server` / `security_gen` / `security_verify` (built if missing, LOCAL) |
| `SEC_PROFILE` | `fast` | dataset scale (`fast` / `large`) |
| `RUN_DRIVER` | `auto` | run the Bolt leg via the official driver (`1`/`0`; auto = on when node/npm present) |
| `GRAPHUS_TARGET_*` | — | set any of `REST`/`BOLT`/`UDS` to switch to EXTERNAL/attach mode (see `_harness/harness.sh`) |

**Requirements:** a Unix host, `bash`, `python3` (3.8+, **stdlib only**). LOCAL also needs `openssl`
(self-signed cert); EXTERNAL needs `curl`. The Bolt leg additionally needs `node` (v18+), `npm`, and
network/cache access (`npm install neo4j-driver`), and in EXTERNAL mode `GRAPHUS_TARGET_BOLT`.

## Evidence

LOCAL emits the standardized, schema-versioned `evidence/report.json` + `report.md` via `measure_server`
(server CPU + peak RSS, the on-disk **tenant** store/WAL footprint, dataset size, the RBAC/DENY/
cross-tenant tallies, the encryption-overhead deltas, the verifier's rotation/backup numbers, and the
auth-failure delta), gated against the committed `baseline.json` on the **structural** metrics only.

The **throughput / latency** vector is the RBAC matrix workload itself: every
`POST /db/{db}/tx/commit` the matrix issues is timed by `matrix.py`, so `operations`, `ops_per_sec` and
`p50` / `p99` / `p999` are the **real** cost of an authorization-enforced REST request (both the
allowed 200s and the rejected 403s — excluding the denials would bias the percentiles toward the
allowed cells). `space_amplification` / `write_amplification` are the durable bytes over the logical
dataset the generator actually emitted.

> **Evidence honesty (`rmp #699`).** This example was the worst offender in the suite: the latency
> percentiles were **hardcoded `0.000` placeholders** (nothing ever measured them), `ops_per_sec` was
> `seeded_statements / server-uptime` — a count of Cypher statements divided by a window they were
> never issued over, which produced the committed baseline's suspiciously round `410.0` — the
> amplification denominator was an invented `nodes*256 + rels*128` formula, `write_amplification` was
> a `0.0` placeholder, and `total_millis` (`0.047` ms) timed the report's own emission. All are now
> really measured.
EXTERNAL emits `report.json` in `measurement_mode=external` via `measure_target`: the process CPU/RSS +
on-disk storage vectors are N/A remotely, and the payload is the server-side `/metrics` before→after
**delta** for the run's dedicated tenant database (committed/aborted txns, query-duration histogram, the
health invariants, and the auth-failure signal as params), with a host-independent invariant gate
(`--assert`: zero statement panics / recovery panics / force-detach; the server observed the workload).
The `evidence/` dir is git-ignored.
