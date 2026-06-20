# security-multitenant

A realistic, end-to-end demonstration of **fine-grained, multi-tenant security** on Graphus. It
boots a real, **encrypted-at-rest** `graphus-server` (AES-256-GCM), provisions **isolated tenant
databases** plus a set of **roles / users / grants** at runtime, and then drives a complete
**allow/deny authorization matrix** against it from **two** wire protocols — the **REST** API
(HTTPS + Bearer-JWT, a pure-stdlib `python3` client) and **Bolt-over-TCP** (TLS, the **official
Neo4j driver**) — asserting every cell. Alongside the live matrix, a **hermetic in-process verifier**
proves the encryption-at-rest guarantees: the sensitive data is **ciphertext on disk**, the master
key **rotates offline** with the old key failing closed, and an **encrypted backup round-trips
losslessly**.

It doubles as an executable E2E test: `run.sh` exits non-zero the moment any assertion fails.

## What it demonstrates

| Capability | How |
| --- | --- |
| Tenant isolation | one Graphus **database per tenant** (`CREATE DATABASE` at runtime — a hard isolation boundary) |
| Fine-grained RBAC | `CREATE ROLE/USER` + `GRANT <action> ON <scope>` with graded actions (Traverse ⊂ Read ⊂ Write) and a containment model (Database ⊇ Graph(db) ⊇ {Label, RelType, Property}) |
| Authorization matrix | read/write/admin × {tenant_a, tenant_b} × {allow, deny}, plus unauthenticated, asserted per cell |
| Two wire protocols | the **same** matrix driven over **REST** (HTTPS + JWT) and **Bolt** (TLS + official driver), from one manifest |
| Cross-tenant denial | a tenant_a-scoped user is denied tenant_b — 403 over REST, value-level filtered (zero rows, no leak) over Bolt |
| Encryption at rest | AES-256-GCM page + WAL encryption via an HKDF keyring from a 32-byte master key file |
| Ciphertext-on-disk proof | a known sensitive token is **absent** from the raw encrypted store but **present** in a cleartext store |
| Offline key rotation | `rotate_master_key` re-keys the database; data intact across, **old key fails closed** |
| Encrypted backup | `backup_store` → `seal_backup` (no plaintext in the sealed bytes) → `open_backup` → `restore` (lossless) |
| Encryption overhead | the same seed workload run encrypted vs cleartext, reporting the time + storage delta |

## The sensitive multi-tenant model

Each tenant lives in its **own database** — a hard isolation boundary. Within a tenant the graph
models sensitive healthcare PII:

| Node label | Key properties | Meaning |
| --- | --- | --- |
| `(:Patient {id, name, ssn, country})` | | a patient holding sensitive PII (`ssn` is a pseudo-SSN) |
| `(:Record {id, patient, diagnosis, secret_token})` | | a clinical record; `secret_token` is a per-record secret |
| `(:Secret {name})` | | one canary per tenant (`A_SECRET` / `B_SECRET`) — the exact probe the RBAC matrix reads |

| Relationship | Direction | Meaning |
| --- | --- | --- |
| `:HAS_RECORD` | `(:Patient)→(:Record)` | a patient owns a clinical record |

The first record of each tenant carries a **stable sensitive token** (`TENANT_A_SECRET_TOKEN` /
`TENANT_B_SECRET_TOKEN`) — the fixed plaintext the **ciphertext-on-disk** proof greps for in the raw
device bytes.

## The RBAC model (roles · users · grants)

| Role | Grant | Meaning |
| --- | --- | --- |
| `reader_a` | `READ ON GRAPH tenant_a` | read-only, tenant_a only |
| `writer_a` | `WRITE ON GRAPH tenant_a` | write **⊇** read (graded), tenant_a only |
| `analyst` | `READ ON DATABASE` | **server-wide** read across **all** tenants |

| User | Role | |
| --- | --- | --- |
| `alice` | `reader_a` | |
| `wendy` | `writer_a` | |
| `ana` | `analyst` | |
| `neo4j` | — (bootstrap) | holds the global **Admin** privilege; provisions everything; read/write any tenant |

### The allow/deny matrix (asserted on every run)

The generator emits this matrix into `manifest.json`; both the REST and the Bolt workload drive and
assert **every cell** from it:

| User | tenant_a READ | tenant_a WRITE | tenant_b READ | tenant_b WRITE |
| --- | --- | --- | --- | --- |
| `alice` (reader_a) | **allow** | deny | deny *(cross-tenant)* | deny |
| `wendy` (writer_a) | allow *(write⊇read)* | **allow** | deny | deny |
| `ana` (analyst) | allow | deny | **allow** *(server-wide)* | deny |
| `neo4j` (admin) | allow | **allow** | allow | **allow** |
| _unauthenticated_ | **401** | — | — | — |

`allow` ⇒ HTTP 200 / no Bolt error; `deny` ⇒ HTTP 403 (`Neo.ClientError.Security.Forbidden`);
unauthenticated ⇒ HTTP 401 (`Neo.ClientError.Security.Unauthorized`).

### How tenants are provisioned (runtime DDL — this works)

Tenants are created **at runtime** by the admin via Graphus's RBAC admin grammar (intercepted before
Cypher, runs over Bolt **or** REST, and persists to `security.toml`). The generator's
`provision.cypher` is exactly this sequence, run as the admin over `/db/graphus/tx/commit` (admin DDL
is database-agnostic and must run as auto-commit — it is rejected inside an explicit transaction):

```cypher
CREATE DATABASE tenant_a IF NOT EXISTS;
CREATE DATABASE tenant_b IF NOT EXISTS;
CREATE ROLE reader_a IF NOT EXISTS;
CREATE ROLE writer_a IF NOT EXISTS;
CREATE ROLE analyst  IF NOT EXISTS;
GRANT READ  ON GRAPH tenant_a TO reader_a;
GRANT WRITE ON GRAPH tenant_a TO writer_a;
GRANT READ  ON DATABASE       TO analyst;
CREATE USER alice SET PASSWORD 'alice-secret-pw' IF NOT EXISTS;
CREATE USER wendy SET PASSWORD 'wendy-secret-pw' IF NOT EXISTS;
CREATE USER ana   SET PASSWORD 'ana-analyst-pw'  IF NOT EXISTS;
GRANT ROLE reader_a TO alice;
GRANT ROLE writer_a TO wendy;
GRANT ROLE analyst  TO ana;
```

### Honest note — how READ deny differs over REST vs Bolt

The two wire protocols both **deny** the wrong tenant and **never leak** data across the boundary,
but they enforce a denied **read** through different layers, which is worth stating precisely:

- **REST** has a coarse up-front gate (`authorize_mode` in `crates/graphus-rest/src/router.rs`):
  before running anything it checks `Privilege::on_graph(action, db)` for the *target* database, so a
  cross-tenant read is rejected with **403** before a single row is scanned.
- **Bolt** has no such coarse gate; it relies on Graphus's **fine-grained, value-level RBAC filter**
  (`AuthorizedGraph` + `EffectivePrivileges` in `crates/graphus-cypher` / `graphus-server`): an
  ungranted label is **filtered out of the scan**, so a cross-tenant read **succeeds but returns zero
  rows** — the canary `:Secret` is invisible. **No sensitive data crosses the tenant boundary** in
  either case; the difference is *403 (REST) vs empty result (Bolt)*. A denied **write** throws
  `Neo.ClientError.Security.Forbidden` on both. The Bolt client asserts exactly this: an allowed read
  returns ≥1 canary row, a denied/cross-tenant read returns **0 rows**, a denied write throws
  Forbidden.

## Encryption at rest

The live server is booted **encrypted** (`run.sh` step 3). The configuration adds an `[encryption]`
section pointing at a 32-byte master key file:

```toml
[encryption]
key_path = "<workdir>/master.key"     # raw 32 bytes (or 64 hex chars) => AES-256-GCM + HKDF keyring
```

`run.sh` generates the key with `head -c 32 /dev/urandom > master.key`. From this master key Graphus
derives, via an **HKDF keyring**, the per-purpose subkeys that encrypt every **store page** and every
**WAL frame** with AES-256-GCM (each page/frame authenticated by its own GCM tag; a key-check value,
KCV, in the device + WAL headers makes a wrong key **fail closed** rather than misread).

### Ciphertext on disk (proof)

The hermetic verifier seeds a known sensitive plaintext (`TENANT_A_SECRET_TOKEN`) into an encrypted
store, then greps the raw `graphus.store` bytes: the token must be **ABSENT**. To prove the test is
*meaningful* (the absence is encryption, not a mis-seed) it builds the **same** graph in a
**cleartext** store and confirms the token **IS present** there in the clear.

### Offline key rotation (stop → rotate → swap key → restart)

Key rotation is an **offline** operation, **not** an online admin command. The verifier drives
`graphus_server::key_rotation::rotate_master_key(db_dir, device_file, wal_file, old, new)` directly
against a store it created. The operator procedure is:

1. **stop** the server (the database must be offline — rotation rewrites the device + WAL),
2. call `rotate_master_key` per database directory (it recovers, re-encrypts the device + WAL under
   the new key, and swaps them atomically via a crash-safe commit marker),
3. **replace** the key file at `encryption.key_path` with the new key,
4. **restart** the server.

The verifier asserts the data is intact + readable **across** the rotation (decrypted pages are
byte-for-byte identical) and that the **OLD key fails closed** (a `Security` error via the KCV — never
a silent misread). The rotation is crash-safe at every window (see the per-window analysis in
`crates/graphus-server/src/key_rotation.rs`).

### Encrypted backup round-trip

`graphus_storage::backup::backup_store` snapshots a (possibly encrypted) store to a **plaintext**
artifact (it reads page *images* above the device seam — which is exactly why the artifact must be
sealed before it leaves the machine). The verifier:

1. `backup_store` → a plaintext artifact (asserted to **contain** the secret in the clear);
2. `graphus_crypto::backup_envelope::seal_backup(artifact, master)` → an **encrypted** artifact,
   asserted to **NOT contain** the secret nor a verbatim prefix of the plaintext;
3. `open_backup(sealed, master)` → `verify_backup` → `restore(...)` into a **fresh** store, asserted
   **lossless** (the restored graph is identical);
4. a **wrong** master key fails `open_backup` closed.

It measures the backup/restore time and the artifact + sealed sizes.

## The deterministic generator — `crates/graphus-security-gen`

A **dev-only leaf crate** (`publish = false`, depended upon by nothing — in particular **not**
`graphus-server`, so it adds zero overhead to the shipped binary). It emits:

- `provision.cypher` — the admin RBAC DDL above (databases, roles, grants, users);
- `tenant_a.cypher` / `tenant_b.cypher` — each tenant's canary `:Secret` + sensitive patient/record
  PII (run inside that tenant's database, as the admin);
- `manifest.json` — the tenants, users (with passwords), roles, grants and the expected allow/deny
  matrix the workloads drive and assert from.

Generation is a pure function of `(seed, profile)` (an internal `SplitMix64` PRNG; no floats, no
`HashMap` iteration, no clock), so the artifacts are **byte-identical** across runs, hosts, and
platforms. `cargo test -p graphus-security-gen` proves this. The RBAC matrix is **structural** and
identical regardless of profile; only the PII volume differs.

| Profile | Patients / tenant | Use |
| --- | --- | --- |
| `fast` (default) | 40 | CI + the live RBAC-matrix E2E assertions |
| `large` | 1500 | evidence-scale (bigger encrypted store footprint) |

```bash
cargo run -p graphus-security-gen --bin security_gen -- --profile fast --out-dir /tmp/sec
```

The crate also ships:

- `security_verify` (behind the `dst-repro` feature) — the hermetic in-process
  encryption/rotation/backup verifier described above (prints `GRAPHUS_SECURITY_VERIFY_OK` +
  a `GRAPHUS_STATS {…}` line). Run with no network:

  ```bash
  cargo run -p graphus-security-gen --features dst-repro --bin security_verify
  ```

- `sec_baseline_cmp` — the committed-baseline regression gate (the structural-only comparator, named
  distinctly to avoid a binary-name collision with the other example crates' comparators).

## Running it

From the repository root:

```bash
examples/security-multitenant/run.sh
```

Reuse pre-built binaries and tune the profile:

```bash
cargo build --release -p graphus-server
cargo build --release -p graphus-security-gen --bin security_gen --bin sec_baseline_cmp
cargo build --release -p graphus-security-gen --features dst-repro --bin security_verify
GRAPHUS_BIN_DIR=target/release SEC_PROFILE=large examples/security-multitenant/run.sh
```

| Env var | Default | Meaning |
| --- | --- | --- |
| `GRAPHUS_BIN_DIR` | `target/release` | where to find `graphus-server` / `security_gen` / `security_verify` (built if missing) |
| `SEC_PROFILE` | `fast` | dataset scale (`fast` / `large`) |
| `RUN_DRIVER` | `auto` | run the Bolt leg via the official driver (`1`/`0`; auto = on when node/npm present) |

**Requirements:** a Unix host (Linux/macOS), `bash`, `openssl` (self-signed cert), and `python3`
(3.8+, **stdlib only** — no pip packages). The Bolt leg additionally needs `node` (v18+), `npm`, and
network/cache access (for `npm install neo4j-driver`). The generator and the crypto verifier are
hermetic and CI-runnable on their own; if `openssl`/`python3` (or node/npm for Bolt) are absent, the
corresponding leg is skipped with a clear note while the hermetic assertions still run.

## Evidence

The python client emits a single machine-readable `GRAPHUS_STATS {…}` line (tenants, roles, users,
matrix cell tallies, seeded statements); `run.sh` feeds it — together with the verifier's
rotation/backup numbers, the **live server process's** CPU + peak RSS, the on-disk store/WAL
footprint, and the **encryption-overhead** measurement — into the dev-only `measure_server` harness,
which writes the standardized, schema-versioned **`evidence/report.json` + `evidence/report.md`** (the
`evidence/` dir is git-ignored). The path is printed in the run summary.

### What is measured

| Vector | Source |
| --- | --- |
| **RBAC matrix** | allow/deny/401 cell tallies, asserted over REST and Bolt |
| **Ciphertext on disk** | sensitive token absent from the encrypted store, present in cleartext |
| **Key rotation** | rotation time; data intact across; old key rejected |
| **Encrypted backup** | artifact + sealed sizes; backup/restore time; lossless; wrong key rejected |
| **Encryption overhead** | seed time + on-disk store bytes, encrypted vs cleartext |
| **Server CPU / RAM** | the live server PID's cumulative CPU + sampled peak RSS |
| **Storage footprint** | on-disk store + WAL bytes/pages after the seed |
| **Dataset size** | nodes + relationships across both tenants |

### STABLE vs MACHINE-VARIANT

The committed-baseline gate (`sec_baseline_cmp`) holds only the **deterministic / structural**
metrics — the dataset size and the on-disk store/WAL footprint, byte-stable for a fixed seed +
profile — to a tight 15 % band, and ignores the **machine-variant** families (CPU, RSS, latency,
throughput, and the single-run encryption-overhead *timing*; the storage *delta* is the stable
overhead signal — bounded per-page GCM tag/nonce cost). A drift in the deterministic metrics **fails
the run**.
