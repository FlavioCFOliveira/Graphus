//! Deterministic, seeded **multi-tenant sensitive-data generator** for the
//! `examples/security-multitenant` demonstration.
//!
//! It produces a healthcare-style, **multi-tenant** Label Property Graph carrying sensitive PII
//! (patients, their clinical records, and the secret access tokens a detector must never see across
//! a tenant boundary), the **admin provisioning script** (the exact `CREATE DATABASE / ROLE / USER`
//! and `GRANT` commands that stand up the tenants and the RBAC), and a **manifest** describing the
//! tenants, users, roles, grants and the expected allow/deny **matrix** — so the workload can both
//! drive the server and assert every authorization cell from a single source of truth.
//!
//! # Determinism
//!
//! Generation is a pure function of `(seed, profile)`: the only randomness is an internal
//! [`SplitMix64`] PRNG seeded from a per-profile seed. For a given [`Profile`] the emitted Cypher,
//! the provisioning script and the manifest JSON are **byte-identical** across runs, hosts, and
//! platforms (no floats, no `HashMap` iteration, no clock, no thread scheduling). This is asserted
//! by `tests/determinism.rs`.
//!
//! # The model (one isolated graph per tenant)
//!
//! Each tenant lives in its own Graphus **database** (a hard isolation boundary). Within a tenant:
//!
//! - `(:Patient {id, name, ssn, country})` — a patient holding sensitive PII.
//! - `(:Record {id, patient, diagnosis, secret_token})` — a clinical record; `secret_token` is the
//!   per-tenant **sensitive secret** the ciphertext-on-disk proof and the cross-tenant denial both
//!   key on.
//! - `(:Patient)-[:HAS_RECORD]->(:Record)` — ownership of a record by a patient.
//! - one canary `(:Secret {name})` node per tenant (`A_SECRET` / `B_SECRET`), the exact probe the
//!   RBAC matrix reads to prove allow/deny per tenant.
//!
//! # The RBAC model (the authorization surface under test)
//!
//! Tenants: `tenant_a`, `tenant_b` (two isolated databases). Roles + grants:
//!
//! - `reader_a` — `READ ON GRAPH tenant_a` (read-only, tenant_a only).
//! - `writer_a` — `WRITE ON GRAPH tenant_a` (write ⊇ read, tenant_a only).
//! - `analyst`  — `READ ON DATABASE` (server-wide read across **all** tenants).
//!
//! Users: `alice → reader_a`, `wendy → writer_a`, `ana → analyst`. The bootstrap admin `neo4j`
//! holds the global Admin privilege (it provisions everything and may read/write any tenant).
//!
//! The manifest's [`MatrixCell`] list enumerates, for every `(user, tenant, access_mode)` triple,
//! the expected outcome (`Allow` ⇒ HTTP 200 / no Bolt error; `Deny` ⇒ HTTP 403 / Bolt
//! `Neo.ClientError.Security.Forbidden`), plus an explicit **unauthenticated** cell (HTTP 401). The
//! REST and Bolt workloads both drive from this list and assert each cell, so the example proves the
//! full read/write/admin × {tenant_a, tenant_b} × {allow, deny} authorization matrix over **both**
//! wire protocols from one deterministic description.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

/// A tiny, fast, fully-deterministic PRNG (SplitMix64 — Steele, Lea & Flood 2014). A *pure* integer
/// mixing function: identical output for identical seeds on every platform, with no global state, no
/// float, and no allocation. The whole generator is reproducible byte-for-byte.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Seeds the generator. Any `u64` seed is valid.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Returns the next pseudo-random `u64`.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Returns a value in `[0, n)` (n > 0) with negligible modulo bias for our small ranges.
    pub fn below(&mut self, n: u64) -> u64 {
        debug_assert!(n > 0, "below(0) is undefined");
        self.next_u64() % n
    }

    /// Returns an `i64` in the inclusive range `[lo, hi]`.
    pub fn range_i64(&mut self, lo: i64, hi: i64) -> i64 {
        debug_assert!(lo <= hi);
        let span = (hi - lo) as u64 + 1;
        lo + (self.below(span) as i64)
    }
}

/// The two generation profiles: a small `Fast` dataset for CI/E2E assertions, and a larger `Large`
/// dataset for evidence collection. Both inject the *same* tenants / roles / users / grants and the
/// same canary secrets (so the RBAC matrix is identical), only the per-tenant PII volume differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Small, fast dataset for CI and the RBAC-matrix E2E assertions.
    Fast,
    /// Larger dataset for evidence collection (storage/CPU/RAM footprint at volume).
    Large,
}

impl Profile {
    /// Parses a profile name (`fast` / `large`), case-insensitively.
    ///
    /// # Errors
    /// Returns `Err` with the offending name if it is neither `fast` nor `large`.
    pub fn parse(name: &str) -> Result<Self, String> {
        match name.to_ascii_lowercase().as_str() {
            "fast" => Ok(Self::Fast),
            "large" => Ok(Self::Large),
            other => Err(format!(
                "unknown profile '{other}' (expected 'fast' or 'large')"
            )),
        }
    }

    /// The stable string name of this profile.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Large => "large",
        }
    }

    /// The scale knobs for this profile. Kept here (not in the binary) so the determinism test and
    /// the binary agree by construction.
    #[must_use]
    pub fn config(self) -> GenConfig {
        match self {
            Self::Fast => GenConfig {
                seed: 0x5EC0_0000_0000_0001,
                patients_per_tenant: 40,
                records_per_patient_max: 3,
            },
            Self::Large => GenConfig {
                seed: 0x5EC0_0000_0000_0001,
                patients_per_tenant: 1_500,
                records_per_patient_max: 4,
            },
        }
    }
}

/// The full set of generation knobs. A [`Dataset`] is a pure function of this struct, so two configs
/// that compare equal produce byte-identical output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenConfig {
    /// PRNG seed: the single source of all randomness.
    pub seed: u64,
    /// Number of patients minted per tenant.
    pub patients_per_tenant: u64,
    /// Upper bound (inclusive) on the records a patient may hold (≥ 1).
    pub records_per_patient_max: u64,
}

/// One tenant's sensitive patient.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Patient {
    /// Tenant-unique patient id.
    pub id: i64,
    /// Display name (`patient-<tenant>-<id>`; deterministic).
    pub name: String,
    /// A deterministic pseudo-SSN (sensitive PII; never crosses a tenant boundary).
    pub ssn: String,
    /// ISO country code.
    pub country: String,
}

/// One clinical record (sensitive), owned by a patient.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    /// Tenant-unique record id.
    pub id: i64,
    /// Owning patient id.
    pub patient: i64,
    /// A coarse diagnosis code (one of a small fixed set).
    pub diagnosis: String,
    /// The per-record sensitive secret token (the ciphertext-on-disk probe keys on the canary one).
    pub secret_token: String,
}

/// A fully-materialized per-tenant dataset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tenant {
    /// The tenant's database name (a Graphus database == a hard isolation boundary).
    pub database: String,
    /// The canary `(:Secret {name})` value the RBAC matrix reads to prove allow/deny per tenant.
    pub canary_secret: String,
    /// The sensitive plaintext token planted in this tenant's store, asserted ABSENT from the raw
    /// encrypted device bytes (the ciphertext-on-disk proof) and present only via authorized reads.
    pub sensitive_token: String,
    /// All patients in this tenant.
    pub patients: Vec<Patient>,
    /// All records in this tenant.
    pub records: Vec<Record>,
}

/// A role and its grant (a single graded action over a single scope, which is all this example
/// needs to exercise the containment model end-to-end).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Role {
    /// The role name.
    pub name: String,
    /// The granted action (`READ` / `WRITE` — graded Traverse ⊂ Read ⊂ Write).
    pub action: String,
    /// The scope kind (`DATABASE` server-wide, or `GRAPH <db>` tenant-scoped).
    pub scope: String,
}

/// A user mapped to a single role (sufficient for the matrix; the model supports more).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    /// The username (the JWT `sub` / the Bolt basic-auth principal).
    pub name: String,
    /// The user's password (≥ 8 chars; used for Bolt basic auth and provisioning).
    pub password: String,
    /// The role granted to this user.
    pub role: String,
}

/// The expected outcome of one authorization attempt.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The operation is authorized (HTTP 200 / no Bolt error).
    Allow,
    /// The operation is denied by authorization (HTTP 403 / Bolt `…Security.Forbidden`).
    Deny,
    /// The request is unauthenticated and must be rejected before authorization (HTTP 401).
    Unauthenticated,
}

/// One cell of the allow/deny matrix: a `(user, tenant, access_mode)` attempt and its expected
/// [`Outcome`]. The workloads drive and assert every cell from this list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatrixCell {
    /// The acting username, or `null` for the unauthenticated probe.
    pub user: Option<String>,
    /// The target tenant database.
    pub tenant: String,
    /// The access mode of the attempt (`READ` / `WRITE`).
    pub access_mode: String,
    /// The expected outcome.
    pub outcome: Outcome,
    /// A short human-readable rationale (carried into the printed matrix table).
    pub why: String,
}

/// The whole deterministic security scenario: the tenants (with their sensitive data), the RBAC
/// roles/users, and the expected authorization matrix. Serialized to `manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// The profile name the dataset was generated for.
    pub profile: String,
    /// The seed used (so a report can pin reproducibility).
    pub seed: u64,
    /// The bootstrap admin username (holds the global Admin privilege).
    pub admin_user: String,
    /// The tenant databases and their sensitive data.
    pub tenants: Vec<Tenant>,
    /// The RBAC roles and their grants.
    pub roles: Vec<Role>,
    /// The users and their role assignments.
    pub users: Vec<User>,
    /// The expected allow/deny/unauthenticated matrix.
    pub matrix: Vec<MatrixCell>,
}

/// A fully-materialized dataset: the per-tenant sensitive data + the manifest. Produced by
/// [`generate`].
#[derive(Debug, Clone)]
pub struct Dataset {
    /// The generation config that produced this dataset.
    pub config: GenConfig,
    /// The complete manifest (tenants, roles, users, matrix).
    pub manifest: Manifest,
}

/// A small fixed set of country codes, indexed deterministically.
const COUNTRIES: [&str; 6] = ["PT", "ES", "FR", "DE", "GB", "NL"];
/// A small fixed set of diagnosis codes.
const DIAGNOSES: [&str; 5] = ["A01", "B12", "C34", "D55", "E07"];

fn pick<'a>(set: &'a [&'a str], v: u64) -> &'a str {
    set[(v as usize) % set.len()]
}

/// The two tenant databases this scenario provisions at runtime via `CREATE DATABASE`.
pub const TENANTS: [&str; 2] = ["tenant_a", "tenant_b"];

/// Generates the full [`Dataset`] from a [`GenConfig`].
///
/// The per-tenant data is laid out in a strictly ordered fashion (patients `0..N`, then each
/// patient's records in id order) so the emitted Cypher and the manifest JSON are a deterministic
/// function of the config alone.
#[must_use]
pub fn generate(config: GenConfig, profile: &str) -> Dataset {
    let mut rng = SplitMix64::new(config.seed);

    let mut tenants: Vec<Tenant> = Vec::with_capacity(TENANTS.len());
    for (t_idx, &db) in TENANTS.iter().enumerate() {
        let tag = db.rsplit('_').next().unwrap_or(db).to_ascii_uppercase(); // tenant_a -> A
        let canary_secret = format!("{tag}_SECRET");
        let sensitive_token = format!("TENANT_{tag}_SECRET_TOKEN");

        let mut patients: Vec<Patient> = Vec::new();
        let mut records: Vec<Record> = Vec::new();
        let mut next_record_id: i64 = 0;

        for p in 0..config.patients_per_tenant {
            let pid = p as i64;
            let country = pick(&COUNTRIES, rng.next_u64()).to_owned();
            // A deterministic pseudo-SSN — sensitive PII, distinct per tenant+patient.
            let ssn = format!(
                "{:03}-{:02}-{:04}",
                rng.below(1000),
                rng.below(100),
                rng.below(10000)
            );
            patients.push(Patient {
                id: pid,
                name: format!("patient-{}-{pid}", tag.to_ascii_lowercase()),
                ssn,
                country,
            });

            let n_records = 1 + rng.below(config.records_per_patient_max);
            for r in 0..n_records {
                let rid = next_record_id;
                next_record_id += 1;
                let diagnosis = pick(&DIAGNOSES, rng.next_u64()).to_owned();
                // The first record of the first patient of each tenant carries the canary sensitive
                // token (a stable, greppable plaintext) so the ciphertext-on-disk proof has a fixed
                // probe; the rest carry per-record derived tokens.
                let secret_token = if p == 0 && r == 0 {
                    sensitive_token.clone()
                } else {
                    format!("tok-{}-{rid:06}", tag.to_ascii_lowercase())
                };
                records.push(Record {
                    id: rid,
                    patient: pid,
                    diagnosis,
                    secret_token,
                });
            }
        }

        // Keep the canary deterministic regardless of which tenant index this is.
        let _ = t_idx;
        tenants.push(Tenant {
            database: db.to_owned(),
            canary_secret,
            sensitive_token,
            patients,
            records,
        });
    }

    // --- RBAC roles / users (fixed; the matrix below references them by name). ---
    let roles = vec![
        Role {
            name: "reader_a".to_owned(),
            action: "READ".to_owned(),
            scope: "GRAPH tenant_a".to_owned(),
        },
        Role {
            name: "writer_a".to_owned(),
            action: "WRITE".to_owned(),
            scope: "GRAPH tenant_a".to_owned(),
        },
        Role {
            name: "analyst".to_owned(),
            action: "READ".to_owned(),
            scope: "DATABASE".to_owned(),
        },
    ];
    let users = vec![
        User {
            name: "alice".to_owned(),
            password: "alice-secret-pw".to_owned(),
            role: "reader_a".to_owned(),
        },
        User {
            name: "wendy".to_owned(),
            password: "wendy-secret-pw".to_owned(),
            role: "writer_a".to_owned(),
        },
        User {
            name: "ana".to_owned(),
            password: "ana-analyst-pw".to_owned(),
            role: "analyst".to_owned(),
        },
    ];

    let admin_user = "neo4j".to_owned();
    let matrix = build_matrix(&admin_user);

    let manifest = Manifest {
        profile: profile.to_owned(),
        seed: config.seed,
        admin_user,
        tenants,
        roles,
        users,
        matrix,
    };

    Dataset { config, manifest }
}

/// Builds the deterministic allow/deny/unauthenticated matrix. Covers read/write/admin ×
/// {tenant_a, tenant_b} × {allow, deny} per user, plus the unauthenticated probe.
fn build_matrix(admin_user: &str) -> Vec<MatrixCell> {
    let cell =
        |user: Option<&str>, tenant: &str, mode: &str, outcome: Outcome, why: &str| MatrixCell {
            user: user.map(str::to_owned),
            tenant: tenant.to_owned(),
            access_mode: mode.to_owned(),
            outcome,
            why: why.to_owned(),
        };
    vec![
        // alice — reader_a (READ ON GRAPH tenant_a): reads tenant_a, nothing else, no writes.
        cell(
            Some("alice"),
            "tenant_a",
            "READ",
            Outcome::Allow,
            "reader_a: READ ON GRAPH tenant_a",
        ),
        cell(
            Some("alice"),
            "tenant_a",
            "WRITE",
            Outcome::Deny,
            "reader_a has no WRITE",
        ),
        cell(
            Some("alice"),
            "tenant_b",
            "READ",
            Outcome::Deny,
            "reader_a grant is scoped to tenant_a",
        ),
        cell(
            Some("alice"),
            "tenant_b",
            "WRITE",
            Outcome::Deny,
            "reader_a grant is scoped to tenant_a",
        ),
        // wendy — writer_a (WRITE ON GRAPH tenant_a): write ⊇ read on tenant_a, nothing on tenant_b.
        cell(
            Some("wendy"),
            "tenant_a",
            "WRITE",
            Outcome::Allow,
            "writer_a: WRITE ON GRAPH tenant_a",
        ),
        cell(
            Some("wendy"),
            "tenant_a",
            "READ",
            Outcome::Allow,
            "write ⊇ read (graded actions)",
        ),
        cell(
            Some("wendy"),
            "tenant_b",
            "WRITE",
            Outcome::Deny,
            "writer_a grant is scoped to tenant_a",
        ),
        cell(
            Some("wendy"),
            "tenant_b",
            "READ",
            Outcome::Deny,
            "writer_a grant is scoped to tenant_a",
        ),
        // ana — analyst (READ ON DATABASE): server-wide read across BOTH tenants, no writes.
        cell(
            Some("ana"),
            "tenant_a",
            "READ",
            Outcome::Allow,
            "analyst: READ ON DATABASE (server-wide)",
        ),
        cell(
            Some("ana"),
            "tenant_b",
            "READ",
            Outcome::Allow,
            "analyst: READ ON DATABASE (server-wide)",
        ),
        cell(
            Some("ana"),
            "tenant_a",
            "WRITE",
            Outcome::Deny,
            "analyst has READ only",
        ),
        cell(
            Some("ana"),
            "tenant_b",
            "WRITE",
            Outcome::Deny,
            "analyst has READ only",
        ),
        // admin — global Admin: read/write any tenant.
        cell(
            Some(admin_user),
            "tenant_a",
            "WRITE",
            Outcome::Allow,
            "bootstrap admin holds global Admin",
        ),
        cell(
            Some(admin_user),
            "tenant_b",
            "WRITE",
            Outcome::Allow,
            "bootstrap admin holds global Admin",
        ),
        // unauthenticated — rejected before authorization.
        cell(
            None,
            "tenant_a",
            "READ",
            Outcome::Unauthenticated,
            "no credentials => 401",
        ),
    ]
}

impl Dataset {
    /// Renders the admin **provisioning** script: the exact RBAC DDL that stands up the tenants and
    /// the roles/users/grants. Every statement runs as an admin auto-commit over the `graphus`
    /// database (admin DDL is database-agnostic and is rejected inside an explicit transaction).
    ///
    /// Order: databases → roles → role grants → users → user→role grants → per-tenant canary seed.
    /// `;`-terminated, one statement per line, so a loader can split on `;`.
    #[must_use]
    pub fn provision_cypher(&self) -> String {
        let m = &self.manifest;
        let mut s = String::with_capacity(1024);

        s.push_str("// databases (one isolated database per tenant — a hard isolation boundary)\n");
        for t in &m.tenants {
            let _ = writeln!(s, "CREATE DATABASE {} IF NOT EXISTS;", t.database);
        }

        s.push_str("// roles\n");
        for r in &m.roles {
            let _ = writeln!(s, "CREATE ROLE {} IF NOT EXISTS;", r.name);
        }

        s.push_str("// role grants (graded action over scope)\n");
        for r in &m.roles {
            let _ = writeln!(s, "GRANT {} ON {} TO {};", r.action, r.scope, r.name);
        }

        s.push_str("// users\n");
        for u in &m.users {
            let _ = writeln!(
                s,
                "CREATE USER {} SET PASSWORD '{}' IF NOT EXISTS;",
                u.name, u.password
            );
        }

        s.push_str("// user -> role\n");
        for u in &m.users {
            let _ = writeln!(s, "GRANT ROLE {} TO {};", u.role, u.name);
        }

        s
    }

    /// Renders one tenant's sensitive-data Cypher load script (run *inside* that tenant's database,
    /// as the admin). Order: canary `:Secret` → patients → records → `HAS_RECORD` edges. Every value
    /// is a literal so the file is self-contained and replayable.
    ///
    /// # Panics
    /// Panics if `db` does not name a tenant in the manifest (a generator-internal invariant).
    #[must_use]
    pub fn tenant_cypher(&self, db: &str) -> String {
        let t = self
            .manifest
            .tenants
            .iter()
            .find(|t| t.database == db)
            .expect("tenant exists in manifest");

        let mut s = String::with_capacity(t.records.len() * 96 + t.patients.len() * 96);
        let _ = writeln!(
            s,
            "// tenant {} — canary secret probed by the RBAC matrix",
            t.database
        );
        let _ = writeln!(s, "CREATE (:Secret {{name: '{}'}});", t.canary_secret);

        s.push_str("// patients (sensitive PII)\n");
        for p in &t.patients {
            let _ = writeln!(
                s,
                "CREATE (:Patient {{id: {}, name: '{}', ssn: '{}', country: '{}'}});",
                p.id, p.name, p.ssn, p.country
            );
        }

        s.push_str("// records (sensitive)\n");
        for r in &t.records {
            let _ = writeln!(
                s,
                "CREATE (:Record {{id: {}, patient: {}, diagnosis: '{}', secret_token: '{}'}});",
                r.id, r.patient, r.diagnosis, r.secret_token
            );
        }

        s.push_str("// ownership\n");
        for r in &t.records {
            let _ = writeln!(
                s,
                "MATCH (p:Patient {{id: {pid}}}), (r:Record {{id: {rid}}}) CREATE (p)-[:HAS_RECORD]->(r);",
                pid = r.patient,
                rid = r.id
            );
        }
        s
    }

    /// Serializes the manifest as pretty JSON (deterministic key order via struct field order).
    ///
    /// # Errors
    /// Returns a `serde_json` error only if serialization fails (it cannot for this plain data).
    pub fn manifest_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.manifest)
    }

    /// Total patient + record + canary node count across all tenants (for the evidence sizing).
    #[must_use]
    pub fn node_count(&self) -> u64 {
        self.manifest
            .tenants
            .iter()
            .map(|t| 1 + t.patients.len() as u64 + t.records.len() as u64)
            .sum()
    }

    /// Total `HAS_RECORD` edge count across all tenants.
    #[must_use]
    pub fn rel_count(&self) -> u64 {
        self.manifest
            .tenants
            .iter()
            .map(|t| t.records.len() as u64)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix_is_deterministic() {
        let mut a = SplitMix64::new(7);
        let mut b = SplitMix64::new(7);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn fast_profile_byte_identical_per_seed() {
        let cfg = Profile::Fast.config();
        let d1 = generate(cfg, "fast");
        let d2 = generate(cfg, "fast");
        assert_eq!(d1.provision_cypher(), d2.provision_cypher());
        assert_eq!(d1.tenant_cypher("tenant_a"), d2.tenant_cypher("tenant_a"));
        assert_eq!(d1.tenant_cypher("tenant_b"), d2.tenant_cypher("tenant_b"));
        assert_eq!(
            d1.manifest_json().unwrap(),
            d2.manifest_json().unwrap(),
            "manifest must be byte-identical"
        );
    }

    #[test]
    fn provisioning_contains_every_rbac_command() {
        let d = generate(Profile::Fast.config(), "fast");
        let p = d.provision_cypher();
        assert!(p.contains("CREATE DATABASE tenant_a IF NOT EXISTS;"));
        assert!(p.contains("CREATE DATABASE tenant_b IF NOT EXISTS;"));
        assert!(p.contains("CREATE ROLE reader_a IF NOT EXISTS;"));
        assert!(p.contains("GRANT READ ON GRAPH tenant_a TO reader_a;"));
        assert!(p.contains("GRANT WRITE ON GRAPH tenant_a TO writer_a;"));
        assert!(p.contains("GRANT READ ON DATABASE TO analyst;"));
        assert!(p.contains("CREATE USER alice SET PASSWORD 'alice-secret-pw' IF NOT EXISTS;"));
        assert!(p.contains("GRANT ROLE reader_a TO alice;"));
    }

    #[test]
    fn canary_secret_and_sensitive_token_are_present_per_tenant() {
        let d = generate(Profile::Fast.config(), "fast");
        let a = d.tenant_cypher("tenant_a");
        let b = d.tenant_cypher("tenant_b");
        assert!(a.contains("CREATE (:Secret {name: 'A_SECRET'});"));
        assert!(b.contains("CREATE (:Secret {name: 'B_SECRET'});"));
        // The canary sensitive token (the ciphertext-on-disk probe) is present in tenant_a's data.
        assert!(a.contains("TENANT_A_SECRET_TOKEN"));
        assert!(b.contains("TENANT_B_SECRET_TOKEN"));
        // tenant_a's token must NOT appear in tenant_b's data (isolation in the generated artifacts).
        assert!(!b.contains("TENANT_A_SECRET_TOKEN"));
    }

    #[test]
    fn matrix_covers_allow_deny_unauth_across_tenants() {
        let d = generate(Profile::Fast.config(), "fast");
        let m = &d.manifest.matrix;
        // Every expected outcome variant appears.
        assert!(m.iter().any(|c| c.outcome == Outcome::Allow));
        assert!(m.iter().any(|c| c.outcome == Outcome::Deny));
        assert!(m.iter().any(|c| c.outcome == Outcome::Unauthenticated));

        // The hard cross-tenant denial: alice (reader_a) reading tenant_b must be Deny.
        let cross = m
            .iter()
            .find(|c| {
                c.user.as_deref() == Some("alice")
                    && c.tenant == "tenant_b"
                    && c.access_mode == "READ"
            })
            .expect("cross-tenant cell exists");
        assert_eq!(cross.outcome, Outcome::Deny);

        // write ⊇ read: wendy READ tenant_a must be Allow.
        let wr = m
            .iter()
            .find(|c| {
                c.user.as_deref() == Some("wendy")
                    && c.tenant == "tenant_a"
                    && c.access_mode == "READ"
            })
            .expect("wendy read cell exists");
        assert_eq!(wr.outcome, Outcome::Allow);

        // analyst server-wide read: ana READ tenant_b must be Allow.
        let an = m
            .iter()
            .find(|c| {
                c.user.as_deref() == Some("ana")
                    && c.tenant == "tenant_b"
                    && c.access_mode == "READ"
            })
            .expect("ana read tenant_b cell exists");
        assert_eq!(an.outcome, Outcome::Allow);
    }

    #[test]
    fn different_profiles_differ_in_volume_but_share_the_matrix() {
        let fast = generate(Profile::Fast.config(), "fast");
        let large = generate(Profile::Large.config(), "large");
        assert!(large.node_count() > fast.node_count());
        // The RBAC matrix is identical regardless of data volume.
        assert_eq!(fast.manifest.matrix, large.manifest.matrix);
        assert_eq!(fast.manifest.roles, large.manifest.roles);
        assert_eq!(fast.manifest.users, large.manifest.users);
    }
}
