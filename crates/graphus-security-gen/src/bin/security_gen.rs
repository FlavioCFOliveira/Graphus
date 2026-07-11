//! `security_gen` — the deterministic multi-tenant sensitive-data generator for
//! `examples/security-multitenant`.
//!
//! Writes, into `--out-dir` for the chosen `--profile`:
//! - `provision.cypher` — the admin RBAC DDL (`CREATE DATABASE / ROLE / USER` + `GRANT`s),
//! - `tenant_<name>.cypher` — one per tenant: the canary `:Secret` + the sensitive patient/record
//!   PII (run inside that tenant's database as admin),
//! - `manifest.json` — the tenants, users (with passwords), roles, grants and the expected
//!   allow/deny/unauthenticated matrix the workloads drive and assert from.
//!
//! Output is a pure function of `(profile)` (each profile pins its own seed), so re-running yields
//! byte-identical files. Hermetic: serde only, no engine, no crypto, no network.
//!
//! Usage:
//!   cargo run -p graphus-security-gen --bin security_gen -- --profile fast  --out-dir <dir>
//!   cargo run -p graphus-security-gen --bin security_gen -- --profile large --out-dir <dir>

use std::path::PathBuf;
use std::process::ExitCode;

use graphus_security_gen::{Profile, generate_namespaced};

fn main() -> ExitCode {
    let mut profile = Profile::Fast;
    let mut out_dir = PathBuf::from(".");
    let mut namespace = String::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" => {
                let v = match args.next() {
                    Some(v) => v,
                    None => return fail("--profile requires a value (fast|large)"),
                };
                profile = match Profile::parse(&v) {
                    Ok(p) => p,
                    Err(e) => return fail(&e),
                };
            }
            "--out-dir" => {
                out_dir = match args.next() {
                    Some(v) => PathBuf::from(v),
                    None => return fail("--out-dir requires a value"),
                };
            }
            // Prefix every tenant-database / role / user name with <ns> (for a SHARED external target:
            // isolated, collision-free provisioning that is torn down unambiguously). Default: none.
            "--namespace" => {
                namespace = match args.next() {
                    Some(v) => v,
                    None => return fail("--namespace requires a value"),
                };
            }
            "-h" | "--help" => {
                eprintln!(
                    "usage: security_gen --profile <fast|large> --out-dir <dir> [--namespace <ns>]\n\
                     writes provision.cypher + deny.cypher + teardown.cypher + tenant_<name>.cypher \
                     + manifest.json"
                );
                return ExitCode::SUCCESS;
            }
            other => return fail(&format!("unexpected argument '{other}'")),
        }
    }

    // A namespace must be a valid identifier fragment (it is prefixed onto database/role/user names).
    if !namespace.is_empty()
        && !namespace
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return fail(
            "--namespace must be lowercase [a-z0-9_] (it prefixes database/role/user names)",
        );
    }

    let cfg = profile.config();
    let dataset = generate_namespaced(cfg, profile.name(), &namespace);

    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        return fail(&format!("cannot create out-dir {}: {e}", out_dir.display()));
    }

    let manifest_json = match dataset.manifest_json() {
        Ok(j) => j,
        Err(e) => return fail(&format!("manifest serialization failed: {e}")),
    };

    let provision_path = out_dir.join("provision.cypher");
    if let Err(e) = std::fs::write(&provision_path, dataset.provision_cypher()) {
        return fail(&format!("cannot write {}: {e}", provision_path.display()));
    }
    let deny_path = out_dir.join("deny.cypher");
    if let Err(e) = std::fs::write(&deny_path, dataset.deny_cypher()) {
        return fail(&format!("cannot write {}: {e}", deny_path.display()));
    }
    let teardown_path = out_dir.join("teardown.cypher");
    if let Err(e) = std::fs::write(&teardown_path, dataset.teardown_cypher()) {
        return fail(&format!("cannot write {}: {e}", teardown_path.display()));
    }
    // One load script per tenant, named by the (possibly namespaced) database: `<database>.cypher`.
    // With no namespace this is the historical `tenant_a.cypher` / `tenant_b.cypher`.
    for t in &dataset.manifest.tenants {
        let path = out_dir.join(format!("{}.cypher", t.database));
        if let Err(e) = std::fs::write(&path, dataset.tenant_cypher(&t.database)) {
            return fail(&format!("cannot write {}: {e}", path.display()));
        }
    }
    let manifest_path = out_dir.join("manifest.json");
    if let Err(e) = std::fs::write(&manifest_path, manifest_json) {
        return fail(&format!("cannot write {}: {e}", manifest_path.display()));
    }

    let m = &dataset.manifest;
    println!(
        "generated profile={} seed={:#018x} tenants={} users={} roles={} grants={} \
         matrix_cells={} nodes={} rels={}",
        profile.name(),
        cfg.seed,
        m.tenants.len(),
        m.users.len(),
        m.roles.len(),
        m.roles.len() + m.users.len(),
        m.matrix.len(),
        dataset.node_count(),
        dataset.rel_count(),
    );
    println!("wrote {}", provision_path.display());
    println!("wrote {}", deny_path.display());
    println!("wrote {}", teardown_path.display());
    for t in &dataset.manifest.tenants {
        println!(
            "wrote {}",
            out_dir.join(format!("{}.cypher", t.database)).display()
        );
    }
    println!("wrote {}", manifest_path.display());

    ExitCode::SUCCESS
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("security_gen: error: {msg}");
    ExitCode::FAILURE
}
