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

use graphus_security_gen::{Profile, TENANTS, generate};

fn main() -> ExitCode {
    let mut profile = Profile::Fast;
    let mut out_dir = PathBuf::from(".");

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
            "-h" | "--help" => {
                eprintln!(
                    "usage: security_gen --profile <fast|large> --out-dir <dir>\n\
                     writes provision.cypher + tenant_<name>.cypher + manifest.json"
                );
                return ExitCode::SUCCESS;
            }
            other => return fail(&format!("unexpected argument '{other}'")),
        }
    }

    let cfg = profile.config();
    let dataset = generate(cfg, profile.name());

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
    for &db in &TENANTS {
        let path = out_dir.join(format!(
            "tenant_{}.cypher",
            db.trim_start_matches("tenant_")
        ));
        if let Err(e) = std::fs::write(&path, dataset.tenant_cypher(db)) {
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
    for &db in &TENANTS {
        println!(
            "wrote {}",
            out_dir
                .join(format!(
                    "tenant_{}.cypher",
                    db.trim_start_matches("tenant_")
                ))
                .display()
        );
    }
    println!("wrote {}", manifest_path.display());

    ExitCode::SUCCESS
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("security_gen: error: {msg}");
    ExitCode::FAILURE
}
