//! Determinism guard: the generator MUST produce byte-identical artifacts for a given profile
//! (the security-multitenant example's acceptance criterion). This is the regression gate for the
//! "BYTE-IDENTICAL provisioning + per-tenant data + manifest for a given seed/profile" requirement.

use graphus_security_gen::{GenConfig, Profile, TENANTS, generate};

/// Both profiles emit byte-identical provisioning + per-tenant Cypher + manifest JSON across runs.
#[test]
fn profiles_are_byte_identical_across_runs() {
    for profile in [Profile::Fast, Profile::Large] {
        let cfg = profile.config();
        let a = generate(cfg, profile.name());
        let b = generate(cfg, profile.name());

        assert_eq!(
            a.provision_cypher(),
            b.provision_cypher(),
            "{} profile: provision.cypher diverged between runs",
            profile.name()
        );
        for &db in &TENANTS {
            assert_eq!(
                a.tenant_cypher(db),
                b.tenant_cypher(db),
                "{} profile: tenant_{db}.cypher diverged between runs",
                profile.name()
            );
        }
        assert_eq!(
            a.manifest_json().unwrap(),
            b.manifest_json().unwrap(),
            "{} profile: manifest.json diverged between runs",
            profile.name()
        );
    }
}

/// A custom config also reproduces byte-for-byte (the determinism is in `generate`, not just the
/// two named profiles).
#[test]
fn custom_config_is_byte_identical() {
    let cfg = GenConfig {
        seed: 0xC0FF_EE00_0000_0001,
        patients_per_tenant: 17,
        records_per_patient_max: 2,
    };
    let a = generate(cfg, "custom");
    let b = generate(cfg, "custom");
    assert_eq!(a.provision_cypher(), b.provision_cypher());
    assert_eq!(a.tenant_cypher("tenant_a"), b.tenant_cypher("tenant_a"));
    assert_eq!(a.tenant_cypher("tenant_b"), b.tenant_cypher("tenant_b"));
    assert_eq!(a.manifest_json().unwrap(), b.manifest_json().unwrap());
}

/// Changing the seed changes the per-tenant PII (the seed is actually load-bearing) while leaving
/// the RBAC matrix fixed (authorization is structural, not seeded).
#[test]
fn seed_changes_data_not_matrix() {
    let mut cfg = Profile::Fast.config();
    let a = generate(cfg, "fast");
    cfg.seed ^= 0xFFFF_FFFF;
    let b = generate(cfg, "fast");
    assert_ne!(
        a.tenant_cypher("tenant_a"),
        b.tenant_cypher("tenant_a"),
        "a different seed must change the patient PII (SSNs/countries)"
    );
    assert!(a.manifest_json().unwrap().contains("\"matrix\""));
    assert_eq!(
        a.manifest.matrix, b.manifest.matrix,
        "the RBAC matrix is structural and must not depend on the seed"
    );
}
