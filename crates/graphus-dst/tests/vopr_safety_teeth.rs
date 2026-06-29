//! The VOPR **safety oracle bundle** must have teeth (rmp #239; mirrors `vopr_oracle_teeth.rs` and
//! `checker_teeth.rs`).
//!
//! Safety mode ([`graphus_dst::vopr::run_safety`]) runs the cooperative interleaver under the unified
//! fault + crash scheduler and asserts **four** inviolable ACID properties on the recovered state,
//! every run: serializability, durability, atomicity, and reference-model equivalence (see
//! [`graphus_dst::SafetyProperty`]). A safety oracle that always passes is worthless — this suite
//! proves each arm can fail when its property is violated, and that a faithful run is `safe`.
//!
//! The four run-level arms (durability / atomicity / reference-model) are exercised against fabricated
//! inputs inside the crate's unit tests (they need a synthetic `VoprReport` the private evaluator
//! consumes); here we exercise the **end-to-end real-engine** behaviour and the **serializability**
//! arm directly via the same [`graphus_elle::check`] the bundle uses.

use graphus_dst::vopr::{VoprConfig, run_safety, run_safety_cli};
use graphus_elle::{Op, Transaction, check};

/// A faithful safety run on a clean seed is `safe`: all four properties hold simultaneously while
/// faults and crashes fire during concurrent interleaved work, and the recorded history is
/// non-empty (the check is non-vacuous).
#[test]
fn safety_run_is_safe_on_a_clean_seed() {
    let r = run_safety(VoprConfig::safety(1));
    assert!(
        r.safe,
        "a clean seed must pass the four-property safety bundle: {:?}",
        r.violations
    );
    assert!(r.violations.is_empty());
    assert!(
        r.checked_txns > 0,
        "the safety check must rule on a non-empty recovered history (non-vacuous)"
    );
    // Non-vacuity: faults and crashes genuinely fired during this certified run.
    assert!(
        r.run.crash_restarts > 0,
        "the safety run must actually crash + recover"
    );
    assert!(
        r.run.disk_faults + r.run.clock_faults + r.run.transport_faults > 0,
        "the safety run must actually inject faults"
    );
}

/// Determinism: the same seed reproduces an identical [`graphus_dst::SafetyReport`] — verdict,
/// recorded-history length, violation list, and the full underlying run.
#[test]
fn safety_report_is_deterministic() {
    let cfg = VoprConfig::safety(2);
    assert_eq!(
        run_safety(cfg),
        run_safety(cfg),
        "same seed ⇒ identical safety report"
    );
}

/// **Teeth (serializability arm).** The bundle's serializability check is exactly
/// [`graphus_elle::check`] over the recorded append-only history. A deliberately non-serializable
/// history (classic write-skew: each txn reads the empty list then appends — a dependency cycle) must
/// be flagged. This is the same checker `run_safety` invokes, so a real recorded cycle would fail the
/// bundle identically.
#[test]
fn serializability_arm_catches_a_non_serializable_history() {
    let history = vec![
        Transaction::committed(
            1,
            vec![
                Op::Read {
                    key: "persons".into(),
                    observed: vec![],
                },
                Op::Append {
                    key: "persons".into(),
                    val: 1,
                },
            ],
        ),
        Transaction::committed(
            2,
            vec![
                Op::Read {
                    key: "persons".into(),
                    observed: vec![],
                },
                Op::Append {
                    key: "persons".into(),
                    val: 2,
                },
            ],
        ),
    ];
    let verdict = check(&history);
    assert!(
        !verdict.serializable,
        "the serializability checker must flag the write-skew cycle: {verdict:?}"
    );
    assert!(verdict.anomaly.unwrap().contains("cycle"));
}

/// **Teeth (serializability arm, recovery-corruption shape).** A history with the **same id committed
/// by two transactions** is an impossible version order (a create lost-then-duplicated across
/// recovery would produce exactly this). The checker flags it — proving the append-only safety history
/// catches recovery corruption, not just classic write-skew.
#[test]
fn serializability_arm_catches_a_duplicate_committed_id() {
    let history = vec![
        Transaction::committed(
            1,
            vec![Op::Append {
                key: "persons".into(),
                val: 7,
            }],
        ),
        Transaction::committed(
            2,
            vec![Op::Append {
                key: "persons".into(),
                val: 7,
            }],
        ),
    ];
    let verdict = check(&history);
    assert!(
        !verdict.serializable,
        "a duplicate committed id must fail the serializability arm: {verdict:?}"
    );
}

/// A faithful append-only history (unique, monotonic ids — exactly what the safety recorder builds for
/// a clean run) is serializable: no false positive.
#[test]
fn serializability_arm_passes_on_a_faithful_append_history() {
    let history: Vec<Transaction> = (0..8i64)
        .map(|id| {
            Transaction::committed(
                id as u64 + 1,
                vec![Op::Append {
                    key: "persons".into(),
                    val: id,
                }],
            )
        })
        .collect();
    assert!(
        check(&history).serializable,
        "a clean append-only history must be serializable"
    );
}

/// **Acceptance (seed sweep with faults+crashes firing, zero violations).** The safety CLI runs the
/// four-property bundle across a seed range under faults + crashes and reports zero violations. This is
/// the empirical proof the real engine upholds all four ACID safety properties simultaneously under
/// fault injection — the core correctness oracle. (A wider 1..=100 sweep was run during development;
/// this committed range stays fast in a debug build.)
#[test]
fn safety_cli_seed_sweep_reports_zero_violations() {
    let (out, violations) = run_safety_cli(
        ["--seed", "1", "--seeds", "30"]
            .into_iter()
            .map(String::from),
    );
    assert_eq!(
        violations, 0,
        "the safety CLI sweep must report zero violations under faults+crashes:\n{out}"
    );
    assert!(out.contains("all SAFE + deterministic"), "{out}");
}

/// **Regression — committed-data loss after an aborted boundary-crossing allocation (`rmp` #479).**
///
/// Seed 5043221 (safety preset: 6 clients × 24 ops, write-heavy, 8 faults + 2 crashes) used to leave a
/// block of EARLY committed `:Person` ids absent from the recovered store while later ids survived — a
/// silent ACID **durability** breach. Traced root cause:
///
/// 1. A `CREATE (a)-[:KNOWS]->(b)` allocated a relationship id that crossed a rel-store **page
///    boundary** (`alloc_id` advanced the high-water) and then `relink_old_head` surfaced a bit-rot
///    checksum error on the old head's page (an injected, *recoverable* disk fault) **before** the new
///    record's page was mapped at write time. That left the catalog inconsistent: rel `high_water` one
///    past the addressable capacity of its mapped `device_pages`.
/// 2. A later checkpoint persisted that inconsistent catalog; a still-later rollback's `reload_catalog`
///    then **rejected** it (`Meta::decode`, `rmp` #452).
/// 3. Because `rollback` had already `mem::take`-n every store's `device_pages` and the `?` on the
///    failed reload skipped the restore, the in-memory page maps were left EMPTY — so the next node
///    create mapped a fresh BLANK device page over a store whose committed records lived on the
///    now-orphaned original page. The early persons were silently destroyed.
///
/// Fixed by mapping a fresh id's page **at allocation time** (keeping `high_water <= capacity` always
/// true) and by making `rollback` exception-safe (restore the page maps if `reload_catalog` fails).
/// This pins the seed SAFE and, more strongly, asserts the engine queried back holds EVERY committed
/// `:Person` row (`persisted == created`, the no-lost-create probe) — the exact invariant that broke.
#[test]
fn safety_seed_5043221_no_committed_node_loss_under_fault_then_rollback() {
    let cfg = VoprConfig::safety(5043221);
    let r = run_safety(cfg);
    assert!(
        r.safe,
        "seed 5043221 must be SAFE (no committed-data loss under crash+disk-fault); violations: {:?}",
        r.violations
    );
    // Strong, interleaving-robust assertion of the durability invariant that broke: the recovered
    // store returns exactly as many `:Person` rows as were committed — none stranded/lost.
    assert_eq!(
        r.run.persisted_nodes, r.run.created_nodes,
        "every committed :Person create must survive (persisted {} != created {})",
        r.run.persisted_nodes, r.run.created_nodes
    );
    // Determinism: same seed ⇒ identical verdict.
    assert_eq!(r, run_safety(cfg), "seed 5043221 must be deterministic");
}
