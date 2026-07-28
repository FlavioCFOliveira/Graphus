//! Regression test for `rmp` #517 (KG finding `bulk-idmap-not-abort-safe`).
//!
//! The `BulkImporter`'s external-id → physical-id map (`id_map`) used to be written to directly by
//! [`BulkImporter::import_nodes`] *before* the owning batch's transaction committed, and was never
//! reverted on [`BulkImporter::import_nodes`]'s internal rollback path. That was harmless while the
//! only recovery story was "delete `--db` and re-run the whole file" (`rmp` #403), because a fresh
//! run always starts from a fresh, empty `id_map`. It becomes a correctness hazard for the planned
//! network bulk-import's automatic per-batch retry (`specification/08-network-bulk-import.md`
//! §7.2.2): if a batch aborts and the *same rows* are retried against the *same* `BulkImporter`
//! instance, a stale `id_map` binding pointed at a physical node id the store had already rolled
//! back — a ghost reference that either fails a legitimate retry with a spurious "duplicate :ID"
//! error (strict policy) or, worse, silently resolves a relationship onto whatever node later comes
//! to occupy that rolled-back id.
//!
//! The fix stages every batch's `id_map` bindings (and its `ImportStats` row counters) and only
//! confirms them once the batch's transaction durably commits; a rollback discards the staged state,
//! so a retried batch starts from exactly the same `id_map` a first attempt would have seen.

use std::collections::{BTreeSet, HashMap};

use graphus_bulk::BulkImporter;
use graphus_core::Value;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// A fresh, empty in-memory record store.
fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("wal create");
    RecordStore::create(device, wal, 256, 1).expect("store create")
}

/// Every live node's `name` string property, keyed by its physical id.
fn node_names(store: &mut Store) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    for id in store.scan_node_ids().expect("scan nodes") {
        let props = store
            .superset_scan_node_property_values(id)
            .expect("node props");
        if let Some(name) = props.iter().find_map(|(_, _tok, v)| match v {
            Value::String(s) => Some(s.clone()),
            _ => None,
        }) {
            out.insert(id, name);
        }
    }
    out
}

/// The `(name, age)` pair of every live node, as an order-independent set — a content fingerprint of
/// the graph's node set that does not depend on the physical ids a particular run happened to hand
/// out.
fn node_name_age_set(store: &mut Store) -> BTreeSet<(String, i64)> {
    let mut out = BTreeSet::new();
    for id in store.scan_node_ids().expect("scan nodes") {
        let props = store
            .superset_scan_node_property_values(id)
            .expect("node props");
        let name = props.iter().find_map(|(_, _tok, v)| match v {
            Value::String(s) => Some(s.clone()),
            _ => None,
        });
        let age = props.iter().find_map(|(_, _tok, v)| match v {
            Value::Integer(n) => Some(*n),
            _ => None,
        });
        if let (Some(name), Some(age)) = (name, age) {
            out.insert((name, age));
        }
    }
    out
}

/// A node CSV batch of three rows (`a`/`b`/`c`), with `c`'s `age` cell either valid (`doomed =
/// false`) or malformed (`doomed = true`, forcing the whole in-flight batch to roll back).
fn node_batch(doomed: bool) -> String {
    let c_age = if doomed { "not-a-number" } else { "40" };
    format!(
        "id:ID,:LABEL,name:string,age:int\n\
         a,Person,Alice,30\n\
         b,Person,Bob,25\n\
         c,Person,Carol,{c_age}\n"
    )
}

const KNOWS_REL: &str = ":START_ID,:END_ID,:TYPE\na,b,KNOWS\n";

// -------------------------------------------------------------------------------------------------
// rmp #517 — a retried batch must not resolve relationships to ghost ids, nor double-count stats.
// -------------------------------------------------------------------------------------------------

/// Regression: rmp #517. A 3-row node batch aborts mid-way (a malformed `:int` cell on the last row
/// rolls back the whole still-open batch, undoing the first two rows' node creations too). Retrying
/// the exact same batch (now valid) on the *same* importer must succeed cleanly — no spurious
/// "duplicate :ID" error — and a subsequent relationship import must join the retried batch's *live*
/// nodes, never a ghost id the store already rolled back.
#[test]
fn retried_batch_after_abort_resolves_relationships_to_live_nodes_not_ghosts() {
    // Regression: rmp #517 (bulk-idmap-not-abort-safe)
    let batch_size = 3usize; // the whole 3-row batch is one transaction.
    let mut importer = BulkImporter::new(fresh_store(), batch_size, b',');

    // First attempt: "a" and "b" ingest fine inside the still-open batch, but "c"'s malformed `:int`
    // cell fails the row, rolling back the whole batch (including "a" and "b"). Before the #517 fix
    // this left `id_map` bound to "a"/"b"'s now-rolled-back physical node ids.
    importer
        .import_nodes(node_batch(true).as_bytes())
        .expect_err("the malformed :int cell must abort the still-open batch");
    assert_eq!(
        importer.stats().nodes,
        0,
        "an aborted batch must not leave any row counted in ImportStats"
    );

    // Retry the identical batch, now fully valid — modelling a network bulk-import's automatic retry
    // of an aborted batch against the same importer/id_map. Before the fix this call itself failed
    // with a spurious "duplicate :ID x" error, because `id_map` still had "a" bound to the rolled-back
    // physical id from the first attempt.
    importer
        .import_nodes(node_batch(false).as_bytes())
        .expect("the retried batch must succeed with no leftover ghost id_map bindings");
    assert_eq!(
        importer.stats().nodes,
        3,
        "the aborted attempt's rows must not be double-counted alongside the successful retry"
    );

    // A relationship import joining on the retried external ids must resolve to the live nodes the
    // successful retry created — not error, and not silently join onto whatever node now occupies a
    // rolled-back physical id.
    importer
        .import_relationships(KNOWS_REL.as_bytes())
        .expect("the relationship must resolve against the retried, live node ids");
    assert_eq!(importer.stats().relationships, 1);

    let (mut store, _stats) = importer.finish();

    let node_ids = store.scan_node_ids().expect("scan nodes");
    assert_eq!(
        node_ids.len(),
        3,
        "exactly 3 live nodes: no orphaned ghost slots and no duplicates left behind"
    );

    let rel_ids = store.scan_rel_ids().expect("scan rels");
    assert_eq!(rel_ids.len(), 1, "exactly one relationship exists");
    let rec = store.rel(rel_ids[0]).expect("rel record");

    let names = node_names(&mut store);
    assert_eq!(
        names.get(&rec.start_node).map(String::as_str),
        Some("Alice"),
        "the relationship must start at the retried Alice node, not a ghost reference"
    );
    assert_eq!(
        names.get(&rec.end_node).map(String::as_str),
        Some("Bob"),
        "the relationship must end at the retried Bob node, not a ghost reference"
    );
}

/// Regression: rmp #517. The graph produced by an abort-then-retry sequence must be indistinguishable
/// (same node/relationship counts, same node content, same edge) from a clean import of the same data
/// that never hit an error and never retried.
#[test]
fn abort_then_retry_yields_the_same_final_graph_as_a_clean_first_try() {
    // Regression: rmp #517 (bulk-idmap-not-abort-safe)

    // Baseline: a single successful attempt, no induced failure, no retry.
    let mut baseline = BulkImporter::new(fresh_store(), 3, b',');
    baseline
        .import_nodes(node_batch(false).as_bytes())
        .expect("baseline import");
    baseline
        .import_relationships(KNOWS_REL.as_bytes())
        .expect("baseline relationship import");
    let baseline_stats = baseline.stats();
    let (mut baseline_store, _) = baseline.finish();
    let baseline_nodes = baseline_store.scan_node_ids().expect("scan nodes").len();
    let baseline_rels = baseline_store.scan_rel_ids().expect("scan rels").len();
    let baseline_content = node_name_age_set(&mut baseline_store);

    // Subject: the batch aborts once, is retried, then the same relationship import runs.
    let mut subject = BulkImporter::new(fresh_store(), 3, b',');
    subject
        .import_nodes(node_batch(true).as_bytes())
        .expect_err("induced failure");
    subject
        .import_nodes(node_batch(false).as_bytes())
        .expect("retried import");
    subject
        .import_relationships(KNOWS_REL.as_bytes())
        .expect("subject relationship import");
    let subject_stats = subject.stats();
    let (mut subject_store, _) = subject.finish();
    let subject_nodes = subject_store.scan_node_ids().expect("scan nodes").len();
    let subject_rels = subject_store.scan_rel_ids().expect("scan rels").len();
    let subject_content = node_name_age_set(&mut subject_store);

    assert_eq!(
        subject_nodes, baseline_nodes,
        "abort+retry must produce the same node count as a clean first try"
    );
    assert_eq!(
        subject_rels, baseline_rels,
        "abort+retry must produce the same relationship count as a clean first try"
    );
    assert_eq!(
        subject_content, baseline_content,
        "abort+retry must produce the exact same (name, age) node content as a clean first try"
    );
    assert_eq!(
        (subject_stats.nodes, subject_stats.relationships),
        (baseline_stats.nodes, baseline_stats.relationships),
        "ImportStats counters must match between an abort+retry run and a clean first-try run"
    );
}

/// Regression: rmp #517. A duplicate `:ID` check must still correctly fire for a *genuine* duplicate
/// across two different, both-committed batches — the fix (staging bindings per batch) must not
/// weaken SEC-196 (CWE-694) duplicate detection once bindings are confirmed.
#[test]
fn genuine_cross_batch_duplicate_is_still_rejected_after_the_fix() {
    // Regression: rmp #517 / SEC-196 interaction check.
    let mut importer = BulkImporter::new(fresh_store(), 1, b',');
    importer
        .import_nodes("id:ID,:LABEL\nx,A\n".as_bytes())
        .expect("first batch commits and confirms the binding for \"x\"");
    let err = importer
        .import_nodes("id:ID,:LABEL\nx,B\n".as_bytes())
        .expect_err(
            "a genuine duplicate against an already-committed batch must still be rejected",
        );
    assert!(
        err.to_string().contains("duplicate :ID") && err.to_string().contains("\"x\""),
        "the error must still name the duplicate external id: {err}"
    );
}
