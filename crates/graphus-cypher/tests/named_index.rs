//! Named node-property indexes end to end at the coordinator layer (`rmp` tasks #623/#624): explicit
//! names, `DROP INDEX <name>`, global name uniqueness across every schema catalog, `IF NOT EXISTS` /
//! `IF EXISTS` idempotency, deterministic auto-naming, and the legacy-anonymous-index migration that
//! backfills a stable auto-name on open.

use graphus_core::TxnId;
use graphus_cypher::coordinator::{TxnCoordinator, auto_index_name};
use graphus_index::fulltext::Analyzer;
use graphus_io::MemBlockDevice;
use graphus_storage::recovery::recover_device;
use graphus_storage::{IndexState, Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

fn fresh_coord() -> Coord {
    TxnCoordinator::new(fresh_store())
}

/// Recovers a no-force crash (mirrors `tests/online_index_build.rs::recover_no_force`).
fn recover_no_force(store: &Store) -> Store {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open store")
}

/// The names in `SHOW INDEXES`, sorted.
fn listed_names(coord: &Coord) -> Vec<String> {
    let mut names: Vec<String> = coord
        .list_node_property_indexes()
        .into_iter()
        .map(|(name, _, _, _)| name)
        .collect();
    names.sort();
    names
}

// =================================================================================================
// Auto-name policy (pure)
// =================================================================================================

#[test]
fn auto_index_name_is_deterministic_and_sanitizes() {
    assert_eq!(auto_index_name("Person", "age"), "index_Person_age");
    // Non-identifier characters (`-`, `.`, space) map to `_`.
    assert_eq!(
        auto_index_name("Sales-Rep", "first.name"),
        "index_Sales_Rep_first_name"
    );
    assert_eq!(auto_index_name("A B", "c/d"), "index_A_B_c_d");
    // Pure: same inputs → same output.
    assert_eq!(auto_index_name("X", "y"), auto_index_name("X", "y"));
}

// =================================================================================================
// Named create + drop-by-name
// =================================================================================================

#[test]
fn named_create_records_name_and_drop_by_name_removes_it() {
    let mut coord = fresh_coord();
    coord
        .begin_online_node_property_index_named(Some("ix_person"), "Person", "name", false)
        .expect("named create");
    assert_eq!(listed_names(&coord), vec!["ix_person".to_owned()]);

    // Drop by name removes it.
    coord
        .drop_node_property_index_by_name("ix_person", false)
        .expect("drop by name");
    assert!(coord.list_node_property_indexes().is_empty());
}

#[test]
fn create_and_drop_report_whether_they_mutated() {
    // `rmp` #626 follow-up: the return flag drives the Neo4j-conformant `indexes-added`/`-removed`
    // counters — a real create/drop is `true`, an idempotent no-op is `false`.
    let mut coord = fresh_coord();

    // First create actually creates → true.
    assert!(
        coord
            .begin_online_node_property_index_named(Some("ix"), "Person", "age", true)
            .expect("create"),
        "the first create mutated the schema"
    );
    // Second create IF NOT EXISTS is a no-op → false (0 indexes-added).
    assert!(
        !coord
            .begin_online_node_property_index_named(Some("ix"), "Person", "age", true)
            .expect("idempotent create"),
        "the IF NOT EXISTS re-create is a no-op"
    );

    // Real drop by name → true; a second IF EXISTS drop of the now-missing index → false (0 removed).
    assert!(
        coord
            .drop_node_property_index_by_name("ix", true)
            .expect("drop"),
        "the drop removed the index"
    );
    assert!(
        !coord
            .drop_node_property_index_by_name("ix", true)
            .expect("idempotent drop"),
        "the IF EXISTS drop of a missing index is a no-op"
    );

    // A by-target drop of a never-declared index is likewise a no-op → false.
    assert!(
        !coord
            .drop_node_property_index("Ghost", "nope")
            .expect("no-op by-target drop"),
        "dropping a never-declared index by target is a no-op"
    );
}

#[test]
fn omitted_name_gets_the_deterministic_auto_name() {
    let mut coord = fresh_coord();
    coord
        .begin_online_node_property_index_named(None, "Person", "age", false)
        .expect("anonymous create");
    assert_eq!(listed_names(&coord), vec!["index_Person_age".to_owned()]);
}

// =================================================================================================
// Global name uniqueness
// =================================================================================================

#[test]
fn duplicate_name_on_a_different_target_is_rejected_unless_if_not_exists() {
    let mut coord = fresh_coord();
    coord
        .begin_online_node_property_index_named(Some("shared"), "Person", "age", false)
        .expect("first create");

    // A second, *different* index reusing the name is rejected (IndexWithNameAlreadyExists).
    let err = coord
        .begin_online_node_property_index_named(Some("shared"), "Company", "founded", false)
        .expect_err("duplicate name must be rejected");
    assert!(
        err.to_string().contains("IndexWithNameAlreadyExists"),
        "expected the name-collision schema class, got: {err}"
    );

    // Under IF NOT EXISTS the duplicate name is a no-op success (no new index created).
    coord
        .begin_online_node_property_index_named(Some("shared"), "Company", "founded", true)
        .expect("IF NOT EXISTS name collision is a no-op");
    assert_eq!(listed_names(&coord), vec!["shared".to_owned()]);
}

#[test]
fn equivalent_index_on_same_target_is_rejected_unless_if_not_exists() {
    let mut coord = fresh_coord();
    coord
        .begin_online_node_property_index_named(Some("a"), "Person", "age", false)
        .expect("first create");

    // A second index on the SAME (label, property) — even under a different name — is an equivalent
    // schema rule (EquivalentSchemaRuleAlreadyExists).
    let err = coord
        .begin_online_node_property_index_named(Some("b"), "Person", "age", false)
        .expect_err("equivalent index must be rejected");
    assert!(
        err.to_string()
            .contains("EquivalentSchemaRuleAlreadyExists"),
        "expected the equivalent-rule schema class, got: {err}"
    );

    // Under IF NOT EXISTS it is a no-op success; the original (name `a`) is untouched.
    coord
        .begin_online_node_property_index_named(Some("b"), "Person", "age", true)
        .expect("IF NOT EXISTS equivalent index is a no-op");
    assert_eq!(listed_names(&coord), vec!["a".to_owned()]);
}

#[test]
fn a_name_is_unique_across_catalogs() {
    // A full-text index and a node-property index cannot share a name (either declaration order).
    let mut coord = fresh_coord();
    coord
        .create_fulltext_index("shared", "Doc", &["body".to_owned()], Analyzer::Standard)
        .expect("fulltext create");
    let err = coord
        .begin_online_node_property_index_named(Some("shared"), "Person", "name", false)
        .expect_err("node-property name collides with a full-text index");
    assert!(
        err.to_string().contains("IndexWithNameAlreadyExists"),
        "got: {err}"
    );

    // The reverse: a full-text create colliding with an existing node-property index name.
    let mut coord = fresh_coord();
    coord
        .begin_online_node_property_index_named(Some("np"), "Person", "name", false)
        .expect("node-property create");
    let err = coord
        .create_fulltext_index("np", "Doc", &["body".to_owned()], Analyzer::Standard)
        .expect_err("full-text name collides with a node-property index");
    assert!(
        err.to_string().contains("IndexWithNameAlreadyExists"),
        "got: {err}"
    );
}

// =================================================================================================
// DROP INDEX <name> [IF EXISTS]
// =================================================================================================

#[test]
fn drop_by_name_missing_is_an_error_without_if_exists_and_a_noop_with_it() {
    let mut coord = fresh_coord();
    // Missing name, no IF EXISTS → IndexDropFailed.
    let err = coord
        .drop_node_property_index_by_name("nope", false)
        .expect_err("dropping a missing index must fail without IF EXISTS");
    assert!(err.to_string().contains("IndexDropFailed"), "got: {err}");
    // Missing name, IF EXISTS → clean no-op success.
    coord
        .drop_node_property_index_by_name("nope", true)
        .expect("IF EXISTS drop of a missing index is a no-op");
}

// =================================================================================================
// Legacy anonymous-index migration (backfill a stable auto-name on open)
// =================================================================================================

/// Builds a store that declares a node-property index the **legacy** way — a durable index-catalog
/// entry with **no** name — exactly the state a pre-#623 image recovers to.
fn store_with_legacy_anonymous_index() -> Store {
    let mut store = fresh_store();
    let txn = TxnId(1);
    store.begin(txn);
    let lt = store
        .intern_token(Namespace::Label, "Person")
        .expect("intern label");
    let pk = store
        .intern_token(Namespace::PropKey, "age")
        .expect("intern prop");
    store.set_node_property_index(lt, pk, IndexState::Online);
    // Deliberately NO set_node_property_index_name — this is the legacy anonymous shape.
    store.commit(txn).expect("commit legacy index");
    store
}

#[test]
fn legacy_anonymous_index_is_backfilled_with_a_stable_auto_name_on_open() {
    let store = store_with_legacy_anonymous_index();
    // Opening a coordinator backfills the auto-name.
    let coord = TxnCoordinator::new(store);
    assert_eq!(
        listed_names(&coord),
        vec!["index_Person_age".to_owned()],
        "the legacy anonymous index is named on open"
    );

    // The name is durable: recover the store and reopen; the name must survive (read back, not lost).
    let store = coord.into_store();
    let recovered = recover_no_force(&store);
    let coord = TxnCoordinator::new(recovered);
    assert_eq!(
        listed_names(&coord),
        vec!["index_Person_age".to_owned()],
        "the backfilled name is stable across a crash/restart"
    );
    // And it is droppable by that auto-name.
    let mut coord = coord;
    coord
        .drop_node_property_index_by_name("index_Person_age", false)
        .expect("drop the backfilled index by its auto-name");
    assert!(coord.list_node_property_indexes().is_empty());
}

// =================================================================================================
// Durability audit regressions (`rmp` #624): colliding auto-name bases must never (a) give one target
// two names — an image `decode_index_name_catalog` rejects (a NON-reopenable store) — nor (c) let a
// nameless CREATE steal an existing explicit name.
// =================================================================================================

/// (a)+(b): two DISTINCT targets whose auto-name bases collide (`index_A_b_c`), then drop the first and
/// **re-create** the second via the idempotent positional API. The second target must keep exactly ONE
/// name, and the resulting `Statistics` image must **reopen** (round-trip decode) rather than being
/// rejected as a duplicate target. This is the exact HIGH sequence the audit flagged.
#[test]
fn colliding_auto_name_rebuild_keeps_one_name_per_target_and_reopens() {
    let mut coord = fresh_coord();
    // `index_A_b_c` is the base of BOTH: sanitize("A")+"_"+sanitize("b_c") == sanitize("A_b")+"_"+sanitize("c").
    assert_eq!(auto_index_name("A", "b_c"), auto_index_name("A_b", "c"));

    coord
        .create_node_property_index("A", "b_c") // T1 → base `index_A_b_c`
        .expect("create T1");
    coord
        .create_node_property_index("A_b", "c") // T2 → base collides → token-suffixed name
        .expect("create T2");
    // Drop T1, freeing the base name `index_A_b_c`.
    assert!(
        coord.drop_node_property_index("A", "b_c").expect("drop T1"),
        "T1 was actually removed"
    );
    // Re-create T2 (positional API is idempotent): the base is now free. T2 must NOT end up with two
    // names — the setter re-points its single name.
    coord
        .create_node_property_index("A_b", "c")
        .expect("re-create T2");

    // (a) exactly one declared index (T2), with exactly one name → no two names for one target.
    let store = coord.into_store();
    let stats = store.statistics();
    let names = stats.node_property_index_names();
    assert_eq!(names.len(), 1, "T2 has exactly one name: {names:?}");
    let mut targets: Vec<(u32, u32)> = names.iter().map(|(_, lt, pk)| (*lt, *pk)).collect();
    let before = targets.len();
    targets.sort_unstable();
    targets.dedup();
    assert_eq!(targets.len(), before, "no target carries two names");

    // (b) the resulting image REOPENS: a full encode→decode round-trip is accepted (not rejected as a
    // duplicate target), and re-opening the real store succeeds.
    let decoded = graphus_storage::Statistics::decode(&stats.encode())
        .expect("the resulting image must reopen (not be rejected as a duplicate target)");
    assert_eq!(&decoded, stats);
    let recovered = recover_no_force(&store);
    let coord = TxnCoordinator::new(recovered); // panics via `open`'s decode if the image were invalid.
    assert_eq!(
        coord.list_node_property_indexes().len(),
        1,
        "the reopened store has T2's single named index"
    );
}

/// (c): a nameless `CREATE INDEX` must never steal an existing explicit name. An index is explicitly
/// named exactly like another target's auto-name **base**; the nameless create on that other target
/// finds the base taken and must fall back to a deterministic, free token-suffixed name — leaving the
/// explicit index's name pointing at its ORIGINAL index.
#[test]
fn anonymous_create_never_steals_an_existing_explicit_name() {
    let mut coord = fresh_coord();
    // Explicitly name an index `index_A_b_c` — which is ALSO the auto-name base of (A, b_c).
    coord
        .begin_online_node_property_index_named(Some("index_A_b_c"), "Person", "email", false)
        .expect("explicit victim index");
    // A nameless create on (A, b_c): its base `index_A_b_c` is taken by the victim, so it must take a
    // different (token-suffixed) name — NOT overwrite the victim's name.
    coord
        .begin_online_node_property_index_named(None, "A", "b_c", false)
        .expect("anonymous create");

    let listed = coord.list_node_property_indexes();
    // The explicit name still points at its ORIGINAL index (Person, email).
    let victim = listed
        .iter()
        .find(|(n, _, _, _)| n == "index_A_b_c")
        .expect("the explicit name is still present");
    assert_eq!(
        (victim.1.as_str(), victim.2.as_str()),
        ("Person", "email"),
        "the explicit name still points at its original index (not stolen)"
    );
    // The anonymous index on (A, b_c) got a different, deterministic token-suffixed name.
    let anon = listed
        .iter()
        .find(|(_, l, p, _)| l == "A" && p == "b_c")
        .expect("the anonymous index is listed");
    assert_ne!(
        anon.0, "index_A_b_c",
        "the anonymous create did not steal the explicit name"
    );
    assert!(
        anon.0.starts_with("index_A_b_c_"),
        "it got a deterministic token-suffixed auto-name, got {:?}",
        anon.0
    );
}
