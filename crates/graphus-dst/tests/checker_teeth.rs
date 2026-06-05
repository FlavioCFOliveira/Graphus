//! The corruption/durability checker must have teeth (task brief; mirrors
//! `graphus-txn/tests/serialization_checker.rs`).
//!
//! A checker that always passes is worse than none — it gives false confidence. This test feeds
//! [`graphus_dst::verify`] deliberately broken reference models against a *correct* recovered store
//! and asserts it reports the right [`CheckFailure`] every time, then confirms it passes on the
//! faithful model (no false positives).
//!
//! The store side is built and recovered through the real engine (commit → no-force recover →
//! reopen), so the checker is exercised against genuine recovered state, not a mock.

use graphus_core::TxnId;
use graphus_dst::{CheckFailure, Model, verify};
use graphus_io::MemBlockDevice;
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Builds a small committed graph, recovers it no-force, and returns the recovered store plus the
/// faithful model and the live ids of interest.
struct Fixture {
    store: Store,
    model: Model,
    node_a: u64,
    node_b: u64,
    rel_ab: u64,
    prop_key: u32,
}

fn build() -> Fixture {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).unwrap();
    let mut s: Store = RecordStore::create(device, wal, 32, 1).unwrap();

    let t = TxnId(1);
    s.begin(t);
    let rt = s.intern_token(Namespace::RelType, "E").unwrap();
    let pk = s.intern_token(Namespace::PropKey, "p").unwrap();
    let (a, _) = s.create_node(t).unwrap();
    let (b, _) = s.create_node(t).unwrap();
    let (r, _) = s.create_rel(t, rt, a, b).unwrap();
    s.add_node_property(t, a, pk, 2, 4242).unwrap();
    s.commit(t).unwrap();

    // No-force recovery onto a fresh device.
    let log = s.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().unwrap();
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).unwrap();
    recover_device(&mut wal, &mut device).unwrap();
    let wal = WalManager::open(sink).unwrap();
    let store = RecordStore::open(device, wal, 64).unwrap();

    // The faithful model.
    let mut model = Model::new();
    model.add_node(a);
    model.add_node(b);
    model.add_rel(r, a, b);
    model.add_node_prop(
        a,
        graphus_dst::model::PropTriple {
            key: pk,
            type_tag: 2,
            value_inline: 4242,
        },
    );

    Fixture {
        store,
        model,
        node_a: a,
        node_b: b,
        rel_ab: r,
        prop_key: pk,
    }
}

/// No false positives: the checker passes on the faithful model.
#[test]
fn checker_passes_on_faithful_model() {
    let mut f = build();
    assert_eq!(
        verify(&mut f.store, &f.model),
        Ok(()),
        "the checker must pass on a correct recovered state"
    );
}

/// Teeth: a model claiming a node that the store does not have is a lost commit.
#[test]
fn checker_catches_a_lost_node() {
    let mut f = build();
    // Claim a never-created node id far past the high-water; the store has no such record page.
    f.model.add_node(9999);
    let result = verify(&mut f.store, &f.model);
    assert!(
        matches!(
            result,
            Err(CheckFailure::LostNode { .. } | CheckFailure::StoreError { .. })
        ),
        "claiming a phantom node must fail the durability check, got {result:?}"
    );
}

/// Teeth: a model claiming an extra incident relationship must trip the incidence check.
#[test]
fn checker_catches_an_incidence_mismatch() {
    let mut f = build();
    // Add a phantom relationship incident to node_a that the store does not have on its chain.
    // Use a rel id the store does not map so it surfaces as a mismatch or a store error.
    f.model.add_rel(7777, f.node_a, f.node_b);
    let result = verify(&mut f.store, &f.model);
    assert!(
        matches!(
            result,
            Err(CheckFailure::IncidenceMismatch { .. }
                | CheckFailure::LostRel { .. }
                | CheckFailure::StoreError { .. })
        ),
        "a phantom incident rel must fail the integrity check, got {result:?}"
    );
}

/// Teeth: a model that forgets a committed relationship still passes durability for that rel (it is
/// absent from the model), but the *store's* incidence for the endpoints then exceeds the model —
/// the incidence check must catch the surplus.
#[test]
fn checker_catches_a_forgotten_committed_rel() {
    let mut f = build();
    // Drop the real relationship from the model's rel map AND its incidence, simulating a checker
    // that under-counts. The store still has rel_ab on a's and b's chains -> incidence mismatch.
    f.model.remove_rel(f.rel_ab);
    let result = verify(&mut f.store, &f.model);
    assert!(
        matches!(result, Err(CheckFailure::IncidenceMismatch { .. })),
        "the store's surplus edge must fail the integrity check, got {result:?}"
    );
}

/// Teeth: a model claiming a property the store does not hold must trip the property check.
#[test]
fn checker_catches_a_property_mismatch() {
    let mut f = build();
    f.model.add_node_prop(
        f.node_b, // node_b has no properties in the store
        graphus_dst::model::PropTriple {
            key: 1,
            type_tag: 2,
            value_inline: 1,
        },
    );
    let result = verify(&mut f.store, &f.model);
    assert!(
        matches!(result, Err(CheckFailure::PropMismatch { .. })),
        "a phantom property must fail the durability check, got {result:?}"
    );
}

/// Teeth: a model with the wrong endpoints for a committed relationship must trip the endpoint
/// check (the durability/integrity boundary). We rebuild the model with rel_ab pointing at a
/// non-existent endpoint.
#[test]
fn checker_catches_wrong_endpoints() {
    let mut f = build();
    // Rebuild a faithful model EXCEPT rel_ab claims endpoints (a, a) instead of (a, b), so the
    // failure isolates to the endpoint/incidence check rather than an unrelated property mismatch.
    let mut model = Model::new();
    model.add_node(f.node_a);
    model.add_node(f.node_b);
    model.add_rel(f.rel_ab, f.node_a, f.node_a); // wrong: real is (a, b)
    model.add_node_prop(
        f.node_a,
        graphus_dst::model::PropTriple {
            key: f.prop_key,
            type_tag: 2,
            value_inline: 4242,
        },
    );
    let result = verify(&mut f.store, &model);
    assert!(
        matches!(
            result,
            Err(CheckFailure::EndpointMismatch { .. } | CheckFailure::IncidenceMismatch { .. })
        ),
        "wrong endpoints must fail a check, got {result:?}"
    );
}
