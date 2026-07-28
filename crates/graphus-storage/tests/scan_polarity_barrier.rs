//! The **decision-polarity barrier** (`rmp` task #905): a [`DecidedProperties`] can only come from a
//! [`Snapshot`], and there must be no second way in.
//!
//! The type system already carries most of this — the struct's fields are private, so nothing outside
//! `scan_polarity` can build one with a struct literal, and every public method that produces one takes
//! a snapshot. What the type system cannot say is "and no future `impl` inside this module adds a
//! constructor that does not". That is a one-line change, it would compile, and it would quietly
//! reopen `rmp` task #902 — a validation path could then hold a "decided" view that no snapshot ever
//! narrowed. So it is pinned here.
//!
//! The functional behaviour of the narrowing is covered by the unit tests in
//! `graphus_storage::scan_polarity`; this file only guards the way in.

use graphus_core::{TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{DecidedProperties, Namespace, RecordStore, SupersetProperties};
use graphus_txn::Snapshot;
use graphus_wal::{MemLogSink, WalManager};

const SCAN_POLARITY: &str = include_str!("../src/scan_polarity.rs");
const STORE: &str = include_str!("../src/store.rs");

/// Source lines of `src`, with doc comments and ordinary comments removed, so a doc example or an
/// explanatory sentence naming a type is never mistaken for code that constructs one.
fn code_lines(src: &str) -> Vec<&str> {
    src.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect()
}

/// The **only** struct literal of `DecidedProperties` in the whole crate is the one inside
/// [`SupersetProperties::decide`], which cannot be called without a [`Snapshot`].
#[test]
fn decided_properties_is_constructed_in_exactly_one_place() {
    // A struct literal, not the declaration, the `impl` header or a return type: the name followed by
    // an opening brace on a line that declares nothing.
    let literals: Vec<&str> = code_lines(SCAN_POLARITY)
        .into_iter()
        .chain(code_lines(STORE))
        .filter(|l| l.contains("DecidedProperties {"))
        .filter(|l| {
            !l.contains("struct ")
                && !l.contains("impl ")
                && !l.contains("fn ")
                && !l.contains("->")
        })
        .collect();
    assert_eq!(
        literals.len(),
        1,
        "`DecidedProperties` must be constructible in exactly one place — inside \
         `SupersetProperties::decide`, which takes the deciding `Snapshot`. Found {} construction \
         site(s): {literals:?}. A second one would let a validation path hold a view no snapshot ever \
         narrowed, which is `rmp` task #902 reopened.",
        literals.len(),
    );
    let decide = SCAN_POLARITY
        .split("pub fn decide(")
        .nth(1)
        .expect("`SupersetProperties::decide` must exist: it is the only way in");
    assert!(
        decide.starts_with("self, snapshot: Snapshot, registry: &CommitRegistry)"),
        "`decide` must take the snapshot and the commit registry it narrows against",
    );
    let decide_body = &decide[..decide.find("\n    }").unwrap_or(decide.len())];
    assert!(
        decide_body.contains("is_visible("),
        "`decide` must narrow through the production `is_visible` predicate, not a local re-derivation",
    );
}

/// Every public function that hands back a [`DecidedProperties`] takes a [`Snapshot`]. Written as a
/// text census because the property is about the *set* of such functions, which no single signature
/// can state.
#[test]
fn every_producer_of_a_decided_view_takes_a_snapshot() {
    let mut producers = 0usize;
    for src in [SCAN_POLARITY, STORE] {
        let lines = code_lines(src);
        for (i, l) in lines.iter().enumerate() {
            if !l.contains("-> DecidedProperties") && !l.contains("Result<DecidedProperties>") {
                continue;
            }
            producers += 1;
            // The signature may be wrapped by rustfmt, so look back a few lines for the parameters.
            let from = i.saturating_sub(6);
            let signature = lines[from..=i].join("\n");
            assert!(
                signature.contains("snapshot: Snapshot"),
                "a function returning `DecidedProperties` must take the snapshot it narrows against; \
                 this one does not:\n{signature}",
            );
        }
    }
    assert!(
        producers >= 3,
        "expected at least `SupersetProperties::decide` plus the two `RecordStore::decision_scan_*` \
         methods to produce a decided view, found {producers} — the census is passing vacuously",
    );
}

/// The superset view does not silently become a sequence: nothing may iterate, index or deref it into
/// the raw records without naming the polarity. This is what forces a would-be `rmp` #902 author to
/// write `every_version()` — a name that states what the slice contains — instead of walking a `Vec`
/// that looks like the entity's properties.
#[test]
fn the_superset_view_is_not_a_transparent_sequence() {
    for forbidden in [
        "impl IntoIterator for SupersetProperties",
        "impl Deref for SupersetProperties",
        "impl std::ops::Deref for SupersetProperties",
        "impl Index<",
    ] {
        assert!(
            !SCAN_POLARITY.contains(forbidden),
            "`SupersetProperties` must not implement `{forbidden}`: reaching the raw records has to \
             go through `every_version()` / `into_every_version()`, whose names say that MVCC \
             tombstones and uncommitted versions are included (`rmp` task #905)",
        );
    }
}

/// A live, end-to-end check that the barrier separates the two answers over the **same** store state:
/// the superset read still holds a committed `REMOVE`'s tombstone, and the decision read does not.
///
/// This is the `rmp` #902 reproduction reduced to the storage layer. Before the split, one read
/// answered both questions and the caller chose — badly.
#[test]
fn the_two_polarities_answer_differently_over_the_same_chain() {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut store: RecordStore<MemBlockDevice, MemLogSink> =
        RecordStore::create(device, wal, 64, 1).expect("create store");

    let key = store
        .intern_token(Namespace::PropKey, "email")
        .expect("intern the property key");
    let writer = TxnId(1);
    store.begin(writer);
    let (node, _) = store.create_node(writer).expect("create the node");
    store
        .set_node_property_value(writer, node, key, &Value::Integer(7))
        .expect("set the property");
    store.commit(writer).expect("commit the write");

    let remover = TxnId(2);
    store.begin(remover);
    store
        .remove_node_property_value(remover, node, key)
        .expect("remove the property");
    store.commit(remover).expect("commit the removal");

    // A reader that begins after the removal committed.
    let snapshot = Snapshot {
        owner: TxnId(3),
        ts: store.snapshot_ts(),
    };

    let superset: SupersetProperties = store
        .superset_scan_node_properties(node)
        .expect("the superset read");
    assert!(
        superset
            .every_version()
            .iter()
            .any(|(_pid, prop)| prop.key == key),
        "the superset must still carry the removed version: its slot is not reclaimed until GC runs, \
         and GC has no automatic trigger (`rmp` #305)",
    );

    let decided: DecidedProperties = store
        .decision_scan_node_properties(node, snapshot)
        .expect("the decision read");
    assert!(
        decided.visible_version(key).is_none(),
        "the decision must not resolve a committed removal as a present value — that is the \
         `rmp` #902 defect, which refused `IS UNIQUE` over a duplicate no `MATCH` could find",
    );
    assert_eq!(decided.snapshot(), snapshot);

    // And the same superset, narrowed by hand, gives the same answer: `decision_scan_*` is the
    // convenience, `decide` is the barrier.
    let by_hand = superset.decide(snapshot, store.commit_registry());
    assert!(by_hand.visible_version(key).is_none());
}
