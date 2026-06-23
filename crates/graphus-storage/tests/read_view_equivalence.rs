//! Equivalence guard for the off-thread read view (`rmp` task #336, Slice 3a).
//!
//! Slice 3a factored the read-**decode** path into a single impl ([`graphus_storage::read_view`]) that
//! both the live [`RecordStore`] `&self` read methods and the owned, `Send + Sync`
//! [`StoreReadView`](graphus_storage::StoreReadView) delegate to. The whole point of the slice is to
//! prove the decode path runs **byte-identically** over an owned `(Arc<pool>, MetaSnapshot)` view as it
//! does over `&RecordStore`, so Slice 3b can move that view to reader threads with no further storage
//! change.
//!
//! This test populates a multi-store fixture exercising the full read surface — nodes, relationships,
//! their property chains, the `strings.store` overflow heap (a String large enough to spill across
//! several blocks, plus a list, every temporal class and a point — every property-storable `Value`
//! class), MVCC tombstones (deleted nodes/rels and
//! overwritten/removed properties left un-GC'd so the chains carry dead versions), a multi-label node,
//! a self-loop, and a dead-link corpse from a rolled-back relationship creation — then asserts that for
//! **every** read method and **every** id in `1..high_water`, `RecordStore::<method>(id)` equals
//! `StoreReadView::<method>(id)`.
//!
//! Note (`rmp` #336): the view carries no visibility logic of its own (that lives above the store, in
//! `graphus-cypher`'s `RecordStoreGraph`), so the equivalence is at the **raw decode** layer: identical
//! records, identical property chains (including not-yet-GC'd tombstones), identical overflow payloads,
//! identical scan id-lists, identical errors. That is exactly the layer Slice 3b moves off-thread.

use graphus_core::error::GraphusError;
use graphus_core::value::temporal::{
    Date, Duration, LocalDateTime, LocalTime, ZonedDateTime, ZonedTime,
};
use graphus_core::{Crs, Point, TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{BLOCK_PAYLOAD, Namespace, RecordStore, StoreKind, StoreReadView};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type View = StoreReadView<MemBlockDevice, MemLogSink>;

/// A fresh store over an in-memory device + log. Small page capacity (8 frames) deliberately, so the
/// fixture forces real buffer-pool eviction + reload during the scans — exercising the same
/// `with_page_fetched` cold path both read routes share.
fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 8, 1).expect("create store")
}

/// Asserts two `Result`s carrying a `PartialEq` value are equivalent: both `Ok` and equal, or both
/// `Err` with the **same message** (`GraphusError` is not `PartialEq`, but the read-view free
/// functions reproduce the live methods' exact format strings, so the `Display` text is the observable
/// contract to compare). `what` names the method+id for a precise failure.
fn assert_results_eq<T: PartialEq + std::fmt::Debug>(
    what: &str,
    live: Result<T, GraphusError>,
    view: Result<T, GraphusError>,
) {
    match (live, view) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "{what}: Ok values differ (live vs view)"),
        (Err(a), Err(b)) => assert_eq!(
            a.to_string(),
            b.to_string(),
            "{what}: Err messages differ (live vs view)"
        ),
        (live, view) => {
            panic!("{what}: Ok/Err disposition differs — live={live:?}, view={view:?}",)
        }
    }
}

/// Builds the populated fixture and returns the committed store. The fixture is intentionally rich so
/// the equivalence sweep covers every decode branch.
fn populated_store() -> Store {
    let mut s = fresh();

    // ---- transaction 1: build the live graph (commit so it is durable, settled state) ----
    let txn = TxnId(1);
    s.begin(txn);

    // Property keys and labels.
    let k_int = s.intern_token(Namespace::PropKey, "i").unwrap();
    let k_float = s.intern_token(Namespace::PropKey, "f").unwrap();
    let k_bool = s.intern_token(Namespace::PropKey, "b").unwrap();
    let k_str = s.intern_token(Namespace::PropKey, "s").unwrap();
    let k_list = s.intern_token(Namespace::PropKey, "l").unwrap();
    let k_date = s.intern_token(Namespace::PropKey, "d").unwrap();
    let k_lt = s.intern_token(Namespace::PropKey, "lt").unwrap();
    let k_ldt = s.intern_token(Namespace::PropKey, "ldt").unwrap();
    let k_zdt = s.intern_token(Namespace::PropKey, "zdt").unwrap();
    let k_dur = s.intern_token(Namespace::PropKey, "dur").unwrap();
    let k_point = s.intern_token(Namespace::PropKey, "p").unwrap();
    let k_ztime = s.intern_token(Namespace::PropKey, "zt").unwrap();
    let k_overwrite = s.intern_token(Namespace::PropKey, "ow").unwrap();
    let k_removed = s.intern_token(Namespace::PropKey, "rm").unwrap();

    let l_person = s.intern_token(Namespace::Label, "Person").unwrap();
    let l_admin = s.intern_token(Namespace::Label, "Admin").unwrap();
    let l_account = s.intern_token(Namespace::Label, "Account").unwrap();
    let t_knows = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let t_owns = s.intern_token(Namespace::RelType, "OWNS").unwrap();

    // Node 1: multi-label, every property-storable scalar (inline) + overflow String/List + every
    // temporal class (incl. ZonedTime) + point, plus an overwritten property (old version tombstoned)
    // and a removed property (tombstoned, no live version) — both left un-GC'd so the chain carries
    // dead versions. (`Bytes`/`Map` are not yet property-storable, so they cannot appear here.)
    let (n1, _) = s.create_node(txn).unwrap();
    s.add_label(txn, n1, l_person).unwrap();
    s.add_label(txn, n1, l_admin).unwrap();
    s.add_label(txn, n1, l_account).unwrap();
    s.set_node_property_value(txn, n1, k_int, &Value::Integer(-42))
        .unwrap();
    s.set_node_property_value(txn, n1, k_float, &Value::Float(2.5))
        .unwrap();
    s.set_node_property_value(txn, n1, k_bool, &Value::Boolean(true))
        .unwrap();
    // A multi-block string (spills into the strings overflow heap).
    let long = "z".repeat(BLOCK_PAYLOAD * 4 + 7);
    s.set_node_property_value(txn, n1, k_str, &Value::String(long))
        .unwrap();
    s.set_node_property_value(
        txn,
        n1,
        k_list,
        &Value::List(vec![
            Value::Integer(1),
            Value::Integer(2),
            Value::Integer(3),
        ]),
    )
    .unwrap();
    s.set_node_property_value(
        txn,
        n1,
        k_date,
        &Value::Date(Date {
            days_since_epoch: -719_528,
        }),
    )
    .unwrap();
    s.set_node_property_value(
        txn,
        n1,
        k_lt,
        &Value::LocalTime(LocalTime {
            nanos_of_day: 86_399_999_999_999,
        }),
    )
    .unwrap();
    s.set_node_property_value(
        txn,
        n1,
        k_ldt,
        &Value::LocalDateTime(LocalDateTime {
            epoch_seconds: -1,
            nanos: 999_999_999,
        }),
    )
    .unwrap();
    s.set_node_property_value(
        txn,
        n1,
        k_zdt,
        &Value::zoned_date_time(ZonedDateTime {
            local: LocalDateTime {
                epoch_seconds: 1_700_000_000,
                nanos: 123_456_789,
            },
            offset_seconds: 3600,
            zone_id: "Europe/Lisbon".to_owned(),
        }),
    )
    .unwrap();
    s.set_node_property_value(
        txn,
        n1,
        k_dur,
        &Value::Duration(Duration {
            months: -1,
            days: 40,
            seconds: -86_400,
            nanos: 999_999_999,
        }),
    )
    .unwrap();
    s.set_node_property_value(
        txn,
        n1,
        k_point,
        &Value::Point(Point::new_3d(Crs::Wgs84_3D, 12.5, -7.25, 100.0)),
    )
    .unwrap();
    // A ZonedTime (time-of-day + fixed offset, distinct from the ZonedDateTime above). NOTE: `Bytes`
    // and `Map` are deliberately NOT exercised — they are not yet storable as property values
    // (`set_property_value` rejects them: "Map/Bytes property values are a follow-up"), so every
    // property-storable `Value` class IS covered here, but the two follow-up classes cannot be.
    s.set_node_property_value(
        txn,
        n1,
        k_ztime,
        &Value::ZonedTime(ZonedTime {
            time: LocalTime {
                nanos_of_day: 3_600_000_000_000,
            },
            offset_seconds: -7200,
        }),
    )
    .unwrap();
    // Overwrite a property twice (leaves two dead versions before the live one).
    s.set_node_property_value(txn, n1, k_overwrite, &Value::Integer(1))
        .unwrap();
    s.set_node_property_value(txn, n1, k_overwrite, &Value::Integer(2))
        .unwrap();
    s.set_node_property_value(txn, n1, k_overwrite, &Value::Integer(3))
        .unwrap();
    // A property set then removed (chain carries the tombstone, no live version).
    s.set_node_property_value(txn, n1, k_removed, &Value::String("gone".repeat(40)))
        .unwrap();
    s.remove_node_property_value(txn, n1, k_removed).unwrap();

    // Nodes 2..=4: plain nodes for relationships + a self-loop owner.
    let (n2, _) = s.create_node(txn).unwrap();
    let (n3, _) = s.create_node(txn).unwrap();
    let (n4, _) = s.create_node(txn).unwrap();
    s.add_label(txn, n2, l_person).unwrap();
    s.add_label(txn, n3, l_account).unwrap();
    s.set_node_property_value(txn, n2, k_int, &Value::Integer(7))
        .unwrap();

    // Relationships: a chain on n1, a typed rel with an overflow property, and a self-loop on n4.
    let (r1, _) = s.create_rel(txn, t_knows, n1, n2).unwrap();
    let (_r2, _) = s.create_rel(txn, t_knows, n1, n3).unwrap();
    let (r3, _) = s.create_rel(txn, t_owns, n2, n3).unwrap();
    s.set_rel_property_value(txn, r1, k_int, &Value::Integer(99))
        .unwrap();
    // Overflow rel property + an overwritten rel property (dead version).
    s.set_rel_property_value(txn, r3, k_str, &Value::String("rel-".repeat(50)))
        .unwrap();
    s.set_rel_property_value(txn, r3, k_overwrite, &Value::Integer(10))
        .unwrap();
    s.set_rel_property_value(txn, r3, k_overwrite, &Value::Integer(20))
        .unwrap();
    let (_self_loop, _) = s.create_rel(txn, t_knows, n4, n4).unwrap();

    s.commit(txn).unwrap();

    // ---- transaction 2: MVCC tombstones left un-GC'd (a deleted node + a deleted rel) ----
    let txn2 = TxnId(2);
    s.begin(txn2);
    // Delete the OWNS rel r3 (tombstone; slot + chain stay until GC).
    s.delete_rel(txn2, r3).unwrap();
    // Make a fresh isolated node then delete it (a node tombstone in the scan range).
    let (n5, _) = s.create_node(txn2).unwrap();
    s.add_label(txn2, n5, l_admin).unwrap();
    s.delete_node(txn2, n5).unwrap();
    s.commit(txn2).unwrap();

    // ---- transaction 3: a ROLLED-BACK rel creation, leaving a dead-link corpse (#220) ----
    let txn3 = TxnId(3);
    s.begin(txn3);
    let (_corpse, _) = s.create_rel(txn3, t_knows, n2, n4).unwrap();
    s.rollback(txn3).unwrap();

    // Deliberately do NOT run GC: the equivalence sweep must see the tombstones, dead versions, and
    // the dead-link corpse — every decode branch the off-thread reader will face.
    s
}

/// The core guard: every read method, over every id in `1..high_water`, is byte-identical between the
/// live `RecordStore` and an owned `StoreReadView`.
#[test]
fn store_read_view_is_byte_identical_to_record_store() {
    let s = populated_store();
    let view: View = s.read_view();

    // The snapshot's high-water bounds must match the live store's (the as-of-capture bound). Read
    // them via the public surface: the scans agree iff the bounds agree, which we cross-check below by
    // comparing the full scan id-lists.
    assert_results_eq("scan_node_ids", s.scan_node_ids(), view.scan_node_ids());
    assert_results_eq("scan_rel_ids", s.scan_rel_ids(), view.scan_rel_ids());

    // Derive the id ranges from the snapshot's high-water marks so the sweep covers EVERY slot in
    // `1..high_water` (live records, tombstones, corpses, and unallocated holes alike — an unallocated
    // id must produce the SAME error on both routes).
    let node_hw = view.meta().store(StoreKind::Node).high_water;
    let rel_hw = view.meta().store(StoreKind::Rel).high_water;
    let prop_hw = view.meta().store(StoreKind::Prop).high_water;
    let strings_hw = view.meta().store(StoreKind::Strings).high_water;

    // Sweep the node store: node, node_labels, node_has_label (for several token ids incl. an
    // unlikely one), node_properties, incident_rels, and the low-level read_mvcc.
    for id in 1..node_hw {
        assert_results_eq(&format!("node({id})"), s.node(id), view.node(id));
        assert_results_eq(
            &format!("node_labels({id})"),
            s.node_labels(id),
            view.node_labels(id),
        );
        for token in [0u32, 1, 2, 3, 62, 100] {
            assert_results_eq(
                &format!("node_has_label({id}, {token})"),
                s.node_has_label(id, token),
                view.node_has_label(id, token),
            );
        }
        assert_results_eq(
            &format!("node_properties({id})"),
            s.node_properties(id),
            view.node_properties(id),
        );
        assert_results_eq(
            &format!("incident_rels({id})"),
            s.incident_rels(id),
            view.incident_rels(id),
        );
        assert_results_eq(
            &format!("read_mvcc(Node, {id})"),
            s.read_mvcc_for_test(StoreKind::Node, id),
            view.read_mvcc(StoreKind::Node, id),
        );
    }

    // Sweep the rel store: rel, rel_properties, rel_property_values, read_mvcc.
    for id in 1..rel_hw {
        assert_results_eq(&format!("rel({id})"), s.rel(id), view.rel(id));
        assert_results_eq(
            &format!("rel_properties({id})"),
            s.rel_properties(id),
            view.rel_properties(id),
        );
        assert_results_eq(
            &format!("rel_property_values({id})"),
            s.rel_property_values(id),
            view.rel_property_values(id),
        );
        assert_results_eq(
            &format!("read_mvcc(Rel, {id})"),
            s.read_mvcc_for_test(StoreKind::Rel, id),
            view.read_mvcc(StoreKind::Rel, id),
        );
    }

    // Sweep the prop store: property(id) (single-record decode) + decode_property_value of each live
    // record's `(type_tag, value_inline)` (exercises both inline and overflow decode), + read_mvcc.
    for id in 1..prop_hw {
        assert_results_eq(
            &format!("property({id})"),
            s.property(id),
            view.read_prop(id),
        );
        // For an in-range record, decode its value through both routes (overflow values walk the heap).
        if let (Ok(live_rec), Ok(view_rec)) = (s.property(id), view.read_prop(id)) {
            assert_eq!(live_rec, view_rec, "property({id}) record mismatch");
            assert_results_eq(
                &format!("decode_property_value@prop({id})"),
                s.decode_property_value(live_rec.type_tag, live_rec.value_inline),
                view.decode_property_value(view_rec.type_tag, view_rec.value_inline),
            );
        }
        assert_results_eq(
            &format!("read_mvcc(Prop, {id})"),
            s.read_mvcc_for_test(StoreKind::Prop, id),
            view.read_mvcc(StoreKind::Prop, id),
        );
    }

    // Sweep the strings overflow heap: read_block(id) + read_mvcc(Strings, id) over the whole range,
    // so every heap block (live and any freed) decodes identically.
    for id in 1..strings_hw {
        assert_results_eq(
            &format!("read_block({id})"),
            s.read_block_for_test(id),
            view.read_block(id),
        );
        assert_results_eq(
            &format!("read_mvcc(Strings, {id})"),
            s.read_mvcc_for_test(StoreKind::Strings, id),
            view.read_mvcc(StoreKind::Strings, id),
        );
    }

    // Also probe a handful of OUT-OF-RANGE ids on every store: an id at the high-water and just past
    // it must produce the IDENTICAL "page not allocated" error on both routes (the device_page miss
    // path is part of the contract).
    for id in [node_hw, node_hw + 1, node_hw + 1000] {
        assert_results_eq(&format!("node({id}) oob"), s.node(id), view.node(id));
    }
    for id in [rel_hw, rel_hw + 1] {
        assert_results_eq(&format!("rel({id}) oob"), s.rel(id), view.rel(id));
    }
    for id in [strings_hw, strings_hw + 1] {
        assert_results_eq(
            &format!("read_block({id}) oob"),
            s.read_block_for_test(id),
            view.read_block(id),
        );
    }

    // A multi-block read_chain on a real overflow head (exercise the chain reassembly explicitly via
    // the live store and confirm the view's decode_property_value of an overflow prop equals it).
    // (read_chain is private; node_property_values already round-trips it above through both routes.)
    assert_results_eq(
        "node_property_values(1)",
        s.node_property_values(1),
        view_node_property_values(&view, 1),
    );
}

/// Reconstructs `node_property_values` over a [`StoreReadView`] from its public surface
/// (`node_properties` + `decode_property_value`), mirroring `RecordStore::node_property_values`, so the
/// overflow-walk path is compared end-to-end. Returns the same `(pid, key, Value)` triples.
fn view_node_property_values(
    view: &View,
    node_id: u64,
) -> Result<Vec<(u64, u32, Value)>, GraphusError> {
    let chain = view.node_properties(node_id)?;
    let mut out = Vec::with_capacity(chain.len());
    for (pid, prop) in chain {
        let value = view.decode_property_value(prop.type_tag, prop.value_inline)?;
        out.push((pid, prop.key, value));
    }
    Ok(out)
}
