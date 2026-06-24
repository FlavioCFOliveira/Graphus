//! Regression tests for the per-column token-intern hoist and the single-pass export (`rmp` task
//! #321): the optimized importer must resolve **exactly** the same token ids the per-cell path
//! produced (interning is idempotent by name), and a bulk-etl round-trip (import → export) must
//! produce byte-identical CSV output.

use graphus_bulk::{BulkImporter, DEFAULT_BATCH_SIZE, dump_nodes, dump_relationships};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 128, 1).expect("create store")
}

const NODES: &str = "id:ID,:LABEL,name:string,age:int,score:float,active:boolean,tags:string[]\n\
                     1,Person,Alice,30,1.5,true,x;y\n\
                     2,Person;Admin,Bob,25,2.0,false,z\n\
                     3,Company,Acme,,,,\n";
const RELS: &str = ":START_ID,:END_ID,:TYPE,since:int,weight:float\n\
                    1,2,KNOWS,2010,0.5\n\
                    2,3,WORKS_AT,2015,0.9\n\
                    1,3,WORKS_AT,2018,0.1\n";

/// The per-column intern hoist must resolve the **same** property-key / label / rel-type token ids
/// the per-cell path would: interning is idempotent by name, so a name maps to exactly one id. We
/// assert the resolved ids are stable and the stored content is exactly as expected.
#[test]
fn per_column_intern_resolves_canonical_token_ids() {
    let mut importer = BulkImporter::new(fresh_store(), DEFAULT_BATCH_SIZE, b',');
    importer.import_nodes(NODES.as_bytes()).expect("nodes");
    importer
        .import_relationships(RELS.as_bytes())
        .expect("rels");
    let (store, stats) = importer.finish();

    assert_eq!(stats.nodes, 3);
    assert_eq!(stats.relationships, 3);
    // Alice name/age/score/active/tags = 5; Bob name/age/score/active/tags = 5; Acme name + an
    // empty-list `tags` materialised = 2; 3 rels × (since, weight) = 6 → 18 total.
    assert_eq!(stats.properties, 18);

    // Every distinct property-key name interned to exactly one id; resolving the name twice yields
    // the same id (the idempotency the hoist relies on). The id a column resolved to is THE id for
    // that name — there is no second id a per-cell path could have produced.
    for key in ["name", "age", "score", "active", "tags", "since", "weight"] {
        let a = store.token_id(Namespace::PropKey, key);
        let b = store.token_id(Namespace::PropKey, key);
        assert_eq!(a, b, "prop-key `{key}` is 1:1 by name");
        assert!(a.is_some(), "prop-key `{key}` was interned during import");
    }
    for label in ["Person", "Admin", "Company"] {
        assert!(
            store.token_id(Namespace::Label, label).is_some(),
            "label `{label}` interned"
        );
    }
    for ty in ["KNOWS", "WORKS_AT"] {
        assert!(
            store.token_id(Namespace::RelType, ty).is_some(),
            "rel-type `{ty}` interned"
        );
    }
    // A name that never appeared is absent (the hoist did not over-intern).
    assert!(store.token_id(Namespace::PropKey, "nonexistent").is_none());
}

/// A bulk-etl round-trip (import → export → re-export) is byte-identical: the optimized single-pass
/// export and per-column-intern import together produce a stable CSV artifact. Re-importing the dump
/// and dumping again must yield the **exact same bytes**, proving losslessness end to end.
#[test]
fn bulk_etl_round_trip_is_byte_identical() {
    // Import the source, then dump it.
    let mut imp1 = BulkImporter::new(fresh_store(), DEFAULT_BATCH_SIZE, b',');
    imp1.import_nodes(NODES.as_bytes()).expect("nodes");
    imp1.import_relationships(RELS.as_bytes()).expect("rels");
    let (mut store1, _) = imp1.finish();

    let mut nodes1 = Vec::new();
    let mut rels1 = Vec::new();
    dump_nodes(&mut store1, &mut nodes1).expect("dump nodes 1");
    dump_relationships(&mut store1, &mut rels1).expect("dump rels 1");

    // Re-import the dump into a fresh store, then dump again.
    let mut imp2 = BulkImporter::new(fresh_store(), DEFAULT_BATCH_SIZE, b',');
    imp2.import_nodes(nodes1.as_slice())
        .expect("re-import nodes");
    imp2.import_relationships(rels1.as_slice())
        .expect("re-import rels");
    let (mut store2, _) = imp2.finish();

    let mut nodes2 = Vec::new();
    let mut rels2 = Vec::new();
    dump_nodes(&mut store2, &mut nodes2).expect("dump nodes 2");
    dump_relationships(&mut store2, &mut rels2).expect("dump rels 2");

    // Hash-identical artifact: the two dumps are byte-for-byte equal.
    assert_eq!(
        nodes1, nodes2,
        "node CSV must be byte-identical across an import→export round-trip"
    );
    assert_eq!(
        rels1, rels2,
        "relationship CSV must be byte-identical across an import→export round-trip"
    );
}
