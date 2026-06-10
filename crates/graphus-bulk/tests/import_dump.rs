//! End-to-end tests for the offline bulk importer and the whole-graph dumper (FR-BK; `rmp` task
//! #22): correct ingestion of node/relationship CSV, a multi-thousand-row throughput measurement,
//! and a dump → import round-trip proving the two graphs are identical.

use std::collections::BTreeMap;

use graphus_bulk::{BulkImporter, DEFAULT_BATCH_SIZE, dump_nodes, dump_relationships};
use graphus_core::Value;
use graphus_io::MemBlockDevice;
use graphus_storage::check::verify_on_open;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// A fresh, empty in-memory record store.
fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 128, 1).expect("create store")
}

/// A structural snapshot of one node: its labels (as a sorted set) and its properties (as a
/// key→value map). Physical ids are deliberately excluded so two stores compare by *content*.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NodeShape {
    labels: Vec<String>,
    props: Vec<(String, ValueKey)>,
}

/// A structural snapshot of one relationship: its type, the shapes of its endpoints, and its
/// properties — all id-independent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RelShape {
    rel_type: String,
    start: NodeShape,
    end: NodeShape,
    props: Vec<(String, ValueKey)>,
}

/// An order/hash-stable rendering of a [`Value`] for set comparison (floats compared by bit pattern,
/// which is exact and total — sufficient because the importer parses the same text both times).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ValueKey {
    Repr(String),
}

fn value_key(v: &Value) -> ValueKey {
    ValueKey::Repr(format!("{v:?}"))
}

/// Builds the id→shape map for every node in `store`.
fn node_shapes(store: &mut Store) -> BTreeMap<u64, NodeShape> {
    let mut out = BTreeMap::new();
    for id in store.scan_node_ids().expect("scan nodes") {
        out.insert(id, node_shape(store, id));
    }
    out
}

/// The structural shape of a single node.
fn node_shape(store: &mut Store, id: u64) -> NodeShape {
    let mut labels: Vec<String> = store
        .node_labels(id)
        .expect("labels")
        .into_iter()
        .map(|t| store.token_name(Namespace::Label, t).unwrap().to_owned())
        .collect();
    labels.sort();

    // Newest-wins per key (the chain is prepend-ordered), then sorted by key for a stable shape.
    let mut by_key: BTreeMap<String, ValueKey> = BTreeMap::new();
    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for (_pid, key_token, value) in store.node_property_values(id).expect("props") {
        if seen.insert(key_token) {
            let key = store
                .token_name(Namespace::PropKey, key_token)
                .unwrap()
                .to_owned();
            by_key.insert(key, value_key(&value));
        }
    }
    NodeShape {
        labels,
        props: by_key.into_iter().collect(),
    }
}

/// The multiset of relationship shapes in `store` (sorted so two stores compare equal regardless of
/// id assignment / scan order).
fn rel_shapes(store: &mut Store) -> Vec<RelShape> {
    let rel_ids = store.scan_rel_ids().expect("scan rels");
    let mut out = Vec::with_capacity(rel_ids.len());
    for id in rel_ids {
        let rec = store.rel(id).expect("rel");
        let rel_type = store
            .token_name(Namespace::RelType, rec.type_id)
            .unwrap()
            .to_owned();
        let start = node_shape(store, rec.start_node);
        let end = node_shape(store, rec.end_node);
        let mut by_key: BTreeMap<String, ValueKey> = BTreeMap::new();
        let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for (_pid, key_token, value) in store.rel_property_values(id).expect("rel props") {
            if seen.insert(key_token) {
                let key = store
                    .token_name(Namespace::PropKey, key_token)
                    .unwrap()
                    .to_owned();
                by_key.insert(key, value_key(&value));
            }
        }
        out.push(RelShape {
            rel_type,
            start,
            end,
            props: by_key.into_iter().collect(),
        });
    }
    out.sort();
    out
}

/// The id-independent snapshot of a whole store: the sorted multiset of node shapes plus rel shapes.
fn graph_snapshot(store: &mut Store) -> (Vec<NodeShape>, Vec<RelShape>) {
    let mut nodes: Vec<NodeShape> = node_shapes(store).into_values().collect();
    nodes.sort();
    (nodes, rel_shapes(store))
}

// =================================================================================================
// Import correctness
// =================================================================================================

#[test]
fn imports_typed_nodes_and_relationships() {
    let nodes = "id:ID,:LABEL,name:string,age:int,score:float,active:boolean\n\
                 1,Person,Alice,30,1.5,true\n\
                 2,Person;Admin,Bob,25,2.0,false\n";
    let rels = ":START_ID,:END_ID,:TYPE,since:int\n\
                1,2,KNOWS,2010\n";

    let mut importer = BulkImporter::new(fresh_store(), DEFAULT_BATCH_SIZE, b',');
    importer
        .import_nodes(nodes.as_bytes())
        .expect("import nodes");
    importer
        .import_relationships(rels.as_bytes())
        .expect("import rels");
    let (mut store, stats) = importer.finish();

    assert_eq!(stats.nodes, 2);
    assert_eq!(stats.relationships, 1);
    // 4 props on Alice + 4 on Bob + 1 on the rel = 9.
    assert_eq!(stats.properties, 9);

    // The store is internally consistent (the inviolable ACID gate).
    verify_on_open(&mut store, &[]).expect("store consistent after import");

    // Alice's node carries the typed properties.
    let shapes = node_shapes(&mut store);
    let alice = shapes
        .values()
        .find(|s| {
            s.props
                .iter()
                .any(|(k, v)| k == "name" && *v == value_key(&Value::String("Alice".into())))
        })
        .expect("Alice present");
    assert_eq!(alice.labels, vec!["Person".to_owned()]);
    assert!(
        alice
            .props
            .iter()
            .any(|(k, v)| k == "age" && *v == value_key(&Value::Integer(30)))
    );
    assert!(
        alice
            .props
            .iter()
            .any(|(k, v)| k == "score" && *v == value_key(&Value::Float(1.5)))
    );
    assert!(
        alice
            .props
            .iter()
            .any(|(k, v)| k == "active" && *v == value_key(&Value::Boolean(true)))
    );

    // Bob has two labels.
    let bob = shapes
        .values()
        .find(|s| {
            s.props
                .iter()
                .any(|(k, v)| k == "name" && *v == value_key(&Value::String("Bob".into())))
        })
        .expect("Bob present");
    assert_eq!(bob.labels, vec!["Admin".to_owned(), "Person".to_owned()]);

    // The KNOWS relationship with its property.
    let rels = rel_shapes(&mut store);
    assert_eq!(rels.len(), 1);
    assert_eq!(rels[0].rel_type, "KNOWS");
    assert!(
        rels[0]
            .props
            .iter()
            .any(|(k, v)| k == "since" && *v == value_key(&Value::Integer(2010)))
    );
}

#[test]
fn imports_array_properties() {
    let nodes = "id:ID,tags:string[],scores:int[]\n\
                 n1,a;b;c,1;2;3\n";
    let mut importer = BulkImporter::new(fresh_store(), DEFAULT_BATCH_SIZE, b',');
    importer.import_nodes(nodes.as_bytes()).expect("import");
    let (mut store, _stats) = importer.finish();

    let shapes = node_shapes(&mut store);
    let n = shapes.values().next().expect("one node");
    let tags = Value::List(vec![
        Value::String("a".into()),
        Value::String("b".into()),
        Value::String("c".into()),
    ]);
    let scores = Value::List(vec![
        Value::Integer(1),
        Value::Integer(2),
        Value::Integer(3),
    ]);
    assert!(
        n.props
            .iter()
            .any(|(k, v)| k == "tags" && *v == value_key(&tags))
    );
    assert!(
        n.props
            .iter()
            .any(|(k, v)| k == "scores" && *v == value_key(&scores))
    );
}

#[test]
fn unknown_endpoint_id_is_an_error() {
    let nodes = "id:ID\n1\n";
    let rels = ":START_ID,:END_ID,:TYPE\n1,999,KNOWS\n"; // 999 has no node
    let mut importer = BulkImporter::new(fresh_store(), DEFAULT_BATCH_SIZE, b',');
    importer
        .import_nodes(nodes.as_bytes())
        .expect("import nodes");
    let err = importer
        .import_relationships(rels.as_bytes())
        .expect_err("unknown :END_ID must error");
    assert!(err.to_string().contains("unknown :END_ID"), "got: {err}");
}

#[test]
fn honors_a_custom_delimiter() {
    let nodes = "id:ID;name:string\n1;Alice\n";
    let mut importer = BulkImporter::new(fresh_store(), DEFAULT_BATCH_SIZE, b';');
    importer.import_nodes(nodes.as_bytes()).expect("import");
    let (_store, stats) = importer.finish();
    assert_eq!(stats.nodes, 1);
    assert_eq!(stats.properties, 1);
}

// =================================================================================================
// Throughput measurement (initial-load throughput, FR-BK)
// =================================================================================================

/// Loads a generated multi-thousand-row dataset and asserts it ingested correctly, **measuring and
/// printing the initial-load throughput** (nodes/sec, rels/sec). Run with `--nocapture` to see the
/// numbers; the test also asserts they are positive so a stall is caught.
///
/// This is an in-memory store (no fsync), so the measured rate reflects the encode/store path rather
/// than disk; the CLI prints the on-disk rate for a real load. The dataset is a chain of `N` nodes
/// with typed properties and `N-1` relationships, sized to exercise multi-batch commits.
#[test]
fn measures_initial_load_throughput() {
    const N: usize = 20_000;

    // Generate the node CSV: an id, a label, a name, and an integer/float property each.
    let mut node_csv = String::with_capacity(N * 24);
    node_csv.push_str("id:ID,:LABEL,name:string,seq:int,ratio:float\n");
    for i in 0..N {
        node_csv.push_str(&format!("n{i},Item,item-{i},{i},{}\n", i as f64 * 0.5));
    }
    // Generate the relationship CSV: a chain n0->n1->...->n(N-1), each NEXT with a weight.
    let mut rel_csv = String::with_capacity(N * 20);
    rel_csv.push_str(":START_ID,:END_ID,:TYPE,weight:int\n");
    for i in 0..N - 1 {
        rel_csv.push_str(&format!("n{i},n{},NEXT,{i}\n", i + 1));
    }

    let mut importer = BulkImporter::new(fresh_store(), DEFAULT_BATCH_SIZE, b',');
    importer
        .import_nodes(node_csv.as_bytes())
        .expect("import nodes");
    importer
        .import_relationships(rel_csv.as_bytes())
        .expect("import rels");
    let (mut store, stats) = importer.finish();

    assert_eq!(stats.nodes, N as u64, "all nodes ingested");
    assert_eq!(stats.relationships, (N - 1) as u64, "all rels ingested");
    verify_on_open(&mut store, &[]).expect("store consistent after bulk load");

    // The store really holds them.
    assert_eq!(store.scan_node_ids().expect("scan").len(), N);
    assert_eq!(store.scan_rel_ids().expect("scan").len(), N - 1);

    // Report the measured initial-load throughput.
    println!(
        "\n=== graphus-bulk initial-load throughput (in-memory store) ===\n\
         nodes: {} in {:.3}s -> {:.0} nodes/s\n\
         rels:  {} in {:.3}s -> {:.0} rels/s\n\
         props: {}\n",
        stats.nodes,
        stats.node_seconds,
        stats.nodes_per_sec(),
        stats.relationships,
        stats.rel_seconds,
        stats.rels_per_sec(),
        stats.properties,
    );
    assert!(
        stats.nodes_per_sec() > 0.0,
        "node throughput must be measurable"
    );
    assert!(
        stats.rels_per_sec() > 0.0,
        "rel throughput must be measurable"
    );
}

// =================================================================================================
// Round-trip: dump → import → identical graph
// =================================================================================================

#[test]
fn dump_import_round_trips_to_an_identical_graph() {
    // Build a richer source graph: 4 nodes with mixed labels + typed props, 3 typed relationships.
    let nodes = "id:ID,:LABEL,name:string,age:int,rating:float,vip:boolean,tags:string[]\n\
                 a,Person,Ada,36,4.5,true,x;y\n\
                 b,Person,Bob,28,3.0,false,\n\
                 c,Person;Admin,Cara,41,5.0,true,z\n\
                 d,Company,Acme,,,,\n";
    let rels = ":START_ID,:END_ID,:TYPE,since:int,weight:float\n\
                a,b,KNOWS,2010,0.5\n\
                b,c,KNOWS,2015,0.9\n\
                a,d,WORKS_AT,,\n";

    let mut imp1 = BulkImporter::new(fresh_store(), DEFAULT_BATCH_SIZE, b',');
    imp1.import_nodes(nodes.as_bytes()).expect("import nodes");
    imp1.import_relationships(rels.as_bytes())
        .expect("import rels");
    let (mut original, _stats) = imp1.finish();
    verify_on_open(&mut original, &[]).expect("original consistent");
    let before = graph_snapshot(&mut original);

    // Dump it to CSV.
    let mut node_csv = Vec::new();
    let mut rel_csv = Vec::new();
    dump_nodes(&mut original, &mut node_csv).expect("dump nodes");
    dump_relationships(&mut original, &mut rel_csv).expect("dump rels");

    // Re-import the dump into a fresh store.
    let mut imp2 = BulkImporter::new(fresh_store(), DEFAULT_BATCH_SIZE, b',');
    imp2.import_nodes(node_csv.as_slice())
        .expect("re-import nodes");
    imp2.import_relationships(rel_csv.as_slice())
        .expect("re-import rels");
    let (mut restored, _stats) = imp2.finish();
    verify_on_open(&mut restored, &[]).expect("restored consistent");
    let after = graph_snapshot(&mut restored);

    // The two graphs are identical: same node shapes (labels + props) and same relationship shapes
    // (type + endpoint shapes + props), independent of physical id assignment.
    assert_eq!(before.0, after.0, "node set must round-trip identically");
    assert_eq!(
        before.1, after.1,
        "relationship set must round-trip identically"
    );
}
