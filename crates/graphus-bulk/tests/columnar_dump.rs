//! End-to-end tests for the lossless **columnar** (`.gcol`) dump/import format (FR-BK; `rmp` task
//! #327).
//!
//! The format is a pure byte→byte transcode of the importer's CSV (see
//! [`graphus_bulk::csv_to_gcol`] / [`graphus_bulk::gcol_to_csv`]); it never touches the store write
//! path. These tests prove:
//!
//! 1. **Byte-identical CSV round-trip** — `gcol_to_csv(csv_to_gcol(csv)) == csv` for the dumper's CSV.
//! 2. **Whole-graph round-trip via `.gcol`** — a store dumped → `.gcol` → re-imported → re-dumped
//!    yields a byte-identical dump (the content-hash equality the task requires), and a structurally
//!    identical graph.
//! 3. **Size win** — on a low-cardinality graph the `.gcol` is strictly smaller than the CSV (printed).
//! 4. **Property-based losslessness** — a generated CSV transcodes byte-identically (proptest).

use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use graphus_bulk::{
    BulkImporter, DEFAULT_BATCH_SIZE, csv_to_gcol, dump_nodes, dump_relationships, gcol_to_csv,
};
use graphus_core::Value;
use graphus_io::MemBlockDevice;
use graphus_storage::check::verify_on_open;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// A fresh, empty in-memory record store (mirrors the harness in `import_dump.rs`).
fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 128, 1).expect("create store")
}

// =================================================================================================
// Id-independent structural snapshot (so two stores compare by *content*, not physical ids).
// Mirrors `import_dump.rs`.
// =================================================================================================

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NodeShape {
    labels: Vec<String>,
    props: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RelShape {
    rel_type: String,
    start: NodeShape,
    end: NodeShape,
    props: Vec<(String, String)>,
}

fn value_repr(v: &Value) -> String {
    format!("{v:?}")
}

fn node_shape(store: &mut Store, id: u64) -> NodeShape {
    let mut labels: Vec<String> = store
        .node_labels(id)
        .expect("labels")
        .into_iter()
        .map(|t| store.token_name(Namespace::Label, t).unwrap().to_owned())
        .collect();
    labels.sort();

    let mut by_key: BTreeMap<String, String> = BTreeMap::new();
    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for (_pid, key_token, value) in store.node_property_values(id).expect("props") {
        if seen.insert(key_token) {
            let key = store
                .token_name(Namespace::PropKey, key_token)
                .unwrap()
                .to_owned();
            by_key.insert(key, value_repr(&value));
        }
    }
    NodeShape {
        labels,
        props: by_key.into_iter().collect(),
    }
}

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
        let mut by_key: BTreeMap<String, String> = BTreeMap::new();
        let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for (_pid, key_token, value) in store.rel_property_values(id).expect("rel props") {
            if seen.insert(key_token) {
                let key = store
                    .token_name(Namespace::PropKey, key_token)
                    .unwrap()
                    .to_owned();
                by_key.insert(key, value_repr(&value));
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

fn graph_snapshot(store: &mut Store) -> (Vec<NodeShape>, Vec<RelShape>) {
    let mut nodes: Vec<NodeShape> = store
        .scan_node_ids()
        .expect("scan nodes")
        .into_iter()
        .map(|id| node_shape(store, id))
        .collect();
    nodes.sort();
    (nodes, rel_shapes(store))
}

/// A 64-bit content hash of a byte buffer (for the printed evidence in the round-trip test).
fn content_hash(bytes: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

/// Imports a node + relationship CSV pair into a fresh store.
fn import_csv(nodes: &[u8], rels: &[u8]) -> Store {
    let mut imp = BulkImporter::new(fresh_store(), DEFAULT_BATCH_SIZE, b',');
    imp.import_nodes(nodes).expect("import nodes");
    imp.import_relationships(rels).expect("import rels");
    let (mut store, _stats) = imp.finish();
    verify_on_open(&mut store, &[]).expect("store consistent");
    store
}

/// Dumps a store to (node CSV, relationship CSV).
fn dump_csv(store: &mut Store) -> (Vec<u8>, Vec<u8>) {
    let mut nodes = Vec::new();
    let mut rels = Vec::new();
    dump_nodes(store, &mut nodes).expect("dump nodes");
    dump_relationships(store, &mut rels).expect("dump rels");
    (nodes, rels)
}

// =================================================================================================
// 1. Byte-identical CSV round-trip on a real dump
// =================================================================================================

#[test]
fn dump_csv_transcodes_byte_identically_through_gcol() {
    // A richly typed source graph (mixed labels, ints, floats, booleans, arrays, empties).
    let nodes = "id:ID,:LABEL,name:string,age:int,rating:float,vip:boolean,tags:string[]\n\
                 a,Person,Ada,36,4.5,true,x;y\n\
                 b,Person,Bob,28,3.0,false,\n\
                 c,Person;Admin,Cara,41,5.0,true,z\n\
                 d,Company,Acme,,,,\n";
    let rels = ":START_ID,:END_ID,:TYPE,since:int,weight:float\n\
                a,b,KNOWS,2010,0.5\n\
                b,c,KNOWS,2015,0.9\n\
                a,d,WORKS_AT,,\n";

    let mut store = import_csv(nodes.as_bytes(), rels.as_bytes());
    let (node_csv, rel_csv) = dump_csv(&mut store);

    // The dumped CSV must survive a csv→gcol→csv round-trip byte-for-byte.
    for (label, csv) in [("nodes", &node_csv), ("rels", &rel_csv)] {
        let gcol = csv_to_gcol(csv, b',').expect("encode gcol");
        let back = gcol_to_csv(&gcol).expect("decode gcol");
        assert_eq!(
            &back, csv,
            "{label}: gcol_to_csv(csv_to_gcol(csv)) must be byte-identical"
        );
    }
}

// =================================================================================================
// 2. Whole-graph round-trip via .gcol → content-hash + structural equality
// =================================================================================================

#[test]
fn whole_graph_round_trips_through_gcol_by_content_hash() {
    let nodes = "id:ID,:LABEL,name:string,age:int,rating:float,vip:boolean,tags:string[]\n\
                 a,Person,Ada,36,4.5,true,x;y\n\
                 b,Person,Bob,28,3.0,false,\n\
                 c,Person;Admin,Cara,41,5.0,true,z\n\
                 d,Company,Acme,,,,\n";
    let rels = ":START_ID,:END_ID,:TYPE,since:int,weight:float\n\
                a,b,KNOWS,2010,0.5\n\
                b,c,KNOWS,2015,0.9\n\
                a,d,WORKS_AT,,\n";

    // Original store → snapshot + CSV dump.
    let mut original = import_csv(nodes.as_bytes(), rels.as_bytes());
    let before = graph_snapshot(&mut original);
    let (node_csv, rel_csv) = dump_csv(&mut original);

    // CSV → .gcol (the on-disk columnar form).
    let node_gcol = csv_to_gcol(&node_csv, b',').expect("encode node gcol");
    let rel_gcol = csv_to_gcol(&rel_csv, b',').expect("encode rel gcol");

    // .gcol → CSV → fresh store (the import side of the gcol path).
    let node_csv2 = gcol_to_csv(&node_gcol).expect("decode node gcol");
    let rel_csv2 = gcol_to_csv(&rel_gcol).expect("decode rel gcol");
    let mut restored = import_csv(&node_csv2, &rel_csv2);
    let after = graph_snapshot(&mut restored);

    // Re-dump the restored store: the dump must be byte-identical to the original dump (the strongest
    // possible content-equality proof — every column, value, order, and quoting preserved).
    let (node_csv3, rel_csv3) = dump_csv(&mut restored);

    println!(
        "\n=== gcol whole-graph round-trip (content hashes) ===\n\
         nodes: original dump hash {:#018x}, re-dump hash {:#018x}\n\
         rels:  original dump hash {:#018x}, re-dump hash {:#018x}\n",
        content_hash(&node_csv),
        content_hash(&node_csv3),
        content_hash(&rel_csv),
        content_hash(&rel_csv3),
    );

    assert_eq!(
        content_hash(&node_csv),
        content_hash(&node_csv3),
        "node dump content hash must match after the gcol round-trip"
    );
    assert_eq!(
        content_hash(&rel_csv),
        content_hash(&rel_csv3),
        "rel dump content hash must match after the gcol round-trip"
    );
    // Byte-equality (stronger than the hash) and structural equality (id-independent).
    assert_eq!(node_csv, node_csv3, "node re-dump must be byte-identical");
    assert_eq!(rel_csv, rel_csv3, "rel re-dump must be byte-identical");
    assert_eq!(before.0, after.0, "node set must round-trip identically");
    assert_eq!(before.1, after.1, "rel set must round-trip identically");
}

// =================================================================================================
// 3. Size: .gcol strictly smaller than CSV on a low-cardinality graph (printed evidence)
// =================================================================================================

#[test]
fn gcol_is_smaller_than_csv_on_low_cardinality_data() {
    // A low-cardinality graph: many rows, few distinct labels / names / categories, and a
    // monotonic integer sequence + a constant float — exactly what dictionary + delta + Gorilla
    // codecs collapse. 5000 nodes.
    const N: usize = 5_000;
    let labels = ["Person", "Admin", "Guest"];
    let cities = ["Lisbon", "Porto", "Madrid", "Braga"];

    let mut node_csv = String::with_capacity(N * 32);
    node_csv.push_str("id:ID,:LABEL,city:string,seq:int,ratio:float\n");
    for i in 0..N {
        // `seq` is a perfect monotonic sequence (delta codec → ~constant size); `ratio` is constant
        // (Gorilla → ~1 bit/row); `city`/`:LABEL` are low-cardinality (dictionary → ~2 bits/row).
        node_csv.push_str(&format!(
            "n{i},{},{},{i},1.5\n",
            labels[i % labels.len()],
            cities[i % cities.len()],
        ));
    }

    let mut rel_csv = String::with_capacity(N * 24);
    rel_csv.push_str(":START_ID,:END_ID,:TYPE,weight:int\n");
    for i in 0..N - 1 {
        rel_csv.push_str(&format!("n{i},n{},NEXT,{i}\n", i + 1));
    }

    // Import → dump (the canonical CSV) → gcol.
    let mut store = import_csv(node_csv.as_bytes(), rel_csv.as_bytes());
    let (dumped_nodes, dumped_rels) = dump_csv(&mut store);
    let node_gcol = csv_to_gcol(&dumped_nodes, b',').expect("encode node gcol");
    let rel_gcol = csv_to_gcol(&dumped_rels, b',').expect("encode rel gcol");

    // Losslessness still holds on this dataset (defensive — the size win must not cost correctness).
    assert_eq!(gcol_to_csv(&node_gcol).unwrap(), dumped_nodes);
    assert_eq!(gcol_to_csv(&rel_gcol).unwrap(), dumped_rels);

    let csv_total = dumped_nodes.len() + dumped_rels.len();
    let gcol_total = node_gcol.len() + rel_gcol.len();
    let ratio = csv_total as f64 / gcol_total as f64;

    println!(
        "\n=== gcol vs CSV size on a {N}-node low-cardinality graph ===\n\
         nodes: CSV {:>9} B  ->  gcol {:>9} B  ({:.2}x)\n\
         rels:  CSV {:>9} B  ->  gcol {:>9} B  ({:.2}x)\n\
         total: CSV {:>9} B  ->  gcol {:>9} B  ({:.2}x smaller)\n",
        dumped_nodes.len(),
        node_gcol.len(),
        dumped_nodes.len() as f64 / node_gcol.len() as f64,
        dumped_rels.len(),
        rel_gcol.len(),
        dumped_rels.len() as f64 / rel_gcol.len() as f64,
        csv_total,
        gcol_total,
        ratio,
    );

    assert!(
        gcol_total < csv_total,
        "gcol ({gcol_total} B) must be strictly smaller than CSV ({csv_total} B) on low-cardinality data"
    );
}

// =================================================================================================
// 4. Property-based losslessness: a generated CSV transcodes byte-identically
// =================================================================================================

mod prop {
    use super::{csv_to_gcol, gcol_to_csv};
    use proptest::prelude::*;

    /// One generated node row: (external id, label selector, name, optional age, optional ratio).
    type Row = (u32, u8, String, Option<i64>, Option<f64>);

    /// Builds a node CSV from generated rows, rendering each scalar the way the dumper does (so it
    /// stays in the codecs' canonical form where applicable) and leaving some cells empty to exercise
    /// the present/absent bitmap.
    fn render_csv(rows: &[Row]) -> String {
        let mut s = String::from("id:ID,:LABEL,name:string,age:int,ratio:float\n");
        for (id, label_sel, name, age, ratio) in rows {
            let label = match label_sel % 3 {
                0 => "Person",
                1 => "Admin",
                _ => "", // empty label cell
            };
            let age_cell = age.map(|a| a.to_string()).unwrap_or_default();
            let ratio_cell = ratio.map(|r| r.to_string()).unwrap_or_default();
            // `name` is constrained to safe chars (no delimiter/quote/newline/leading formula sigil)
            // so it renders verbatim; the dedicated quoting test covers the quoting path.
            s.push_str(&format!("n{id},{label},{name},{age_cell},{ratio_cell}\n"));
        }
        s
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn generated_csv_round_trips_byte_identically(
            rows in proptest::collection::vec(
                (
                    any::<u32>(),
                    any::<u8>(),
                    "[a-zA-Z][a-zA-Z0-9_]{0,12}",
                    proptest::option::of(any::<i64>()),
                    proptest::option::of(any::<f64>().prop_filter("finite", |f| f.is_finite())),
                ),
                0..40usize,
            )
        ) {
            let csv = render_csv(&rows);
            let gcol = csv_to_gcol(csv.as_bytes(), b',').expect("encode");
            let back = gcol_to_csv(&gcol).expect("decode");
            prop_assert_eq!(
                back.as_slice(),
                csv.as_bytes(),
                "csv->gcol->csv must be byte-identical",
            );
        }
    }
}
