//! An **id-independent content hash** of a populated [`RecordStore`], used to prove a bulk
//! `import -> dump -> re-import` round-trip is **lossless**.
//!
//! # Why a content hash (not a byte diff of the store files)
//!
//! Two stores that hold the *same graph* are **not** byte-identical on disk: physical node/rel ids,
//! free-list state, page layout, and WAL contents all differ between an original load and a re-load
//! of its dump. The round-trip guarantee is *logical* — same labels, same relationship types, same
//! property values, same connectivity — independent of physical id assignment. So we canonicalise the
//! graph into an **order-independent, id-independent** digest:
//!
//! - each node becomes a record of its sorted label set + its sorted `(key, value)` property pairs;
//! - each relationship becomes a record of its type + the *shapes* of its two endpoints + its sorted
//!   property pairs (endpoints by shape, never by physical id);
//! - every per-node and per-relationship record is hashed, the hashes are **sorted** (so scan order
//!   is irrelevant), and a single rolling digest is folded over the sorted hashes.
//!
//! This is exactly the equivalence the crate's own `tests/import_dump.rs` round-trip asserts, reduced
//! to one comparable 128-bit hex string so a driver can print "before == after" as evidence.
//!
//! The hash function is a hand-rolled FNV-1a-style 128-bit fold over the canonical byte stream: it is
//! dependency-free, deterministic across platforms, and has no cryptographic claims (it is a
//! *content fingerprint* for equality, not a security primitive). Collisions are astronomically
//! unlikely for these inputs, and a [`ContentHash`] mismatch is conclusive proof of divergence.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;

use graphus_core::Value;
use graphus_io::BlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::LogSink;

/// A 128-bit content fingerprint of a graph's logical contents, rendered as a 32-char hex string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentHash {
    /// The fingerprint as a lowercase hex string.
    pub hex: String,
    /// The number of nodes folded in (a quick cross-check alongside the hash).
    pub nodes: u64,
    /// The number of relationships folded in.
    pub relationships: u64,
}

/// A 128-bit FNV-1a-style hasher (two 64-bit lanes mixed independently then combined). Deterministic,
/// dependency-free, no cryptographic claim — a content fingerprint for equality.
#[derive(Debug, Clone, Copy)]
struct Fnv128 {
    lo: u64,
    hi: u64,
}

impl Fnv128 {
    const PRIME_LO: u64 = 0x0000_0100_0000_01B3; // FNV-1a 64-bit prime
    const PRIME_HI: u64 = 0x9E37_79B9_7F4A_7C15; // a distinct odd multiplier for the second lane

    fn new() -> Self {
        Self {
            lo: 0xCBF2_9CE4_8422_2325, // FNV-1a 64-bit offset basis
            hi: 0x1234_5678_9ABC_DEF0,
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.lo = (self.lo ^ u64::from(b)).wrapping_mul(Self::PRIME_LO);
            // Feed the running lo into the hi lane so the two lanes are not independent of order.
            self.hi = (self.hi ^ u64::from(b) ^ (self.lo >> 7)).wrapping_mul(Self::PRIME_HI);
        }
        // A length-sensitive separator so concatenations of different shapes cannot alias.
        self.lo ^= bytes.len() as u64;
    }

    /// The combined 128-bit value.
    fn finish128(self) -> u128 {
        (u128::from(self.hi) << 64) | u128::from(self.lo)
    }
}

/// The canonical structural shape of one node: sorted labels + sorted `(key, value-repr)` pairs.
fn node_shape_bytes<D: BlockDevice, S: LogSink>(store: &mut RecordStore<D, S>, id: u64) -> Vec<u8> {
    let mut labels: Vec<String> = store
        .node_labels(id)
        .expect("labels")
        .into_iter()
        .map(|t| store.token_name(Namespace::Label, t).unwrap().to_owned())
        .collect();
    labels.sort();

    // Newest-wins per key (the property chain is prepend-ordered), then sorted by key.
    let mut by_key: BTreeMap<String, String> = BTreeMap::new();
    let mut seen: HashSet<u32> = HashSet::new();
    for (_pid, key_token, value) in store.node_property_values(id).expect("props") {
        if seen.insert(key_token) && !is_empty_value(&value) {
            let key = store
                .token_name(Namespace::PropKey, key_token)
                .unwrap()
                .to_owned();
            by_key.insert(key, value_repr(&value));
        }
    }

    let mut buf = String::with_capacity(64);
    buf.push_str("L:");
    buf.push_str(&labels.join(";"));
    buf.push_str("|P:");
    for (k, v) in &by_key {
        let _ = write!(buf, "{k}={v};");
    }
    buf.into_bytes()
}

/// A total, exact textual rendering of a [`Value`] for hashing (floats by their `Debug` bit-exact
/// form — sound because the importer parses the same text on both sides of the round-trip).
fn value_repr(v: &Value) -> String {
    format!("{v:?}")
}

/// Whether a property value is the **present-but-empty** sentinel that a dump → re-import introduces.
///
/// `graphus-bulk dump` unifies every property key across all node labels into a single CSV file, so a
/// node is written with EMPTY cells for keys other labels carry. On re-import, graphus-bulk's value
/// semantics turn an empty `string` cell into `Value::String("")` and an empty `string[]` cell into
/// `Value::List([])` (a present-but-empty property), whereas the original node never had that key at
/// all. Treating these empties as *absent* makes the canonical content shape invariant to the dump's
/// column-unification, so a lossless round-trip hashes identically. (Non-string scalars are never
/// affected: the importer already treats an empty `int`/`float`/`boolean` cell as absent.)
fn is_empty_value(v: &Value) -> bool {
    match v {
        Value::String(s) => s.is_empty(),
        Value::List(items) => items.is_empty(),
        _ => false,
    }
}

/// Computes the id-independent [`ContentHash`] of every node and relationship in `store`.
///
/// # Panics
///
/// Panics if the store's low-level scans fail — these are infallible on a consistent store and a
/// failure here means the store is corrupt (the round-trip driver verifies consistency separately).
#[must_use]
pub fn content_hash<D: BlockDevice, S: LogSink>(store: &mut RecordStore<D, S>) -> ContentHash {
    // --- Node record hashes (sorted, so scan order is irrelevant). ---
    let node_ids = store.scan_node_ids().expect("scan node ids");
    let nodes = node_ids.len() as u64;
    let mut node_hashes: Vec<u128> = Vec::with_capacity(node_ids.len());
    for id in &node_ids {
        let mut h = Fnv128::new();
        h.write(b"NODE\x00");
        h.write(&node_shape_bytes(store, *id));
        node_hashes.push(h.finish128());
    }
    node_hashes.sort_unstable();

    // --- Relationship record hashes (type + endpoint shapes + props), sorted. ---
    let rel_ids = store.scan_rel_ids().expect("scan rel ids");
    let relationships = rel_ids.len() as u64;
    let mut rel_hashes: Vec<u128> = Vec::with_capacity(rel_ids.len());
    for id in &rel_ids {
        let rec = store.rel(*id).expect("rel");
        let rel_type = store
            .token_name(Namespace::RelType, rec.type_id)
            .unwrap()
            .to_owned();
        let start_shape = node_shape_bytes(store, rec.start_node);
        let end_shape = node_shape_bytes(store, rec.end_node);

        let mut by_key: BTreeMap<String, String> = BTreeMap::new();
        let mut seen: HashSet<u32> = HashSet::new();
        for (_pid, key_token, value) in store.rel_property_values(*id).expect("rel props") {
            if seen.insert(key_token) && !is_empty_value(&value) {
                let key = store
                    .token_name(Namespace::PropKey, key_token)
                    .unwrap()
                    .to_owned();
                by_key.insert(key, value_repr(&value));
            }
        }

        let mut h = Fnv128::new();
        h.write(b"REL\x00");
        h.write(rel_type.as_bytes());
        h.write(b"\x00S:");
        h.write(&start_shape);
        h.write(b"\x00E:");
        h.write(&end_shape);
        h.write(b"\x00P:");
        for (k, v) in &by_key {
            h.write(k.as_bytes());
            h.write(b"=");
            h.write(v.as_bytes());
            h.write(b";");
        }
        rel_hashes.push(h.finish128());
    }
    rel_hashes.sort_unstable();

    // --- Fold the sorted record hashes into one digest. ---
    let mut digest = Fnv128::new();
    digest.write(b"GRAPHUS-BULK-ETL-CONTENT-HASH-v1\x00");
    for nh in &node_hashes {
        digest.write(&nh.to_le_bytes());
    }
    digest.write(b"||REL||");
    for rh in &rel_hashes {
        digest.write(&rh.to_le_bytes());
    }
    let value = digest.finish128();

    ContentHash {
        hex: format!("{value:032x}"),
        nodes,
        relationships,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_bulk::{BulkImporter, DEFAULT_BATCH_SIZE, dump_nodes, dump_relationships};
    use graphus_io::MemBlockDevice;
    use graphus_wal::{MemLogSink, WalManager};

    type Store = RecordStore<MemBlockDevice, MemLogSink>;

    fn fresh_store() -> Store {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        RecordStore::create(device, wal, 128, 1).expect("create store")
    }

    fn load(nodes: &str, rels: &str) -> Store {
        let mut imp = BulkImporter::new(fresh_store(), DEFAULT_BATCH_SIZE, b',');
        imp.import_nodes(nodes.as_bytes()).expect("import nodes");
        imp.import_relationships(rels.as_bytes())
            .expect("import rels");
        imp.finish().0
    }

    const NODES: &str = "id:ID,:LABEL,name:string,age:int,tags:string[]\n\
                         a,Person,Ada,36,x;y\n\
                         b,Person,Bob,28,\n\
                         c,Person;Admin,Cara,41,z\n";
    const RELS: &str = ":START_ID,:END_ID,:TYPE,since:int\n\
                        a,b,KNOWS,2010\n\
                        b,c,KNOWS,2015\n";

    #[test]
    fn round_trip_through_dump_preserves_the_content_hash() {
        let mut original = load(NODES, RELS);
        let before = content_hash(&mut original);

        // Dump, then re-import into a fresh store.
        let mut node_csv = Vec::new();
        let mut rel_csv = Vec::new();
        dump_nodes(&mut original, &mut node_csv).expect("dump nodes");
        dump_relationships(&mut original, &mut rel_csv).expect("dump rels");

        let mut imp = BulkImporter::new(fresh_store(), DEFAULT_BATCH_SIZE, b',');
        imp.import_nodes(node_csv.as_slice())
            .expect("re-import nodes");
        imp.import_relationships(rel_csv.as_slice())
            .expect("re-import rels");
        let mut restored = imp.finish().0;
        let after = content_hash(&mut restored);

        assert_eq!(before.hex, after.hex, "content hash must round-trip");
        assert_eq!(before.nodes, 3);
        assert_eq!(before.relationships, 2);
    }

    #[test]
    fn a_different_graph_has_a_different_hash() {
        let mut g1 = load(NODES, RELS);
        // Change one property value.
        let altered = NODES.replace("Ada,36", "Ada,99");
        let mut g2 = load(&altered, RELS);
        assert_ne!(
            content_hash(&mut g1).hex,
            content_hash(&mut g2).hex,
            "a changed property must change the hash"
        );
    }

    #[test]
    fn hash_is_independent_of_node_insertion_order() {
        // The same logical graph loaded with rows in a different order hashes identically.
        let reordered = "id:ID,:LABEL,name:string,age:int,tags:string[]\n\
                         c,Person;Admin,Cara,41,z\n\
                         a,Person,Ada,36,x;y\n\
                         b,Person,Bob,28,\n";
        let mut g1 = load(NODES, RELS);
        let mut g2 = load(reordered, RELS);
        assert_eq!(content_hash(&mut g1).hex, content_hash(&mut g2).hex);
    }
}
