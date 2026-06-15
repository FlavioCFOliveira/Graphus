//! `graphus-bulk` — offline high-throughput CSV **bulk import** and whole-graph **export** for
//! Graphus (FR-BK; `rmp` task #22).
//!
//! This crate complements the in-query [`LOAD CSV`](../graphus_cypher/index.html) clause (transactional
//! ad-hoc ingestion) with the *offline* data-loading path: a fast importer that builds a **fresh**
//! [`RecordStore`](graphus_storage::RecordStore) directly through the low-level store API, and a
//! dumper that serialises a whole store back to the same CSV format — so a dump → import round-trips
//! to an identical graph.
//!
//! # Why a separate crate
//!
//! Keeping the importer/dumper here (not in `graphus-storage`) keeps the `csv` dependency and the
//! file-handling out of the storage core. The dependency edge is acyclic: `graphus-bulk` depends on
//! `graphus-storage`, never the reverse.
//!
//! # CSV format (`neo4j-admin import`-flavoured)
//!
//! - **Node file** — header declares one id column `<name>:ID`, an optional `:LABEL` column (a
//!   `;`-separated label set per row), and typed property columns `<key>:<type>` (`string`, `int`,
//!   `float`, `boolean`, and their `<type>[]` array forms). See [`header`].
//! - **Relationship file** — header declares `:START_ID`, `:END_ID`, `:TYPE`, and typed property
//!   columns. The `:START_ID`/`:END_ID` cells match node `:ID` values.
//!
//! # Example
//!
//! ```
//! use graphus_bulk::{BulkImporter, DEFAULT_BATCH_SIZE, dump_nodes, dump_relationships};
//! use graphus_io::MemBlockDevice;
//! use graphus_storage::RecordStore;
//! use graphus_wal::{MemLogSink, WalManager};
//!
//! // A fresh in-memory store.
//! let device = MemBlockDevice::new(0);
//! let wal = WalManager::create(MemLogSink::new()).unwrap();
//! let store = RecordStore::create(device, wal, 64, 1).unwrap();
//!
//! // Import two nodes and one relationship from in-memory CSV.
//! let nodes = "id:ID,:LABEL,name:string,age:int\n1,Person,Alice,30\n2,Person,Bob,25\n";
//! let rels = ":START_ID,:END_ID,:TYPE,since:int\n1,2,KNOWS,2010\n";
//! let mut importer = BulkImporter::new(store, DEFAULT_BATCH_SIZE, b',');
//! importer.import_nodes(nodes.as_bytes()).unwrap();
//! importer.import_relationships(rels.as_bytes()).unwrap();
//! let (mut store, stats) = importer.finish();
//! assert_eq!(stats.nodes, 2);
//! assert_eq!(stats.relationships, 1);
//!
//! // Dump it back out to CSV (round-trippable by the importer).
//! let mut node_csv = Vec::new();
//! let mut rel_csv = Vec::new();
//! dump_nodes(&mut store, &mut node_csv).unwrap();
//! dump_relationships(&mut store, &mut rel_csv).unwrap();
//! assert!(String::from_utf8(node_csv).unwrap().contains(":ID"));
//! ```
#![forbid(unsafe_code)]

pub mod dump;
pub mod header;
pub mod import;
pub mod value_parse;

pub use dump::{dump_nodes, dump_relationships};
pub use header::{ColumnRole, HeaderError, NodeHeader, PropertyType, RelHeader, ScalarType};
pub use import::{BulkImporter, DEFAULT_BATCH_SIZE, DuplicatePolicy, ImportStats};
pub use value_parse::ValueParseError;
