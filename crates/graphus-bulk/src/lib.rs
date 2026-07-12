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

/// The record-store device file an offline `graphus-bulk import` writes inside its `--db` directory.
///
/// The offline layout deliberately differs from the server's (`graphus.store`/`graphus.wal`): a
/// `graphus-bulk` `--db` directory is a standalone import artifact, not a server data root. The
/// server's `adopt` path (`rmp` #681) reads these two names to relocate an imported store into a
/// server-servable database directory, so they are exported here as the single source of truth for
/// the offline on-disk names (the `graphus-bulk` CLI's own `--db` layout uses them too).
pub const IMPORT_STORE_FILE_NAME: &str = "graph.store";

/// The WAL directory an offline `graphus-bulk import` writes inside its `--db` directory (a segmented
/// directory of an `anchor` + `seg.<base>` files — `rmp` #116). See [`IMPORT_STORE_FILE_NAME`].
pub const IMPORT_WAL_DIR_NAME: &str = "graph.wal";

pub mod columnar;
pub mod dump;
pub mod header;
pub mod import;
pub mod pool_sizing;
pub mod row_parse;
pub mod value_parse;

pub use columnar::{ColumnarError, csv_to_gcol, gcol_to_csv, gcol_to_csv_limited};
pub use dump::{dump_nodes, dump_relationships};
pub use header::{ColumnRole, HeaderError, NodeHeader, PropertyType, RelHeader, ScalarType};
pub use import::{
    BulkImporter, DEFAULT_BATCH_SIZE, DuplicatePolicy, ImportStats, ingest_node_row,
    ingest_rel_row, intern_property_key_tokens,
};
// Adaptive buffer-pool sizing (`rmp` #718): the offline loader sizes its pool to the store it is
// about to build (import) or open (dump), so the random-access relationship phase never thrashes.
pub use pool_sizing::{
    InputFormatHint, auto_pool_pages_for_input, auto_pool_pages_for_store, ram_ceiling_pages,
};
// `row_parse` (`rmp` #520): the store-independent CSV row-parsing helpers network bulk-import Mode B
// drives directly (never `ingest_node_row`/`ingest_rel_row`, which write through a raw `RecordStore`).
pub use row_parse::{
    ParsedNodeRow, ParsedRelRow, RowParseError, parse_node_row, parse_node_row_with_limits,
    parse_rel_row, parse_rel_row_with_limits,
};
// Pre-existing re-export gap (found while implementing `rmp` #520, fixed on the spot per CLAUDE.md's
// self-contained-development policy): `value_parse::parse_cell`/`parse_cell_with_limits`/`ParseLimits`
// were already `pub` in `value_parse.rs` but never re-exported at the crate root, forcing an external
// caller through the internal `graphus_bulk::value_parse::` path instead of the crate's normal
// re-export surface (every other public item in this module is re-exported this way).
pub use value_parse::ValueParseError;
pub use value_parse::{
    DEFAULT_MAX_ARRAY_ELEMS, DEFAULT_MAX_CELL_BYTES, ParseLimits, parse_cell,
    parse_cell_with_limits,
};
