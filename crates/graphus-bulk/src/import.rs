//! The offline **bulk importer** (FR-BK; `rmp` task #22): high-throughput ingestion of node and
//! relationship CSV files into a **fresh** [`RecordStore`], writing **directly through the low-level
//! store API** (bypassing the Cypher pipeline) with **batched commits**.
//!
//! # Why bypass Cypher
//!
//! The in-query [`LOAD CSV`](../../graphus_cypher/index.html) clause is transactional and goes through
//! the full parse→plan→execute pipeline — correct for ad-hoc ingestion, but per-row planning and the
//! executor's row model are overhead a one-shot offline load does not need. The bulk importer instead
//! calls [`RecordStore::create_node`] / [`RecordStore::set_node_labels`] /
//! [`RecordStore::set_node_property_value`] / [`RecordStore::create_rel`] /
//! [`RecordStore::set_rel_property_value`] directly, committing every `batch_size` rows. This is the
//! initial-load fast path; throughput is reported by [`ImportStats`].
//!
//! # Two passes
//!
//! 1. **Nodes** — for each node CSV, create a node per record, set its labels (the `:LABEL` cell) and
//!    typed properties, and record `external :ID → physical node id` in a map.
//! 2. **Relationships** — for each relationship CSV, look up the `:START_ID`/`:END_ID` external ids in
//!    that map and create the relationship with its `:TYPE` and typed properties.
//!
//! Each pass streams its file record-by-record (never slurped), so file size is bounded by disk, not
//! memory; the only in-memory structure is the id map (one entry per node), which a relationship pass
//! fundamentally requires.

use std::collections::HashMap;
use std::io::Read;

use graphus_core::{Result, TxnId};
use graphus_io::BlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::LogSink;

use crate::header::{ColumnRole, NodeHeader, RelHeader};
use crate::value_parse::parse_cell;

/// How many CSV records to ingest per transaction before committing.
///
/// Batching amortises the per-commit catalog checkpoint + WAL fsync over many rows (the dominant
/// cost of a tiny transaction), which is what makes bulk load fast; a larger batch trades a bigger
/// redo window on a crash for higher throughput. The catalog scales past 1000 pages (`rmp` task
/// #51), so a large batch commits fine.
pub const DEFAULT_BATCH_SIZE: usize = 10_000;

/// Cumulative statistics of a bulk import, including the wall-clock throughput.
#[derive(Debug, Clone, Copy, Default)]
pub struct ImportStats {
    /// Total nodes created.
    pub nodes: u64,
    /// Total relationships created.
    pub relationships: u64,
    /// Total properties set (across nodes and relationships).
    pub properties: u64,
    /// Wall-clock seconds spent in the node pass.
    pub node_seconds: f64,
    /// Wall-clock seconds spent in the relationship pass.
    pub rel_seconds: f64,
}

impl ImportStats {
    /// Nodes ingested per second over the node pass (`0.0` if the pass took no measurable time).
    #[must_use]
    pub fn nodes_per_sec(&self) -> f64 {
        if self.node_seconds > 0.0 {
            self.nodes as f64 / self.node_seconds
        } else {
            0.0
        }
    }

    /// Relationships ingested per second over the relationship pass.
    #[must_use]
    pub fn rels_per_sec(&self) -> f64 {
        if self.rel_seconds > 0.0 {
            self.relationships as f64 / self.rel_seconds
        } else {
            0.0
        }
    }
}

/// A streaming bulk importer over a fresh [`RecordStore`].
///
/// Generic over the block device `D` and WAL sink `S` so the same loader drives an in-memory store
/// (tests / benches) or a file-backed one (the CLI). Construct with [`new`](Self::new), run
/// [`import_nodes`](Self::import_nodes) for every node file, then
/// [`import_relationships`](Self::import_relationships) for every relationship file, and finish with
/// [`finish`](Self::finish) to recover the store and the [`ImportStats`].
pub struct BulkImporter<D: BlockDevice, S: LogSink> {
    store: RecordStore<D, S>,
    /// External `:ID` → physical node id, populated by the node pass and read by the rel pass.
    id_map: HashMap<String, u64>,
    /// The next transaction id to use (monotonic; bulk load is single-threaded).
    next_txn: u64,
    /// Rows per committed transaction.
    batch_size: usize,
    /// The byte delimiter for every CSV read (default `,`).
    delimiter: u8,
    stats: ImportStats,
}

impl<D: BlockDevice, S: LogSink> BulkImporter<D, S> {
    /// Creates an importer over `store` (expected to be freshly [`RecordStore::create`]d / empty),
    /// committing every `batch_size` rows (pass [`DEFAULT_BATCH_SIZE`] for the default) and reading
    /// CSV with the field separator `delimiter` (e.g. `b','`).
    pub fn new(store: RecordStore<D, S>, batch_size: usize, delimiter: u8) -> Self {
        Self {
            store,
            id_map: HashMap::new(),
            next_txn: 1,
            batch_size: batch_size.max(1),
            delimiter,
            stats: ImportStats::default(),
        }
    }

    /// A CSV reader builder configured with this importer's delimiter, treating the first record as a
    /// header (we read it explicitly to decode the schema).
    fn reader_builder(&self) -> csv::ReaderBuilder {
        let mut b = csv::ReaderBuilder::new();
        b.has_headers(false)
            .delimiter(self.delimiter)
            .flexible(true);
        b
    }

    /// Imports one node CSV file from `reader`, streaming its records into fresh nodes.
    ///
    /// The first record is the header (decoded by [`NodeHeader`]); each subsequent record creates one
    /// node, sets its `:LABEL` set and typed properties, and binds its `:ID` in the id map for the
    /// relationship pass. Commits every `batch_size` nodes.
    ///
    /// # Errors
    ///
    /// Returns a storage / header / value-parse error (all converted to [`graphus_core::GraphusError`])
    /// on a malformed header, an unparseable typed cell, or a store write failure. On error the
    /// current batch's transaction is rolled back, leaving the store consistent.
    pub fn import_nodes<R: Read>(&mut self, reader: R) -> Result<()> {
        let start = std::time::Instant::now();
        let mut csv_reader = self.reader_builder().from_reader(reader);

        let mut header_record = csv::StringRecord::new();
        if !csv_reader
            .read_record(&mut header_record)
            .map_err(csv_err)?
        {
            return Ok(()); // empty file: nothing to import
        }
        let header =
            NodeHeader::parse(header_record.iter()).map_err(graphus_core::GraphusError::from)?;

        let mut txn = self.begin_batch();
        let mut in_batch = 0usize;
        let mut record = csv::StringRecord::new();
        loop {
            let more = match csv_reader.read_record(&mut record) {
                Ok(more) => more,
                Err(e) => {
                    self.rollback(txn);
                    return Err(csv_err(e));
                }
            };
            if !more {
                break;
            }
            if let Err(e) = self.ingest_node_record(txn, &header, &record) {
                self.rollback(txn);
                return Err(e);
            }
            in_batch += 1;
            if in_batch >= self.batch_size {
                self.store.commit(txn)?;
                txn = self.begin_batch();
                in_batch = 0;
            }
        }
        // Commit the final (possibly partial) batch.
        self.store.commit(txn)?;
        self.stats.node_seconds += start.elapsed().as_secs_f64();
        Ok(())
    }

    /// Ingests one node record under `txn`: create the node, set labels + typed properties, and map
    /// its external id.
    fn ingest_node_record(
        &mut self,
        txn: TxnId,
        header: &NodeHeader,
        record: &csv::StringRecord,
    ) -> Result<()> {
        let (node_id, _eid) = self.store.create_node(txn)?;

        // External id (the join key for relationships).
        let external_id = record.get(header.id_index).unwrap_or("").to_owned();

        // Collect labels first (a single `set_node_labels` write), then properties.
        let mut label_tokens: Vec<u32> = Vec::new();
        for (i, role) in header.columns.iter().enumerate() {
            let cell = record.get(i).unwrap_or("");
            match role {
                ColumnRole::Label => {
                    for label in cell.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                        let token = self.store.intern_token(Namespace::Label, label)?;
                        if !label_tokens.contains(&token) {
                            label_tokens.push(token);
                        }
                    }
                }
                ColumnRole::Property { key, ty } => {
                    if let Some(value) =
                        parse_cell(cell, *ty, key).map_err(graphus_core::GraphusError::from)?
                    {
                        let key_token = self.store.intern_token(Namespace::PropKey, key)?;
                        self.store
                            .set_node_property_value(txn, node_id, key_token, &value)?;
                        self.stats.properties += 1;
                    }
                }
                // `:ID` is consumed via `header.id_index`; reserved rel roles never appear in a node
                // header; `Ignore` columns are skipped.
                ColumnRole::Id
                | ColumnRole::StartId
                | ColumnRole::EndId
                | ColumnRole::Type
                | ColumnRole::Ignore => {}
            }
        }
        if !label_tokens.is_empty() {
            self.store.set_node_labels(txn, node_id, &label_tokens)?;
        }

        // Bind the external id last (after a successful write): a duplicate id keeps the latest, like
        // a re-`CREATE`; an empty id column still maps (the empty string key) so anonymous nodes load.
        self.id_map.insert(external_id, node_id);
        self.stats.nodes += 1;
        Ok(())
    }

    /// Imports one relationship CSV file from `reader`, joining `:START_ID`/`:END_ID` against the id
    /// map built by the node pass.
    ///
    /// # Errors
    ///
    /// Returns an error on a malformed header, an unknown endpoint id (a `:START_ID`/`:END_ID` with no
    /// matching node), an unparseable typed cell, or a store write failure. The current batch's
    /// transaction is rolled back on error.
    pub fn import_relationships<R: Read>(&mut self, reader: R) -> Result<()> {
        let start = std::time::Instant::now();
        let mut csv_reader = self.reader_builder().from_reader(reader);

        let mut header_record = csv::StringRecord::new();
        if !csv_reader
            .read_record(&mut header_record)
            .map_err(csv_err)?
        {
            return Ok(());
        }
        let header =
            RelHeader::parse(header_record.iter()).map_err(graphus_core::GraphusError::from)?;

        let mut txn = self.begin_batch();
        let mut in_batch = 0usize;
        let mut record = csv::StringRecord::new();
        loop {
            let more = match csv_reader.read_record(&mut record) {
                Ok(more) => more,
                Err(e) => {
                    self.rollback(txn);
                    return Err(csv_err(e));
                }
            };
            if !more {
                break;
            }
            if let Err(e) = self.ingest_rel_record(txn, &header, &record) {
                self.rollback(txn);
                return Err(e);
            }
            in_batch += 1;
            if in_batch >= self.batch_size {
                self.store.commit(txn)?;
                txn = self.begin_batch();
                in_batch = 0;
            }
        }
        self.store.commit(txn)?;
        self.stats.rel_seconds += start.elapsed().as_secs_f64();
        Ok(())
    }

    /// Ingests one relationship record under `txn`: resolve endpoints, create the relationship, set
    /// its typed properties.
    fn ingest_rel_record(
        &mut self,
        txn: TxnId,
        header: &RelHeader,
        record: &csv::StringRecord,
    ) -> Result<()> {
        let start_ext = record.get(header.start_index).unwrap_or("");
        let end_ext = record.get(header.end_index).unwrap_or("");
        let type_name = record.get(header.type_index).unwrap_or("");

        let start_id = *self.id_map.get(start_ext).ok_or_else(|| {
            graphus_core::GraphusError::Storage(format!(
                "relationship references unknown :START_ID `{start_ext}` (no such node)"
            ))
        })?;
        let end_id = *self.id_map.get(end_ext).ok_or_else(|| {
            graphus_core::GraphusError::Storage(format!(
                "relationship references unknown :END_ID `{end_ext}` (no such node)"
            ))
        })?;
        let type_token = self.store.intern_token(Namespace::RelType, type_name)?;
        let (rel_id, _eid) = self.store.create_rel(txn, type_token, start_id, end_id)?;

        for (i, role) in header.columns.iter().enumerate() {
            if let ColumnRole::Property { key, ty } = role {
                let cell = record.get(i).unwrap_or("");
                if let Some(value) =
                    parse_cell(cell, *ty, key).map_err(graphus_core::GraphusError::from)?
                {
                    let key_token = self.store.intern_token(Namespace::PropKey, key)?;
                    self.store
                        .set_rel_property_value(txn, rel_id, key_token, &value)?;
                    self.stats.properties += 1;
                }
            }
        }
        self.stats.relationships += 1;
        Ok(())
    }

    /// Begins the next batch transaction and returns its id.
    fn begin_batch(&mut self) -> TxnId {
        let txn = TxnId(self.next_txn);
        self.next_txn += 1;
        self.store.begin(txn);
        txn
    }

    /// Best-effort rollback of a failed batch (the error being returned is the primary failure).
    fn rollback(&mut self, txn: TxnId) {
        let _ = self.store.rollback(txn);
    }

    /// Finishes the import, returning the populated store and the cumulative [`ImportStats`].
    #[must_use]
    pub fn finish(self) -> (RecordStore<D, S>, ImportStats) {
        (self.store, self.stats)
    }

    /// The statistics accumulated so far (without consuming the importer).
    #[must_use]
    pub fn stats(&self) -> ImportStats {
        self.stats
    }
}

/// Converts a `csv` crate error into a [`graphus_core::GraphusError`].
fn csv_err(e: csv::Error) -> graphus_core::GraphusError {
    graphus_core::GraphusError::Storage(format!("bulk-import CSV read: {e}"))
}
