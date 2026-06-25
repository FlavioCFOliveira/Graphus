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

use std::collections::{HashMap, HashSet};
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
    /// Node rows whose non-empty external `:ID` duplicated an earlier binding and were skipped under
    /// [`DuplicatePolicy::SkipDuplicate`] (always `0` under the strict default, which errors instead).
    pub skipped_duplicate_ids: u64,
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

/// How the importer reacts to a node row whose non-empty external `:ID` was already bound by an
/// earlier row (SEC-196, CWE-694).
///
/// A silently-overwritten id map is a data-integrity hazard: two physical nodes share an external
/// id but the map keeps only the last, so every relationship that references that id joins to the
/// *second* node, never the first — a corrupted import with no error. `neo4j-admin import` fails on
/// duplicate ids by default; Graphus mirrors that fail-closed stance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DuplicatePolicy {
    /// Reject a duplicate non-empty `:ID` with an error (the safe default).
    #[default]
    Strict,
    /// Keep the first binding and skip the duplicate row's id remap, counting it in
    /// [`ImportStats`]. The duplicate's node is still created (it is a real node), but it stays
    /// unreferenceable by external id. Use only when duplicate ids are known-benign.
    SkipDuplicate,
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
    /// How a duplicate non-empty external `:ID` is handled (SEC-196). Default: [`DuplicatePolicy::Strict`].
    duplicate_policy: DuplicatePolicy,
    stats: ImportStats,
}

impl<D: BlockDevice, S: LogSink> BulkImporter<D, S> {
    /// Creates an importer over `store` (expected to be freshly [`RecordStore::create`]d / empty),
    /// committing every `batch_size` rows (pass [`DEFAULT_BATCH_SIZE`] for the default) and reading
    /// CSV with the field separator `delimiter` (e.g. `b','`).
    ///
    /// Duplicate-`:ID` handling defaults to [`DuplicatePolicy::Strict`] (fail-closed); override with
    /// [`with_duplicate_policy`](Self::with_duplicate_policy).
    pub fn new(store: RecordStore<D, S>, batch_size: usize, delimiter: u8) -> Self {
        Self {
            store,
            id_map: HashMap::new(),
            next_txn: 1,
            batch_size: batch_size.max(1),
            delimiter,
            duplicate_policy: DuplicatePolicy::default(),
            stats: ImportStats::default(),
        }
    }

    /// Sets how the importer reacts to a duplicate non-empty external `:ID` (SEC-196). Returns
    /// `self` for builder-style chaining.
    #[must_use]
    pub fn with_duplicate_policy(mut self, policy: DuplicatePolicy) -> Self {
        self.duplicate_policy = policy;
        self
    }

    /// Borrows the underlying [`RecordStore`] — a test/DST hook (`rmp` #403 crash-recovery gate) for
    /// inspecting the durable WAL prefix mid-import without consuming the importer via
    /// [`finish`](Self::finish).
    #[doc(hidden)]
    #[must_use]
    pub fn store_ref_for_test(&self) -> &RecordStore<D, S> {
        &self.store
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
    /// # Performance: per-column token interning (`rmp` task #321)
    ///
    /// A property column's key is fixed for the whole file, so its `PropKey` token is interned **once**
    /// per column (here, before the row loop) and the resolved id is reused for every cell — instead of
    /// re-interning the same name on every row (a `HashMap` probe + UTF-8 hash per property cell, which
    /// at millions of rows × several columns dominated the node pass). Interning is idempotent by name
    /// (a name maps to exactly one id), so the per-column id is byte-for-byte the one the per-cell path
    /// produced. `:LABEL` cells vary per row (a `;`-separated set), so label tokens are memoised by name
    /// in a small per-pass cache rather than hoisted.
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
        // Intern every property column's key token ONCE (idempotent → same id as the per-cell path).
        // `prop_key_tokens[i]` is `Some(token)` iff column `i` is a `Property` column.
        let prop_key_tokens = self.resolve_property_key_tokens(&header.columns)?;
        // Per-pass label-name → token memo (label cells vary per row; this dedups re-interns).
        let mut label_tokens: HashMap<String, u32> = HashMap::new();

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
            if let Err(e) =
                self.ingest_node_record(txn, &header, &prop_key_tokens, &mut label_tokens, &record)
            {
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
    ///
    /// `prop_key_tokens[i]` carries the pre-interned `PropKey` token for column `i` (`Some` iff that
    /// column is a `Property`), interned once per file rather than per cell (`rmp` task #321).
    /// `label_memo` memoises label-name → token across rows so a repeated label is interned once.
    fn ingest_node_record(
        &mut self,
        txn: TxnId,
        header: &NodeHeader,
        prop_key_tokens: &[Option<u32>],
        label_memo: &mut HashMap<String, u32>,
        record: &csv::StringRecord,
    ) -> Result<()> {
        let (node_id, _eid) = self.store.create_node(txn)?;

        // External id (the join key for relationships).
        let external_id = record.get(header.id_index).unwrap_or("").to_owned();

        // Collect labels first (a single `set_node_labels` write), then properties.
        // PERF (C18): dedup via a `HashSet` (O(1) membership) instead of `Vec::contains` (O(n) per
        // probe, O(n^2) per row). `set_node_labels` treats labels as a set, so order is irrelevant.
        let mut label_set: HashSet<u32> = HashSet::new();
        for (i, role) in header.columns.iter().enumerate() {
            let cell = record.get(i).unwrap_or("");
            match role {
                ColumnRole::Label => {
                    for label in cell.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                        // Memoise label-name → token: intern once per distinct name, not per cell.
                        let token = match label_memo.get(label) {
                            Some(&t) => t,
                            None => {
                                let t = self.store.intern_token(Namespace::Label, label)?;
                                label_memo.insert(label.to_owned(), t);
                                t
                            }
                        };
                        label_set.insert(token);
                    }
                }
                ColumnRole::Property { key, ty } => {
                    if let Some(value) =
                        parse_cell(cell, *ty, key).map_err(graphus_core::GraphusError::from)?
                    {
                        // Reuse the per-column pre-interned key token (`rmp` task #321).
                        let key_token = prop_key_tokens[i].expect(
                            "INVARIANT: a Property column has a pre-interned PropKey token (#321)",
                        );
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
        if !label_set.is_empty() {
            let label_tokens: Vec<u32> = label_set.into_iter().collect();
            self.store.set_node_labels(txn, node_id, &label_tokens)?;
        }

        // Bind the external id last (after a successful write). SEC-196 (CWE-694): a duplicate
        // *non-empty* external id must not silently overwrite an earlier binding — that would
        // re-point every relationship referencing it onto the wrong node. Detect the collision and,
        // per the configured policy, either reject the import (strict, default) or keep the first
        // binding and count the skip. An *empty* id is the anonymous-node convention (no relationship
        // can reference it), so multiple anonymous nodes are allowed to share the empty key.
        if external_id.is_empty() {
            self.id_map.insert(external_id, node_id);
        } else if let Some(&existing) = self.id_map.get(&external_id) {
            match self.duplicate_policy {
                DuplicatePolicy::Strict => {
                    return Err(graphus_core::GraphusError::Storage(format!(
                        "bulk-import: duplicate :ID {external_id:?} (first bound to node {existing}, \
                         row {} would rebind to node {node_id}); relationships would join the wrong \
                         node. Deduplicate the input or use a skip-duplicate policy.",
                        self.stats.nodes + 1
                    )));
                }
                DuplicatePolicy::SkipDuplicate => {
                    // Keep the first binding; the duplicate's node exists but stays unreferenceable
                    // by external id. Count the skip for the operator.
                    self.stats.skipped_duplicate_ids += 1;
                }
            }
        } else {
            self.id_map.insert(external_id, node_id);
        }
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
        // Intern every property column's key token ONCE (idempotent → same id as per-cell). `:TYPE`
        // cells vary per row, so type tokens are memoised by name in a per-pass cache (`rmp` task #321).
        let prop_key_tokens = self.resolve_property_key_tokens(&header.columns)?;
        let mut type_memo: HashMap<String, u32> = HashMap::new();

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
            if let Err(e) =
                self.ingest_rel_record(txn, &header, &prop_key_tokens, &mut type_memo, &record)
            {
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
        prop_key_tokens: &[Option<u32>],
        type_memo: &mut HashMap<String, u32>,
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
        // Memoise rel-type-name → token: intern once per distinct type, not per row (`rmp` task #321).
        let type_token = match type_memo.get(type_name) {
            Some(&t) => t,
            None => {
                let t = self.store.intern_token(Namespace::RelType, type_name)?;
                type_memo.insert(type_name.to_owned(), t);
                t
            }
        };
        let (rel_id, _eid) = self.store.create_rel(txn, type_token, start_id, end_id)?;

        for (i, role) in header.columns.iter().enumerate() {
            if let ColumnRole::Property { key, ty } = role {
                let cell = record.get(i).unwrap_or("");
                if let Some(value) =
                    parse_cell(cell, *ty, key).map_err(graphus_core::GraphusError::from)?
                {
                    // Reuse the per-column pre-interned key token (`rmp` task #321).
                    let key_token = prop_key_tokens[i].expect(
                        "INVARIANT: a Property column has a pre-interned PropKey token (#321)",
                    );
                    self.store
                        .set_rel_property_value(txn, rel_id, key_token, &value)?;
                    self.stats.properties += 1;
                }
            }
        }
        self.stats.relationships += 1;
        Ok(())
    }

    /// Interns every `Property` column's key token once and returns a vector aligned with `columns`:
    /// `out[i]` is `Some(token)` iff column `i` is a [`ColumnRole::Property`], else `None` (`rmp` task
    /// #321). Because token interning is idempotent by name (a name maps to exactly one id), the token
    /// resolved here for a column equals the one a per-cell intern would have produced on every row —
    /// so reusing it is content-identical while interning the key exactly once per file rather than
    /// once per cell.
    ///
    /// # Errors
    ///
    /// Propagates a store write failure from interning a new property-key token.
    fn resolve_property_key_tokens(&mut self, columns: &[ColumnRole]) -> Result<Vec<Option<u32>>> {
        let mut out = Vec::with_capacity(columns.len());
        for role in columns {
            match role {
                ColumnRole::Property { key, .. } => {
                    out.push(Some(self.store.intern_token(Namespace::PropKey, key)?));
                }
                _ => out.push(None),
            }
        }
        Ok(out)
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
