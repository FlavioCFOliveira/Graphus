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

use graphus_core::{Result, TxnId, Value};
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
    ///
    /// Only holds bindings from **committed** batches (`rmp` #517) — see [`Self::pending_id_map`].
    id_map: HashMap<String, u64>,
    /// External `:ID` → physical node id bindings staged by the *current, not-yet-committed* batch
    /// (`rmp` #517: `bulk-idmap-not-abort-safe`).
    ///
    /// A batch's rows are written to the store speculatively and only become durable when the batch's
    /// transaction commits; the physical ids created by a rolled-back batch cease to exist in the
    /// store. Staging id-map bindings here (instead of directly in `id_map`) and merging them only on
    /// a successful [`Self::commit_batch`] keeps the two in lock-step: a batch that aborts leaves
    /// `id_map` exactly as if it had never run, so a *retried* batch (a future network bulk-import
    /// retry, or simply calling the node pass again over the same rows) never resolves an external id
    /// to a ghost physical id that the store has already rolled back.
    pending_id_map: HashMap<String, u64>,
    /// `stats` as of the start of the in-flight batch (`rmp` #517), restored verbatim on rollback (or
    /// a failed commit) so per-row counters (`nodes`, `relationships`, `properties`,
    /// `skipped_duplicate_ids`) never count rows from a batch that did not durably commit.
    batch_start_stats: ImportStats,
    /// The next transaction id to use (monotonic; bulk load is single-threaded).
    next_txn: u64,
    /// Rows per committed transaction.
    batch_size: usize,
    /// The byte delimiter for every CSV read (default `,`).
    delimiter: u8,
    /// How a duplicate non-empty external `:ID` is handled (SEC-196). Default: [`DuplicatePolicy::Strict`].
    duplicate_policy: DuplicatePolicy,
    /// Whether each node's external `:ID` is also persisted as a queryable **string node property**
    /// named after the `:ID` column (`rmp` #681). `false` by default: the external id stays a physical
    /// join key only, so the durable graph — and a dump → import round-trip — is byte-identical to the
    /// pre-#681 importer. Enabled via [`with_persist_id`](Self::with_persist_id) (the offline
    /// `graphus-bulk import --persist-id` flag), which additionally requires the `:ID` column to be
    /// named (the property key). See [`ingest_node_row`].
    persist_id: bool,
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
            pending_id_map: HashMap::new(),
            batch_start_stats: ImportStats::default(),
            next_txn: 1,
            batch_size: batch_size.max(1),
            delimiter,
            duplicate_policy: DuplicatePolicy::default(),
            persist_id: false,
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

    /// Opts into persisting every node's external `:ID` as a queryable **string node property**
    /// (`rmp` #681) so a bulk-imported, then server-adopted, store can be queried by original id
    /// (e.g. `MATCH (n:Person {personId: '42'})`). The property key is the `:ID` column's name — the
    /// `neo4j-admin import` convention that a **named** id column keeps its id as a property — so
    /// [`import_nodes`](Self::import_nodes) **requires the `:ID` column to be named** when this is set
    /// (a bare `:ID` errors, telling the operator to name it). `false` by default (the external id is
    /// a physical join key only), which keeps the durable graph byte-identical to the pre-#681
    /// importer. Returns `self` for builder-style chaining.
    #[must_use]
    pub fn with_persist_id(mut self, persist_id: bool) -> Self {
        self.persist_id = persist_id;
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

    /// Mutable twin of [`store_ref_for_test`](Self::store_ref_for_test), so a Deterministic
    /// Simulation Test can arm a device fault on the LIVE store between two batches (`rmp` #955) —
    /// the importer owns the store outright, so there is no other way to reach the seam mid-import.
    #[doc(hidden)]
    pub fn store_mut_for_test(&mut self) -> &RecordStore<D, S> {
        &mut self.store
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
        // Opt-in persist-id (`rmp` #681): when enabled, resolve the PropKey token for the `:ID`
        // column's name ONCE (idempotent, same as any property key) and pass it down so every node
        // also gets a string property `<id-name> = <external id>`. A bare `:ID` cannot be persisted
        // (there is no property key), so require the column to be named — fail closed with a clear,
        // actionable message rather than silently importing without the queryable id.
        let id_prop_token = if self.persist_id {
            let name = header.id_name.as_deref().ok_or_else(|| {
                graphus_core::GraphusError::Storage(
                    "persist-id was requested but the :ID column is unnamed; name it (e.g. \
                     `personId:ID`) so the external id can be stored as the node property `personId`"
                        .to_owned(),
                )
            })?;
            Some(self.store.intern_token(Namespace::PropKey, name)?)
        } else {
            None
        };
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
            if let Err(e) = self.ingest_node_record(
                txn,
                &header,
                &prop_key_tokens,
                id_prop_token,
                &mut label_tokens,
                &record,
            ) {
                self.rollback(txn);
                return Err(e);
            }
            in_batch += 1;
            if in_batch >= self.batch_size {
                self.commit_batch(txn)?;
                txn = self.begin_batch();
                in_batch = 0;
            }
        }
        // Commit the final (possibly partial) batch.
        self.commit_batch(txn)?;
        self.stats.node_seconds += start.elapsed().as_secs_f64();
        Ok(())
    }

    /// Ingests one node record under `txn`: create the node, set labels + typed properties, and map
    /// its external id.
    ///
    /// `prop_key_tokens[i]` carries the pre-interned `PropKey` token for column `i` (`Some` iff that
    /// column is a `Property`), interned once per file rather than per cell (`rmp` task #321).
    /// `label_memo` memoises label-name → token across rows so a repeated label is interned once.
    ///
    /// Thin forwarding wrapper over [`ingest_node_row`] (`rmp` #519): the store-mutation logic lives
    /// there as a free function so `graphus-server`'s network bulk-import Mode A batch handler (which
    /// drives a store it *borrows* from a live engine's `TxnCoordinator`, never one it owns) reuses it
    /// byte-for-byte instead of duplicating it.
    fn ingest_node_record(
        &mut self,
        txn: TxnId,
        header: &NodeHeader,
        prop_key_tokens: &[Option<u32>],
        id_prop_token: Option<u32>,
        label_memo: &mut HashMap<String, u32>,
        record: &csv::StringRecord,
    ) -> Result<()> {
        ingest_node_row(
            &self.store,
            txn,
            header,
            prop_key_tokens,
            id_prop_token,
            label_memo,
            record,
            &self.id_map,
            &mut self.pending_id_map,
            self.duplicate_policy,
            &mut self.stats,
        )
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
                self.commit_batch(txn)?;
                txn = self.begin_batch();
                in_batch = 0;
            }
        }
        self.commit_batch(txn)?;
        self.stats.rel_seconds += start.elapsed().as_secs_f64();
        Ok(())
    }

    /// Ingests one relationship record under `txn`: resolve endpoints, create the relationship, set
    /// its typed properties.
    ///
    /// Thin forwarding wrapper over [`ingest_rel_row`] (`rmp` #519) — see [`ingest_node_record`]'s
    /// doc for why the logic is a free function.
    fn ingest_rel_record(
        &mut self,
        txn: TxnId,
        header: &RelHeader,
        prop_key_tokens: &[Option<u32>],
        type_memo: &mut HashMap<String, u32>,
        record: &csv::StringRecord,
    ) -> Result<()> {
        ingest_rel_row(
            &self.store,
            txn,
            header,
            prop_key_tokens,
            type_memo,
            record,
            &self.id_map,
            &mut self.stats,
        )
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
    ///
    /// Thin forwarding wrapper over [`intern_property_key_tokens`] (`rmp` #519) — see
    /// [`ingest_node_record`]'s doc for why the logic is a free function.
    fn resolve_property_key_tokens(&mut self, columns: &[ColumnRole]) -> Result<Vec<Option<u32>>> {
        intern_property_key_tokens(&self.store, columns)
    }

    /// Begins the next batch transaction and returns its id.
    fn begin_batch(&mut self) -> TxnId {
        let txn = TxnId(self.next_txn);
        self.next_txn += 1;
        self.store.begin(txn);
        self.batch_start_stats = self.stats;
        debug_assert!(
            self.pending_id_map.is_empty(),
            "INVARIANT: pending_id_map is always drained (on commit) or cleared (on rollback) \
             before the next batch begins (#517)"
        );
        txn
    }

    /// Commits the batch transaction `txn` and, only once that succeeds, confirms the batch's staged
    /// work: merges `pending_id_map` into the visible `id_map` (`rmp` #517).
    ///
    /// If the commit itself fails, the batch's writes never became durable, so its staged id-map
    /// bindings and stats deltas are discarded exactly as an explicit [`Self::rollback`] would — the
    /// importer's visible state always matches "this batch either fully happened or never happened".
    /// The store-side undo is discarded with them (`rmp` #955): a failure inside `commit_prepare`
    /// leaves the transaction OPEN with its rows physically present, so without the rollback below the
    /// batch would be neither committed nor undone — and, because the active-set entry survives a
    /// failed commit by design (`rmp` #866), the store would keep reporting a live uncommitted writer
    /// forever, holding the `rmp` #902 constraint-DDL guard closed on a transaction nobody will ever
    /// finish. [`Self::rollback`] is conditioned on [`RecordStore::is_txn_active`] because the other
    /// failure shape — the post-commit auto-checkpoint — leaves a genuinely COMMITTED transaction that
    /// must not be undone.
    ///
    /// # Errors
    ///
    /// Propagates the underlying [`RecordStore::commit`] failure.
    fn commit_batch(&mut self, txn: TxnId) -> Result<()> {
        match self.store.commit(txn) {
            Ok(()) => {
                self.id_map.extend(self.pending_id_map.drain());
                Ok(())
            }
            Err(e) => {
                if self.store.is_txn_active(txn) {
                    self.rollback(txn);
                } else {
                    self.pending_id_map.clear();
                    self.stats = self.batch_start_stats;
                }
                Err(e)
            }
        }
    }

    /// Best-effort rollback of a failed batch (the error being returned is the primary failure).
    ///
    /// Also discards this batch's staged `pending_id_map` bindings and restores `stats` to its
    /// pre-batch snapshot (`rmp` #517): the store already undid the batch's writes, so retaining
    /// either would let a retried batch resolve relationships against physical ids the store no
    /// longer has, or double-count rows the store never durably kept.
    fn rollback(&mut self, txn: TxnId) {
        let _ = self.store.rollback(txn);
        self.pending_id_map.clear();
        self.stats = self.batch_start_stats;
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

// ------------------------------------------------------------------------------------------------
// Free functions (rmp #519): the exact low-level per-record store-mutation logic `BulkImporter`
// uses internally, extracted so it can be driven against a store this crate does not own.
//
// `BulkImporter` (above) is the **offline** path: it owns its `RecordStore` outright (constructed
// fresh by the CLI) and allocates its own monotonic `TxnId`s, safe only because that store has
// never had a transaction run against it. The **network** bulk-import Mode A path (`08 §5.1`,
// `graphus-server`) is different: it writes into a store a *live, already-running* database engine
// already owns (`graphus_cypher::TxnCoordinator`), so it must borrow that store for the scope of one
// engine command and use a `TxnId` the coordinator's own counter allocated (never a private
// from-1 counter, which could collide with ids the coordinator already issued). Extracting the
// per-record body into free functions taking `&RecordStore` + an externally-supplied `TxnId`
// lets both callers share byte-identical store-mutation logic — "shared, unmodified code between
// the offline tool and the network endpoint" per `08 §4.2` — while each owns its transaction/id
// lifecycle appropriately for its own environment.
// ------------------------------------------------------------------------------------------------

/// Interns every `Property` column's key token once against `store` and returns a vector aligned
/// with `columns`: `out[i]` is `Some(token)` iff column `i` is a [`ColumnRole::Property`], else
/// `None` (`rmp` task #321). Token interning is idempotent by name, so calling this once per file
/// (rather than once per cell) is content-identical to a per-cell intern.
///
/// # Errors
/// Propagates a store write failure from interning a new property-key token.
pub fn intern_property_key_tokens<D: BlockDevice, S: LogSink>(
    store: &RecordStore<D, S>,
    columns: &[ColumnRole],
) -> Result<Vec<Option<u32>>> {
    let mut out = Vec::with_capacity(columns.len());
    for role in columns {
        match role {
            ColumnRole::Property { key, .. } => {
                out.push(Some(store.intern_token(Namespace::PropKey, key)?));
            }
            _ => out.push(None),
        }
    }
    Ok(out)
}

/// Ingests one node record into `store` under `txn`: creates the node, sets its `:LABEL` set and
/// typed properties, and stages its external-id binding into `pending_id_map` — never directly into
/// `id_map` (`rmp` #517's abort-safety invariant: a binding becomes visible to relationship
/// resolution only once the caller's transaction durably commits and merges `pending_id_map` in).
///
/// `prop_key_tokens[i]` is the token [`intern_property_key_tokens`] resolved for column `i`;
/// `label_memo` memoises label-name → token across rows within one caller-chosen scope (a whole
/// file for the offline path, one batch for the network path — both are correct, since interning is
/// idempotent by name and a memo only saves redundant `intern_token` calls, never changes the
/// result).
///
/// SEC-196 (CWE-694): a duplicate non-empty external `:ID` is rejected under
/// [`DuplicatePolicy::Strict`] (checked against both `id_map` and `pending_id_map`, so a collision
/// within the very same in-flight batch is caught too) or counted and kept-first under
/// [`DuplicatePolicy::SkipDuplicate`] — silently overwriting the binding would re-point every
/// relationship referencing it onto the wrong node.
///
/// `id_prop_token` (`rmp` #681): when `Some(token)`, the node's non-empty external `:ID` is also
/// stored as the **string property** `token` (the `:ID` column's name interned once by the caller),
/// so a bulk-imported store can be queried by original id after the server adopts it. `None` (the
/// default, and always the network Mode A path) keeps the external id a physical join key only, so the
/// durable graph is byte-identical to the pre-#681 importer. An empty `:ID` cell stores no property
/// (there is no id to record).
///
/// # Errors
/// A header/value-parse/storage error, or [`DuplicatePolicy::Strict`]'s duplicate-`:ID` rejection.
/// The caller is responsible for rolling back `txn` on `Err` (this function never does, since it
/// does not own the transaction's lifecycle).
#[allow(clippy::too_many_arguments)]
pub fn ingest_node_row<D: BlockDevice, S: LogSink>(
    store: &RecordStore<D, S>,
    txn: TxnId,
    header: &NodeHeader,
    prop_key_tokens: &[Option<u32>],
    id_prop_token: Option<u32>,
    label_memo: &mut HashMap<String, u32>,
    record: &csv::StringRecord,
    id_map: &HashMap<String, u64>,
    pending_id_map: &mut HashMap<String, u64>,
    duplicate_policy: DuplicatePolicy,
    stats: &mut ImportStats,
) -> Result<()> {
    let (node_id, _eid) = store.create_node(txn)?;

    // External id (the join key for relationships).
    let external_id = record.get(header.id_index).unwrap_or("").to_owned();

    // Opt-in persist-id (`rmp` #681): also store the external id as a queryable string property. Done
    // before the labels/properties writes purely for locality; it is one more property write under the
    // same batch transaction, so it is committed/rolled-back atomically with the rest of the node. An
    // empty `:ID` records nothing (the node simply has no id property).
    if let Some(token) = id_prop_token {
        if !external_id.is_empty() {
            store.set_node_property_value(
                txn,
                node_id,
                token,
                &Value::String(external_id.clone()),
            )?;
            stats.properties += 1;
        }
    }

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
                            let t = store.intern_token(Namespace::Label, label)?;
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
                    store.set_node_property_value(txn, node_id, key_token, &value)?;
                    stats.properties += 1;
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
        store.set_node_labels(txn, node_id, &label_tokens)?;
    }

    // Bind the external id last (after a successful write) — see the doc comment above for why
    // this stages into `pending_id_map` rather than `id_map` directly, and the duplicate-id policy.
    if external_id.is_empty() {
        pending_id_map.insert(external_id, node_id);
    } else if let Some(existing) = pending_id_map
        .get(&external_id)
        .or_else(|| id_map.get(&external_id))
        .copied()
    {
        match duplicate_policy {
            DuplicatePolicy::Strict => {
                return Err(graphus_core::GraphusError::Storage(format!(
                    "bulk-import: duplicate :ID {external_id:?} (first bound to node {existing}, \
                     row {} would rebind to node {node_id}); relationships would join the wrong \
                     node. Deduplicate the input or use a skip-duplicate policy.",
                    stats.nodes + 1
                )));
            }
            DuplicatePolicy::SkipDuplicate => {
                // Keep the first binding; the duplicate's node exists but stays unreferenceable
                // by external id. Count the skip for the operator.
                stats.skipped_duplicate_ids += 1;
            }
        }
    } else {
        pending_id_map.insert(external_id, node_id);
    }
    stats.nodes += 1;
    Ok(())
}

/// Ingests one relationship record into `store` under `txn`: resolves `:START_ID`/`:END_ID` against
/// the **confirmed** `id_map` (never `pending_id_map` — a relationship must join to an already
/// durably-committed node, not one still in-flight in the current batch), creates the relationship,
/// and sets its typed properties.
///
/// `type_memo` memoises `:TYPE` name → token across rows within one caller-chosen scope (mirrors
/// `label_memo` in [`ingest_node_row`]).
///
/// # Errors
/// A header/value-parse/storage error, or an unknown `:START_ID`/`:END_ID` (no node bound to that
/// external id in `id_map`). The caller is responsible for rolling back `txn` on `Err`.
#[allow(clippy::too_many_arguments)]
pub fn ingest_rel_row<D: BlockDevice, S: LogSink>(
    store: &RecordStore<D, S>,
    txn: TxnId,
    header: &RelHeader,
    prop_key_tokens: &[Option<u32>],
    type_memo: &mut HashMap<String, u32>,
    record: &csv::StringRecord,
    id_map: &HashMap<String, u64>,
    stats: &mut ImportStats,
) -> Result<()> {
    let start_ext = record.get(header.start_index).unwrap_or("");
    let end_ext = record.get(header.end_index).unwrap_or("");
    let type_name = record.get(header.type_index).unwrap_or("");

    let start_id = *id_map.get(start_ext).ok_or_else(|| {
        graphus_core::GraphusError::Storage(format!(
            "relationship references unknown :START_ID `{start_ext}` (no such node)"
        ))
    })?;
    let end_id = *id_map.get(end_ext).ok_or_else(|| {
        graphus_core::GraphusError::Storage(format!(
            "relationship references unknown :END_ID `{end_ext}` (no such node)"
        ))
    })?;
    // Memoise rel-type-name → token: intern once per distinct type, not per row (`rmp` task #321).
    let type_token = match type_memo.get(type_name) {
        Some(&t) => t,
        None => {
            let t = store.intern_token(Namespace::RelType, type_name)?;
            type_memo.insert(type_name.to_owned(), t);
            t
        }
    };
    let (rel_id, _eid) = store.create_rel(txn, type_token, start_id, end_id)?;

    for (i, role) in header.columns.iter().enumerate() {
        if let ColumnRole::Property { key, ty } = role {
            let cell = record.get(i).unwrap_or("");
            if let Some(value) =
                parse_cell(cell, *ty, key).map_err(graphus_core::GraphusError::from)?
            {
                // Reuse the per-column pre-interned key token (`rmp` task #321).
                let key_token = prop_key_tokens[i]
                    .expect("INVARIANT: a Property column has a pre-interned PropKey token (#321)");
                store.set_rel_property_value(txn, rel_id, key_token, &value)?;
                stats.properties += 1;
            }
        }
    }
    stats.relationships += 1;
    Ok(())
}
