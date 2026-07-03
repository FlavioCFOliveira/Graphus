//! Low-level per-batch bulk-write session state for **network bulk import Mode A**
//! (`rmp` #519, `08-network-bulk-import.md` §5.1/§7.1). Lives on the engine thread's own stack
//! across many [`crate::engine::command::EngineCommand::BulkImportBatch`] dispatches — the external-id
//! map and the per-file token caches must persist across many HTTP requests within one session, so
//! they cannot live inside a single command's handling.
//!
//! ## Why this reuses `graphus-bulk`'s free functions
//!
//! [`graphus_bulk::intern_property_key_tokens`] / [`graphus_bulk::ingest_node_row`] /
//! [`graphus_bulk::ingest_rel_row`] are the **exact** low-level per-record store-mutation logic the
//! offline `BulkImporter` uses internally, extracted (`rmp` #519) into free functions parameterized
//! over an externally-owned `&mut RecordStore` and an externally-supplied `TxnId` instead of an
//! owned importer. This module is the network-side caller: it borrows the store for the scope of one
//! [`graphus_cypher::TxnCoordinator::raw_txn`] call per batch and drives the identical ingestion
//! functions, so "shared, unmodified code between the offline tool and the network endpoint"
//! (`08` §4.2) holds for the low-level write path, not just the CSV/`.gcol` parsing.
//!
//! ## The durable checkpoint sentinel node (`08` §7.1)
//!
//! On the first batch of a session, one node is created carrying the reserved label
//! [`SESSION_SENTINEL_LABEL`] and four properties (`batch_seq`, `nodes`, `relationships`,
//! `properties`) recording the session's progress. Every subsequent batch **updates** those
//! properties inside that batch's own transaction — the same `commit` call that durably lands the
//! batch's data — so the checkpoint is provably atomic with the data it describes by construction,
//! never a separate, driftable bookkeeping write (`08` §7.1: "the server durably records, in the
//! same commit as the data, a session checkpoint"). [`BulkImportBatchInput::End`] deletes the
//! sentinel in one final small transaction, so a subsequent fresh Mode A session against the (now
//! `Offline`) database still finds it empty.
//!
//! ## Resumability guarantee — read this before building the REST-handler resume protocol
//!
//! This layer deliberately does **not** attempt to recover [`LoadingSession`]'s in-memory
//! `id_map`/token caches from the sentinel node's properties after a full process crash/restart.
//! Doing so would require serializing a potentially huge external-id map into node properties, which
//! is not the right storage shape (`08` §7.1 explicitly scopes the checkpoint to `batch_seq` + the
//! stats counters, not the map). Concretely, this layer guarantees:
//!
//! - **Resuming within the same still-alive engine process** (a dropped HTTP connection, the engine
//!   thread untouched): the existing [`LoadingSession`] is still parked in [`Option`] state on the
//!   engine thread (threaded through [`crate::engine::run_engine_loop`] / [`crate::engine::LocalEngine`]),
//!   so a new batch dispatch continues against the SAME `id_map`/caches. No data is ever re-applied;
//!   the caller resumes mid-file from its own last-acknowledged batch.
//! - **Resuming after a full process crash/restart**: [`crate::dbcatalog::DatabaseCatalog::start_catalog_databases`]
//!   recovers the database back into the `Loading` state (`08` §7.1: WAL replay to the last committed
//!   batch), but the engine thread is rebuilt from scratch — there is no [`LoadingSession`] to
//!   resume. The **next** `BulkImportBatch::Nodes`/`Relationships` dispatch against this recovered
//!   session starts a **fresh, empty** `LoadingSession` (empty `id_map`, empty token caches). The
//!   sentinel node's `batch_seq`/counters (and all previously committed data) survive intact via
//!   ordinary WAL crash recovery, but this layer has no way to repopulate `id_map` from them.
//!
//! **Known residual gap, explicitly flagged for the REST-handler stage (`rmp` #520/the next task):**
//! because a post-restart fresh `LoadingSession` has an empty `id_map`, blindly re-ingesting rows
//! from a node file that was *already fully committed* before the crash would wrongly create
//! duplicate nodes rather than erroring cleanly (the in-memory duplicate-`:ID` detection in
//! [`graphus_bulk::ingest_node_row`] only catches a collision against `id_map`/`pending_id_map` —
//! both empty after a restart — not against the store's actual committed rows). The safe, correct
//! mitigation belongs at the HTTP layer, **not** here: the client-facing resume protocol must always
//! resume from the last **fully durable file boundary** after a process restart (never mid-file),
//! using the checkpoint's `batch_seq`/byte-offset to detect "this checkpoint predates a process
//! restart" (e.g. an engine/session generation marker the REST layer tracks) and falling back to
//! re-supplying the current file from its start ONLY when the process itself never restarted. This
//! module intentionally does not attempt that reconciliation — it is out of scope for the
//! `dbcatalog`/engine layer and is the REST-handler stage's responsibility to design and implement.
//!
//! **What this layer *does* still guarantee across a crash, unconditionally**: [`BulkImportBatchInput::End`]
//! against a crash-recovered engine (`session == None`, no batches submitted since the restart) is
//! **not** a silent no-op — [`recover_and_delete_orphaned_sentinel`] scans for the durable checkpoint
//! sentinel by its reserved label, reports the `nodes`/`relationships`/`properties` counters it last
//! recorded (an accurate final summary even though the in-memory `id_map` is gone), and deletes it, so
//! an operator who decides to **abandon** a crashed session (rather than resume it) still ends up with
//! a database containing exactly the imported graph data and nothing else — no permanent, orphaned
//! `__graphus_bulk_import_session__` bookkeeping node left behind regardless of whether the process
//! crashed. This is deliberately narrower than full `id_map` recovery (which remains the residual gap
//! above): it closes the "`End` after a crash silently leaves stray data" hazard without attempting the
//! (out-of-scope) full resume reconciliation.

use std::collections::HashMap;
use std::sync::Arc;

use graphus_bulk::{
    DuplicatePolicy, ImportStats, NodeHeader, RelHeader, ingest_node_row, ingest_rel_row,
    intern_property_key_tokens,
};
use graphus_core::error::Result;
use graphus_core::{TxnId, Value};
use graphus_cypher::TxnCoordinator;
use graphus_io::BlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::LogSink;

/// The reserved internal label marking the durable Mode A session-checkpoint sentinel node
/// (`08` §7.1). Double-underscore-prefixed so it can never collide with an operator's own label —
/// this is not a plausible identifier an operator would choose, and it is grep-able as an internal
/// bookkeeping marker (no other reserved/internal-node convention exists elsewhere in the codebase
/// as of `rmp` #519; this establishes one for this feature only).
const SESSION_SENTINEL_LABEL: &str = "__graphus_bulk_import_session__";

/// One already-parsed batch of rows submitted to the engine for low-level ingestion
/// (`rmp` #519, `08` §5.1/§7.1). `csv::StringRecord` parsing happens OFF the engine thread (in the
/// REST handler / a blocking task); only the store mutation needs the engine's single-writer thread.
///
/// Node and relationship batches are never mixed (the two-phase, node-file-then-rel-file model,
/// `08` §4.2): a relationship batch resolves `:START_ID`/`:END_ID` only against nodes from
/// **earlier, already-committed** batches, never the in-flight one.
pub enum BulkImportBatchInput {
    /// One batch of node rows from a single node file.
    Nodes {
        /// The parsed node-file header (shared, `Arc`-wrapped, across every batch of the same file so
        /// the engine-local session state can cheaply detect "same file, reuse the cached
        /// property-key tokens" via [`Arc::ptr_eq`]).
        header: Arc<NodeHeader>,
        /// The parsed rows to ingest, in file order.
        records: Vec<csv::StringRecord>,
    },
    /// One batch of relationship rows from a single relationship file.
    Relationships {
        /// The parsed relationship-file header (see `Nodes::header`'s doc for the caching rationale).
        header: Arc<RelHeader>,
        /// The parsed rows to ingest, in file order.
        records: Vec<csv::StringRecord>,
    },
    /// Ends the session: deletes the durable checkpoint sentinel node (so a subsequent Mode A
    /// session against this now-`Offline` database still finds it empty) and clears the session-local
    /// state. Idempotent: a no-op (returning the zero/default cumulative stats) if no session is
    /// currently active on this engine.
    End,
}

/// The outcome of one `BulkImportBatch` dispatch.
#[derive(Debug, Clone, Copy, Default)]
pub struct BulkImportBatchOutcome {
    /// Cumulative stats for the **whole session so far** (not just this batch) — what the REST
    /// handler ultimately reports to the client.
    pub stats: ImportStats,
}

/// Session-local state kept on the engine thread across many `BulkImportBatch` dispatches
/// (`rmp` #519). See the module docs for the resumability guarantee this state's lifetime implies.
#[derive(Default)]
pub struct LoadingSession {
    /// External `:ID` → physical node id, populated by committed node batches and read by
    /// relationship batches. Only ever holds bindings from **committed** batches (mirrors
    /// `graphus_bulk::BulkImporter`'s `rmp` #517 abort-safety invariant): a batch's rows are staged
    /// into a scratch map local to that batch's attempt and merged in only after its `commit`
    /// succeeds, so a retried/aborted batch never pollutes this map with bindings to a rolled-back
    /// (no-longer-existent) physical id.
    id_map: HashMap<String, u64>,
    /// Label-name → token memo, shared across every node batch in the session (interning is
    /// idempotent by name, so a session-wide memo is strictly more effective than the offline
    /// importer's per-file memo without changing any result).
    label_memo: HashMap<String, u32>,
    /// Relationship-type-name → token memo, mirroring `label_memo`.
    type_memo: HashMap<String, u32>,
    /// Cumulative stats for the whole session, advanced only on a batch's successful commit.
    stats: ImportStats,
    /// The most recently ingested node file's header + its pre-interned property-key tokens
    /// (`rmp` task #321's per-column interning, extended here to persist across the many small
    /// network batches of one file rather than being recomputed every batch). Recomputed only when a
    /// **new** header arrives (`Arc::ptr_eq` against the cached one — the REST handler hands the same
    /// `Arc` to every batch of one file).
    node_ctx: Option<(Arc<NodeHeader>, Vec<Option<u32>>)>,
    /// The relationship-file analogue of `node_ctx`.
    rel_ctx: Option<(Arc<RelHeader>, Vec<Option<u32>>)>,
    /// The durable checkpoint sentinel node's physical id, once created by the first batch of this
    /// session (`08` §7.1). `None` before the first batch has committed.
    sentinel_node_id: Option<u64>,
    /// The checkpoint's `batch_seq` counter: incremented once per successfully committed batch.
    batch_seq: u64,
}

impl LoadingSession {
    /// The cumulative stats for the session so far.
    #[must_use]
    pub(crate) fn stats(&self) -> ImportStats {
        self.stats
    }

    /// Ingests one batch of node rows under a single [`TxnCoordinator::raw_txn`] transaction,
    /// creating/updating the durable checkpoint sentinel node in the same commit (`08` §7.1).
    ///
    /// Mirrors `graphus_bulk::BulkImporter`'s `rmp` #517 abort-safety pattern exactly: `id_map`
    /// bindings are staged into a batch-local scratch map and merged in only after a successful
    /// commit; `stats` is snapshotted before the batch and restored verbatim on any failure (a row
    /// error, a sentinel-checkpoint failure, or the commit itself failing), so a retried batch never
    /// double-counts or resolves relationships against a physical id the store has already rolled
    /// back.
    ///
    /// # Errors
    /// A header/value-parse/storage error from any row, or the underlying commit failure. The
    /// batch's transaction is always rolled back on error — no partial batch is ever left visible.
    fn ingest_nodes<D: BlockDevice, S: LogSink>(
        &mut self,
        coordinator: &mut TxnCoordinator<D, S>,
        header: &Arc<NodeHeader>,
        records: &[csv::StringRecord],
    ) -> Result<()> {
        let refresh = !matches!(&self.node_ctx, Some((cached, _)) if Arc::ptr_eq(cached, header));
        let next_batch_seq = self.batch_seq + 1;
        let stats_before = self.stats;

        coordinator.raw_txn(|txn, store| -> Result<()> {
            store.begin(txn);
            if refresh {
                let tokens = intern_property_key_tokens(store, &header.columns)?;
                self.node_ctx = Some((Arc::clone(header), tokens));
            }
            // Cloned out (cheap: one `Option<u32>` per column) so the row loop below can freely
            // borrow other `self` fields (`label_memo`, `id_map`, `stats`) without holding a
            // simultaneous borrow of `self.node_ctx`.
            let prop_key_tokens = self
                .node_ctx
                .as_ref()
                .expect("INVARIANT: node_ctx populated above")
                .1
                .clone();

            let mut pending_id_map: HashMap<String, u64> = HashMap::new();
            for record in records {
                if let Err(e) = ingest_node_row(
                    store,
                    txn,
                    header,
                    &prop_key_tokens,
                    &mut self.label_memo,
                    record,
                    &self.id_map,
                    &mut pending_id_map,
                    DuplicatePolicy::Strict,
                    &mut self.stats,
                ) {
                    let _ = store.rollback(txn);
                    self.stats = stats_before;
                    return Err(e);
                }
            }
            if let Err(e) = checkpoint_sentinel(
                store,
                txn,
                &mut self.sentinel_node_id,
                next_batch_seq,
                &self.stats,
            ) {
                let _ = store.rollback(txn);
                self.stats = stats_before;
                return Err(e);
            }
            match store.commit(txn) {
                Ok(()) => {
                    self.id_map.extend(pending_id_map.drain());
                    self.batch_seq = next_batch_seq;
                    Ok(())
                }
                Err(e) => {
                    self.stats = stats_before;
                    Err(e)
                }
            }
        })
    }

    /// Ingests one batch of relationship rows, mirroring [`Self::ingest_nodes`]'s transaction/
    /// checkpoint/abort-safety shape. Endpoints resolve only against `id_map`'s **confirmed**
    /// (already-committed) bindings — never a same-batch node, which is correct by construction
    /// under the two-phase node-file-then-rel-file model (`08` §4.2).
    ///
    /// # Errors
    /// As [`Self::ingest_nodes`]; additionally an unknown `:START_ID`/`:END_ID` (no committed node
    /// bound to that external id).
    fn ingest_relationships<D: BlockDevice, S: LogSink>(
        &mut self,
        coordinator: &mut TxnCoordinator<D, S>,
        header: &Arc<RelHeader>,
        records: &[csv::StringRecord],
    ) -> Result<()> {
        let refresh = !matches!(&self.rel_ctx, Some((cached, _)) if Arc::ptr_eq(cached, header));
        let next_batch_seq = self.batch_seq + 1;
        let stats_before = self.stats;

        coordinator.raw_txn(|txn, store| -> Result<()> {
            store.begin(txn);
            if refresh {
                let tokens = intern_property_key_tokens(store, &header.columns)?;
                self.rel_ctx = Some((Arc::clone(header), tokens));
            }
            let prop_key_tokens = self
                .rel_ctx
                .as_ref()
                .expect("INVARIANT: rel_ctx populated above")
                .1
                .clone();

            for record in records {
                if let Err(e) = ingest_rel_row(
                    store,
                    txn,
                    header,
                    &prop_key_tokens,
                    &mut self.type_memo,
                    record,
                    &self.id_map,
                    &mut self.stats,
                ) {
                    let _ = store.rollback(txn);
                    self.stats = stats_before;
                    return Err(e);
                }
            }
            if let Err(e) = checkpoint_sentinel(
                store,
                txn,
                &mut self.sentinel_node_id,
                next_batch_seq,
                &self.stats,
            ) {
                let _ = store.rollback(txn);
                self.stats = stats_before;
                return Err(e);
            }
            match store.commit(txn) {
                Ok(()) => {
                    self.batch_seq = next_batch_seq;
                    Ok(())
                }
                Err(e) => {
                    self.stats = stats_before;
                    Err(e)
                }
            }
        })
    }

    /// Ends the session: deletes the durable checkpoint sentinel node (a no-op if no batch ever
    /// committed — `sentinel_node_id` is still `None`) and returns the final cumulative stats.
    ///
    /// # Errors
    /// A storage error deleting the sentinel node. The delete's own transaction is rolled back on
    /// error, exactly like an ordinary batch.
    fn finish<D: BlockDevice, S: LogSink>(
        self,
        coordinator: &mut TxnCoordinator<D, S>,
    ) -> Result<ImportStats> {
        if let Some(node_id) = self.sentinel_node_id {
            coordinator.raw_txn(|txn, store| -> Result<()> {
                store.begin(txn);
                if let Err(e) = store.delete_node(txn, node_id) {
                    let _ = store.rollback(txn);
                    return Err(e);
                }
                store.commit(txn)
            })?;
        }
        Ok(self.stats)
    }
}

/// Whether `err` is [`RecordStore::delete_node`]'s specific "node is not in use" validation failure
/// (a dead/non-existent node — not a genuine storage fault) — the exact wording `delete_node` itself
/// emits (`graphus_storage::RecordStore::delete_node`: `"node {id} is not in use"`), matched by
/// substring since [`graphus_core::GraphusError::Storage`] carries a plain rendered message, not a
/// structured error code. Used by [`recover_and_delete_orphaned_sentinel`] to distinguish "this
/// sentinel candidate was already cleaned up by an earlier `End`" from a real fault.
fn is_not_in_use(err: &graphus_core::GraphusError) -> bool {
    err.to_string().contains("is not in use")
}

/// Creates (on the first batch of a session) or updates (on every subsequent batch) the durable
/// session-checkpoint sentinel node, in the **same transaction** as the batch's data (`08` §7.1): its
/// `batch_seq`/`nodes`/`relationships`/`properties` properties are set from `stats`'s current
/// counters, so the checkpoint is provably atomic with the data it describes — never a separate,
/// driftable bookkeeping write.
///
/// # Errors
/// A storage error creating the node, interning a property-key token, or writing a property. The
/// caller is responsible for rolling back `txn` on `Err` (mirrors `graphus_bulk::ingest_node_row`'s
/// contract — this function never owns the transaction's lifecycle).
fn checkpoint_sentinel<D: BlockDevice, S: LogSink>(
    store: &mut RecordStore<D, S>,
    txn: TxnId,
    sentinel_node_id: &mut Option<u64>,
    batch_seq: u64,
    stats: &ImportStats,
) -> Result<()> {
    let node_id = match *sentinel_node_id {
        Some(id) => id,
        None => {
            let (id, _eid) = store.create_node(txn)?;
            let label = store.intern_token(Namespace::Label, SESSION_SENTINEL_LABEL)?;
            store.set_node_labels(txn, id, &[label])?;
            *sentinel_node_id = Some(id);
            id
        }
    };
    let batch_seq_key = store.intern_token(Namespace::PropKey, "batch_seq")?;
    let nodes_key = store.intern_token(Namespace::PropKey, "nodes")?;
    let rels_key = store.intern_token(Namespace::PropKey, "relationships")?;
    let props_key = store.intern_token(Namespace::PropKey, "properties")?;
    store.set_node_property_value(
        txn,
        node_id,
        batch_seq_key,
        &Value::Integer(i64::try_from(batch_seq).unwrap_or(i64::MAX)),
    )?;
    store.set_node_property_value(
        txn,
        node_id,
        nodes_key,
        &Value::Integer(i64::try_from(stats.nodes).unwrap_or(i64::MAX)),
    )?;
    store.set_node_property_value(
        txn,
        node_id,
        rels_key,
        &Value::Integer(i64::try_from(stats.relationships).unwrap_or(i64::MAX)),
    )?;
    store.set_node_property_value(
        txn,
        node_id,
        props_key,
        &Value::Integer(i64::try_from(stats.properties).unwrap_or(i64::MAX)),
    )?;
    Ok(())
}

/// Dispatches one [`BulkImportBatchInput`] against `coordinator`, threading `session` (the
/// engine-thread-local [`LoadingSession`], `None` before the first batch / after [`End`](BulkImportBatchInput::End))
/// through the call. Runs on the engine thread — see the module docs for why the free-function shape
/// (rather than a method taking `&mut self`) is needed to let `dispatch_command` thread `session`
/// alongside its many other per-loop locals.
///
/// # Errors
/// Propagates any row/storage error from the underlying ingest/checkpoint/commit (see
/// [`LoadingSession::ingest_nodes`]/[`LoadingSession::ingest_relationships`]/[`LoadingSession::finish`]),
/// or from [`recover_and_delete_orphaned_sentinel`] on the crash-recovered `End` path.
pub(crate) fn handle_bulk_import_batch<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
    session: &mut Option<LoadingSession>,
    batch: BulkImportBatchInput,
) -> Result<BulkImportBatchOutcome> {
    match batch {
        BulkImportBatchInput::Nodes { header, records } => {
            let sess = session.get_or_insert_with(LoadingSession::default);
            sess.ingest_nodes(coordinator, &header, &records)?;
            Ok(BulkImportBatchOutcome {
                stats: sess.stats(),
            })
        }
        BulkImportBatchInput::Relationships { header, records } => {
            let sess = session.get_or_insert_with(LoadingSession::default);
            sess.ingest_relationships(coordinator, &header, &records)?;
            Ok(BulkImportBatchOutcome {
                stats: sess.stats(),
            })
        }
        BulkImportBatchInput::End => {
            // `session` is `None` in two cases: (a) `End` was called with no batch ever submitted in
            // this engine's lifetime (a genuine no-op — nothing to clean up), or (b) a process
            // crash/restart happened mid-session (the module doc's documented resumability
            // boundary): the engine thread was rebuilt from scratch, so the in-memory `LoadingSession`
            // is gone even though the durable checkpoint sentinel node (and every batch it recorded)
            // survived via ordinary WAL recovery. Without the fallback below, case (b) would silently
            // leave the sentinel node behind forever — `End` is meant to be a deliberate, explicit
            // session-close action, not something that only works when the process never crashed.
            let session_was_active = session.is_some();
            let stats = match session.take() {
                Some(sess) => sess.finish(coordinator)?,
                None => recover_and_delete_orphaned_sentinel(coordinator)?,
            };
            // `rmp` #579: drain the WAL backlog this Mode A load accumulated NOW, before the `End`
            // reply is acked (and therefore before a following `STOP DATABASE`/`end_loading` can queue
            // a `Shutdown`), so the next `START DATABASE` reopen does not materialise the whole
            // un-reclaimed WAL into the ARIES recovery heap. Skipped for a genuine no-op `End` (no
            // session was active and no orphaned sentinel carrying real counts was found) — there is
            // nothing to reclaim and no reason to pay a full-store scan on an idle database. See
            // [`reclaim_after_bulk_load`].
            let loaded_something = session_was_active
                || stats.nodes != 0
                || stats.relationships != 0
                || stats.properties != 0;
            if loaded_something {
                reclaim_after_bulk_load(coordinator);
            }
            Ok(BulkImportBatchOutcome { stats })
        }
    }
}

/// Forces a one-shot **reclaiming checkpoint** at the end of a Mode A bulk-import session (`rmp` #579)
/// so the WAL backlog the load accumulated is drained *before* the database is stopped — collapsing the
/// ARIES recovery heap the next `START DATABASE` reopen would otherwise pay.
///
/// ## The bug this fixes
///
/// A Mode A load only ever *creates* rows, and `rmp` #556 deliberately widens the background
/// maintenance cadence during a `Loading` session (to dodge its `O(N²)` full-store-GC cost), so the WAL
/// reclaim floor — drained only by a GC **freeze** sweep — never advances during the load: the WAL grows
/// to `O(edges)` (measured ≈ 1270 B/edge; ≈ 1.2 GB for 1 M edges, ≈ 9 GB for 7.2 M). At the subsequent
/// `START DATABASE`, `graphus-wal` recovery materialises that whole un-reclaimed WAL into heap 2–3×
/// (`recovery.rs`'s `log: Vec<u8>` + `ordered: Vec<LogRecord>`, plus `store.rs`'s
/// `committed_transactions`), driving the reopen to ≈ 25 GB RSS on a 30 GB host — a near-OOM
/// (`rmp` #579 / storage audit F3). This runs one GC freeze + checkpoint at session close, which lowers
/// the reclaim floor and physically frees the WAL prefix below it, so the reopen reads almost nothing:
/// the recovery heap drops from `O(edges)` toward `O(1)`. It also fixes the on-disk WAL amplification of
/// the loaded database.
///
/// ## Why running it here does *not* re-introduce the `rmp` #565 force-detach hazard
///
/// This is called from inside the `End` command's synchronous handling, **before**
/// [`handle_bulk_import_batch`] returns and therefore before the engine acks the `End` reply. The REST
/// `?end=true` handler (`listeners::extra_routes::bulk_import::handle_end`) blocks on that reply and only
/// *then* calls `end_loading`, which is what queues the engine's `Shutdown`. So on the ordinary,
/// single-client `End`→`STOP` path the `Shutdown` cannot even be *queued* until this checkpoint has
/// already completed — the engine is back parked on `recv` when it arrives and `stop_engine`'s drain
/// deadline never races an in-flight checkpoint. This is the opposite ordering from the post-command
/// `maybe_run_maintenance` sweep `rmp` #565 had to *skip* on the loading→not-loading edge: that sweep ran
/// the checkpoint *after* the reply, while a `STOP DATABASE` could already have queued the `Shutdown`
/// behind it, blocking the ack past the drain deadline and force-detaching a healthy engine (the
/// `rmp` #555 corruption trigger). That skip stays; this replaces its deferred "reclaim on the ordinary
/// cadence after the next `START`" — which never runs in time to stop the reopen itself from OOMing —
/// with an eager, race-free reclaim *before* the stop.
///
/// One reachable *concurrent* window remains, and is safe for a different reason worth stating: because
/// `handle_end` drives the `End` through the `loading_handle` **without** holding the catalog admin lock,
/// another actor can take that lock and issue a plain `STOP DATABASE` on the `Loading` database — or a
/// process-wide `shutdown_all` (SIGTERM) — *while* this checkpoint is in flight, queuing a `Shutdown`
/// behind the in-flight `End` with `stop_engine`'s drain deadline already armed. This still does not
/// reintroduce `rmp` #555: the reclaim is *not* an opaque stall — its GC freeze bumps the `rmp` #563
/// drain-progress beacon every few thousand records and its checkpoint flush bumps it per double-write
/// chunk, so `stop_engine`'s progress-aware drain classifies the engine as healthy-but-slow and never
/// force-detaches it; and even in a pathological worst case the `store.lock` `flock` (also `rmp` #563) is
/// the ultimate anti-corruption backstop — a force-detached thread holds it until it fully closes the
/// store, so a concurrent reopen fails fast instead of racing (the actual #555 corruption mechanism).
///
/// ## Cost and failure handling
///
/// One-shot: a single `O(total store)` GC freeze + checkpoint, run once at session close — never the
/// per-batch `O(N²)` cadence `rmp` #522/#556 guard against. The freeze is *required*, not optional: it
/// is what drains the store's `unfrozen_commit_lsn` map and lowers the WAL reclaim floor; a reclaim that
/// skipped it would free nothing.
///
/// Best-effort: a checkpoint failure leaves the store fully durable and consistent (the reclaim floor is
/// always respected — [`TxnCoordinator::checkpoint`]'s contract), only the WAL un-reclaimed, i.e. the
/// pre-fix reopen cost. It must therefore **never** fail the `End` response (the data landed and the
/// session closed successfully); it is logged and swallowed, mirroring the background maintenance
/// cadence's own non-fatal treatment of a checkpoint error (`crate::engine::maybe_run_maintenance`).
fn reclaim_after_bulk_load<D: BlockDevice, S: LogSink>(coordinator: &mut TxnCoordinator<D, S>) {
    match coordinator.checkpoint() {
        Ok(report) => {
            // `report.frozen` is the load-bearing signal: the freeze sweep settled that many committed
            // MVCC stamps, draining the store's `unfrozen_commit_lsn` map and so lowering the WAL reclaim
            // floor — which is what let the checkpoint physically free the WAL prefix below it. (The
            // absolute retained-WAL shrink is not logged because the coordinator's `wal_durable_len` is a
            // monotonic lifetime offset that reclamation never lowers, so it would read as growth, not a
            // shrink; the drop is instead observed on disk / in RSS by the `rmp` #579 verification.)
            tracing::info!(
                reclaimed_versions = report.reclaimed,
                frozen = report.frozen,
                "bulk-import Mode A session end: reclaimed the WAL before the database is stopped, so \
                 the next START DATABASE reopen does not replay it (rmp #579)"
            );
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "bulk-import Mode A session end: the end-of-load reclaim checkpoint failed; the \
                 database is fully durable but its WAL was not reclaimed, so the next START DATABASE \
                 reopen will replay the full WAL (rmp #579, best-effort — never fatal)"
            );
        }
    }
}

/// The crash-recovery fallback for [`BulkImportBatchInput::End`] when no in-memory [`LoadingSession`]
/// exists (`08` §7.1's "engine rebuilt from scratch after a crash" case — see the module doc's
/// resumability guarantee). Scans every node id for the reserved sentinel label (a full store scan —
/// acceptable here since `End` runs at most once, at explicit session close, never on the per-batch hot
/// path), and, if found, reads back its last-recorded `nodes`/`relationships`/`properties` counters
/// before deleting it in one transaction, so the caller still gets an accurate final summary and the
/// database is left genuinely clean (no leftover `__graphus_bulk_import_session__` node) — exactly as
/// if the process had never crashed.
///
/// Zero sentinel nodes found (no session ever began, or an earlier `End` already cleaned one up) is a
/// legitimate, silent no-op: returns [`ImportStats::default`].
///
/// # Errors
/// A storage error reading the sentinel's properties or deleting it; the delete's own transaction is
/// rolled back on error, exactly like an ordinary batch.
fn recover_and_delete_orphaned_sentinel<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
) -> Result<ImportStats> {
    coordinator.raw_txn(|txn, store| -> Result<ImportStats> {
        let label = store.intern_token(Namespace::Label, SESSION_SENTINEL_LABEL)?;
        let mut sentinel_ids = Vec::new();
        for id in store.scan_node_ids()? {
            if store.node_has_label(id, label)? {
                sentinel_ids.push(id);
            }
        }
        if sentinel_ids.is_empty() {
            return Ok(ImportStats::default());
        }

        let nodes_key = store.intern_token(Namespace::PropKey, "nodes")?;
        let rels_key = store.intern_token(Namespace::PropKey, "relationships")?;
        let props_key = store.intern_token(Namespace::PropKey, "properties")?;

        store.begin(txn);
        let mut stats = ImportStats::default();
        for id in sentinel_ids {
            // `scan_node_ids`/`node_has_label` both report a node whose **slot** is still occupied,
            // which includes an MVCC tombstone not yet GC'd (module docs, `graphus_storage::RecordStore`)
            // — the label bitmap survives a delete until reclamation. So a STALE candidate (a sentinel
            // an earlier `End` call already tombstoned in a prior committed transaction, e.g. a second
            // `End` on the same recovered engine) can resurface here. `delete_node`'s own liveness
            // check (`is_live_version`) is the only reliable oracle for "is this actually still live",
            // and it runs BEFORE any mutation on a genuinely dead node (pure validation, no partial
            // state to unwind) — so attempt the delete FIRST and simply skip a stale candidate rather
            // than treating it as an error.
            match store.delete_node(txn, id) {
                Ok(()) => {}
                Err(e) if is_not_in_use(&e) => continue,
                Err(e) => {
                    let _ = store.rollback(txn);
                    return Err(e);
                }
            }
            // Read AFTER the (successful) delete: `delete_node` tombstones only the node's own MVCC
            // header, never its property chain, so the chain remains fully readable within this same
            // transaction. `node_property_values` returns the WHOLE chain, prepend-ordered (newest
            // first) — every `checkpoint_sentinel` call on a prior batch appended a fresh version of
            // each of these three keys rather than overwriting in place (MVCC), so older, stale values
            // are still walked here until GC reclaims them. Only the FIRST (newest) occurrence of each
            // key must win; a naive last-write-in-iteration-order assignment would end up keeping the
            // OLDEST recorded value instead.
            let (mut have_nodes, mut have_rels, mut have_props) = (false, false, false);
            for (_pid, key, value) in store.node_property_values(id)? {
                let Value::Integer(n) = value else { continue };
                let n = u64::try_from(n).unwrap_or(0);
                if key == nodes_key && !have_nodes {
                    stats.nodes = n;
                    have_nodes = true;
                } else if key == rels_key && !have_rels {
                    stats.relationships = n;
                    have_rels = true;
                } else if key == props_key && !have_props {
                    stats.properties = n;
                    have_props = true;
                }
            }
        }
        store.commit(txn)?;
        Ok(stats)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_bulk::{ColumnRole, PropertyType, ScalarType};
    use graphus_io::MemBlockDevice;
    use graphus_storage::RecordStore;
    use graphus_wal::{MemLogSink, WalManager};

    fn coordinator() -> TxnCoordinator<MemBlockDevice, MemLogSink> {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create WAL");
        let store = RecordStore::create(device, wal, 64, 1).expect("create store");
        TxnCoordinator::new(store)
    }

    fn node_header() -> Arc<NodeHeader> {
        Arc::new(NodeHeader {
            columns: vec![
                ColumnRole::Id,
                ColumnRole::Label,
                ColumnRole::Property {
                    key: "name".to_owned(),
                    ty: PropertyType::Scalar(ScalarType::String),
                },
            ],
            id_index: 0,
        })
    }

    fn rel_header() -> Arc<RelHeader> {
        Arc::new(RelHeader {
            columns: vec![
                ColumnRole::StartId,
                ColumnRole::EndId,
                ColumnRole::Type,
                ColumnRole::Property {
                    key: "since".to_owned(),
                    ty: PropertyType::Scalar(ScalarType::Integer),
                },
            ],
            start_index: 0,
            end_index: 1,
            type_index: 2,
        })
    }

    fn record(fields: &[&str]) -> csv::StringRecord {
        csv::StringRecord::from(fields.to_vec())
    }

    #[test]
    fn nodes_then_relationships_then_end_round_trips() {
        let mut coord = coordinator();
        let mut session: Option<LoadingSession> = None;
        let nh = node_header();

        let out = handle_bulk_import_batch(
            &mut coord,
            &mut session,
            BulkImportBatchInput::Nodes {
                header: Arc::clone(&nh),
                records: vec![
                    record(&["1", "Person", "Ada"]),
                    record(&["2", "Person", "Bob"]),
                ],
            },
        )
        .expect("node batch");
        assert_eq!(out.stats.nodes, 2);
        assert_eq!(out.stats.properties, 2);

        let rh = rel_header();
        let out = handle_bulk_import_batch(
            &mut coord,
            &mut session,
            BulkImportBatchInput::Relationships {
                header: Arc::clone(&rh),
                records: vec![record(&["1", "2", "KNOWS", "2010"])],
            },
        )
        .expect("rel batch");
        assert_eq!(out.stats.nodes, 2, "cumulative across batches");
        assert_eq!(out.stats.relationships, 1);
        assert_eq!(out.stats.properties, 3);

        // The sentinel node exists and is NOT one of the two `Person` nodes created above.
        assert!(
            session.as_ref().unwrap().sentinel_node_id.is_some(),
            "the checkpoint sentinel was created by the first batch"
        );

        let out = handle_bulk_import_batch(&mut coord, &mut session, BulkImportBatchInput::End)
            .expect("end");
        assert_eq!(out.stats.nodes, 2);
        assert_eq!(out.stats.relationships, 1);
        assert!(session.is_none(), "End clears the session");
    }

    #[test]
    fn end_without_a_session_is_a_no_op() {
        let mut coord = coordinator();
        let mut session: Option<LoadingSession> = None;
        let out = handle_bulk_import_batch(&mut coord, &mut session, BulkImportBatchInput::End)
            .expect("end with no session");
        assert_eq!(out.stats.nodes, 0);
        assert!(session.is_none());
    }

    #[test]
    fn a_failed_row_rolls_back_the_whole_batch_and_restores_stats() {
        let mut coord = coordinator();
        let mut session: Option<LoadingSession> = None;
        let nh = node_header();

        // First batch: one good node.
        let out = handle_bulk_import_batch(
            &mut coord,
            &mut session,
            BulkImportBatchInput::Nodes {
                header: Arc::clone(&nh),
                records: vec![record(&["1", "Person", "Ada"])],
            },
        )
        .expect("first batch");
        assert_eq!(out.stats.nodes, 1);

        // Second batch: a good row followed by a duplicate `:ID` (strict policy) — the WHOLE batch
        // must roll back, so `stats.nodes` stays at 1 (the first row's success is NOT retained).
        let err = handle_bulk_import_batch(
            &mut coord,
            &mut session,
            BulkImportBatchInput::Nodes {
                header: Arc::clone(&nh),
                records: vec![
                    record(&["2", "Person", "Bob"]),
                    record(&["1", "Person", "Duplicate"]),
                ],
            },
        );
        assert!(err.is_err(), "the duplicate :ID must fail the batch");
        assert_eq!(
            session.as_ref().unwrap().stats().nodes,
            1,
            "stats revert to the pre-batch snapshot on any row failure (rmp #517 pattern)"
        );

        // A subsequent, all-good batch still works (the session is not poisoned by the failure).
        let out = handle_bulk_import_batch(
            &mut coord,
            &mut session,
            BulkImportBatchInput::Nodes {
                header: Arc::clone(&nh),
                records: vec![record(&["2", "Person", "Bob"])],
            },
        )
        .expect("retry batch");
        assert_eq!(out.stats.nodes, 2);
    }

    /// A [`LogSink`] over [`MemLogSink`] that records the highest `up_to` floor ever passed to
    /// [`LogSink::reclaim`] (`rmp` #579), so a test can prove the end-of-load reclaiming checkpoint
    /// actually ran and advanced the WAL reclaim floor. The coordinator surfaces no after-the-fact
    /// "was the WAL reclaimed, and to where" hook, so a recording sink is the idiomatic observable
    /// (mirrors `graphus_storage`'s own `SyncCountingSink` test pattern).
    struct ReclaimSpySink {
        inner: MemLogSink,
        max_reclaim_up_to: Arc<std::sync::atomic::AtomicU64>,
    }

    impl LogSink for ReclaimSpySink {
        fn append(&mut self, bytes: &[u8]) {
            self.inner.append(bytes);
        }
        fn sync(&mut self) -> Result<()> {
            self.inner.sync()
        }
        fn durable_len(&self) -> u64 {
            self.inner.durable_len()
        }
        fn buffered_len(&self) -> u64 {
            self.inner.buffered_len()
        }
        fn read_durable(&self, from: u64, into: &mut Vec<u8>) -> Result<()> {
            self.inner.read_durable(from, into)
        }
        fn read_bounded(&self, from: u64, to: u64, into: &mut Vec<u8>) -> Result<()> {
            self.inner.read_bounded(from, to, into)
        }
        fn reclaim(&mut self, from: u64, up_to: u64) -> Result<()> {
            self.max_reclaim_up_to
                .fetch_max(up_to, std::sync::atomic::Ordering::SeqCst);
            self.inner.reclaim(from, up_to)
        }
        fn reclaimed_floor(&self) -> u64 {
            self.inner.reclaimed_floor()
        }
    }

    /// A coordinator over a [`ReclaimSpySink`] with the store's own auto-checkpoint cadence **disabled**
    /// (`set_checkpoint_interval_bytes(0)`), so nothing reclaims during the load and any recorded reclaim
    /// is provably attributable to the `End`-time checkpoint under test.
    fn spy_coordinator() -> (
        TxnCoordinator<MemBlockDevice, ReclaimSpySink>,
        Arc<std::sync::atomic::AtomicU64>,
    ) {
        let max_reclaim = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(ReclaimSpySink {
            inner: MemLogSink::new(),
            max_reclaim_up_to: Arc::clone(&max_reclaim),
        })
        .expect("create WAL");
        let mut store = RecordStore::create(device, wal, 64, 1).expect("create store");
        store.set_checkpoint_interval_bytes(0);
        (TxnCoordinator::new(store), max_reclaim)
    }

    /// `rmp` #579: ending a Mode A session that ingested data must force a reclaiming checkpoint that
    /// advances the WAL reclaim floor above the header — the mechanism that collapses the next
    /// `START DATABASE` reopen's ARIES recovery heap from `O(edges)` toward `O(1)`.
    #[test]
    fn end_forces_a_reclaiming_checkpoint_that_advances_the_wal_floor() {
        use std::sync::atomic::Ordering;
        let (mut coord, max_reclaim) = spy_coordinator();
        let mut session: Option<LoadingSession> = None;
        let nh = node_header();

        // Load many small node batches so the WAL grows well past the 8-byte header.
        for i in 0..64u32 {
            handle_bulk_import_batch(
                &mut coord,
                &mut session,
                BulkImportBatchInput::Nodes {
                    header: Arc::clone(&nh),
                    records: vec![record(&[&i.to_string(), "Person", &format!("name{i}")])],
                },
            )
            .expect("node batch");
        }

        // No reclaim has happened yet: the auto-checkpoint cadence is disabled and Mode A batches never
        // reclaim on their own (the whole reason the WAL grew to O(edges) in the first place).
        assert_eq!(
            max_reclaim.load(Ordering::SeqCst),
            0,
            "nothing must reclaim the WAL during the load itself"
        );

        handle_bulk_import_batch(&mut coord, &mut session, BulkImportBatchInput::End).expect("end");

        let floor = max_reclaim.load(Ordering::SeqCst);
        assert!(
            floor > 8,
            "End must drive a reclaiming checkpoint that advances the WAL reclaim floor past \
             HEADER_LEN (=8), got {floor}"
        );
        assert!(session.is_none(), "End clears the session");
    }

    /// `rmp` #579: a genuine no-op `End` (no session was ever active and no orphaned sentinel exists)
    /// must NOT pay a reclaiming checkpoint — there is nothing loaded to reclaim, so no full-store GC
    /// scan should run on an idle database.
    #[test]
    fn end_with_no_session_and_no_data_does_not_reclaim() {
        use std::sync::atomic::Ordering;
        let (mut coord, max_reclaim) = spy_coordinator();
        let mut session: Option<LoadingSession> = None;

        let out = handle_bulk_import_batch(&mut coord, &mut session, BulkImportBatchInput::End)
            .expect("no-op end");
        assert_eq!(out.stats.nodes, 0);
        assert_eq!(
            max_reclaim.load(Ordering::SeqCst),
            0,
            "a no-op End must not drive a reclaiming checkpoint"
        );
        assert!(session.is_none());
    }

    #[test]
    fn relationship_batch_resolves_only_against_committed_nodes() {
        let mut coord = coordinator();
        let mut session: Option<LoadingSession> = None;
        let nh = node_header();
        let rh = rel_header();

        handle_bulk_import_batch(
            &mut coord,
            &mut session,
            BulkImportBatchInput::Nodes {
                header: Arc::clone(&nh),
                records: vec![record(&["1", "Person", "Ada"])],
            },
        )
        .expect("node batch");

        // `:END_ID` "2" was never committed — the relationship batch must fail cleanly, not panic.
        let err = handle_bulk_import_batch(
            &mut coord,
            &mut session,
            BulkImportBatchInput::Relationships {
                header: Arc::clone(&rh),
                records: vec![record(&["1", "2", "KNOWS", "2010"])],
            },
        );
        assert!(err.is_err(), "an unknown endpoint id must be a clean error");
    }
}
