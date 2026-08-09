//! Engine-thread chunk handler for **network bulk-import Mode B** (`08-network-bulk-import.md`
//! §5.3/§7.2, `rmp` #520): loading into an already-**live**, already-serving database, concurrent
//! with ordinary Bolt/REST traffic, with **zero exclusivity**.
//!
//! ## Why this is architecturally distinct from Mode A ([`super::bulk_load`])
//!
//! Mode A ([`super::bulk_load::LoadingSession`]) bypasses [`TxnCoordinator`] entirely
//! ([`TxnCoordinator::raw_txn`], no SSI/locks) because its target database is exclusively `Loading` —
//! no concurrent access exists to reason about. **Mode B has concurrent access by construction**, so
//! every row it ingests goes through the coordinator's ordinary transactional write path: a chunk is
//! applied inside an already-open (`Begin`-opened) [`TxnCoordinator`] transaction via
//! [`TxnCoordinator::statement`], calling the exact same [`graphus_cypher::GraphAccess`] methods
//! (`create_node`/`create_rel`) an equivalent Cypher `CREATE` would call — never a raw
//! `RecordStore::create_node`/`create_rel`, and never a "bulk-optimized" shortcut that skips
//! SIREAD/predicate-marker registration or write-locking (`08` §7.2, explicitly disallowed: "the
//! audit confirmed this is the one point where cutting a corner reopens a real serializability
//! hole").
//!
//! `create_node`/`create_rel` take **label/property/type names** (owned `String`s), not
//! pre-interned tokens — they intern their own tokens internally
//! (`graphus_cypher::record_graph::RecordStoreGraph::create_node`/`create_rel`). This means Mode B's
//! row ingestion needs **none** of Mode A's `label_memo`/`type_memo`/pre-interned-property-key-token
//! caching machinery: that machinery exists in `graphus_bulk::ingest_node_row`/`ingest_rel_row` only
//! because those functions call the raw, token-based `RecordStore` API directly. Mode B instead
//! reuses only the **parsing** half of `graphus-bulk` ([`graphus_bulk::parse_node_row`]/
//! [`graphus_bulk::parse_rel_row`]).
//!
//! ## Reusing `Begin`/`Commit`/`Rollback` — no new transaction-lifecycle command
//!
//! Unlike Mode A (which has no ordinary transaction to open — `raw_txn` bypasses the `active` set
//! entirely), a Mode B batch **is** an ordinary `TxnCoordinator` SERIALIZABLE transaction. This module
//! therefore adds **exactly one** new [`EngineCommand`](super::command::EngineCommand) variant
//! (chunk ingestion); the surrounding `Begin`/`Commit`/`Rollback` verbs are the **existing** ones
//! (`crate::engine::command::EngineCommand::{Begin,Commit,Rollback}`), which already thread a
//! [`super::TxTicket`] through `super::open_tx`/`commit_prepare_tx`/`rollback_tx`. The `graphus-server`
//! driver (`crate::bulk_import_mode_b`) calls `EngineHandle::begin`/`bulk_import_mode_b_chunk` (N
//! times)/`commit`/`rollback` — an ordinary, first-class transaction from the coordinator's point of
//! view, indistinguishable from a client's own `BEGIN … COMMIT` except that its writes happen to come
//! from parsed CSV rows instead of a Cypher `CREATE`.
//!
//! ## `id_map` bookkeeping lives OFF the engine thread, in the async driver
//!
//! Unlike Mode A's [`super::bulk_load::LoadingSession`] (which must live engine-thread-resident,
//! because Mode A's whole session survives many HTTP requests exclusively through the `Loading`-state
//! engine's lifetime), Mode B's session state (the external-id → physical-id map, cumulative stats)
//! lives in `crate::bulk_import_mode_b::ModeBSession`, owned by the **async driver** — never on the
//! engine thread. [`BulkImportModeBChunkOutcome::new_node_bindings`] hands the chunk's *new*
//! `(external_id, physical_id)` pairs back to the driver, which merges them into its durable map only
//! after the **whole batch's** `Commit` succeeds (mirroring the `rmp` #517 stage-then-confirm pattern
//! at the driver level, not the chunk level — see `crate::bulk_import_mode_b`'s module docs for why a
//! chunk-level merge would reopen the exact abort-safety hole #517 fixed).
//!
//! This design choice keeps the engine-thread dispatch small and stateless per command (no new
//! `HashMap<SessionId, …>` threaded through `dispatch_command`'s already-long parameter list) and
//! keeps all id_map staging/merge logic in exactly one place (the driver), auditable as a single
//! unit against the #517 pattern it must faithfully reproduce.

use std::collections::HashMap;
use std::sync::Arc;

use graphus_bulk::{NodeHeader, RelHeader, parse_node_row, parse_rel_row};
use graphus_core::GraphusError;
use graphus_core::error::Result;
use graphus_cypher::{GraphAccess, NodeId, TxnCoordinator};
use graphus_io::BlockDevice;
use graphus_wal::LogSink;

use super::{OpenTxTable, TxTicket};

/// One chunk of already-parsed CSV rows submitted to the engine for Mode B ingestion (`rmp` #520).
/// Parsing (header decode, `csv::StringRecord` splitting) happens OFF the engine thread (the async
/// driver); only the `GraphAccess` write calls need the engine's single-writer thread.
///
/// Mirrors [`super::bulk_load::BulkImportBatchInput`]'s shape but carries **no `End` variant**: Mode
/// B has no engine-thread-resident session/sentinel to end (see the module docs) — ending a Mode B
/// session is purely a driver/registry-side bookkeeping action (`crate::bulk_import_mode_b`).
pub enum BulkImportModeBChunkInput {
    /// One chunk of node rows from a single node file.
    Nodes {
        /// The parsed node-file header (shared, `Arc`-wrapped, across every chunk of the same file —
        /// mirrors Mode A's per-file `Arc` reuse, though Mode B has no per-file token cache to key off
        /// it; the `Arc` is kept for a cheap, allocation-free clone per chunk).
        header: Arc<NodeHeader>,
        /// The parsed rows to ingest, in file order.
        records: Vec<csv::StringRecord>,
    },
    /// One chunk of relationship rows from a single relationship file.
    Relationships {
        /// The parsed relationship-file header.
        header: Arc<RelHeader>,
        /// The parsed rows to ingest, in file order.
        records: Vec<csv::StringRecord>,
        /// The caller's durable, **confirmed-only** external-id → physical-id map, snapshotted once
        /// per batch attempt (never rebuilt per chunk) and shared (`Arc`) across every chunk of the
        /// same attempt. A relationship row resolves its `:START_ID`/`:END_ID` **only** against this
        /// map — never a same-in-flight-batch node — mirroring Mode A's `LoadingSession` rule
        /// ("Endpoints resolve only against `id_map`'s confirmed (already-committed) bindings"). This
        /// is a hard correctness requirement inherited from the universal two-phase
        /// node-file-then-relationship-file model (`08` §4.2), not a Mode-B-specific choice.
        id_map: Arc<HashMap<String, u64>>,
    },
}

/// The outcome of one [`BulkImportModeBChunkInput`] dispatch.
#[derive(Debug, Clone, Default)]
pub struct BulkImportModeBChunkOutcome {
    /// The `(external_id, physical_node_id)` pairs this chunk's node rows produced. **Not yet
    /// committed** at reply time — the caller merges them into its durable map only after the whole
    /// batch's `Commit` succeeds (see the module docs). Empty for a relationship chunk.
    pub new_node_bindings: Vec<(String, u64)>,
    /// Nodes created by this chunk.
    pub nodes: u64,
    /// Relationships created by this chunk.
    pub relationships: u64,
    /// Non-null properties written by this chunk (nodes + relationships).
    pub properties: u64,
}

/// Ingests one [`BulkImportModeBChunkInput`] against `coordinator`'s already-open transaction
/// `ticket`, driving every row through the ordinary [`GraphAccess`] write seam (`08` §7.2's governing
/// rule). Does **not** commit — committing is the caller's job via the ordinary
/// [`super::command::EngineCommand::Commit`] (the driver runs `Begin` → N×this → `Commit`/`Rollback`
/// itself).
///
/// # Errors
/// - [`GraphusError::Transaction`] if `ticket` is unknown/inactive (mirrors `commit_prepare_tx`'s
///   error shape).
/// - A row-parse error (terminal — a malformed row will not fix itself on retry).
/// - [`GraphusError::Storage`]/[`GraphusError::Runtime`] for an unknown `:START_ID`/`:END_ID` (a
///   relationship referencing a node that was never committed — terminal, the same clean-error
///   convention `graphus_bulk::ingest_rel_row` uses).
/// - Whatever [`GraphAccess::create_node`]/[`GraphAccess::create_rel`] captured internally
///   (`graph.take_error()`), most commonly [`GraphusError::Transaction`] on a write-write lock
///   conflict or an SSI predicate conflict registered **mid-statement** — this is the **retriable**
///   case the caller's batch-retry loop (`crate::bulk_import_mode_b`) detects via
///   `matches!(err, GraphusError::Transaction(_))`.
pub(super) fn ingest_mode_b_chunk<D, S>(
    coordinator: &TxnCoordinator<D, S>,
    open: &OpenTxTable,
    ticket: TxTicket,
    chunk: BulkImportModeBChunkInput,
) -> Result<BulkImportModeBChunkOutcome>
where
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
{
    let txn = open.get(&ticket.0).map(|t| t.txn).ok_or_else(|| {
        GraphusError::Transaction(format!(
            "bulk-import Mode B chunk: unknown or inactive transaction ticket {}",
            ticket.0
        ))
    })?;
    let mut graph = coordinator.statement(txn)?;

    let mut outcome = BulkImportModeBChunkOutcome::default();
    match chunk {
        BulkImportModeBChunkInput::Nodes { header, records } => {
            for record in &records {
                let parsed =
                    parse_node_row(&header, record).map_err(graphus_core::GraphusError::from)?;
                let node_property_count = parsed.properties.len() as u64;
                let node_id = graph.create_node(&parsed.labels, &parsed.properties);
                if let Some(err) = graph.take_error() {
                    return Err(err);
                }
                outcome.nodes += 1;
                outcome.properties += node_property_count;
                outcome
                    .new_node_bindings
                    .push((parsed.external_id, node_id.0));
            }
        }
        BulkImportModeBChunkInput::Relationships {
            header,
            records,
            id_map,
        } => {
            for record in &records {
                let parsed =
                    parse_rel_row(&header, record).map_err(graphus_core::GraphusError::from)?;
                let start_id = *id_map.get(&parsed.start_external_id).ok_or_else(|| {
                    GraphusError::Storage(format!(
                        "relationship references unknown :START_ID `{}` (no such committed node)",
                        parsed.start_external_id
                    ))
                })?;
                let end_id = *id_map.get(&parsed.end_external_id).ok_or_else(|| {
                    GraphusError::Storage(format!(
                        "relationship references unknown :END_ID `{}` (no such committed node)",
                        parsed.end_external_id
                    ))
                })?;
                let rel_property_count = parsed.properties.len() as u64;
                let _rel_id = graph.create_rel(
                    &parsed.rel_type,
                    NodeId(start_id),
                    NodeId(end_id),
                    &parsed.properties,
                );
                if let Some(err) = graph.take_error() {
                    return Err(err);
                }
                outcome.relationships += 1;
                outcome.properties += rel_property_count;
            }
        }
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_bulk::{ColumnRole, PropertyType, ScalarType};
    use graphus_io::MemBlockDevice;
    use graphus_storage::RecordStore;
    use graphus_txn::IsolationLevel;
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
            id_name: None,
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

    fn open_txn(
        coord: &TxnCoordinator<MemBlockDevice, MemLogSink>,
        open: &mut OpenTxTable,
        next_ticket: &mut u64,
    ) -> TxTicket {
        let txn = coord.begin(IsolationLevel::Serializable);
        *next_ticket += 1;
        let ticket = *next_ticket;
        // `OpenTx`'s fields are module-private but visible here: this test module is a descendant of
        // `crate::engine`, where `OpenTx` is defined (ordinary Rust privacy — private items are
        // visible in the defining module and all its descendants).
        open.insert(
            ticket,
            super::super::OpenTx {
                txn,
                mode: super::super::AccessMode::Write,
                auto_commit: false,
            },
        );
        TxTicket(ticket)
    }

    #[test]
    fn unknown_ticket_is_a_clean_transaction_error() {
        let coord = coordinator();
        let open = OpenTxTable::new();
        let err = ingest_mode_b_chunk(
            &coord,
            &open,
            TxTicket(999),
            BulkImportModeBChunkInput::Nodes {
                header: node_header(),
                records: vec![],
            },
        )
        .unwrap_err();
        assert!(matches!(err, GraphusError::Transaction(_)));
    }

    #[test]
    fn ingests_node_chunk_through_the_graph_access_seam() {
        let coord = coordinator();
        let mut open = OpenTxTable::new();
        let mut next_ticket = 0u64;
        let ticket = open_txn(&coord, &mut open, &mut next_ticket);

        let out = ingest_mode_b_chunk(
            &coord,
            &open,
            ticket,
            BulkImportModeBChunkInput::Nodes {
                header: node_header(),
                records: vec![
                    record(&["n1", "Person", "Ada"]),
                    record(&["n2", "Person", "Bob"]),
                ],
            },
        )
        .expect("node chunk");
        assert_eq!(out.nodes, 2);
        assert_eq!(out.properties, 2);
        assert_eq!(out.new_node_bindings.len(), 2);
        assert_eq!(out.new_node_bindings[0].0, "n1");
        assert_eq!(out.new_node_bindings[1].0, "n2");
    }

    #[test]
    fn ingests_rel_chunk_resolving_against_the_confirmed_id_map() {
        let coord = coordinator();
        let mut open = OpenTxTable::new();
        let mut next_ticket = 0u64;
        let ticket = open_txn(&coord, &mut open, &mut next_ticket);

        let node_out = ingest_mode_b_chunk(
            &coord,
            &open,
            ticket,
            BulkImportModeBChunkInput::Nodes {
                header: node_header(),
                records: vec![
                    record(&["n1", "Person", "Ada"]),
                    record(&["n2", "Person", "Bob"]),
                ],
            },
        )
        .expect("node chunk");
        let mut id_map = HashMap::new();
        for (ext, id) in node_out.new_node_bindings {
            id_map.insert(ext, id);
        }
        let out = ingest_mode_b_chunk(
            &coord,
            &open,
            ticket,
            BulkImportModeBChunkInput::Relationships {
                header: rel_header(),
                records: vec![record(&["n1", "n2", "KNOWS", "2020"])],
                id_map: Arc::new(id_map),
            },
        )
        .expect("rel chunk");
        assert_eq!(out.relationships, 1);
        assert_eq!(out.properties, 1);
    }

    #[test]
    fn unknown_endpoint_is_a_terminal_storage_error() {
        let coord = coordinator();
        let mut open = OpenTxTable::new();
        let mut next_ticket = 0u64;
        let ticket = open_txn(&coord, &mut open, &mut next_ticket);

        let err = ingest_mode_b_chunk(
            &coord,
            &open,
            ticket,
            BulkImportModeBChunkInput::Relationships {
                header: rel_header(),
                records: vec![record(&["nope", "nope2", "KNOWS", "2020"])],
                id_map: Arc::new(HashMap::new()),
            },
        )
        .unwrap_err();
        assert!(matches!(err, GraphusError::Storage(_)));
    }

    #[test]
    fn malformed_typed_cell_is_a_terminal_parse_error() {
        let coord = coordinator();
        let mut open = OpenTxTable::new();
        let mut next_ticket = 0u64;
        let ticket = open_txn(&coord, &mut open, &mut next_ticket);

        let bad_header = Arc::new(NodeHeader {
            columns: vec![
                ColumnRole::Id,
                ColumnRole::Property {
                    key: "age".to_owned(),
                    ty: PropertyType::Scalar(ScalarType::Integer),
                },
            ],
            id_index: 0,
            id_name: None,
        });
        let err = ingest_mode_b_chunk(
            &coord,
            &open,
            ticket,
            BulkImportModeBChunkInput::Nodes {
                header: bad_header,
                records: vec![record(&["n1", "not-a-number"])],
            },
        )
        .unwrap_err();
        assert!(matches!(err, GraphusError::Storage(_)));
    }
}
