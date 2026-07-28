//! Regression test for `rmp` #955: a bulk batch whose **commit fails** must be rolled back.
//!
//! `BulkImporter::commit_batch` used to treat a failed `RecordStore::commit` as a bookkeeping event:
//! it cleared the staged `id_map` bindings and reverted the `ImportStats` snapshot (the `rmp` #517
//! abort-safety pattern) and returned the error, without ever telling the store to undo anything. But
//! a commit that fails inside `commit_prepare` — a failed catalog checkpoint, a failed `COMMIT`
//! append — deliberately leaves the transaction OPEN (`rmp` #866, so its count delta and schema undo
//! log survive for the rollback that must follow). Nothing followed. The batch's rows stayed
//! physically on the page under a transaction that would never resolve, which:
//!
//! * keeps `RecordStore::uncommitted_data_writer` naming it forever, so every subsequent
//!   `CREATE CONSTRAINT` on the resulting database is refused (`rmp` #902) — and the store is handed
//!   to the caller by `finish()`, so "the process is ending anyway" is not an answer;
//! * leaves the transaction's live-record count delta folded into the shared tally with nothing left
//!   to withdraw it, so the durable catalogue over-counts (`rmp` #866);
//! * leaves rows visible to a raw scan that no MVCC snapshot will ever resolve.
//!
//! The network Mode A loader (`graphus_server::engine::bulk_load`) carried the identical shape and is
//! covered by the second test below, through the same `LocalEngine` dispatch the production engine
//! loop uses.
//!
//! ## Landing the fault in the COMMIT, and proving it landed there
//!
//! `MemBlockDevice::arm_io_error` is one-shot on the next home write, so the batch must be shaped so
//! that the commit performs the FIRST such write. Two things make that true:
//!
//! * the doomed batch's header declares a fresh set of property keys, so interning them (which happens
//!   once, up front, and writes nothing to the device) pushes the encoded catalog past another
//!   metadata page — and the commit's `checkpoint_meta` must therefore GROW the metadata chain, a
//!   fresh page allocation plus a home write;
//! * every one of its row's property cells is EMPTY, so the row writes no property record and the
//!   ingestion itself allocates no page. A batch with populated cells allocates hundreds of property
//!   pages, each of which is a home write, and the fault fires during ingestion instead — which the
//!   row-error path already rolled back long before `rmp` #955, making the test pass against the
//!   defective code. That is not a hypothetical: it is what the first version of this test did, and it
//!   was caught by running it against the pre-fix code.
//!
//! Which is also the proof: these tests FAIL against the pre-fix code. A fault that landed anywhere
//! but in the commit would leave them passing there, so their failure is what pins the fault's
//! position — no internal instrumentation required.
//!
//! This lives in `graphus-dst` rather than beside the code it exercises because arming a device fault
//! needs `graphus-storage`'s `dst` feature, which this crate already enables; the alternative would be
//! to turn a test-only seam on for every consumer of `graphus-bulk`.

use std::sync::Arc;

use graphus_bulk::{BulkImporter, ColumnRole, NodeHeader, PropertyType, ScalarType};
use graphus_io::MemBlockDevice;
use graphus_server::engine::{
    BulkImportBatchInput, ConstraintCommand, ConstraintCreateKind, ConstraintEntity,
    CreateConstraint, LocalEngine,
};
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// A fresh, empty in-memory record store.
fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("wal create");
    RecordStore::create(device, wal, 256, 1).expect("store create")
}

/// How many distinct property keys one file's header declares. Enough that interning them pushes the
/// encoded catalog past another metadata page; the exact figure is a property of the page size, not of
/// the scenario, so it is generated rather than written out.
const PROPERTY_COLUMNS: usize = 512;

/// A node CSV whose header declares [`PROPERTY_COLUMNS`] property keys prefixed by `generation`, so
/// two calls with different generations intern two DISJOINT sets of tokens and each grows the catalog
/// again.
///
/// `populate` decides whether the rows carry values. An unpopulated row leaves every cell empty, which
/// `parse_cell` skips, so the row creates a node and **no property record** — and therefore allocates
/// no property page. That is what leaves the commit's metadata-chain growth as the batch's first home
/// write, which is where the injected fault must land.
fn wide_node_csv(generation: u32, rows: usize, populate: bool) -> String {
    let mut out = String::from(":ID,:LABEL");
    for i in 0..PROPERTY_COLUMNS {
        out.push_str(&format!(",gen{generation}_property_key_number_{i:08}:int"));
    }
    for r in 0..rows {
        out.push('\n');
        out.push_str(&format!("g{generation}n{r},Person"));
        for i in 0..PROPERTY_COLUMNS {
            if populate {
                out.push_str(&format!(",{i}"));
            } else {
                out.push(',');
            }
        }
    }
    out.push('\n');
    out
}

/// The batch's commit fails; the importer must roll the batch's transaction back, leaving no open
/// writer and no half-applied rows behind.
///
/// Fails against the pre-#955 code on the `uncommitted_data_writer` assertion: the transaction was
/// left open forever.
#[test]
fn a_failed_batch_commit_is_rolled_back_955() {
    let mut importer = BulkImporter::new(fresh_store(), 64, b',');

    // A first batch that COMMITS, so the assertions below are made against a non-empty store and the
    // "no writer remains" claim is not a statement about a store nothing ever wrote to.
    importer
        .import_nodes(wide_node_csv(0, 2, true).as_bytes())
        .expect("the clean batch must import");
    assert_eq!(
        importer.store_ref_for_test().uncommitted_data_writer(),
        None,
        "precondition: a committed batch leaves no open writer"
    );
    let committed_nodes = importer.stats().nodes;
    assert!(
        committed_nodes > 0,
        "precondition: the clean batch must actually have written rows"
    );

    // ARM: the next home write fails. The doomed batch's header interns a fresh generation of keys, so
    // its commit must grow the metadata chain; its single row carries no values, so ingestion allocates
    // nothing. The commit's chain growth is therefore the batch's first home write.
    importer
        .store_mut_for_test()
        .with_device_mut(MemBlockDevice::arm_io_error);
    let doomed = importer.import_nodes(wide_node_csv(1, 1, false).as_bytes());
    let err = doomed.expect_err("the armed I/O error must fail the batch");
    assert!(
        err.to_string().contains("injected I/O error"),
        "non-vacuity: the batch must fail on the INJECTED fault, not on something else; got {err}"
    );

    // THE ASSERTION: the failed batch's transaction was rolled back, not left open.
    assert_eq!(
        importer.store_ref_for_test().uncommitted_data_writer(),
        None,
        "a batch whose commit failed must be ROLLED BACK: before rmp #955 its transaction stayed \
         open forever, permanently refusing every CREATE CONSTRAINT on the resulting database \
         (rmp #902) and leaving its count delta unwithdrawable (rmp #866)"
    );
    assert_eq!(
        importer.stats().nodes,
        committed_nodes,
        "the failed batch must not advance the cumulative row counters (rmp #517, preserved)"
    );

    let (store, _stats) = importer.finish();
    assert_eq!(
        store.uncommitted_data_writer(),
        None,
        "the store handed to the caller must carry no unresolved writer"
    );
    assert!(
        store.counts_match_committed_image(),
        "the durable catalogue counters must agree with the committed image: a transaction left \
         open would keep its uncommitted increments folded into the shared tally (rmp #866)"
    );
    assert_eq!(
        store.scan_node_ids().expect("scan nodes").len(),
        committed_nodes as usize,
        "only the committed batch's rows may remain in use"
    );
}

/// The **network Mode A** loader (`graphus_server::engine::bulk_load`) carried the identical defect
/// on all three of its commit sites, and reaches it through a live server whose database keeps
/// serving afterwards — so the orphaned transaction is not a process-lifetime nuisance but a
/// permanent one.
///
/// Driven through `LocalEngine::bulk_import_batch`, the same dispatch the production engine loop
/// uses. The observable consequence asserted here is the `rmp` #902 guard: a `CREATE CONSTRAINT`
/// issued after the failed batch must be ACCEPTED, which it can only be once the batch's transaction
/// has actually been rolled back.
///
/// Fails against the pre-#955 code: the DDL is refused, naming a bulk transaction that will never
/// resolve.
#[test]
fn a_failed_mode_a_batch_commit_is_rolled_back_955() {
    let mut eng: LocalEngine<MemBlockDevice, MemLogSink> =
        LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 256).expect("engine");
    let header = wide_node_header(0);

    // A first batch that COMMITS, so the store is non-empty and the sentinel checkpoint node exists.
    eng.bulk_import_batch(BulkImportBatchInput::Nodes {
        header: Arc::clone(&header),
        records: vec![wide_node_row("n0", true)],
    })
    .expect("the clean batch must import");

    // Precondition: with the session quiet, the DDL is accepted — so a refusal afterwards is
    // attributable to the failed batch and not to the fixture. Over a property no batch writes, so it
    // cannot become an equivalent-schema conflict for the assertion below.
    eng.constraint_ddl(unique_constraint("u_probe", "Person", "probe_only"))
        .expect("the DDL must be accepted over a quiet, committed graph");

    // A fresh header generation, so its interning grows the catalog again and the commit must grow the
    // metadata chain; an unpopulated row, so the ingestion allocates nothing. See the module docs.
    let doomed_header = wide_node_header(1);
    eng.with_device_mut(MemBlockDevice::arm_io_error)
        .expect("the engine is live, so the device seam must be reachable");
    let doomed = eng.bulk_import_batch(BulkImportBatchInput::Nodes {
        header: Arc::clone(&doomed_header),
        records: vec![wide_node_row("n1", false)],
    });
    let err = doomed.expect_err("the armed I/O error must fail the batch");
    assert!(
        err.to_string().contains("injected I/O error"),
        "non-vacuity: the batch must fail on the INJECTED fault; got {err}"
    );

    eng.constraint_ddl(unique_constraint("u_after", "Person", "gen0_property_key_number_00000000"))
        .expect(
            "the rmp #902 guard must be open after the failed batch — it can only be if the batch's \
             transaction was rolled back. Before rmp #955 the Mode A loader returned the commit error \
             without any rollback, orphaning the transaction for the life of the database",
        );
}

/// A `CREATE CONSTRAINT … IS UNIQUE` engine command.
fn unique_constraint(name: &str, label: &str, property: &str) -> ConstraintCommand {
    ConstraintCommand::Create(CreateConstraint {
        name: name.to_owned(),
        entity: ConstraintEntity::Node {
            label: label.to_owned(),
        },
        properties: vec![property.to_owned()],
        kind: ConstraintCreateKind::Unique,
        if_not_exists: false,
        or_replace: false,
    })
}

/// The Mode A twin of [`wide_node_csv`]'s header: `:ID`, `:LABEL` and [`PROPERTY_COLUMNS`] integer
/// property columns, so a batch's catalog outgrows one metadata page.
fn wide_node_header(generation: u32) -> Arc<NodeHeader> {
    let mut columns = vec![ColumnRole::Id, ColumnRole::Label];
    for i in 0..PROPERTY_COLUMNS {
        columns.push(ColumnRole::Property {
            key: format!("gen{generation}_property_key_number_{i:08}"),
            ty: PropertyType::Scalar(ScalarType::Integer),
        });
    }
    Arc::new(NodeHeader {
        columns,
        id_index: 0,
        id_name: None,
    })
}

/// One row matching [`wide_node_header`]'s column order. `populate == false` leaves every property
/// cell empty, so the row creates a node and no property record — see the module docs for why that is
/// load-bearing.
fn wide_node_row(external_id: &str, populate: bool) -> csv::StringRecord {
    let mut fields = vec![external_id.to_owned(), "Person".to_owned()];
    for i in 0..PROPERTY_COLUMNS {
        fields.push(if populate {
            i.to_string()
        } else {
            String::new()
        });
    }
    csv::StringRecord::from(fields)
}
