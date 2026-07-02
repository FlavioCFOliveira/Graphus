//! Bulk-import validity contract for the product-recommendation graph generator (`rmp` task #539).
//!
//! `tests/determinism.rs` proves the emitted CSV is *reproducible*; this test proves it is a *valid
//! bulk-import artifact*. The `fast`-profile CSV file set is streamed into a fresh in-memory
//! [`RecordStore`] through the PRODUCTION offline importer [`graphus_bulk::BulkImporter`] — the same
//! ingest path the network bulk-import endpoint drives (`crates/graphus-server/tests/bulk_import_endpoint.rs`,
//! `network_mode_a_matches_the_offline_importer_stats`) — and the resulting node / relationship counts
//! are asserted to match the generator's own [`Generator::summary`]. If a header were malformed, a
//! typed cell unparseable, an `:ID` duplicated, or a `:START_ID`/`:END_ID` unresolvable, the importer
//! would error here and the test would fail — so a green run certifies the whole file set round-trips.
//!
//! The store / WAL / device construction is copied precisely from the server's own parity test.

use graphus_bulk::{BulkImporter, DEFAULT_BATCH_SIZE};
use graphus_io::MemBlockDevice;
use graphus_reco_gen::{GenConfig, Generator};
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// Collects a full CSV stream (header + all data chunks) into one byte buffer.
fn collect_csv(stream: impl FnOnce(&mut dyn FnMut(Vec<u8>))) -> Vec<u8> {
    let mut out = Vec::new();
    let mut sink = |chunk: Vec<u8>| out.extend_from_slice(&chunk);
    stream(&mut sink);
    out
}

#[test]
fn fast_profile_bulk_imports_into_a_fresh_store_with_matching_counts() {
    let generator = Generator::new(GenConfig::fast());
    let summary = generator.summary();

    // Materialize each stream into a `Vec<u8>` first (the importer wants a single reader per file).
    let users_csv = collect_csv(|sink| generator.stream_user_csv(sink));
    let products_csv = collect_csv(|sink| generator.stream_product_csv(sink));
    let mut friend_total = 0u64;
    let friends_csv = collect_csv(|sink| {
        friend_total = generator.stream_friend_csv(sink);
    });
    let mut purchased_total = 0u64;
    let purchased_csv = collect_csv(|sink| {
        purchased_total = generator.stream_purchased_csv(sink);
    });

    // A fresh, empty in-memory store (same construction as the server's offline-parity test).
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store = RecordStore::create(device, wal, 64, 1).expect("create store");

    let mut importer = BulkImporter::new(store, DEFAULT_BATCH_SIZE, b',');
    // Both node files first (the importer accumulates external-id → physical-id bindings across calls),
    // then both relationship files (whose endpoints resolve against every imported node).
    importer
        .import_nodes(users_csv.as_slice())
        .expect("import users.csv");
    importer
        .import_nodes(products_csv.as_slice())
        .expect("import products.csv");
    importer
        .import_relationships(friends_csv.as_slice())
        .expect("import friends.csv");
    importer
        .import_relationships(purchased_csv.as_slice())
        .expect("import purchased.csv");
    let (_store, stats) = importer.finish();

    // The importer's realised counts must match the generator's own summary exactly.
    assert_eq!(
        stats.nodes,
        summary.users + summary.products,
        "imported node count must equal users + products"
    );
    assert_eq!(
        stats.relationships,
        summary.friend_edges + summary.purchased_edges,
        "imported relationship count must equal friend + purchased edges"
    );

    // Sanity: the stream-return counts agree with the summary the assertions above trusted.
    assert_eq!(friend_total, summary.friend_edges, "FRIEND stream return");
    assert_eq!(
        purchased_total, summary.purchased_edges,
        "PURCHASED stream return"
    );
}
