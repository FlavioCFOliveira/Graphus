//! `rmp` #1009 (layer 1 of #975) — the coordinator's leaves are `Send + Sync`.
//!
//! # What this gate is for
//!
//! The `TxnCoordinator` holds six pieces of shared state. Making the engine multi-writer means making
//! the coordinator `Send`, and the `Rc<RefCell<…>>` wrapper around those six is only the *packaging* —
//! the real obstacle is whether the **contents** are `Send + Sync`. Three of them were not:
//!
//! | Leaf | What made it `!Send` / `!Sync` | Fixed by |
//! | --- | --- | --- |
//! | [`IndexSet`] | `graphus_index::recovery::SharedWal` was `Rc<RefCell<WalManager>>` | `Arc<Mutex<…>>` |
//! | [`ColumnCache`] | `RefCell<Option<Rc<…>>>` lazy memos, `Cell<u64>` counters | `OnceLock<Arc<…>>`, `AtomicU64` |
//! | [`ZoneMap`] | `Cell<u64>` observability counters | `AtomicU64` |
//!
//! The other three — the record store, the SSI tracker and the CSR adjacency — were already clean;
//! `graphus_storage` has asserted its own half since `rmp` #337
//! (`RecordStore`'s `record_store_is_send_and_sync`), and the index crate's `SharedWal` was simply the
//! unfinished twin of the storage one.
//!
//! # Why a compile-time assertion and not a runtime test
//!
//! There is no runtime behaviour to observe: `Send`/`Sync` are auto-derived, so the only way to state
//! the property is to make the build fail when it stops holding. This file has no runtime body worth
//! the name — it fails to **compile** the moment a `Rc`, `RefCell` or `Cell` is reintroduced into any
//! of these types, which is exactly the regression it exists to catch. It is the same device
//! `graphus_storage`'s own gate uses, and it is deliberately placed in an integration test so it is
//! stated against the crate's **public** surface.
//!
//! Run with `cargo test -p graphus-cypher --test coordinator_leaves_are_send_1009`.

use graphus_cypher::column_cache::ColumnCache;
use graphus_cypher::csr_adjacency::CsrAdjacency;
use graphus_cypher::index_set::IndexSet;
use graphus_cypher::zone_map::ZoneMap;
use graphus_io::MemBlockDevice;
use graphus_txn::SsiTracker;
use graphus_wal::MemLogSink;

fn assert_send_sync<T: Send + Sync>() {}

/// Every leaf the coordinator shares is `Send + Sync`.
///
/// Stated leaf by leaf rather than as one assertion on the coordinator, on purpose: when this breaks,
/// the failing line names the type that regressed instead of leaving the reader to bisect six fields.
#[test]
fn the_coordinators_shared_leaves_are_send_and_sync() {
    assert_send_sync::<IndexSet>();
    assert_send_sync::<ColumnCache>();
    assert_send_sync::<ZoneMap>();
    assert_send_sync::<CsrAdjacency>();
    assert_send_sync::<SsiTracker>();
}

/// The tree types `IndexSet` is built out of, stated **generically** so the property is a bound
/// rather than a fact about the one `(Dev, Sink)` pair `IndexSet` happens to pin.
///
/// `IndexSet` itself is not generic — it fixes its device and sink, because every derived index is
/// ephemeral and rebuilt from the store on open. Asserting only the concrete `IndexSet` would
/// therefore leave the underlying trees unconstrained, and a future `IndexSet` over a different pair
/// could silently regress. This states the bound where it actually lives.
#[test]
fn the_index_trees_are_send_and_sync_for_every_send_device_and_sink() {
    fn assert_generic<
        D: graphus_io::BlockDevice + Send + Sync,
        S: graphus_wal::LogSink + Send + Sync,
    >() {
        assert_send_sync::<graphus_index::BTree<D, S>>();
        assert_send_sync::<graphus_index::recovery::SharedWal<S>>();
    }
    assert_generic::<MemBlockDevice, MemLogSink>();
}

/// The index WAL handle itself, named separately because it is the one that moved.
///
/// `graphus_storage::wal_rule::SharedWal` has asserted this since `rmp` #337; its index twin only
/// caught up here, and stating both makes the pair auditable in one place.
#[test]
fn both_shared_wal_handles_are_send_and_sync() {
    assert_send_sync::<graphus_index::recovery::SharedWal<MemLogSink>>();
    assert_send_sync::<graphus_storage::wal_rule::SharedWal<MemLogSink>>();
}
