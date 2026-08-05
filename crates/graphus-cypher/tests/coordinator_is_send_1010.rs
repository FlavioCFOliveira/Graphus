//! `rmp` #1010 (layer 2 of #975) — the coordinator itself is `Send`.
//!
//! # What this gate is for
//!
//! [`coordinator_leaves_are_send_1009`](../coordinator_leaves_are_send_1009/index.html) made the six
//! pieces of state the `TxnCoordinator` shares `Send + Sync`. That was necessary and not sufficient:
//! the coordinator stayed `!Send` because of the **packaging**, six `Rc<RefCell<…>>` fields, and an
//! `Rc` is `!Send` no matter what it points at.
//!
//! Layer 2 replaced that packaging with [`SharedCell`](graphus_cypher::shared_cell::SharedCell). This
//! file states the resulting property where a regression would be caught: the moment anyone
//! reintroduces an `Rc`, a `RefCell` or any other `!Send` field into the coordinator or into the
//! statement seam it hands out, this stops compiling.
//!
//! # Why a compile-time assertion and not a runtime test
//!
//! `Send` is auto-derived, so there is no runtime behaviour to observe — the only way to state the
//! property is to make the build fail when it stops holding. The *behavioural* half of layer 2 lives
//! elsewhere: [`graphus_cypher::shared_cell`]'s own tests prove the re-entrancy tripwire panics rather
//! than hanging, and `graphus-dst`'s `multi_writer_coordinator_1010` drives two real writer threads
//! through one coordinator — the scenario this `Send` bound is what makes expressible.
//!
//! Run with `cargo test -p graphus-cypher --test coordinator_is_send_1010`.

use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::record_graph::RecordStoreGraph;
use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_wal::{LogSink, MemLogSink};

fn assert_send<T: Send>() {}
fn assert_send_sync<T: Send + Sync>() {}

/// **Acceptance criterion 1.** The coordinator crosses a thread boundary.
#[test]
fn the_coordinator_is_send() {
    assert_send::<TxnCoordinator<MemBlockDevice, MemLogSink>>();
}

/// The same bound stated **generically**, so it is a property of the type rather than a fact about the
/// one `(device, sink)` pair the DST fixtures happen to use.
///
/// Without this, a coordinator over the production file device and file log could silently regress
/// while the in-memory instantiation above kept compiling.
#[test]
fn the_coordinator_is_send_for_every_send_device_and_sink() {
    fn generic<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>() {
        assert_send::<TxnCoordinator<D, S>>();
    }
    generic::<MemBlockDevice, MemLogSink>();
}

/// `Arc<TxnCoordinator<…>>` is shareable between threads.
///
/// Strictly stronger than [`the_coordinator_is_send`]: `Arc<T>: Send + Sync` requires `T: Sync` too,
/// which is what lets two threads hold the *same* coordinator rather than merely move one between
/// them. This is the type behind `graphus-dst`'s two-writer scenario.
#[test]
fn an_arc_of_the_coordinator_is_send_and_sync() {
    assert_send_sync::<std::sync::Arc<TxnCoordinator<MemBlockDevice, MemLogSink>>>();
    // And the form a writer actually needs, because the transaction lifecycle is still `&mut self`.
    // `Mutex<T>: Sync` requires `T: Send` — precisely what layer 2 delivered.
    assert_send_sync::<std::sync::Arc<std::sync::Mutex<TxnCoordinator<MemBlockDevice, MemLogSink>>>>(
    );
}

/// The statement seam is `Send` too.
///
/// Not required by the acceptance criteria, and stated deliberately anyway: the seam holds clones of
/// five of the coordinator's six cells, so it is the place a reintroduced `Rc` would most plausibly
/// hide — a coordinator field could stay clean while the seam that shares it regressed.
///
/// It is **not** `Sync`, and that is correct rather than an oversight: the seam keeps genuinely
/// statement-local interior mutability (`error`, `counters`, `tally`, `defer_constraint_check`) that
/// only ever runs on one thread at a time. `Send` without `Sync` states exactly that — the seam may be
/// moved to a thread, never shared between two.
#[test]
fn the_statement_seam_is_send_but_not_shared() {
    assert_send::<RecordStoreGraph<MemBlockDevice, MemLogSink>>();
}
