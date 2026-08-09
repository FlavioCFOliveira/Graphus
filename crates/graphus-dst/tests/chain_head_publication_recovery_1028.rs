//! **Crash recovery across a contended chain-head publication** (`rmp` #1028, acceptance criterion 4).
//!
//! # What this proves
//!
//! A node's `first_rel` is a chain head: writers PREPEND to it, and since `rmp` #1028 they publish it
//! with a compare-and-set whose redo image is itself conditional ([`graphus_storage`]'s
//! `encode_cas_patch`, replayed by the same `apply_patch` that serves live rollback). Two things have
//! to survive a crash, and this scenario asserts both:
//!
//! 1. **The winners replay.** Every committed prepend's publication is a conditional redo record, and
//!    ARIES redo must reconstruct exactly the chain the live system had. A conditional record that
//!    declined at replay would leave the head naming an older entry and silently drop every edge
//!    published after it — so this walks the hub's full incidence chain after recovery and requires
//!    every committed relationship to still be on it.
//! 2. **A refused publication leaves nothing behind.** The scenario reproduces the interleaving a
//!    second writer would produce: it reads the head, lets another transaction publish onto it, and
//!    then replays the first writer's now-stale publication. That publication must be refused *and
//!    must append no record at all* — because a record whose write never happened is only harmless
//!    while the log order matches the order the page actually changed, and under N writers it need
//!    not. Recovery must therefore see no trace of it.
//!
//! # Why the interleaving is scripted rather than raced
//!
//! Graphus has one writer thread per database until `rmp` #1016, and `RecordStore`'s write methods
//! take `&mut self`, so no scenario here can put two writers on one chain at the same instant; the
//! deterministic scheduler of `rmp` #973 says the same in its own doc comments (its four write-path
//! yield points are installed and not yet exercisable). The window is therefore opened by hand,
//! through the `dst`-gated `dst_publish_node_first_rel` seam, which is the same window a race would
//! open. The *concurrent* half of the property — two real threads, both entries in the chain — is
//! proved by the `loom` model in `graphus-chainhead`.
//!
//! # Non-vacuity
//!
//! Both halves were confirmed to fail with the defect present, by reverting the fix and re-running:
//! an unconditional publication lets the stale write land and the committed edges leave the chain;
//! a redo image built with `expect`/`new` transposed replays to nothing and the recovered hub has no
//! edges at all. `recovery_after_a_contended_prepend_keeps_every_committed_edge` also asserts a
//! non-zero edge count, so it cannot pass by finding nothing to check.
//!
//! # Running it
//!
//! ```text
//! cargo test -p graphus-dst --test chain_head_publication_recovery_1028
//! ```

use graphus_core::{PageId, TxnId};
use graphus_dst::rng::DetRng;
use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore, verify_on_open};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Deliberately small, so eviction and the WAL-before-data rule are live during the workload rather
/// than everything staying resident until the crash.
const POOL_CAPACITY: usize = 16;

const SEEDS: u64 = 200;

fn next_txn(next: &mut u64) -> TxnId {
    let t = TxnId(*next);
    *next += 1;
    t
}

/// What one seed's run observed, so the sweep can assert on it and a replay can be compared for
/// determinism.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Report {
    seed: u64,
    /// Whether this run crashed by the steal shape (dirty pages flushed home first) or the no-force
    /// shape (only the durable WAL prefix survives).
    steal: bool,
    /// Relationships committed onto the hub before the crash.
    committed_edges: usize,
    /// Of those, how many the recovered store still reaches by walking the hub's incidence chain.
    recovered_edges: usize,
    /// Whether the scripted stale publication was refused.
    stale_publication_refused: bool,
}

fn run(seed: u64) -> Report {
    let mut rng = DetRng::new(seed);
    let steal = rng.chance(50);

    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");

    let mut next = 1u64;
    let setup = next_txn(&mut next);
    store.begin(setup);
    let rel_type = store
        .intern_token(Namespace::RelType, "LINK")
        .expect("intern reltype");
    let (hub, _) = store.create_node(setup).expect("hub");
    // Peers enough that several transactions can each prepend onto the hub.
    let peer_count = rng.range_inclusive(3, 6) as usize;
    let peers: Vec<u64> = (0..peer_count)
        .map(|_| store.create_node(setup).expect("peer").0)
        .collect();
    store.commit(setup).expect("commit setup");

    // --- Committed prepends, one transaction each, all onto the SAME head. ---
    let mut committed: Vec<u64> = Vec::new();
    for peer in &peers {
        let t = next_txn(&mut next);
        store.begin(t);
        let (r, _) = store
            .create_rel(t, rel_type, hub, *peer)
            .expect("create_rel");
        store.commit(t).expect("commit edge");
        committed.push(r);
    }

    // --- The scripted interleaving. ---
    //
    // A writer observes the head here. Everything after this point stands in for the work that
    // writer does before it publishes — allocating an id, mapping a page, writing a whole record —
    // during which another writer legitimately publishes onto the same head.
    let observed = store.node(hub).expect("hub").first_rel;

    let t_win = next_txn(&mut next);
    store.begin(t_win);
    let (r_win, _) = store
        .create_rel(t_win, rel_type, hub, peers[0])
        .expect("winner");
    store.commit(t_win).expect("commit winner");
    committed.push(r_win);

    // The stale publication finally arrives. It must be refused: `observed` is no longer the head.
    // The entry id is one past the highest real id, so a publication that DID land would be
    // detectable as a head naming nothing.
    let t_late = next_txn(&mut next);
    store.begin(t_late);
    let bogus = committed.iter().copied().max().unwrap_or(0) + 1;
    let published = store
        .dst_publish_node_first_rel(hub, observed, bogus, t_late)
        .expect("stale publication");
    let stale_publication_refused = !published;
    // The would-be writer aborts, exactly as one whose retry then failed would.
    store.rollback(t_late).expect("rollback the late writer");

    // Harden the tail so the crash WAL carries everything above.
    store.with_wal(WalManager::flush);

    let store = if steal {
        crash_steal(store)
    } else {
        crash_no_force(store)
    };

    // ---- The recovered store must be structurally consistent, chains included. ----
    verify_on_open(&store, &[]).expect("the recovered store must be consistent");

    // ---- and every committed edge must still be reachable from the hub. ----
    let reachable: Vec<u64> = store
        .incident_rels(hub)
        .expect("the hub's incidence chain must be walkable")
        .into_iter()
        .collect();
    let recovered_edges = committed.iter().filter(|r| reachable.contains(r)).count();

    Report {
        seed,
        steal,
        committed_edges: committed.len(),
        recovered_edges,
        stale_publication_refused,
    }
}

/// No-force crash: rebuild onto a fresh empty device from the durable WAL prefix, then reopen.
fn crash_no_force(store: Store) -> Store {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, POOL_CAPACITY).expect("open store")
}

/// Steal crash: flush dirty pages home, snapshot that on-disk image, then recover onto it.
fn crash_steal(store: Store) -> Store {
    store.flush().expect("flush (steal)");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    for p in &pages {
        let bytes = store.read_device_page(*p).expect("read device page");
        device.write_page(PageId(p.0), &bytes).expect("stage page");
    }
    device.sync_all().expect("persist disk image");
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, POOL_CAPACITY).expect("open store")
}

/// **Acceptance criterion 4.** Across a seed sweep and both crash shapes, recovery after a crash that
/// follows a contended chain-head publication restores a consistent state in which every committed
/// relationship is still on the hub's incidence chain.
#[test]
fn recovery_after_a_contended_prepend_keeps_every_committed_edge() {
    let mut steal_runs = 0usize;
    let mut noforce_runs = 0usize;

    for seed in 0..SEEDS {
        let r = run(seed);

        assert!(
            r.stale_publication_refused,
            "seed {seed}: a publication against a head that had already been displaced must be \
             refused; landing it severs every edge published after the one it observed (`rmp` #220)"
        );
        // NON-VACUITY: the run has to have built a chain in the first place.
        assert!(
            r.committed_edges >= 4,
            "seed {seed}: the fixture must commit several prepends onto one head, got {}",
            r.committed_edges
        );
        assert_eq!(
            r.recovered_edges,
            r.committed_edges,
            "seed {seed} ({}): {} of {} committed relationships survived recovery on the hub's \
             incidence chain. A missing edge means the conditional redo of a chain-head publication \
             did not replay to the verdict the live system reached (`rmp` #1028)",
            if r.steal { "steal" } else { "no-force" },
            r.recovered_edges,
            r.committed_edges
        );

        if r.steal {
            steal_runs += 1;
        } else {
            noforce_runs += 1;
        }
    }

    // NON-VACUITY: both crash shapes must actually have been exercised, or half the property is
    // untested and the sweep would still be green.
    assert!(
        steal_runs > 0 && noforce_runs > 0,
        "the sweep must exercise both crash shapes: {steal_runs} steal, {noforce_runs} no-force"
    );
}

/// The sweep is a deterministic function of the seed, so a failure above reproduces exactly.
#[test]
fn the_sweep_is_deterministic() {
    for seed in [0, 3, 17, 91] {
        assert_eq!(
            run(seed),
            run(seed),
            "seed {seed} did not replay identically"
        );
    }
}
