//! WAL-before-data across an **eviction-driven steal crash** (`rmp` #974).
//!
//! # Why this test exists
//!
//! `rmp` #974 moved the WAL harden out from under the buffer pool's frame latch. The harden used to
//! run inside `write_back`, immediately before the home write, in one latched region; it now happens
//! *earlier* — `select_victim` declines a dirty victim whose `page_lsn` the log is not yet durable
//! through, releases its latch, and the caller hardens with nothing held before re-sweeping.
//!
//! That is a change to **when** the log is made durable relative to **when** the page is stolen, so
//! it is exactly the kind of change that can silently break the steal/no-force rule: if a page ever
//! reaches its home location while its redo record is not durable, a crash leaves that page on disk
//! with no log record to undo it, and the uncommitted effect survives recovery. There is no checksum
//! or assertion at read time that would catch it — the store simply comes back wrong.
//!
//! # The crash model
//!
//! This is a genuine **steal** crash, not a flush-then-crash: nothing is flushed on the way out. The
//! only pages on the captured disk image are the ones the *eviction path itself* wrote home, and the
//! only log is the durable prefix. Recovery then replays that prefix onto that image, exactly as a
//! reopen after a power loss does.
//!
//! The pool is deliberately tiny relative to the working set, so eviction — and therefore the
//! hoisted write-back path — runs constantly and a loser transaction's dirty pages are genuinely
//! stolen to disk before the crash. [`working_set_exceeds_the_pool`] is the non-vacuity control for
//! that: without it the scenario could pass by never evicting anything at all.
//!
//! The frame-latch tripwire (`graphus_core::latch`) is armed throughout, so if the harden ever slid
//! back under a latch these tests would panic rather than quietly regress.

use graphus_core::{PageId, TxnId};
use graphus_io::{BlockDevice, MemBlockDevice, Page};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// A pool far smaller than the working set these tests build, so every page touch after the first
/// few must evict a victim and a dirty victim takes the write-back path.
const TINY_POOL: usize = 8;

/// Committed nodes to create so the working set comfortably spills [`TINY_POOL`].
///
/// Node records are small and pack many to an 8 KiB page, so a few hundred nodes still fit in a
/// handful of pages — nowhere near enough to force eviction. This count is sized so the store maps
/// tens of pages against an 8-frame pool, which every test below asserts explicitly rather than
/// assumes.
const NODES_TO_SPILL: u64 = 6_000;

/// Builds a fresh store over an in-memory device + log with a `cap`-frame buffer pool.
fn fresh(cap: usize) -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, cap, 1).expect("create store")
}

/// Captures the state a power loss would leave behind and recovers from it.
///
/// Unlike the `recover_steal` helper in `crash_recovery.rs`, this **does not flush**: the disk image
/// is whatever the eviction path already wrote home (each such write is `fdatasync`ed by
/// `write_back`, so it is genuinely durable), and the log is the group-committed durable prefix.
/// This is the mid-eviction crash — the state in which WAL-before-data is the only thing standing
/// between a stolen uncommitted page and a corrupt recovered store.
fn crash_mid_eviction_and_recover(store: &mut Store) -> Store {
    // Snapshot the on-disk image as the eviction path left it.
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    let mut staged: Vec<(u64, Box<Page>)> = Vec::new();
    for p in &pages {
        staged.push((p.0, store.read_device_page(*p).expect("read device page")));
    }
    for (idx, bytes) in staged {
        device.write_page(PageId(idx), &bytes).expect("stage page");
    }
    device.sync_all().expect("persist disk image");

    // The durable WAL prefix — the only log a crash leaves behind.
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");

    let mut wal = WalManager::open(sink).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    // Reopen over the log RECOVERY WROTE TO, CLRs included (`rmp` #1031). `MemLogSink` derives
    // `Clone` as a deep copy, so recovering over a clone and reopening over the original discards
    // every compensation record the undo phase appended — and leaves the pages it compensated
    // stamped with LSNs that name no record in the log the store then reopens over.
    let wal = WalManager::open(wal.sink().clone()).expect("reopen over the recovered log");
    RecordStore::open(device, wal, 64).expect("open store")
}

/// Creates `n` committed nodes in their own transactions, returning their physical ids. Each
/// transaction commits, so every one of these must survive the crash.
fn commit_nodes(s: &mut Store, first_txn: u64, n: u64) -> Vec<u64> {
    let mut ids = Vec::with_capacity(n as usize);
    for i in 0..n {
        let txn = TxnId(first_txn + i);
        s.begin(txn);
        let (id, _) = s.create_node(txn).expect("create node");
        s.commit(txn).expect("commit");
        ids.push(id);
    }
    ids
}

/// **The non-vacuity control.** The scenario is only meaningful if the working set genuinely spilled
/// the buffer pool, because that is what forces the eviction write-back path — the path `rmp` #974
/// restructured — to run at all. A scenario that fits in the pool never evicts, never steals, and
/// would pass no matter how broken the write-back ordering was.
#[test]
fn working_set_exceeds_the_pool() {
    let mut s = fresh(TINY_POOL);
    commit_nodes(&mut s, 1, NODES_TO_SPILL);
    assert!(
        s.mapped_pages().len() > TINY_POOL,
        "the working set ({} pages) must exceed the {TINY_POOL}-frame pool, otherwise nothing is \
         ever evicted and the crash tests below prove nothing",
        s.mapped_pages().len()
    );
}

/// Committed work survives a crash taken **in the middle of eviction churn**, with no flush on the
/// way out: every page that reached disk did so through the hoisted write-back path, and everything
/// else is reconstructed by redo from the durable log.
#[test]
fn committed_work_survives_a_crash_during_eviction_churn() {
    let mut s = fresh(TINY_POOL);
    let ids = commit_nodes(&mut s, 1, NODES_TO_SPILL);
    // A committed relationship too, so adjacency (a multi-page structure) is exercised.
    let t = TxnId(10_000);
    s.begin(t);
    let rel_type = s.intern_token(Namespace::RelType, "KNOWS").expect("token");
    let (r, _) = s
        .create_rel(t, rel_type, ids[0], ids[1])
        .expect("create rel");
    s.commit(t).expect("commit rel");

    assert!(
        s.mapped_pages().len() > TINY_POOL,
        "non-vacuity: the working set must have spilled the pool"
    );

    let rec = crash_mid_eviction_and_recover(&mut s);

    for id in &ids {
        assert!(
            rec.node(*id).expect("recovered node").mvcc.in_use(),
            "committed node {id} must survive a mid-eviction crash"
        );
    }
    assert_eq!(
        rec.incident_rels(ids[0]).expect("incident"),
        vec![r],
        "the committed relationship must survive with its adjacency intact"
    );
    assert_eq!(
        rec.token_id(Namespace::RelType, "KNOWS"),
        Some(rel_type),
        "the committed reltype token must survive"
    );
}

/// Forces eviction **without committing anything**, by reading a wide spread of already-committed
/// nodes so every fetch misses and steals a victim.
///
/// This matters: a commit hardens the whole appended log, so *any* committed transaction after the
/// loser's writes would make the loser's records durable and satisfy WAL-before-data by accident —
/// masking the very property under test. Reads commit nothing, so the only thing that can harden the
/// log here is the buffer pool's own write-back rule.
fn evict_by_reading(s: &Store, ids: &[u64]) {
    for id in ids {
        let _ = s.node(*id).expect("read committed node");
    }
}

/// **The WAL-before-data gate.** A loser transaction dirties pages whose redo/undo records are
/// **appended but not yet durable**, and eviction then steals those pages to disk. The crash is
/// taken with the transaction still open.
///
/// The gate has teeth precisely because nothing in the test hardens the loser's tail: if the buffer
/// pool wrote a page home without first making the log durable through its `page_lsn`, the crash
/// would leave that page on disk with no record to undo it, and the uncommitted relationship would
/// survive recovery. Eviction is driven by **reads only** — a commit would harden the whole log and
/// satisfy the invariant by accident, which is exactly how an earlier draft of this test managed to
/// pass with WAL-before-data deliberately removed.
///
/// Verified non-vacuous: with the harden removed from both the eviction and batch paths, this test
/// fails on the surviving uncommitted relationship.
#[test]
fn stolen_uncommitted_work_is_undone_after_a_crash_during_eviction_churn() {
    let mut s = fresh(TINY_POOL);

    // Committed baseline: two nodes joined by one relationship, plus a large committed population
    // whose pages are what the reads below will churn through.
    let t1 = TxnId(1);
    s.begin(t1);
    let (a, _) = s.create_node(t1).expect("node a");
    let (b, _) = s.create_node(t1).expect("node b");
    let rel_type = s.intern_token(Namespace::RelType, "E").expect("token");
    let committed_rel = s.create_rel(t1, rel_type, a, b).expect("committed rel").0;
    s.commit(t1).expect("commit baseline");
    let population = commit_nodes(&mut s, 100, NODES_TO_SPILL);
    assert!(
        s.mapped_pages().len() > TINY_POOL,
        "non-vacuity: the population must exceed the {TINY_POOL}-frame pool"
    );

    // A LOSER: creates a second relationship on the same nodes and is never committed. Its records
    // are appended to the log but NOT hardened — nothing below commits, so the only path that can
    // make them durable is the buffer pool's WAL-before-data rule on write-back.
    let loser = TxnId(2);
    s.begin(loser);
    let _uncommitted_rel = s.create_rel(loser, rel_type, a, b).expect("loser rel");

    // Steal the loser's dirty pages by reading the committed population: every read misses the tiny
    // pool and evicts a victim.
    evict_by_reading(&s, &population);

    let rec = crash_mid_eviction_and_recover(&mut s);

    // The committed relationship is intact and the loser's is gone from BOTH endpoint chains.
    assert_eq!(
        rec.incident_rels(a).expect("incident a"),
        vec![committed_rel],
        "node a: the stolen uncommitted relationship must be undone, leaving only the committed one"
    );
    assert_eq!(
        rec.incident_rels(b).expect("incident b"),
        vec![committed_rel],
        "node b: the stolen uncommitted relationship must be undone, leaving only the committed one"
    );
    // Undoing the loser must not have taken committed work with it.
    for id in &population {
        assert!(
            rec.node(*id).expect("recovered node").mvcc.in_use(),
            "committed node {id} must survive alongside the loser's rollback"
        );
    }
}

/// The same gate with the loser's work spread over **many** pages and many un-hardened records, so
/// the steal is a sustained interleaving rather than one lucky page. This is the case where a stale
/// durability watermark would show: the loser keeps appending, so its `page_lsn` keeps rising past
/// whatever the log was last hardened through.
///
/// Verified non-vacuous alongside the test above.
#[test]
fn a_wide_loser_is_fully_undone_after_a_crash_during_eviction_churn() {
    let mut s = fresh(TINY_POOL);

    let t1 = TxnId(1);
    s.begin(t1);
    let (anchor, _) = s.create_node(t1).expect("anchor");
    let rel_type = s.intern_token(Namespace::RelType, "W").expect("token");
    s.commit(t1).expect("commit anchor");

    // Committed peers the loser will attach to, plus the population the reads churn through.
    let peers = commit_nodes(&mut s, 10, 40);
    let population = commit_nodes(&mut s, 1_000, NODES_TO_SPILL);
    assert!(
        s.mapped_pages().len() > TINY_POOL,
        "non-vacuity: the population must exceed the {TINY_POOL}-frame pool"
    );

    // The loser attaches to every peer, interleaved with read-driven eviction so its dirty pages are
    // continuously stolen while its records are still only in the un-synced log tail.
    let loser = TxnId(500);
    s.begin(loser);
    for (i, peer) in peers.iter().enumerate() {
        s.create_rel(loser, rel_type, anchor, *peer)
            .expect("loser rel");
        if i % 4 == 0 {
            evict_by_reading(&s, &population[..population.len().min(400)]);
        }
    }
    evict_by_reading(&s, &population);

    let rec = crash_mid_eviction_and_recover(&mut s);

    assert_eq!(
        rec.incident_rels(anchor).expect("incident anchor"),
        Vec::<u64>::new(),
        "every one of the loser's {} stolen relationships must be undone",
        peers.len()
    );
    for peer in &peers {
        assert_eq!(
            rec.incident_rels(*peer).expect("incident peer"),
            Vec::<u64>::new(),
            "peer {peer}: the loser's relationship must be undone on this endpoint too"
        );
        assert!(
            rec.node(*peer).expect("recovered peer").mvcc.in_use(),
            "peer {peer} was committed before the loser and must survive"
        );
    }
}
