//! Integration tests for **incremental backup chains + point-in-time recovery (PITR)** (`rmp` task
//! #71). These drive a real [`RecordStore`] over the in-memory DST devices, exercising the full
//! chain lifecycle end to end:
//!
//! * **Full-chain round-trip** — take a base, commit more transactions, capture increments, restore
//!   the chain at [`RestoreTarget::Latest`], and assert the restored graph is **byte-identical**
//!   (page-for-page) to a fresh full [`backup_store`] of the live store at the same point.
//! * **PITR to timestamp / LSN** — commit `T1 < T2 < T3`, restore to the commit point of `T2`, and
//!   assert the graph reflects exactly `T1 + T2` and **not** `T3` (the live state right after `T2`
//!   committed). Same for an LSN cut.
//! * **Base-only equivalence** — a base with zero increments restored at `Latest` is byte-identical
//!   to a plain [`restore_onto`] of that base.
//! * **Chain integrity** — a flipped byte in an increment, a missing/gap link, and a corrupt base
//!   are each detected by [`verify_chain`] / [`verify_backup`] precisely.
//! * **Encryption via an injected codec** — a chain sealed through a [`LinkCodec`] leaks no page
//!   content, verifies + restores with the right key, and fails closed on a wrong key / flipped byte.
//!   (The production codec is `graphus_crypto::{seal_backup, open_backup}`; here a small XOR-stream
//!   stand-in proves the *seam* without a dependency cycle — `graphus-crypto` carries the real
//!   end-to-end encrypted-chain test, where both crates are in scope.)
//!
//! All tests are deterministic and use only the in-memory devices + log.

use std::cell::RefCell;

use graphus_core::error::{GraphusError, Result};
use graphus_core::{PageId, TxnId};
use graphus_io::{BlockDevice, MemBlockDevice, PAGE_SIZE, Page};
use graphus_storage::{
    ChainLinks, ChainManifest, LinkCodec, Namespace, Plain, RecordStore, RestoreTarget,
    backup_store, begin_chain, capture_increment, restore_chain_file_atomic, restore_onto,
    restore_to, verify_chain,
};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Builds a fresh store over an in-memory device + log.
fn fresh(cap: usize) -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, cap, 1).expect("create store")
}

/// Materialises a store's *current durable image* into a fresh device by snapshotting every mapped
/// page after a flush — the same recipe `crash_recovery.rs` uses. This is the "live state at this
/// point" the restored chain must match.
fn live_device_image(store: &mut Store) -> MemBlockDevice {
    store.flush().expect("flush");
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
    device.sync_all().expect("persist image");
    device
}

/// Opens a store over a (recovered) device with a fresh empty WAL, then re-derives a full backup
/// artifact from it. Two stores with the same durable graph produce the same artifact page section,
/// so this is the canonical byte-identity yardstick (it also flushes + checkpoints, normalising any
/// in-memory-only differences).
fn artifact_of_device(device: MemBlockDevice, cap: usize) -> Vec<u8> {
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut store = RecordStore::open(device, wal, cap).expect("open store");
    backup_store(&mut store).expect("backup restored")
}

/// The page section of a backup artifact (everything between the fixed header and the digest
/// trailer): the actual page images, independent of the creation marker / digest framing. Two stores
/// with an identical durable graph have an identical page section.
fn page_section(artifact: &[u8]) -> &[u8] {
    // Header is magic(8)+ver(4)+page_size(4)+creation_mark(16)+page_count(8) = 40 bytes; trailer is a
    // 4-byte digest. (Mirrors `graphus_storage::backup`'s frozen layout.)
    const HEADER_LEN: usize = 8 + 4 + 4 + 16 + 8;
    const DIGEST_LEN: usize = 4;
    &artifact[HEADER_LEN..artifact.len() - DIGEST_LEN]
}

/// Commits one transaction creating two fresh nodes and a relationship between them, returning the
/// physical id of the start node so later assertions can probe liveness. Forces the WAL durable so
/// the next increment captures this transaction.
fn commit_edge(store: &mut Store, txn: TxnId, rel_type: &str) -> (u64, u64, u64) {
    store.begin(txn);
    let (a, _) = store.create_node(txn).unwrap();
    let (b, _) = store.create_node(txn).unwrap();
    let t = store.intern_token(Namespace::RelType, rel_type).unwrap();
    let (r, _) = store.create_rel(txn, t, a, b).unwrap();
    store.commit(txn).unwrap(); // group commit hardens the log through this COMMIT
    (a, b, r)
}

// =================================================================================================
// 1. Full-chain round-trip: base + increments restored at Latest == fresh full backup at that point.
// =================================================================================================

#[test]
fn full_chain_latest_is_byte_identical_to_a_full_backup() {
    let mut store = fresh(64);

    // Seed some committed state, then start the chain (base captures it).
    commit_edge(&mut store, TxnId(1), "KNOWS");
    let (mut manifest, base_link) = begin_chain(&mut store, &Plain).expect("begin chain");
    let mut links = ChainLinks {
        base: base_link,
        increments: Vec::new(),
    };

    // Commit more work in three batches, capturing an increment after each.
    for (i, rt) in ["LIKES", "FOLLOWS", "BLOCKS"].iter().enumerate() {
        commit_edge(&mut store, TxnId(2 + i as u64), rt);
        let inc = capture_increment(&mut store, &mut manifest, &Plain).expect("capture");
        links.increments.push(inc);
    }

    // The live image at this final point.
    let live_artifact = {
        let device = live_device_image(&mut store);
        artifact_of_device(device, 64)
    };

    // Restore the chain at Latest onto a fresh device, then re-derive its artifact.
    let mut restored = MemBlockDevice::new(0);
    restore_to(
        &manifest,
        &links,
        RestoreTarget::Latest,
        &mut restored,
        &Plain,
    )
    .expect("restore");
    let restored_artifact = artifact_of_device(restored, 64);

    assert_eq!(
        page_section(&restored_artifact),
        page_section(&live_artifact),
        "chain restored at Latest must be page-for-page identical to a full backup at that point"
    );
}

#[test]
fn manifest_round_trips_through_its_own_codec() {
    let mut store = fresh(64);
    commit_edge(&mut store, TxnId(1), "KNOWS");
    let (mut manifest, _base) = begin_chain(&mut store, &Plain).expect("begin");
    commit_edge(&mut store, TxnId(2), "LIKES");
    let _ = capture_increment(&mut store, &mut manifest, &Plain).expect("capture");

    let bytes = manifest.encode();
    let got = ChainManifest::decode(&bytes).expect("decode");
    assert_eq!(got, manifest);
}

// =================================================================================================
// 2. PITR: restore to the commit point of T2 reflects T1+T2 but not T3.
// =================================================================================================

#[test]
fn pitr_to_timestamp_reflects_exactly_the_committed_prefix() {
    let mut store = fresh(64);

    // Base on an empty-ish store; capture each transaction as its own increment so we can pinpoint
    // commit boundaries. Record the snapshot timestamp right after each commit.
    let (mut manifest, base_link) = begin_chain(&mut store, &Plain).expect("begin");
    let mut links = ChainLinks {
        base: base_link,
        increments: Vec::new(),
    };

    let (a1, _, _) = commit_edge(&mut store, TxnId(1), "T1");
    let ts1 = store.snapshot_ts();
    links
        .increments
        .push(capture_increment(&mut store, &mut manifest, &Plain).expect("inc1"));

    let (a2, _, _) = commit_edge(&mut store, TxnId(2), "T2");
    let ts2 = store.snapshot_ts();
    links
        .increments
        .push(capture_increment(&mut store, &mut manifest, &Plain).expect("inc2"));

    let (a3, _, _) = commit_edge(&mut store, TxnId(3), "T3");
    links
        .increments
        .push(capture_increment(&mut store, &mut manifest, &Plain).expect("inc3"));

    assert!(ts1 < ts2, "timestamps must be monotonic: {ts1:?} < {ts2:?}");

    // Restore to T2's commit timestamp: T1 and T2 are present, T3 is not.
    let mut device = MemBlockDevice::new(0);
    restore_to(
        &manifest,
        &links,
        RestoreTarget::Timestamp(ts2),
        &mut device,
        &Plain,
    )
    .expect("restore @ ts2");

    let wal = WalManager::create(MemLogSink::new()).expect("wal");
    let mut restored = RecordStore::open(device, wal, 64).expect("open restored");
    assert!(
        restored.node(a1).unwrap().mvcc.in_use(),
        "T1's node must be live at ts2"
    );
    assert!(
        restored.node(a2).unwrap().mvcc.in_use(),
        "T2's node must be live at ts2"
    );
    // T3 committed after ts2: its node must NOT be present/live (its record slot is either absent or
    // rolled back by undo).
    let t3_present = restored.node(a3).map(|n| n.mvcc.in_use()).unwrap_or(false);
    assert!(
        !t3_present,
        "T3's node must be absent at ts2 (committed after the cut)"
    );
}

#[test]
fn pitr_to_lsn_cuts_at_a_record_boundary() {
    let mut store = fresh(64);
    let (mut manifest, base_link) = begin_chain(&mut store, &Plain).expect("begin");
    let mut links = ChainLinks {
        base: base_link,
        increments: Vec::new(),
    };

    let (a1, _, _) = commit_edge(&mut store, TxnId(1), "T1");
    // The durable WAL length right after T1's commit is a valid record-boundary LSN cut.
    let cut = graphus_core::Lsn(store.with_wal(|w| w.durable_len()));
    links
        .increments
        .push(capture_increment(&mut store, &mut manifest, &Plain).expect("inc1"));

    let (a2, _, _) = commit_edge(&mut store, TxnId(2), "T2");
    links
        .increments
        .push(capture_increment(&mut store, &mut manifest, &Plain).expect("inc2"));

    // Restore to exactly the LSN at the end of T1's commit: T1 present, T2 absent.
    let mut device = MemBlockDevice::new(0);
    restore_to(
        &manifest,
        &links,
        RestoreTarget::Lsn(cut),
        &mut device,
        &Plain,
    )
    .expect("restore @ lsn");

    let wal = WalManager::create(MemLogSink::new()).expect("wal");
    let mut restored = RecordStore::open(device, wal, 64).expect("open restored");
    assert!(
        restored.node(a1).unwrap().mvcc.in_use(),
        "T1 live at the LSN cut"
    );
    let t2_present = restored.node(a2).map(|n| n.mvcc.in_use()).unwrap_or(false);
    assert!(!t2_present, "T2 must be absent at the LSN cut");
}

#[test]
fn pitr_before_any_commit_restores_the_base_only() {
    let mut store = fresh(64);
    commit_edge(&mut store, TxnId(1), "SEED");
    let (mut manifest, base_link) = begin_chain(&mut store, &Plain).expect("begin");
    let mut links = ChainLinks {
        base: base_link,
        increments: Vec::new(),
    };
    let (a2, _, _) = commit_edge(&mut store, TxnId(2), "LATER");
    links
        .increments
        .push(capture_increment(&mut store, &mut manifest, &Plain).expect("inc"));

    // A timestamp of 0 is before any real commit -> cut at base_lsn -> base only, no increment work.
    let mut device = MemBlockDevice::new(0);
    restore_to(
        &manifest,
        &links,
        RestoreTarget::Timestamp(graphus_core::Timestamp(0)),
        &mut device,
        &Plain,
    )
    .expect("restore @ ts0");

    let wal = WalManager::create(MemLogSink::new()).expect("wal");
    let mut restored = RecordStore::open(device, wal, 64).expect("open restored");
    // The base (which included T1) is present; T2 (committed after the base) is undone.
    let t2_present = restored.node(a2).map(|n| n.mvcc.in_use()).unwrap_or(false);
    assert!(
        !t2_present,
        "T2 committed after the base must be absent at ts0"
    );
}

// =================================================================================================
// 3. Base-only equivalence: a chain with zero increments == a plain restore_onto of the base.
// =================================================================================================

#[test]
fn base_only_chain_equals_a_plain_restore() {
    let mut store = fresh(64);
    commit_edge(&mut store, TxnId(1), "KNOWS");
    commit_edge(&mut store, TxnId(2), "LIKES");

    let (manifest, base_link) = begin_chain(&mut store, &Plain).expect("begin");
    let links = ChainLinks {
        base: base_link.clone(),
        increments: Vec::new(),
    };

    // Plain restore_onto of the base artifact (base_link is plaintext under Plain).
    let mut expected = MemBlockDevice::new(0);
    restore_onto(&base_link, &mut expected).expect("restore_onto");

    // Chain restore at Latest with no increments.
    let mut got = MemBlockDevice::new(0);
    restore_to(&manifest, &links, RestoreTarget::Latest, &mut got, &Plain).expect("restore chain");

    assert_eq!(
        expected.page_count(),
        got.page_count(),
        "base-only chain restore must have the same page count as restore_onto"
    );
    for p in 0..expected.page_count() {
        let mut a = [0u8; PAGE_SIZE];
        let mut b = [0u8; PAGE_SIZE];
        expected.read_page(PageId(p), &mut a).unwrap();
        got.read_page(PageId(p), &mut b).unwrap();
        assert_eq!(
            a, b,
            "page {p} must be byte-identical (base-only chain == restore_onto)"
        );
    }
}

// =================================================================================================
// 4. Chain integrity: flipped increment byte, gap link, corrupt base — all detected.
// =================================================================================================

fn build_two_increment_chain() -> (ChainManifest, ChainLinks) {
    let mut store = fresh(64);
    commit_edge(&mut store, TxnId(1), "SEED");
    let (mut manifest, base_link) = begin_chain(&mut store, &Plain).expect("begin");
    let mut links = ChainLinks {
        base: base_link,
        increments: Vec::new(),
    };
    commit_edge(&mut store, TxnId(2), "A");
    links
        .increments
        .push(capture_increment(&mut store, &mut manifest, &Plain).expect("inc1"));
    commit_edge(&mut store, TxnId(3), "B");
    links
        .increments
        .push(capture_increment(&mut store, &mut manifest, &Plain).expect("inc2"));
    (manifest, links)
}

#[test]
fn untampered_chain_verifies() {
    let (manifest, links) = build_two_increment_chain();
    verify_chain(&manifest, &links, &Plain).expect("a well-formed chain must verify");
}

/// Atomic, verified PITR file restore of a chain (storage audit F2/F7/F11): restoring a chain at
/// `Latest` into a fresh file yields exactly the same committed image as the in-memory `restore_to`,
/// and the on-disk image passes the consistency check. Proves `restore_chain_file_atomic` wraps the
/// chain restore in the same atomic temp+rename+verify machinery as the full-backup path.
#[test]
fn restore_chain_file_atomic_round_trips_at_latest() {
    use graphus_io::FileBlockDevice;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "graphus-atomic-chain-{}-{n}.blk",
        std::process::id()
    ));

    let (manifest, links) = build_two_increment_chain();

    // Expected: in-memory chain restore -> backup -> page section.
    let mut mem = MemBlockDevice::new(0);
    restore_to(&manifest, &links, RestoreTarget::Latest, &mut mem, &Plain).expect("mem restore");
    let expected = artifact_of_device(mem, 64);

    // Actual: atomic file restore -> reopen -> backup -> page section.
    restore_chain_file_atomic(
        &manifest,
        &links,
        RestoreTarget::Latest,
        &Plain,
        &path,
        |p| FileBlockDevice::open(p),
        64,
    )
    .expect("atomic chain restore");
    let dev = FileBlockDevice::open(&path).expect("reopen file");
    let mut store = RecordStore::open(dev, WalManager::create(MemLogSink::new()).unwrap(), 64)
        .expect("open restored store");
    let actual = backup_store(&mut store).expect("backup restored store");

    assert_eq!(
        page_section(&expected),
        page_section(&actual),
        "atomic chain file restore must be byte-identical to the in-memory chain restore"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn flipped_increment_byte_is_detected_by_crc() {
    let (manifest, mut links) = build_two_increment_chain();
    // Flip a byte deep inside the second increment's WAL bytes (not its framing).
    let inc = &mut links.increments[1];
    assert!(inc.len() > 20, "increment should carry real WAL bytes");
    inc[10] ^= 0xFF;
    let err = verify_chain(&manifest, &links, &Plain)
        .unwrap_err()
        .to_string();
    assert!(err.contains("CRC mismatch"), "got: {err}");
}

#[test]
fn a_gap_link_is_detected() {
    let (mut manifest, links) = build_two_increment_chain();
    // Open a gap: advance the second increment's from_lsn past the first's to_lsn.
    manifest.increments[1].from_lsn = graphus_core::Lsn(manifest.increments[1].from_lsn.0 + 4);
    manifest.increments[1].to_lsn = graphus_core::Lsn(manifest.increments[1].to_lsn.0 + 4);
    let err = verify_chain(&manifest, &links, &Plain)
        .unwrap_err()
        .to_string();
    assert!(err.contains("gap or overlap"), "got: {err}");
}

#[test]
fn a_dropped_increment_link_is_detected() {
    let (manifest, mut links) = build_two_increment_chain();
    // Drop the last link: the count no longer matches the manifest.
    links.increments.pop();
    let err = verify_chain(&manifest, &links, &Plain)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("increment link") || err.contains("declares"),
        "a missing link must be detected; got: {err}"
    );
}

#[test]
fn a_corrupt_base_is_detected() {
    let (manifest, mut links) = build_two_increment_chain();
    // Flip a byte in the base artifact's page section so verify_backup's digest fails.
    let pos = links.base.len() / 2;
    links.base[pos] ^= 0xFF;
    assert!(
        verify_chain(&manifest, &links, &Plain).is_err(),
        "a corrupt base must fail verify_chain (via verify_backup)"
    );
}

#[test]
fn a_restore_of_a_corrupt_chain_fails() {
    let (manifest, mut links) = build_two_increment_chain();
    links.increments[0][5] ^= 0xFF; // corrupt the first increment
    let mut device = MemBlockDevice::new(0);
    assert!(
        restore_to(
            &manifest,
            &links,
            RestoreTarget::Latest,
            &mut device,
            &Plain
        )
        .is_err(),
        "restore must refuse a corrupt chain (verify_chain runs first)"
    );
}

// =================================================================================================
// 5. Encryption via an injected codec (the LinkCodec seam).
// =================================================================================================

/// A toy keystream codec standing in for `graphus_crypto::{seal_backup, open_backup}`: it XOR-masks
/// each link with a key-derived byte and frames it with a 1-byte tag so a wrong key / flipped byte
/// fails closed. This proves the **seam** (`graphus-storage` is codec-agnostic) without importing
/// `graphus-crypto` (which depends on `graphus-storage` — the real AEAD chain test lives there).
struct XorCodec {
    key: u8,
    /// Counts opens for assertions; interior-mutable so the codec can be shared by `&self`.
    opens: RefCell<usize>,
}

impl XorCodec {
    fn new(key: u8) -> Self {
        Self {
            key,
            opens: RefCell::new(0),
        }
    }
}

impl LinkCodec for XorCodec {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(plaintext.len() + 1);
        // A 1-byte "tag": the key, masked, so opening with the wrong key is detectable.
        out.push(self.key ^ 0xA5);
        out.extend(plaintext.iter().map(|b| b ^ self.key));
        Ok(out)
    }

    fn open(&self, stored: &[u8]) -> Result<Vec<u8>> {
        *self.opens.borrow_mut() += 1;
        let (&tag, body) = stored
            .split_first()
            .ok_or_else(|| GraphusError::Security("sealed link is empty".to_owned()))?;
        if tag != self.key ^ 0xA5 {
            return Err(GraphusError::Security(
                "wrong key or tampered sealed link".to_owned(),
            ));
        }
        Ok(body.iter().map(|b| b ^ self.key).collect())
    }
}

/// Seals a chain through `codec` end to end and returns it with the live image's artifact for the
/// equivalence assertion.
fn sealed_chain(codec: &XorCodec) -> (ChainManifest, ChainLinks, Vec<u8>) {
    let mut store = fresh(64);
    commit_edge(&mut store, TxnId(1), "SEED");
    let (mut manifest, base_link) = begin_chain(&mut store, codec).expect("begin sealed");
    let mut links = ChainLinks {
        base: base_link,
        increments: Vec::new(),
    };
    commit_edge(&mut store, TxnId(2), "MORE");
    links
        .increments
        .push(capture_increment(&mut store, &mut manifest, codec).expect("sealed inc"));

    let live_artifact = {
        let device = live_device_image(&mut store);
        artifact_of_device(device, 64)
    };
    (manifest, links, live_artifact)
}

#[test]
fn a_sealed_chain_leaks_no_page_content() {
    let codec = XorCodec::new(0x5C);
    let (_manifest, links, live_artifact) = sealed_chain(&codec);
    // Take a real page image from the live store and confirm a sizable window of it does NOT appear
    // verbatim in the sealed base link.
    let section = page_section(&live_artifact);
    assert!(
        section.len() >= 64,
        "need real page bytes to test for leakage"
    );
    let window = &section[..64];
    assert!(
        !links.base.windows(window.len()).any(|w| w == window),
        "a sealed base link must not contain a verbatim page-image window"
    );
}

#[test]
fn a_sealed_chain_verifies_and_restores_with_the_right_key() {
    let codec = XorCodec::new(0x5C);
    let (manifest, links, live_artifact) = sealed_chain(&codec);

    verify_chain(&manifest, &links, &codec).expect("sealed chain must verify with the right key");

    let mut device = MemBlockDevice::new(0);
    restore_to(
        &manifest,
        &links,
        RestoreTarget::Latest,
        &mut device,
        &codec,
    )
    .expect("restore sealed");
    let restored_artifact = artifact_of_device(device, 64);
    assert_eq!(
        page_section(&restored_artifact),
        page_section(&live_artifact),
        "a sealed chain restored with the right key must match the live image"
    );
    assert!(
        *codec.opens.borrow() > 0,
        "the codec's open path must have run"
    );
}

#[test]
fn a_sealed_chain_fails_closed_with_the_wrong_key() {
    let writer = XorCodec::new(0x5C);
    let (manifest, links, _live) = sealed_chain(&writer);

    let wrong = XorCodec::new(0x42);
    assert!(
        verify_chain(&manifest, &links, &wrong).is_err(),
        "verify_chain must fail closed under the wrong key"
    );
    let mut device = MemBlockDevice::new(0);
    assert!(
        restore_to(
            &manifest,
            &links,
            RestoreTarget::Latest,
            &mut device,
            &wrong
        )
        .is_err(),
        "restore must fail closed under the wrong key"
    );
}

#[test]
fn a_flipped_byte_in_a_sealed_link_fails_closed() {
    let codec = XorCodec::new(0x5C);
    let (manifest, mut links, _live) = sealed_chain(&codec);
    // Flip the sealed tag of the first increment -> open() rejects it.
    links.increments[0][0] ^= 0xFF;
    assert!(
        verify_chain(&manifest, &links, &codec).is_err(),
        "a tampered sealed link must fail closed"
    );
}
