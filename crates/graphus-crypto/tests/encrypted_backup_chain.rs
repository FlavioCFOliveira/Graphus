//! Integration test (DST / mem-backed): a **backup chain sealed with the production AEAD envelope**
//! (`graphus_crypto::{seal_backup, open_backup}`) round-trips end to end (`rmp` task #71 encryption
//! integration). This is the real encrypted-chain proof: the [`LinkCodec`] seam exposed by
//! `graphus-storage` is bound here to `seal_backup`/`open_backup`, where both crates are in scope
//! (the dependency runs `graphus-crypto -> graphus-storage`, so the storage crate cannot call the
//! crypto primitives itself — it takes the codec by injection).
//!
//! The flow:
//!
//! * build a real [`RecordStore`], commit some work, [`begin_chain`] (base sealed) and
//!   [`capture_increment`] (increment sealed), all through the [`CryptoCodec`];
//! * assert the sealed links **leak no page content** (the sealed base never contains a verbatim
//!   page-image window);
//! * [`verify_chain`] + [`restore_to`] with the right key reproduce the live image **page-for-page**;
//! * a **wrong key** and a **flipped byte** in a sealed link each fail closed (AEAD authentication).
//!
//! All deterministic, mem-backed devices + log.

use graphus_core::error::Result;
use graphus_core::{PageId, TxnId};
use graphus_crypto::{KEY_LEN, open_backup, seal_backup};
use graphus_io::{BlockDevice, MemBlockDevice, Page};
use graphus_storage::{
    ChainLinks, LinkCodec, Namespace, RecordStore, RestoreTarget, backup_store, begin_chain,
    capture_increment, restore_to, verify_chain,
};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// The production chain link codec: every link (base artifact + each increment) is sealed with
/// [`seal_backup`] and recovered with [`open_backup`] under a fixed master key. This is exactly the
/// adapter the server installs when a master key is configured.
struct CryptoCodec {
    master: [u8; KEY_LEN],
}

impl CryptoCodec {
    fn new(master: [u8; KEY_LEN]) -> Self {
        Self { master }
    }
}

impl LinkCodec for CryptoCodec {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        seal_backup(plaintext, &self.master)
    }

    fn open(&self, stored: &[u8]) -> Result<Vec<u8>> {
        open_backup(stored, &self.master)
    }
}

const MASTER_A: [u8; KEY_LEN] = [0x11; KEY_LEN];
const MASTER_B: [u8; KEY_LEN] = [0x22; KEY_LEN];

fn fresh(cap: usize) -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, cap, 1).expect("create store")
}

fn commit_edge(store: &mut Store, txn: TxnId, rel_type: &str) {
    store.begin(txn);
    let (a, _) = store.create_node(txn).unwrap();
    let (b, _) = store.create_node(txn).unwrap();
    let t = store.intern_token(Namespace::RelType, rel_type).unwrap();
    let _ = store.create_rel(txn, t, a, b).unwrap();
    store.commit(txn).unwrap();
}

/// Snapshots the store's current durable image into a fresh device, then re-derives its full backup
/// artifact — the page-for-page yardstick for "the live state at this point".
fn live_artifact(store: &mut Store, cap: usize) -> Vec<u8> {
    store.flush().expect("flush");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    let mut staged: Vec<(u64, Box<Page>)> = Vec::new();
    for p in &pages {
        staged.push((p.0, store.read_device_page(*p).expect("read page")));
    }
    for (idx, bytes) in staged {
        device.write_page(PageId(idx), &bytes).expect("stage");
    }
    device.sync_all().expect("persist");
    artifact_of_device(device, cap)
}

fn artifact_of_device(device: MemBlockDevice, cap: usize) -> Vec<u8> {
    let wal = WalManager::create(MemLogSink::new()).expect("wal");
    let mut store = RecordStore::open(device, wal, cap).expect("open");
    backup_store(&mut store).expect("backup")
}

/// The page-image section of a full backup artifact (header 40 bytes, trailer 4-byte digest).
fn page_section(artifact: &[u8]) -> &[u8] {
    const HEADER_LEN: usize = 8 + 4 + 4 + 16 + 8;
    const DIGEST_LEN: usize = 4;
    &artifact[HEADER_LEN..artifact.len() - DIGEST_LEN]
}

/// Builds a 1-increment chain sealed with `codec` and returns it plus the live image's artifact.
fn sealed_chain(codec: &CryptoCodec) -> (graphus_storage::ChainManifest, ChainLinks, Vec<u8>) {
    let mut store = fresh(64);
    commit_edge(&mut store, TxnId(1), "SEED");
    let (mut manifest, base) = begin_chain(&mut store, codec).expect("begin sealed chain");
    let mut links = ChainLinks {
        base,
        increments: Vec::new(),
    };
    commit_edge(&mut store, TxnId(2), "MORE");
    links
        .increments
        .push(capture_increment(&mut store, &mut manifest, codec).expect("sealed increment"));
    let live = live_artifact(&mut store, 64);
    (manifest, links, live)
}

#[test]
fn sealed_chain_leaks_no_page_content() {
    let codec = CryptoCodec::new(MASTER_A);
    let (_m, links, live) = sealed_chain(&codec);
    let section = page_section(&live);
    assert!(section.len() >= 64, "need real page bytes");
    let window = &section[..64];
    assert!(
        !links.base.windows(window.len()).any(|w| w == window),
        "the sealed base must not contain a verbatim page-image window"
    );
}

#[test]
fn sealed_chain_verifies_and_restores_with_the_right_key() {
    let codec = CryptoCodec::new(MASTER_A);
    let (manifest, links, live) = sealed_chain(&codec);

    verify_chain(&manifest, &links, &codec).expect("sealed chain must verify with the right key");

    let mut device = MemBlockDevice::new(0);
    restore_to(
        &manifest,
        &links,
        RestoreTarget::Latest,
        &mut device,
        &codec,
    )
    .expect("restore");
    let restored = artifact_of_device(device, 64);
    assert_eq!(
        page_section(&restored),
        page_section(&live),
        "an encrypted chain restored with the right key must match the live image page-for-page"
    );
}

#[test]
fn sealed_chain_fails_closed_with_the_wrong_key() {
    let writer = CryptoCodec::new(MASTER_A);
    let (manifest, links, _live) = sealed_chain(&writer);

    let wrong = CryptoCodec::new(MASTER_B);
    assert!(
        verify_chain(&manifest, &links, &wrong).is_err(),
        "verify_chain must fail closed under the wrong key (AEAD authentication)"
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
    let codec = CryptoCodec::new(MASTER_A);
    let (manifest, mut links, _live) = sealed_chain(&codec);
    // Flip a byte in the sealed base envelope: AEAD authentication must reject it.
    let pos = links.base.len() / 2;
    links.base[pos] ^= 0xFF;
    assert!(
        verify_chain(&manifest, &links, &codec).is_err(),
        "a tampered sealed link must fail closed under AEAD"
    );
}

#[test]
fn a_base_only_sealed_chain_round_trips() {
    // A chain with zero increments, sealed, must still verify + restore to exactly the base graph.
    let codec = CryptoCodec::new(MASTER_A);
    let mut store = fresh(64);
    commit_edge(&mut store, TxnId(1), "ONLY");
    let (manifest, base) = begin_chain(&mut store, &codec).expect("begin");
    let links = ChainLinks {
        base,
        increments: Vec::new(),
    };
    let live = live_artifact(&mut store, 64);

    verify_chain(&manifest, &links, &codec).expect("verify base-only sealed chain");
    let mut device = MemBlockDevice::new(0);
    restore_to(
        &manifest,
        &links,
        RestoreTarget::Latest,
        &mut device,
        &codec,
    )
    .expect("restore");
    let restored = artifact_of_device(device, 64);
    assert_eq!(page_section(&restored), page_section(&live));
}

/// A sealed link must not be openable as a plaintext artifact, and a plaintext chain's links must
/// not be openable by the crypto codec — the two formats are distinct (envelope magic vs backup
/// magic), so a configuration mistake fails loudly rather than silently mis-restoring.
#[test]
fn a_sealed_base_is_not_a_bare_artifact() {
    let codec = CryptoCodec::new(MASTER_A);
    let (_m, links, _live) = sealed_chain(&codec);
    // The sealed base is an envelope (magic "GRAPHUSB"), not a bare backup artifact ("GRPHBKUP").
    assert_ne!(
        &links.base[0..8],
        b"GRPHBKUP",
        "a sealed base must be an envelope, not a bare backup artifact"
    );
    assert!(
        open_backup(&links.base, &MASTER_A).is_ok(),
        "the sealed base must open with the right key"
    );
}
