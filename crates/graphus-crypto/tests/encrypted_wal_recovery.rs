//! Integration test (DST / mem-backed): a real [`graphus_wal::WalManager`] runs over the
//! **encrypted** log sink, proving the WAL encryption seam is transparent to the WAL manager and
//! recovery (rmp #88 acceptance criteria).
//!
//! Two things are asserted:
//! 1. An encrypted WAL run produces the **same LSNs and the same decoded record stream** as a
//!    plaintext WAL run for identical logical operations (the byte-offset == LSN invariant is
//!    preserved — the encrypted sink presents plaintext logical offsets upward).
//! 2. ARIES recovery over a **reopened** encrypted sink reconstructs the same committed state and
//!    rolls back the same losers as the plaintext path (the encrypted sink is a drop-in `LogSink`).

use std::collections::HashMap;

use graphus_core::error::Result;
use graphus_core::{Lsn, PageId, TxnId};
use graphus_crypto::{EncryptedLogSink, KEY_LEN, Keyring, SALT_LEN};
use graphus_wal::{
    ApplyTarget, HEADER_LEN, LogRecord, LogSink, MemLogSink, RecordType, WalManager, recover,
};

const SALT: [u8; SALT_LEN] = [0x7E; SALT_LEN];

fn keyring(byte: u8) -> Keyring {
    Keyring::from_key_file_bytes(&[byte; KEY_LEN], &SALT).expect("keyring")
}

type EncSink = EncryptedLogSink<MemLogSink>;

fn fresh_encrypted(kr: &Keyring) -> EncSink {
    EncryptedLogSink::create(MemLogSink::new(), kr).expect("create encrypted sink")
}

/// A page-per-counter store whose redo/undo images are 8-byte little-endian deltas (the same model
/// the WAL crate's own recovery tests use).
#[derive(Debug, Default)]
struct DeltaStore {
    pages: HashMap<u64, (Lsn, i64)>,
}

impl DeltaStore {
    fn value(&self, p: u64) -> i64 {
        self.pages.get(&p).map_or(0, |&(_, v)| v)
    }
}

impl ApplyTarget for DeltaStore {
    fn page_lsn(&self, page: PageId) -> Lsn {
        self.pages.get(&page.0).map_or(Lsn(0), |&(l, _)| l)
    }

    fn apply(&mut self, page: PageId, lsn: Lsn, image: &[u8]) -> Result<()> {
        let delta = i64::from_le_bytes(image.try_into().expect("8-byte delta"));
        let e = self.pages.entry(page.0).or_insert((Lsn(0), 0));
        e.0 = lsn;
        e.1 += delta;
        Ok(())
    }
}

fn d(v: i64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

/// Drives an identical sequence of WAL operations over any sink, returning the per-step LSNs and the
/// decoded record stream (read back through the sink, i.e. decrypted for the encrypted case).
fn run_workload<S: LogSink>(mut wal: WalManager<S>) -> (Vec<Lsn>, Vec<(RecordType, Lsn, u64)>) {
    // Each call mutably borrows `wal`, so these run in order; bind the LSNs first, then collect.
    let begin1 = wal.begin(TxnId(1));
    let upd5 = wal.log_update(TxnId(1), PageId(5), d(10), d(-10));
    let upd6 = wal.log_update(TxnId(1), PageId(6), d(20), d(-20));
    let commit1 = wal.commit(TxnId(1)).expect("commit t1");
    let begin2 = wal.begin(TxnId(2));
    let upd7 = wal.log_update(TxnId(2), PageId(7), d(30), d(-30));
    wal.flush(); // make t2's (uncommitted) tail durable so it is a recoverable loser
    let lsns = vec![begin1, upd5, upd6, commit1, begin2, upd7];

    let mut bytes = Vec::new();
    wal.read_durable(Lsn(0), &mut bytes).expect("read durable");
    let mut recs = Vec::new();
    let mut cur = HEADER_LEN as usize;
    while cur < bytes.len() {
        let (r, n) = LogRecord::decode(&bytes[cur..]).expect("decode");
        cur += n;
        recs.push((r.rec_type, r.lsn, r.prev_lsn.0));
    }
    (lsns, recs)
}

#[test]
fn encrypted_wal_produces_identical_lsns_and_record_stream() {
    let kr = keyring(0x01);

    let (plain_lsns, plain_recs) = run_workload(WalManager::create(MemLogSink::new()).unwrap());
    let (enc_lsns, enc_recs) = run_workload(WalManager::create(fresh_encrypted(&kr)).unwrap());

    assert_eq!(
        plain_lsns, enc_lsns,
        "the encrypted WAL must allocate byte-identical LSNs (offset == LSN invariant)"
    );
    assert_eq!(
        plain_recs, enc_recs,
        "the decoded record stream over the encrypted WAL must equal the plaintext one"
    );
}

#[test]
fn recovery_over_a_reopened_encrypted_wal_matches_the_plaintext_path() {
    let kr = keyring(0x02);

    // Build the same workload over an encrypted sink, capture the durable backing, reopen it, and
    // run recovery. T1 committed (its deltas must be redone); T2 is a loser (its delta undone).
    let mut wal = WalManager::create(fresh_encrypted(&kr)).unwrap();
    wal.begin(TxnId(1));
    wal.log_update(TxnId(1), PageId(5), d(10), d(-10));
    wal.log_update(TxnId(1), PageId(6), d(20), d(-20));
    wal.commit(TxnId(1)).expect("commit t1");
    wal.begin(TxnId(2));
    wal.log_update(TxnId(2), PageId(7), d(30), d(-30));
    wal.flush();

    // Capture the encrypted sink's durable physical backing bytes (the only thing that survives a
    // crash), rebuild a fresh backing holding them, reopen a fresh encrypted sink over it
    // (decrypting + authenticating the frame index), and recover — mirroring the store-recovery
    // test's "reopen over the durable prefix" pattern.
    let physical = wal.sink().backing().durable_bytes().to_vec();
    let mut backing = MemLogSink::new();
    backing.append(&physical);
    backing.sync().expect("sync physical prefix");
    let reopened = EncryptedLogSink::open(backing, &kr).expect("reopen encrypted sink");
    let mut wal2 = WalManager::open(reopened).expect("open wal over encrypted sink");

    let mut store = DeltaStore::default();
    let report = recover(&mut wal2, &mut store).expect("recover");

    assert_eq!(
        store.value(5),
        10,
        "t1's committed delta on page 5 is redone"
    );
    assert_eq!(
        store.value(6),
        20,
        "t1's committed delta on page 6 is redone"
    );
    assert_eq!(
        store.value(7),
        0,
        "t2 is a loser: its delta is undone (net zero)"
    );
    assert_eq!(report.losers, 1);
    assert_eq!(report.redo_applied, 3, "3 page-change deltas are redone");
}
