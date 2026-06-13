//! Deterministic-Simulation-Testing proof of the durability acceptance criterion (`rmp` task
//! `graphus-wal`): *after injected crashes at any LSN, recovery yields only committed-or-nothing
//! with no corruption.*
//!
//! The workload is a bank of accounts under random transfers (each transfer is balance-neutral,
//! so a correct database always conserves the total). Transactions are logged with **delta**
//! redo/undo images — physiological redo, logical undo — which is what makes recovery sound when
//! several transactions interleave writes to the same account (`04-technical-design.md` §4.1).
//!
//! "Crash at any LSN" is exercised exhaustively: because the log only ever hardens whole
//! records, every possible crash leaves a durable *prefix* ending on a record boundary. The test
//! enumerates **every** record boundary, truncates the durable log there, runs ARIES recovery,
//! and asserts the recovered state equals the independently computed committed-only state — under
//! both a no-force disk (nothing flushed) and a force/steal disk (everything flushed, including
//! uncommitted writes). Many random seeds give many independent histories.

use graphus_core::capability::Rng;
use graphus_core::{Lsn, PageId, TxnId};
use graphus_sim::SimRng;
use graphus_wal::{ApplyTarget, HEADER_LEN, LogRecord, LogSink, MemLogSink, WalManager, recover};
use std::collections::HashMap;

/// A page-per-account store whose redo/undo images are 8-byte little-endian balance deltas.
#[derive(Debug, Clone, Default)]
struct DeltaStore {
    pages: HashMap<u64, (Lsn, i64)>,
}

impl DeltaStore {
    fn with_initial(n_accounts: u64, balance: i64) -> Self {
        let mut pages = HashMap::new();
        for p in 0..n_accounts {
            pages.insert(p, (Lsn(0), balance));
        }
        Self { pages }
    }

    fn value(&self, p: u64) -> i64 {
        self.pages.get(&p).map_or(0, |&(_, v)| v)
    }

    fn total(&self) -> i64 {
        self.pages.values().map(|&(_, v)| v).sum()
    }
}

impl ApplyTarget for DeltaStore {
    fn page_lsn(&self, page: PageId) -> Lsn {
        self.pages.get(&page.0).map_or(Lsn(0), |&(l, _)| l)
    }

    fn apply(&mut self, page: PageId, lsn: Lsn, image: &[u8]) -> graphus_core::Result<()> {
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

/// One generated transaction: the per-account deltas it applied and, if it committed, the LSN of
/// its COMMIT record.
struct TxnRec {
    commit_lsn: Option<u64>,
    effects: Vec<(u64, i64)>,
}

/// A generated history: the full durable log and the per-transaction ground truth.
struct History {
    full: Vec<u8>,
    txns: Vec<TxnRec>,
    n_accounts: u64,
    initial: i64,
}

/// Generates a random transfer history for `seed` and returns its full durable log plus the
/// ground truth needed to compute the expected committed-only state at any prefix.
fn generate(seed: u64, n_accounts: u64, n_txns: usize, initial: i64) -> History {
    let mut rng = SimRng::new(seed);
    let mut wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut txns = Vec::with_capacity(n_txns);

    for i in 0..n_txns {
        let txn = TxnId((i + 1) as u64);
        let a = rng.next_u64() % n_accounts;
        let mut b = rng.next_u64() % n_accounts;
        if b == a {
            b = (b + 1) % n_accounts;
        }
        let amt = (rng.next_u64() % 50 + 1) as i64;

        wal.begin(txn);
        wal.log_update(txn, PageId(a), d(-amt), d(amt)); // debit a
        wal.log_update(txn, PageId(b), d(amt), d(-amt)); // credit b

        // ~70% commit; the rest are left in-flight (losers) to be rolled back by recovery.
        let commit_lsn = if rng.next_u64() % 100 < 70 {
            Some(wal.commit(txn).expect("commit").0)
        } else {
            None
        };
        txns.push(TxnRec {
            commit_lsn,
            effects: vec![(a, -amt), (b, amt)],
        });
    }

    wal.flush(); // harden the in-flight losers' tail so the full log is durable for the test
    History {
        full: wal.sink().durable_bytes().to_vec(),
        txns,
        n_accounts,
        initial,
    }
}

/// Every record-boundary offset in `full` (candidate crash LSNs), starting with the empty log.
fn record_boundaries(full: &[u8]) -> Vec<u64> {
    let mut bounds = vec![HEADER_LEN];
    let mut cursor = HEADER_LEN as usize;
    while cursor < full.len() {
        let (_, n) = LogRecord::decode(&full[cursor..]).expect("intact record");
        cursor += n;
        bounds.push(cursor as u64);
    }
    bounds
}

impl History {
    /// The expected committed-only balances if the crash left the durable prefix `[0, l)`.
    fn expected(&self, l: u64) -> Vec<i64> {
        let mut bal = vec![self.initial; self.n_accounts as usize];
        for t in &self.txns {
            if let Some(cl) = t.commit_lsn {
                if cl < l {
                    for (p, delta) in &t.effects {
                        bal[*p as usize] += delta;
                    }
                }
            }
        }
        bal
    }

    /// The disk state under a *force/steal* policy: every change in `[0, l)` (committed or not)
    /// is already on the page, with its writer's LSN — so redo must skip it and undo must revert
    /// the uncommitted ones.
    fn forced_disk(&self, l: u64) -> DeltaStore {
        let mut store = DeltaStore::with_initial(self.n_accounts, self.initial);
        let mut cursor = HEADER_LEN as usize;
        while (cursor as u64) < l {
            let (rec, n) = LogRecord::decode(&self.full[cursor..]).expect("intact record");
            if rec.rec_type.is_page_change() && !rec.redo.is_empty() {
                store.apply(rec.page_id, rec.lsn, &rec.redo).unwrap();
            }
            cursor += n;
        }
        store
    }

    /// Recovers from the durable prefix `[0, l)` onto `disk` and returns the recovered store.
    fn recover_prefix(&self, l: u64, disk: DeltaStore) -> DeltaStore {
        let mut sink = MemLogSink::new();
        sink.append(&self.full[..l as usize]);
        sink.sync().expect("sync prefix");
        let mut wal = WalManager::open(sink).expect("open wal");
        let mut store = disk;
        recover(&mut wal, &mut store).expect("recover");
        store
    }
}

#[test]
fn crash_at_any_lsn_yields_committed_or_nothing() {
    for seed in 1..=24u64 {
        let h = generate(seed, 6, 14, 100);
        let total = h.initial * h.n_accounts as i64;

        for &l in &record_boundaries(&h.full) {
            let expected = h.expected(l);

            // No-force disk: nothing was flushed; redo must reconstruct all committed work.
            let recovered = h.recover_prefix(l, DeltaStore::with_initial(h.n_accounts, h.initial));
            for p in 0..h.n_accounts {
                assert_eq!(
                    recovered.value(p),
                    expected[p as usize],
                    "no-force seed={seed} crash_lsn={l} account={p}"
                );
            }
            assert_eq!(
                recovered.total(),
                total,
                "no-force conservation seed={seed} lsn={l}"
            );

            // Force/steal disk: everything (incl. uncommitted) was flushed; undo must revert the
            // losers and redo must be a no-op thanks to the page_lsn guard.
            let recovered = h.recover_prefix(l, h.forced_disk(l));
            for p in 0..h.n_accounts {
                assert_eq!(
                    recovered.value(p),
                    expected[p as usize],
                    "force seed={seed} crash_lsn={l} account={p}"
                );
            }
            assert_eq!(
                recovered.total(),
                total,
                "force conservation seed={seed} lsn={l}"
            );
        }
    }
}

#[test]
fn recovery_is_idempotent_when_run_twice() {
    // A crash *during* recovery must be safe: running recovery again reaches the same state.
    let h = generate(7, 5, 12, 100);
    let bounds = record_boundaries(&h.full);
    let l = bounds[bounds.len() / 2];
    let expected = h.expected(l);

    let mut sink = MemLogSink::new();
    sink.append(&h.full[..l as usize]);
    sink.sync().unwrap();

    // First recovery pass (writes CLRs + ABORTs into the sink).
    let mut store = DeltaStore::with_initial(h.n_accounts, 100);
    {
        let mut wal = WalManager::open(sink.clone()).unwrap();
        recover(&mut wal, &mut store).unwrap();
    }
    // Second pass over the post-recovery log onto a fresh disk must match.
    let mut store2 = DeltaStore::with_initial(h.n_accounts, 100);
    {
        let mut wal = WalManager::open(sink).unwrap();
        recover(&mut wal, &mut store2).unwrap();
    }
    for p in 0..h.n_accounts {
        assert_eq!(store.value(p), expected[p as usize], "pass1 account {p}");
        assert_eq!(store2.value(p), expected[p as usize], "pass2 account {p}");
    }
}

#[test]
fn torn_tail_record_is_ignored_and_its_txn_rolled_back() {
    // T1 commits fully; T2 commits but its COMMIT record is torn by the crash.
    let mut wal = WalManager::create(MemLogSink::new()).unwrap();
    wal.begin(TxnId(1));
    wal.log_update(TxnId(1), PageId(0), d(-10), d(10));
    wal.log_update(TxnId(1), PageId(1), d(10), d(-10));
    wal.commit(TxnId(1)).unwrap();

    wal.begin(TxnId(2));
    wal.log_update(TxnId(2), PageId(0), d(-5), d(5));
    wal.log_update(TxnId(2), PageId(1), d(5), d(-5));
    let c2 = wal.commit(TxnId(2)).unwrap();

    let full = wal.sink().durable_bytes().to_vec();
    // Truncate a few bytes into T2's COMMIT record: a torn tail.
    let torn_len = (c2.0 + 3) as usize;

    let mut sink = MemLogSink::new();
    sink.append(&full[..torn_len]);
    sink.sync().unwrap();
    let mut wal2 = WalManager::open(sink).unwrap();
    let mut store = DeltaStore::with_initial(3, 100);
    let report = recover(&mut wal2, &mut store).unwrap();

    assert!(report.tail_truncated, "the torn COMMIT must end the scan");
    assert_eq!(report.losers, 1, "T2 is a loser (its COMMIT was lost)");
    // Only T1's committed transfer survives.
    assert_eq!(store.value(0), 90);
    assert_eq!(store.value(1), 110);
    assert_eq!(store.total(), 300);
}

#[test]
fn reclaim_respects_the_active_transaction_floor_and_recovery_skips_the_freed_prefix() {
    // T1 and T2 commit; T3 is still in flight (a loser) when a reclaim runs. The reclaim is asked to
    // free everything up to the end, but must clamp to T3's first record so T3's undo back-chain
    // stays readable. The freed prefix (T1+T2) reads back as zeros (MemLogSink models a deleted
    // segment); recovery skips it, redoes nothing below the floor, and rolls T3 back — without a
    // false interior-corruption alarm.
    let mut wal = WalManager::create(MemLogSink::new()).unwrap();
    wal.begin(TxnId(1));
    wal.log_update(TxnId(1), PageId(0), d(-10), d(10));
    wal.commit(TxnId(1)).unwrap();
    wal.begin(TxnId(2));
    wal.log_update(TxnId(2), PageId(1), d(5), d(-5));
    wal.commit(TxnId(2)).unwrap();
    let t3_first = wal.next_lsn(); // T3's BEGIN lands here
    wal.begin(TxnId(3));
    wal.log_update(TxnId(3), PageId(0), d(-7), d(7)); // a stolen, uncommitted write
    wal.flush(); // harden the loser's tail so recovery must undo it

    // Ask to reclaim the whole log; the active-transaction floor clamps it to T3's first record.
    wal.reclaim(Lsn(wal.durable_len())).unwrap();

    // T3's records survive the reclaim (its bytes at/after t3_first are NOT zeroed).
    let durable = wal.sink().durable_bytes();
    assert!(
        durable[t3_first.0 as usize..].iter().any(|&b| b != 0),
        "the active transaction's records must not be reclaimed"
    );
    // The committed prefix below the floor WAS freed (reads as zeros).
    assert!(
        durable[HEADER_LEN as usize..t3_first.0 as usize]
            .iter()
            .all(|&b| b == 0),
        "the committed prefix below the floor must be reclaimed to zeros"
    );

    // Recovery over the reclaimed log: a steal disk already holds T1+T2's committed effects and T3's
    // stolen write; recovery skips the zero prefix and undoes the loser T3.
    let mut store = DeltaStore::with_initial(2, 100);
    // Pre-apply the durable, committed-or-stolen disk state at the pages' last LSNs so redo is a
    // no-op and only undo runs. (T1: page0 -10 ; T2: page1 +5 ; T3 stolen: page0 -7.)
    store
        .pages
        .insert(0, (Lsn(wal.durable_len()), 100 - 10 - 7));
    store.pages.insert(1, (Lsn(wal.durable_len()), 100 + 5));
    let mut sink = MemLogSink::new();
    sink.append(wal.sink().durable_bytes());
    sink.sync().unwrap();
    let mut wal2 = WalManager::open(sink).unwrap();
    let report = recover(&mut wal2, &mut store).expect("recovery over a reclaimed log succeeds");
    assert_eq!(report.losers, 1, "T3 is the loser to undo");
    // T3's stolen write is rolled back; T1+T2 stand.
    assert_eq!(store.value(0), 90, "page0 = 100 - 10 (T3's -7 undone)");
    assert_eq!(store.value(1), 105, "page1 = 100 + 5");
}

#[test]
fn interior_log_corruption_is_detected_not_silently_truncated() {
    // Three fully-committed transactions. Bit-rot flips a body byte of the FIRST transaction's
    // record (interior corruption), leaving every later committed record intact and self-consistent.
    // Recovery must FAIL LOUD rather than silently truncate at the bad spot and drop the committed
    // T2 + T3 — the cardinal ACID violation the original "any decode error == torn tail" rule caused
    // (storage audit F4).
    let mut wal = WalManager::create(MemLogSink::new()).unwrap();
    for t in 1..=3u64 {
        wal.begin(TxnId(t));
        wal.log_update(TxnId(t), PageId(0), d(-1), d(1));
        wal.log_update(TxnId(t), PageId(1), d(1), d(-1));
        wal.commit(TxnId(t)).unwrap();
    }
    let mut full = wal.sink().durable_bytes().to_vec();

    // Corrupt a body byte (the txn-id field) of the FIRST record: its CRC32C now fails, but its
    // length/type are intact so the scan decodes it as BadCrc, and every later record is untouched.
    let bounds = record_boundaries(&full);
    assert!(
        bounds.len() > 4,
        "need several intact records after the first"
    );
    let txn_id_byte = bounds[0] as usize + 20; // OFF_TXN_ID inside record 0
    full[txn_id_byte] ^= 0xFF;

    let mut sink = MemLogSink::new();
    sink.append(&full);
    sink.sync().unwrap();
    let mut wal2 = WalManager::open(sink).unwrap();
    let mut store = DeltaStore::with_initial(3, 100);
    let err = recover(&mut wal2, &mut store)
        .expect_err("interior corruption must fail recovery, not silently truncate");
    let msg = err.to_string();
    assert!(
        msg.contains("interior log corruption"),
        "must report interior corruption; got: {msg}"
    );
}

#[test]
fn a_torn_tail_after_committed_records_still_truncates_cleanly() {
    // The complement of the interior-corruption test: a genuine torn tail at the very end (the last
    // append never completed, with NO valid record after the torn point) must still truncate to
    // committed-or-nothing across MULTIPLE preceding committed transactions — the fail-loud rule must
    // not regress the legitimate, common torn-tail case.
    let mut wal = WalManager::create(MemLogSink::new()).unwrap();
    wal.begin(TxnId(1));
    wal.log_update(TxnId(1), PageId(0), d(-10), d(10));
    wal.log_update(TxnId(1), PageId(1), d(10), d(-10));
    wal.commit(TxnId(1)).unwrap();
    wal.begin(TxnId(2));
    wal.log_update(TxnId(2), PageId(0), d(-10), d(10));
    wal.log_update(TxnId(2), PageId(1), d(10), d(-10));
    wal.commit(TxnId(2)).unwrap();
    // T3 commits (so its records are durable), then the crash tears its COMMIT record — nothing
    // valid follows the torn point.
    wal.begin(TxnId(3));
    wal.log_update(TxnId(3), PageId(0), d(-5), d(5));
    wal.log_update(TxnId(3), PageId(1), d(5), d(-5));
    let c3 = wal.commit(TxnId(3)).unwrap();
    let full = wal.sink().durable_bytes().to_vec();
    let torn_len = (c3.0 + 3) as usize; // a few bytes into T3's COMMIT: a torn tail

    let mut sink = MemLogSink::new();
    sink.append(&full[..torn_len]);
    sink.sync().unwrap();
    let mut wal2 = WalManager::open(sink).unwrap();
    let mut store = DeltaStore::with_initial(2, 100);
    let report = recover(&mut wal2, &mut store).expect("a clean torn tail must still recover");
    assert!(report.tail_truncated, "the torn tail ends the scan");
    assert_eq!(report.losers, 1, "T3 is a loser (its COMMIT was torn)");
    // T1 + T2 committed; T3 fully undone.
    assert_eq!(store.value(0), 80);
    assert_eq!(store.value(1), 120);
    assert_eq!(store.total(), 200);
}

#[test]
fn checkpoint_sets_the_redo_start_without_losing_changes() {
    let mut wal = WalManager::create(MemLogSink::new()).unwrap();
    wal.begin(TxnId(1));
    let u = wal.log_update(TxnId(1), PageId(5), d(-10), d(10));
    wal.log_update(TxnId(1), PageId(6), d(10), d(-10));
    wal.commit(TxnId(1)).unwrap();

    // Fuzzy checkpoint claiming page 5 still dirty since its update `u`.
    wal.checkpoint(&[(PageId(5), u)]);

    wal.begin(TxnId(2));
    wal.log_update(TxnId(2), PageId(6), d(-7), d(7));
    wal.log_update(TxnId(2), PageId(7), d(7), d(-7));
    wal.commit(TxnId(2)).unwrap();

    let sink = wal.sink().clone();
    let mut wal2 = WalManager::open(sink).unwrap();
    let mut store = DeltaStore::with_initial(8, 100);
    let report = recover(&mut wal2, &mut store).unwrap();

    assert_eq!(
        report.redo_start, u,
        "redo starts at the checkpoint's min recovery_lsn"
    );
    // Both committed transfers are reflected, nothing lost despite the later redo start.
    assert_eq!(store.value(5), 90);
    assert_eq!(store.value(6), 103); // +10 (T1) then -7 (T2)
    assert_eq!(store.value(7), 107);
    assert_eq!(store.total(), 800);
}
