//! Tests for the deterministic serialization-graph checker ([`graphus_txn::HistoryChecker`]).
//!
//! Two duties (acceptance criterion 3):
//! 1. **It has teeth.** Fed a hand-built anomalous history (write-skew G2, and a longer
//!    anti-dependency cycle) it MUST report a cycle.
//! 2. **No false positives.** Fed a clean serial history it MUST report none.
//!
//! The empirical "Elle-style no anomalies under SERIALIZABLE" proof lives in `elle_no_anomalies.rs`.

use graphus_core::TxnId;
use graphus_txn::{HistoryChecker, TxnHistory};

/// Write-skew, the SI anomaly: two transactions each read the initial version of one key and write
/// the other, producing rw edges in both directions -> a 2-cycle the checker must catch.
#[test]
fn checker_catches_write_skew() {
    let mut c = HistoryChecker::new();

    let mut t1 = TxnHistory::new(TxnId(1));
    t1.read(200, 0); // read y (initial)
    t1.write(100, 1); // write x

    let mut t2 = TxnHistory::new(TxnId(2));
    t2.read(100, 0); // read x (initial)
    t2.write(200, 1); // write y

    c.add(t1);
    c.add(t2);

    let cycle = c
        .find_anomaly()
        .expect("write-skew is non-serializable and MUST be flagged");
    assert!(cycle.contains(&TxnId(1)));
    assert!(cycle.contains(&TxnId(2)));
}

/// A longer G2 anti-dependency cycle T1 -> T2 -> T3 -> T1 must also be caught (the checker is not
/// limited to two-transaction cycles).
#[test]
fn checker_catches_three_transaction_cycle() {
    let mut c = HistoryChecker::new();
    for (i, (read_key, write_key)) in [(30, 10), (10, 20), (20, 30)].into_iter().enumerate() {
        let mut t = TxnHistory::new(TxnId(i as u64 + 1));
        t.read(read_key, 0);
        t.write(write_key, 1);
        c.add(t);
    }
    let cycle = c.find_anomaly().expect("3-cycle MUST be flagged");
    assert_eq!(cycle.len(), 3);
}

/// A clean serial history (T1 writes, T2 reads-and-extends) has an acyclic DSG -> no anomaly.
#[test]
fn checker_passes_clean_serial_history() {
    let mut c = HistoryChecker::new();

    let mut t1 = TxnHistory::new(TxnId(1));
    t1.write(1, 1);
    t1.write(2, 1);

    let mut t2 = TxnHistory::new(TxnId(2));
    t2.read(1, 1); // reads T1's value
    t2.write(1, 2); // installs the successor

    let mut t3 = TxnHistory::new(TxnId(3));
    t3.read(1, 2); // reads T2's value
    t3.read(2, 1);

    c.add(t1);
    c.add(t2);
    c.add(t3);

    assert_eq!(
        c.find_anomaly(),
        None,
        "a serial history must have an acyclic DSG"
    );
}

/// Read-only transactions piling onto committed data never create a cycle.
#[test]
fn checker_passes_many_readers() {
    let mut c = HistoryChecker::new();
    let mut writer = TxnHistory::new(TxnId(1));
    writer.write(1, 1);
    c.add(writer);
    for i in 2..=10 {
        let mut r = TxnHistory::new(TxnId(i));
        r.read(1, 1);
        c.add(r);
    }
    assert_eq!(c.find_anomaly(), None);
}
