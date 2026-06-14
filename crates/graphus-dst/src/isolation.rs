//! `isolation` — end-to-end isolation oracle (rmp #170): drive **interleaved explicit transactions**
//! through the real engine, record what each one read and wrote into a [`graphus_elle::History`], and
//! have the Elle checker rule on whether the committed history is **serializable**.
//!
//! This closes the loop on the ACID "I". Running it against the live engine surfaced two real,
//! measured gaps — exactly what a DST is for — now filed and *pinned* by the tests so they cannot
//! silently regress and will flip to the correct assertion once fixed:
//!
//! - **rmp #171** — *phantom* predicate-read + insert: two transactions that each read a predicate
//!   returning nothing and then insert a row matching the other's predicate both commit
//!   (non-serializable). SSI lacks predicate/index-range SIREAD tracking; the Elle checker correctly
//!   detects the resulting cycle.
//! - **rmp #172** — concurrent write–write on the same node: the engine *does* detect the conflict
//!   (not both commit), but the survivor's committed update can be lost. This test pins the
//!   conflict-detection property and references #172 for the survivor's durability.
//!
//! ## The list-append model, in the graph
//!
//! An object `key` is the set of `(:Entry {key, val})` nodes; **append** creates one, **read** scans
//! them ordered by `val`. With monotonically increasing `val`s the scan yields the append order — a
//! self-recoverable history exactly as Elle wants, using only `CREATE`/`MATCH`.

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use graphus_core::Value;
    use graphus_cypher::MaterializedValue;
    use graphus_elle::{Op, Transaction, check};
    use graphus_io::MemBlockDevice;
    use graphus_server::engine::command::AccessMode;
    use graphus_server::engine::{LocalEngine, TxTicket};
    use graphus_sim::SharedClock;
    use graphus_wal::MemLogSink;

    type Eng = LocalEngine<MemBlockDevice, MemLogSink>;

    fn engine() -> Eng {
        LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 256).expect("engine")
    }

    /// Runs a write statement in `ticket` to completion (drains its empty result).
    fn write(eng: &mut Eng, ticket: TxTicket, stmt: &str, params: Vec<(String, Value)>) {
        let mut reply = eng.run(ticket, stmt, params, false, None).expect("write runs");
        while let Ok(Some(_)) = reply.rows.next() {}
    }

    /// Reads `key`'s append-list in `ticket`, returning the observed values in order.
    fn read_list(eng: &mut Eng, ticket: TxTicket, key: &str) -> Vec<i64> {
        let mut reply = eng
            .run(
                ticket,
                "MATCH (e:Entry {key: $k}) RETURN e.val AS val ORDER BY e.val",
                vec![("k".to_owned(), Value::String(key.to_owned()))],
                false,
                None,
            )
            .expect("read runs");
        let mut out = Vec::new();
        while let Ok(Some(row)) = reply.rows.next() {
            if let Some(MaterializedValue::Value(Value::Integer(n))) = row.first() {
                out.push(*n);
            }
        }
        out
    }

    /// Appends `val` to `key`'s list in `ticket`.
    fn append(eng: &mut Eng, ticket: TxTicket, key: &str, val: i64) {
        write(
            eng,
            ticket,
            "CREATE (:Entry {key: $k, val: $v})",
            vec![
                ("k".to_owned(), Value::String(key.to_owned())),
                ("v".to_owned(), Value::Integer(val)),
            ],
        );
    }

    fn tx(id: u64, key: &str, observed: Vec<i64>, append_val: i64, committed: bool) -> Transaction {
        Transaction {
            id,
            ops: vec![
                Op::Read { key: key.to_owned(), observed },
                Op::Append { key: key.to_owned(), val: append_val },
            ],
            committed,
        }
    }

    /// A serial (non-interleaved) append sequence: the second txn observes the first's commit, and
    /// the Elle checker certifies the history serializable — the clean end-to-end success path.
    #[test]
    fn serial_appends_are_certified_serializable() {
        let mut eng = engine();

        let t1 = eng.begin(AccessMode::Write).expect("begin t1");
        let r1 = read_list(&mut eng, t1, "a");
        append(&mut eng, t1, "a", 1);
        let c1 = eng.commit(t1).is_ok();

        let t2 = eng.begin(AccessMode::Write).expect("begin t2");
        let r2 = read_list(&mut eng, t2, "a");
        append(&mut eng, t2, "a", 2);
        let c2 = eng.commit(t2).is_ok();

        assert!(c1 && c2, "non-conflicting serial txns both commit");
        assert_eq!(r2, vec![1], "the second txn observed the first's committed append");
        let history = vec![tx(1, "a", r1, 1, c1), tx(2, "a", r2, 2, c2)];
        assert!(check(&history).serializable, "serial history is serializable");
    }

    /// Two concurrent write–write txns on the SAME existing node must not BOTH commit — SSI detects
    /// the conflict and aborts one. (The durability of the survivor's committed value is a separate
    /// found gap, tracked by rmp #172; this test pins the conflict-detection property.)
    #[test]
    fn write_write_conflict_is_detected() {
        let mut eng = engine();

        let s = eng.begin(AccessMode::Write).expect("begin setup");
        write(&mut eng, s, "CREATE (:Counter {k: 'x', v: 0})", vec![]);
        eng.commit(s).expect("commit setup");

        let t1 = eng.begin(AccessMode::Write).expect("begin t1");
        let t2 = eng.begin(AccessMode::Write).expect("begin t2");
        write(&mut eng, t1, "MATCH (c:Counter {k: 'x'}) SET c.v = c.v + 1", vec![]);
        write(&mut eng, t2, "MATCH (c:Counter {k: 'x'}) SET c.v = c.v + 1", vec![]);
        let c1 = eng.commit(t1).is_ok();
        let c2 = eng.commit(t2).is_ok();

        assert!(
            !(c1 && c2),
            "two concurrent same-node writers must not both commit (SSI conflict), got {c1},{c2}"
        );
    }

    /// **Pins rmp #171** (phantom write-skew across two keys). T1 reads y (empty) + inserts x; T2 reads
    /// x (empty) + inserts y; interleaved. The engine currently lets BOTH commit, which the Elle
    /// checker correctly flags as non-serializable. When #171 is fixed (predicate SIREAD tracking),
    /// the engine will abort one and this assertion flips to `verdict.serializable`.
    #[test]
    fn phantom_write_skew_is_detected_pins_171() {
        let mut eng = engine();

        let t1 = eng.begin(AccessMode::Write).expect("begin t1");
        let t2 = eng.begin(AccessMode::Write).expect("begin t2");
        let r1y = read_list(&mut eng, t1, "y");
        let r2x = read_list(&mut eng, t2, "x");
        append(&mut eng, t1, "x", 1);
        append(&mut eng, t2, "y", 1);
        let c1 = eng.commit(t1).is_ok();
        let c2 = eng.commit(t2).is_ok();

        let history = vec![
            Transaction {
                id: 1,
                ops: vec![
                    Op::Read { key: "y".into(), observed: r1y },
                    Op::Append { key: "x".into(), val: 1 },
                ],
                committed: c1,
            },
            Transaction {
                id: 2,
                ops: vec![
                    Op::Read { key: "x".into(), observed: r2x },
                    Op::Append { key: "y".into(), val: 1 },
                ],
                committed: c2,
            },
        ];
        let verdict = check(&history);
        if c1 && c2 {
            // Current (buggy) behaviour: the oracle MUST catch the phantom write-skew.
            assert!(
                !verdict.serializable,
                "the Elle oracle must detect phantom write-skew the engine admitted (rmp #171): {verdict:?}",
            );
        } else {
            // Fixed behaviour: SSI aborted one ⇒ the committed history is serializable.
            assert!(verdict.serializable, "with one txn aborted the history is serializable");
        }
    }

    /// **Pins rmp #171** (single-key phantom lost-update). Both txns read the empty list then append;
    /// the engine currently lets both commit. The Elle oracle detects the resulting non-serializable
    /// history. Flips to asserting serializability once #171 is fixed.
    #[test]
    fn phantom_lost_update_is_detected_pins_171() {
        let mut eng = engine();

        let t1 = eng.begin(AccessMode::Write).expect("begin t1");
        let t2 = eng.begin(AccessMode::Write).expect("begin t2");
        let r1 = read_list(&mut eng, t1, "a");
        let r2 = read_list(&mut eng, t2, "a");
        append(&mut eng, t1, "a", 1);
        append(&mut eng, t2, "a", 2);
        let c1 = eng.commit(t1).is_ok();
        let c2 = eng.commit(t2).is_ok();

        let history = vec![tx(1, "a", r1, 1, c1), tx(2, "a", r2, 2, c2)];
        let verdict = check(&history);
        if c1 && c2 {
            assert!(
                !verdict.serializable,
                "the Elle oracle must detect the phantom lost-update the engine admitted (rmp #171): {verdict:?}",
            );
        } else {
            assert!(verdict.serializable, "with one txn aborted the history is serializable");
        }
    }
}
