//! `isolation` — end-to-end isolation oracle (rmp #170): drive **interleaved explicit transactions**
//! through the real engine, record what each one read and wrote into a [`graphus_elle::History`], and
//! have the Elle checker rule on whether the committed history is **serializable**.
//!
//! This closes the loop on the ACID "I". Running it against the live engine surfaced two real,
//! measured gaps — exactly what a DST is for — both now **fixed** and *guarded* by the tests so they
//! cannot silently regress:
//!
//! - **rmp #171** — *phantom* predicate-read + insert: two transactions that each read a predicate
//!   returning nothing and then insert a row matching the other's predicate. FIXED by predicate
//!   SIREAD tracking in the SSI validator (`graphus-txn`'s `ssi.rs` [`PredicateRead`] + the
//!   `record_graph` read/write wiring): the empty predicate read now registers a marker the
//!   concurrent matching insert closes an rw-antidependency against, so SSI aborts exactly one. The
//!   guard tests assert at most one commits and the committed history is serializable.
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
        let mut reply = eng
            .run(ticket, stmt, params, false, None)
            .expect("write runs");
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

    /// Deletes the `(:Entry {key, val})` node from `key`'s list in `ticket` (read-then-delete model).
    fn delete_entry(eng: &mut Eng, ticket: TxTicket, key: &str, val: i64) {
        write(
            eng,
            ticket,
            "MATCH (e:Entry {key: $k, val: $v}) DELETE e",
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
                Op::Read {
                    key: key.to_owned(),
                    observed,
                },
                Op::Append {
                    key: key.to_owned(),
                    val: append_val,
                },
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
        assert_eq!(
            r2,
            vec![1],
            "the second txn observed the first's committed append"
        );
        let history = vec![tx(1, "a", r1, 1, c1), tx(2, "a", r2, 2, c2)];
        assert!(
            check(&history).serializable,
            "serial history is serializable"
        );
    }

    /// Two concurrent write–write txns on the SAME existing node: SSI detects the conflict and aborts
    /// exactly one, AND the survivor's committed update is **durable** — the final value reflects
    /// exactly one increment, never the loser's clobber back to the pre-image (`rmp` #172, FIXED).
    ///
    /// The durability arm was previously a found gap (the SSI loser's rollback restored a stale
    /// `first_prop` chain-head pre-image over the survivor's committed value, reverting it to 0 and
    /// even severing unrelated properties of the node). The storage-layer fix (chain-head
    /// compare-and-set logical undo + header-only creation undo) guarantees the loser's abort unlinks
    /// only its own push and never reverts the survivor's committed value.
    #[test]
    fn write_write_conflict_is_detected() {
        let mut eng = engine();

        let s = eng.begin(AccessMode::Write).expect("begin setup");
        write(&mut eng, s, "CREATE (:Counter {k: 'x', v: 0})", vec![]);
        eng.commit(s).expect("commit setup");

        let t1 = eng.begin(AccessMode::Write).expect("begin t1");
        let t2 = eng.begin(AccessMode::Write).expect("begin t2");
        write(
            &mut eng,
            t1,
            "MATCH (c:Counter {k: 'x'}) SET c.v = c.v + 1",
            vec![],
        );
        write(
            &mut eng,
            t2,
            "MATCH (c:Counter {k: 'x'}) SET c.v = c.v + 1",
            vec![],
        );
        let c1 = eng.commit(t1).is_ok();
        let c2 = eng.commit(t2).is_ok();

        // SSI must abort exactly one of the two write–write conflicting transactions.
        assert!(
            c1 ^ c2,
            "exactly one concurrent same-node writer must commit (SSI conflict), got {c1},{c2}"
        );

        // The survivor's committed increment must persist: the node is still found by its unchanged
        // key `k`, and `v` reflects exactly one increment (1), never reverted to the pre-image 0.
        let reader = eng.begin(AccessMode::Read).expect("begin reader");
        let mut reply = eng
            .run(
                reader,
                "MATCH (c:Counter {k: 'x'}) RETURN c.v AS v",
                vec![],
                false,
                None,
            )
            .expect("read runs");
        let mut observed = Vec::new();
        while let Ok(Some(row)) = reply.rows.next() {
            if let Some(MaterializedValue::Value(Value::Integer(n))) = row.first() {
                observed.push(*n);
            }
        }
        let _ = eng.commit(reader);
        assert_eq!(
            observed,
            vec![1],
            "the SSI survivor's committed value must persist as exactly one increment (rmp #172), \
             not be reverted by the loser's undo; got {observed:?}"
        );
    }

    /// **Guards rmp #171** (phantom write-skew across two keys), FIXED. T1 reads y (empty) + inserts x;
    /// T2 reads x (empty) + inserts y; interleaved. Each transaction's predicate read of the *absence*
    /// of the other's key now registers a predicate SIREAD marker, so the concurrent matching insert
    /// closes an rw-antidependency and SSI's dangerous-structure detection aborts exactly one
    /// transaction. This guards serializability: with one txn aborted, **at most one commits** and the
    /// committed history the Elle checker rules on is serializable. (Before the fix the engine admitted
    /// both, a non-serializable phantom write-skew — see the SSI predicate-tracking unit tests in
    /// `graphus-txn`'s `ssi.rs` for the tracker-level guard.)
    #[test]
    fn phantom_write_skew_is_prevented() {
        let mut eng = engine();

        let t1 = eng.begin(AccessMode::Write).expect("begin t1");
        let t2 = eng.begin(AccessMode::Write).expect("begin t2");
        let r1y = read_list(&mut eng, t1, "y");
        let r2x = read_list(&mut eng, t2, "x");
        append(&mut eng, t1, "x", 1);
        append(&mut eng, t2, "y", 1);
        let c1 = eng.commit(t1).is_ok();
        let c2 = eng.commit(t2).is_ok();

        // SSI must abort exactly one of the two phantom-conflicting transactions (predicate SIREAD
        // tracking, rmp #171): the two rw-antidependencies form a dangerous structure and the pivot
        // rule aborts one. At most one commits.
        assert!(
            c1 ^ c2,
            "exactly one of the two phantom write-skew transactions must commit (rmp #171), got {c1},{c2}"
        );

        let history = vec![
            Transaction {
                id: 1,
                ops: vec![
                    Op::Read {
                        key: "y".into(),
                        observed: r1y,
                    },
                    Op::Append {
                        key: "x".into(),
                        val: 1,
                    },
                ],
                committed: c1,
            },
            Transaction {
                id: 2,
                ops: vec![
                    Op::Read {
                        key: "x".into(),
                        observed: r2x,
                    },
                    Op::Append {
                        key: "y".into(),
                        val: 1,
                    },
                ],
                committed: c2,
            },
        ];
        let verdict = check(&history);
        assert!(
            verdict.serializable,
            "with one transaction aborted the committed history must be serializable: {verdict:?}",
        );
    }

    /// **Guards rmp #171** (single-key phantom lost-update), FIXED. Both txns read the empty list for
    /// key `a` then append to it; interleaved. Each empty predicate read registers a predicate SIREAD
    /// marker that the other's concurrent insert matches, closing the rw-antidependencies that make
    /// the pair a dangerous structure — so SSI aborts one. With one aborted there is no lost update and
    /// the committed history is serializable.
    #[test]
    fn phantom_lost_update_is_prevented() {
        let mut eng = engine();

        let t1 = eng.begin(AccessMode::Write).expect("begin t1");
        let t2 = eng.begin(AccessMode::Write).expect("begin t2");
        let r1 = read_list(&mut eng, t1, "a");
        let r2 = read_list(&mut eng, t2, "a");
        append(&mut eng, t1, "a", 1);
        append(&mut eng, t2, "a", 2);
        let c1 = eng.commit(t1).is_ok();
        let c2 = eng.commit(t2).is_ok();

        // SSI must abort exactly one of the two phantom-lost-update transactions (rmp #171).
        assert!(
            c1 ^ c2,
            "exactly one of the two phantom lost-update transactions must commit (rmp #171), got {c1},{c2}"
        );

        let history = vec![tx(1, "a", r1, 1, c1), tx(2, "a", r2, 2, c2)];
        let verdict = check(&history);
        assert!(
            verdict.serializable,
            "with one transaction aborted the committed history must be serializable: {verdict:?}",
        );
    }

    /// **Guards rmp #171 blocker B1** (read-then-delete write-skew), FIXED. Two entries (`val 1`,
    /// `val 2`) exist under key `a` with the invariant "at least one entry must remain". T1 reads the
    /// list (sees both) then deletes `val 1`; T2 reads the list (sees both) then deletes `val 2`;
    /// interleaved. Serially the second transaction would see only one entry left and its read would
    /// differ — concurrently, **both** deletes would empty the list, violating the invariant: a classic
    /// non-serializable read-then-delete write-skew.
    ///
    /// The fix announces each delete's **pre-image** predicate footprint (`MATCH (e:Entry {key:'a'})`'s
    /// `Label`/`Equality` markers), so each transaction's predicate read of the list closes an
    /// rw-antidependency against the *other's* delete. The two edges form a dangerous structure and SSI
    /// aborts exactly one — so at least one entry survives.
    #[test]
    fn read_then_delete_write_skew_is_prevented_b1() {
        let mut eng = engine();

        // Setup: two entries under key `a`.
        let s = eng.begin(AccessMode::Write).expect("begin setup");
        append(&mut eng, s, "a", 1);
        append(&mut eng, s, "a", 2);
        eng.commit(s).expect("commit setup");

        let t1 = eng.begin(AccessMode::Write).expect("begin t1");
        let t2 = eng.begin(AccessMode::Write).expect("begin t2");
        // Each reads the predicate (the whole list) — the read that the concurrent delete invalidates.
        let r1 = read_list(&mut eng, t1, "a");
        let r2 = read_list(&mut eng, t2, "a");
        assert_eq!(r1, vec![1, 2], "T1 sees both entries");
        assert_eq!(r2, vec![1, 2], "T2 sees both entries");
        // Each deletes a *different* entry: serially the invariant "≥1 remains" holds; concurrently it
        // would be violated unless SSI aborts one.
        delete_entry(&mut eng, t1, "a", 1);
        delete_entry(&mut eng, t2, "a", 2);
        let c1 = eng.commit(t1).is_ok();
        let c2 = eng.commit(t2).is_ok();

        // SSI must abort at least one (predicate pre-image tracking, blocker B1). Both committing would
        // be the non-serializable read-then-delete write-skew.
        assert!(
            !(c1 && c2),
            "both read-then-delete transactions must not commit (rmp #171 B1), got {c1},{c2}"
        );

        // The invariant must hold: at least one entry remains (no empty list from a double delete).
        let reader = eng.begin(AccessMode::Read).expect("begin reader");
        let remaining = read_list(&mut eng, reader, "a");
        let _ = eng.commit(reader);
        assert!(
            !remaining.is_empty(),
            "the read-then-delete invariant (≥1 entry remains) must hold; got {remaining:?}"
        );
    }

    /// **Guards rmp #171 blocker A1** (relationship phantom write-skew), FIXED. Two anchor nodes exist;
    /// T1 reads `(a)-[:KNOWS]->()` (sees no such edge) then creates `(b)-[:KNOWS]->(b)`; T2 reads
    /// `(b)-[:KNOWS]->()` (sees none) then creates `(a)-[:KNOWS]->(a)`; interleaved. Each transaction's
    /// relationship-pattern read of the *absence* of a `:KNOWS` edge now registers a `RelType` predicate
    /// marker that the other's concurrent `CREATE` of a `:KNOWS` edge closes an rw-antidependency
    /// against — the relationship analogue of the #171 node phantom. The two edges form a dangerous
    /// structure and SSI aborts exactly one.
    #[test]
    fn relationship_phantom_write_skew_is_prevented_a1() {
        let mut eng = engine();

        // Setup: two distinct anchor nodes a and b.
        let s = eng.begin(AccessMode::Write).expect("begin setup");
        write(&mut eng, s, "CREATE (:Anchor {name: 'a'})", vec![]);
        write(&mut eng, s, "CREATE (:Anchor {name: 'b'})", vec![]);
        eng.commit(s).expect("commit setup");

        /// Counts `(:Anchor {name})-[:KNOWS]->()` edges visible to `ticket`.
        fn count_knows(eng: &mut Eng, ticket: TxTicket, name: &str) -> i64 {
            let mut reply = eng
                .run(
                    ticket,
                    "MATCH (a:Anchor {name: $n})-[r:KNOWS]->() RETURN count(r) AS c",
                    vec![("n".to_owned(), Value::String(name.to_owned()))],
                    false,
                    None,
                )
                .expect("read runs");
            let mut c = 0;
            while let Ok(Some(row)) = reply.rows.next() {
                if let Some(MaterializedValue::Value(Value::Integer(n))) = row.first() {
                    c = *n;
                }
            }
            c
        }

        let t1 = eng.begin(AccessMode::Write).expect("begin t1");
        let t2 = eng.begin(AccessMode::Write).expect("begin t2");
        // Each reads the rel-pattern predicate (absence of a :KNOWS edge from its anchor).
        let r1 = count_knows(&mut eng, t1, "a");
        let r2 = count_knows(&mut eng, t2, "b");
        assert_eq!(r1, 0, "T1 sees no :KNOWS edge from a");
        assert_eq!(r2, 0, "T2 sees no :KNOWS edge from b");
        // Each creates a :KNOWS edge on the OTHER's anchor (a self-loop keeps the model simple).
        write(
            &mut eng,
            t1,
            "MATCH (b:Anchor {name: 'b'}) CREATE (b)-[:KNOWS]->(b)",
            vec![],
        );
        write(
            &mut eng,
            t2,
            "MATCH (a:Anchor {name: 'a'}) CREATE (a)-[:KNOWS]->(a)",
            vec![],
        );
        let c1 = eng.commit(t1).is_ok();
        let c2 = eng.commit(t2).is_ok();

        // SSI must abort at least one (relationship predicate tracking, blocker A1). Both committing is
        // the non-serializable relationship phantom write-skew.
        assert!(
            !(c1 && c2),
            "both relationship-phantom transactions must not commit (rmp #171 A1), got {c1},{c2}"
        );
    }
}
