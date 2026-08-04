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
//! - **rmp #902 / #903** — `CREATE CONSTRAINT` as a participant in concurrency control. The DDL used
//!   to be a bare store transaction registered in neither the SSI tracker nor the active set, so it
//!   formed no rw-edge with anything: it could be decided on another transaction's uncommitted write
//!   (#902), and — the window a fail-closed guard cannot close — a transaction whose snapshot predates
//!   the constraint could afterwards commit a duplicate its own snapshot hid from it (#903). FIXED by
//!   running the DDL as a first-class serializable transaction that reads through its own snapshot and
//!   announces a predicate footprint (`Label`/`RelType` + per-value `Equality`/`RelEquality`), so such
//!   a writer becomes an SSI pivot and is aborted. Four scenarios guard it, for nodes and for
//!   relationships, with an isolating control that pins the mechanism.
//!
//! ## The list-append model, in the graph
//!
//! An object `key` is the set of `(:Entry {key, val})` nodes; **append** creates one, **read** scans
//! them ordered by `val`. With monotonically increasing `val`s the scan yields the append order — a
//! self-recoverable history exactly as Elle wants, using only `CREATE`/`MATCH`.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use graphus_core::Value;
    use graphus_cypher::MaterializedValue;
    use graphus_cypher::TxnCoordinator;
    use graphus_elle::{Op, Transaction, check};
    use graphus_io::MemBlockDevice;
    use graphus_server::engine::command::AccessMode;
    use graphus_server::engine::{
        ConstraintCommand, ConstraintCreateKind, ConstraintEntity, ConstraintTypeFilter,
        CreateConstraint, LocalEngine, TxTicket,
    };
    use graphus_sim::SharedClock;
    use graphus_storage::RecordStore;
    use graphus_wal::{MemLogSink, WalManager};

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

    /// Runs `stmt` in `ticket` and reports whether the write path **admitted** it: `Ok(())` when the
    /// statement ran to a clean end of stream, `Err(message)` when it was rejected — either before the
    /// first row or as the stream's terminal item. The message is returned because the *class* of the
    /// refusal is what the retry contract is keyed on.
    fn try_write(eng: &mut Eng, ticket: TxTicket, stmt: &str) -> Result<(), String> {
        let mut reply = match eng.run(ticket, stmt, vec![], false, None) {
            Ok(reply) => reply,
            Err(e) => return Err(e.to_string()),
        };
        loop {
            match reply.rows.next() {
                Ok(Some(_)) => {}
                Ok(None) => return Ok(()),
                Err(e) => return Err(e.to_string()),
            }
        }
    }

    /// **Guards `rmp` #967** — the loser of a write–write conflict must not be able to COMMIT.
    ///
    /// A write–write conflict is refused at two sites that agree on the victim: the coordinator's
    /// first-updater-wins `LockTable` (`RecordGraph::note_write`) and, since `rmp` #967, the store's
    /// `RecordStore::ensure_no_conflicting_writer` (`D-property-write-conflict`). Both raise a
    /// **retriable** `GraphusError::Transaction`, and both document the same contract: the error is
    /// captured *so the caller rolls this transaction back*. That caller existed only for auto-commit
    /// statements; an explicit transaction whose write was refused stayed open and **committed
    /// successfully**, reporting success for a write the engine had rejected.
    ///
    /// That is not merely untidy: the refused writer's SSI footprint is announced *before* the refusal
    /// (`note_write` records the write marker before it acquires the lock), so while it stays open the
    /// holder acquires an outbound rw-edge to a write that never happened, becomes a Case-A pivot and
    /// is aborted — leaving the phantom writer as the sole committer and the counter at its pre-image.
    /// [`write_write_conflict_is_detected`] is the end-to-end oracle for that lost update; this is the
    /// isolating control that pins the mechanism, so a regression is attributable rather than merely
    /// visible.
    #[test]
    fn a_refused_second_writer_cannot_commit_967() {
        let mut eng = engine();

        let s = eng.begin(AccessMode::Write).expect("begin setup");
        write(&mut eng, s, "CREATE (:Counter {k: 'x', v: 0})", vec![]);
        eng.commit(s).expect("commit setup");

        let t1 = eng.begin(AccessMode::Write).expect("begin t1");
        let t2 = eng.begin(AccessMode::Write).expect("begin t2");

        // T1 takes the entity. Non-vacuity: if this were refused the scenario would never reach the
        // window under test.
        try_write(&mut eng, t1, "MATCH (c:Counter {k: 'x'}) SET c.v = c.v + 1")
            .expect("T1 is the first writer, so its write must be admitted");

        assert_eq!(
            eng.status_open_txns().expect("status"),
            2,
            "non-vacuity: both transactions must really be open here, so the count below measures \
             T2's retirement and not an empty table"
        );

        // T2 is refused — and with the retriable class, not some incidental storage error.
        let refused = try_write(&mut eng, t2, "MATCH (c:Counter {k: 'x'}) SET c.v = c.v + 1")
            .expect_err("a second writer on an entity T1 holds must be refused");
        assert!(
            refused.contains("serialization failure"),
            "non-vacuity: the refusal must be the retriable serialization class the driver retry \
             logic keys on, not an unrelated failure; got {refused}"
        );

        // THE ASSERTION THIS SCENARIO EXISTS FOR. The refused writer is retired at STATEMENT END, so
        // its phantom SSI footprint is gone before anybody commits. Asserted as a count rather than
        // through `commit`, deliberately: a still-open T2 *also* fails to commit here — SSI aborts it
        // as a pivot on the very structure the phantom footprint creates — so a `commit(t2).is_err()`
        // oracle passes with and without the fix and measures nothing. (Observed, not reasoned about:
        // the first draft of this test used exactly that oracle and passed against the unfixed
        // engine.) The open-transaction count is the one observation the two states disagree on.
        assert_eq!(
            eng.status_open_txns().expect("status"),
            1,
            "a transaction whose write was REFUSED with a retriable serialization failure must be \
             rolled back at statement end, leaving only its holder open (rmp #967)"
        );
        assert!(
            eng.commit(t2).is_err(),
            "and it must therefore not be committable — before the fix it committed cleanly, telling \
             its client that a rejected write had been applied"
        );

        // ...and with the phantom footprint retired, the holder commits its increment.
        eng.commit(t1).expect("the entity holder must commit");

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
            "the holder's increment must be the committed value; got {observed:?}"
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

    /// **Guards rmp #341** (concurrency-ready SSI tracker): the SSI abort **victim is a deterministic
    /// function of the input** — the same concurrent write-skew workload, replayed on a fresh engine,
    /// aborts the **same** transaction every time.
    ///
    /// This is the engine-level "same seed ⇒ same victim" assertion the #341 design requires. #341
    /// moved SIREAD-marker recording off the inline path into a per-statement [`SsiReadBuffer`] that
    /// is sorted+deduped and merged at statement-end; if that merge ordering (or the
    /// `detect_pivot_abort` `.min()` tie-break it feeds) were sensitive to anything other than the
    /// marker *set*, the victim could vary run-to-run, breaking the DST's "same input ⇒ identical
    /// trace" invariant. The `FxHashMap`-based tracker has no per-process seed and the merge sorts
    /// before replay, so the victim is pinned; this replays the canonical write-skew several times and
    /// asserts the abortee is invariant.
    #[test]
    fn ssi_abort_victim_is_deterministic_rmp341() {
        // Run the identical write-skew workload on a fresh engine and report which transaction was
        // the abort victim (`1` = t1 aborted, `2` = t2 aborted). Exactly one must abort each run.
        fn write_skew_victim() -> u64 {
            let mut eng = engine();
            // Seed both single-row registers x and y (committed before the concurrent pair).
            let s = eng.begin(AccessMode::Write).expect("begin setup");
            append(&mut eng, s, "x", 0);
            append(&mut eng, s, "y", 0);
            eng.commit(s).expect("commit setup");

            let t1 = eng.begin(AccessMode::Write).expect("begin t1");
            let t2 = eng.begin(AccessMode::Write).expect("begin t2");
            // Each reads the other's register, then writes its own — the write-skew shape.
            let _ = read_list(&mut eng, t1, "y");
            let _ = read_list(&mut eng, t2, "x");
            append(&mut eng, t1, "x", 1);
            append(&mut eng, t2, "y", 1);
            let c1 = eng.commit(t1).is_ok();
            let c2 = eng.commit(t2).is_ok();
            assert!(
                c1 ^ c2,
                "exactly one of the write-skew pair must abort, got {c1},{c2}"
            );
            if c1 { 2 } else { 1 } // the one that did NOT commit is the victim
        }

        let victim = write_skew_victim();
        // Replaying the identical workload must abort the identical transaction every time.
        for run in 0..8 {
            assert_eq!(
                write_skew_victim(),
                victim,
                "run {run}: the SSI abort victim must be a deterministic function of the input \
                 (rmp #341 — buffered+merged SIREAD markers must not perturb the victim)"
            );
        }
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

    // ---------------------------------------------------------------------------------------------
    // `CREATE CONSTRAINT` as a first-class participant in concurrency control (rmp #902 / #903)
    // ---------------------------------------------------------------------------------------------

    /// A `CREATE CONSTRAINT … IS UNIQUE` engine command over `(label, property)`.
    fn create_unique(name: &str, label: &str, property: &str) -> ConstraintCommand {
        ConstraintCommand::Create(CreateConstraint {
            name: name.to_owned(),
            entity: ConstraintEntity::Node {
                label: label.to_owned(),
            },
            properties: vec![property.to_owned()],
            kind: ConstraintCreateKind::Unique,
            if_not_exists: false,
            or_replace: false,
        })
    }

    /// Creates `(:P {email})` inside `ticket`.
    fn create_person(eng: &mut Eng, ticket: TxTicket, email: &str) {
        assert!(
            try_create_person(eng, ticket, email),
            "CREATE (:P {{email: '{email}'}}) must succeed here"
        );
    }

    /// Creates `(:P {email})` inside `ticket`, reporting whether the write path **admitted** it.
    /// `false` means the statement itself was rejected — a constraint violation raised either before
    /// the first row or while draining the (empty) stream.
    fn try_create_person(eng: &mut Eng, ticket: TxTicket, email: &str) -> bool {
        let Ok(mut reply) = eng.run(
            ticket,
            "CREATE (:P {email: $e})",
            vec![("e".to_owned(), Value::String(email.to_owned()))],
            false,
            None,
        ) else {
            return false;
        };
        loop {
            match reply.rows.next() {
                Ok(Some(_)) => {}
                Ok(None) => return true,
                Err(_) => return false,
            }
        }
    }

    /// A `CREATE` carrying enough distinct property keys to push the token dictionary — and with it
    /// the encoded catalog — past a single metadata page. Built programmatically because the exact
    /// count is a property of the page size, not of the scenario.
    fn wide_property_create() -> String {
        let props: Vec<String> = (0..512)
            .map(|i| format!("chain_growth_property_key_number_{i:08}: {i}"))
            .collect();
        format!("CREATE (:Filler {{{}}})", props.join(", "))
    }

    /// Counts the `(:P {email})` nodes visible to a fresh auto-committed read — the post-state oracle
    /// for "did a duplicate survive under a live `IS UNIQUE`?".
    fn count_persons(eng: &mut Eng, email: &str) -> i64 {
        let t = eng.begin(AccessMode::Read).expect("begin counter");
        let mut reply = eng
            .run(
                t,
                "MATCH (p:P {email: $e}) RETURN count(p) AS c",
                vec![("e".to_owned(), Value::String(email.to_owned()))],
                false,
                None,
            )
            .expect("count runs");
        let mut c = 0;
        while let Ok(Some(row)) = reply.rows.next() {
            if let Some(MaterializedValue::Value(Value::Integer(n))) = row.first() {
                c = *n;
            }
        }
        let _ = eng.commit(t);
        c
    }

    /// **Guards `rmp` #902 / #903 — reproduction 1: the uncommitted-write window.** Two committed
    /// duplicates exist; a transaction `A` holds an **uncommitted** `SET` that would remove the
    /// duplicate; `CREATE CONSTRAINT … IS UNIQUE` is issued while `A` is still open; `A` then rolls
    /// back.
    ///
    /// The DDL must NOT be accepted. Before `rmp` task #902 it read `A`'s dirty `'b'`, found no
    /// duplicate and declared the constraint durably — and once `A` rolled back the graph held two
    /// committed `'a'`s under a live `IS UNIQUE`, which nothing re-validates and no rw-edge can undo.
    /// The decision is now made over `A`'s *invisible* uncommitted write (the walk reads through the
    /// DDL transaction's own snapshot, `rmp` task #903), and the DDL is additionally refused outright
    /// while a writer is open — see `TxnCoordinator::refuse_constraint_ddl_while_writers_open` for why
    /// that refusal is not expressible as a predicate.
    ///
    /// The oracle is deliberately "refused, whatever the reason": both a `ConstraintViolation` over the
    /// committed duplicate and the retryable concurrency refusal are correct answers, and which one
    /// fires is a property of the guard, not of the invariant under test. What must never happen is a
    /// declared constraint over data that violates it.
    #[test]
    fn constraint_ddl_is_not_decided_on_an_uncommitted_write_902() {
        let mut eng = engine();

        // Two committed duplicates.
        let s = eng.begin(AccessMode::Write).expect("begin setup");
        create_person(&mut eng, s, "a");
        create_person(&mut eng, s, "a");
        eng.commit(s).expect("commit setup");
        assert_eq!(
            count_persons(&mut eng, "a"),
            2,
            "non-vacuity: the graph must really hold two committed duplicates before the DDL runs"
        );

        // A holds an uncommitted SET that would make the data conform. It is never committed.
        let a = eng.begin(AccessMode::Write).expect("begin a");
        write(
            &mut eng,
            a,
            "MATCH (p:P {email: 'a'}) WITH p LIMIT 1 SET p.email = 'b'",
            vec![],
        );

        // B declares the constraint while A is still open.
        let declared = eng.constraint_ddl(create_unique("u_email", "P", "email"));
        assert!(
            declared.is_err(),
            "CREATE CONSTRAINT must not be decided on transaction A's uncommitted write (rmp #902); \
             it was accepted: {declared:?}"
        );

        eng.rollback(a).expect("a rolls back");

        // The committed graph still holds the duplicate, and no constraint claims otherwise.
        assert_eq!(
            count_persons(&mut eng, "a"),
            2,
            "A rolled back, so both committed duplicates must survive"
        );
        let listing = eng
            .constraint_ddl(ConstraintCommand::Show {
                filter: ConstraintTypeFilter::All,
                tail: None,
            })
            .expect("show constraints");
        assert!(
            listing.rows.is_empty(),
            "no constraint may be declared over data that violates it, got {} row(s)",
            listing.rows.len()
        );
    }

    /// **Guards `rmp` #903 — reproduction 2: the declare-while-open window.** The interleaving the
    /// `rmp` #902 guard deliberately does not close, because nothing is uncommitted when the DDL runs:
    ///
    /// 1. `R` opens and is entirely idle — it holds only a snapshot.
    /// 2. `W` commits `(:P {email: 'a'})`, **after** `R`'s snapshot.
    /// 3. `CREATE CONSTRAINT … IS UNIQUE` validates (exactly one live `'a'`) and is accepted.
    /// 4. `R` writes its own `(:P {email: 'a'})`. The write path's duplicate check re-checks candidates
    ///    against `R`'s own snapshot, in which step 2's row is invisible, so the write is admitted.
    /// 5. `R` commits — and used to commit two `'a'`s under a live `IS UNIQUE`.
    ///
    /// Step 3 is what closes it now: the DDL runs as a registered SSI transaction and announces the
    /// `Label(P)` + `Equality{P, email, 'a'}` predicate SIREAD markers for what it read. `R`'s write in
    /// step 4 announces a matching write footprint, closing `DDL --rw--> R`, while `R`'s own duplicate
    /// check reads a predicate `W` wrote, closing `R --rw--> W`. `R` is therefore a pivot with both an
    /// inbound and an outbound conflict whose outbound partner has already committed, and the pivot rule
    /// aborts it at commit. Without the DDL's markers `R` has no inbound edge, is not a pivot, and
    /// commits the violation.
    ///
    /// The oracle is the *data*, not the abort: after the dust settles at most one `(:P {email:'a'})`
    /// may exist while the constraint is live.
    ///
    /// # No probe may run between step 2 and step 5
    ///
    /// Every observation is deferred to the end, and that is load-bearing rather than tidy. A `MATCH
    /// (p:P {email:'a'})` inserted as a mid-scenario non-vacuity check is itself a transaction that
    /// registers an `Equality{P, email, 'a'}` SIREAD marker: it reads a predicate `W` wrote (closing
    /// `probe --rw--> W`) and `R`'s later write closes `probe --rw--> R`, which supplies exactly the
    /// third participant the structure was missing — so the scenario passes against the **unfixed**
    /// engine and measures nothing. This was observed, not reasoned about: an earlier draft of this
    /// test placed `count_persons` after step 3 and passed against the pre-`rmp` #903 coordinator.
    /// The only in-scenario assertion is therefore step 4's, which introduces no transaction.
    #[test]
    fn constraint_declared_while_an_older_reader_is_open_903() {
        let mut eng = engine();

        // 1. R opens and stays idle: it only pins a snapshot.
        let r = eng.begin(AccessMode::Write).expect("begin r");

        // 2. W commits the first 'a' AFTER R's snapshot.
        let w = eng.begin(AccessMode::Write).expect("begin w");
        create_person(&mut eng, w, "a");
        eng.commit(w).expect("w commits");

        // 3. The constraint is valid over the committed graph (exactly one 'a'), so it is accepted.
        //    Acceptance is itself the evidence that the graph held no duplicate at this instant: the
        //    validation walk refuses on one.
        eng.constraint_ddl(create_unique("u_email", "P", "email"))
            .expect("the constraint holds over the committed graph and must be accepted");

        // 4. R writes a duplicate it cannot see. The write path MUST admit it — W's row is invisible to
        //    R's snapshot — otherwise the scenario never reaches the window under test.
        let admitted = try_create_person(&mut eng, r, "a");
        assert!(
            admitted,
            "non-vacuity: R's write path must ADMIT the duplicate, because W's row is invisible to R's \
             snapshot; a rejection here means the scenario is exercising the write-path check instead \
             of the constraint DDL's predicate footprint"
        );

        // 5. R tries to commit.
        let committed = eng.commit(r).is_ok();

        // The invariant: never two committed 'a's under a live IS UNIQUE.
        let live = count_persons(&mut eng, "a");
        assert_eq!(
            live, 1,
            "a live IS UNIQUE must not admit a second committed 'a' (rmp #903); R committed = \
             {committed}, found {live}"
        );
        assert!(
            !committed,
            "R must be aborted on the SSI dangerous structure the constraint DDL's predicate markers \
             close (rmp #903)"
        );
    }

    /// **Guards `rmp` task #903 — the DDL's live-transaction entry is created and always retired.** The
    /// engine registers a validating `CREATE CONSTRAINT` in the live-transaction registry so an
    /// operator can see it in `SHOW TRANSACTIONS` and stop it with `TERMINATE TRANSACTIONS`. The entry
    /// is RAII-scoped to the DDL, so what must hold deterministically is that it is gone afterwards —
    /// on the success path *and* on the refusal path. An entry that outlived its work would be a
    /// phantom row an operator could try to terminate forever.
    ///
    /// # What this scenario deliberately does not assert
    ///
    /// Observing the entry *while* the DDL runs, or terminating it mid-flight, is not expressible here.
    /// The DST driver is single-threaded by mandate — that is what makes it reproducible — and a
    /// constraint DDL is one synchronous engine command, so there is no point at which a deterministic
    /// scheduler could interleave an observer between the registration and the deregistration. Those
    /// two properties are gated where a second thread is legitimate:
    /// `graphus-server`'s `constraint_ddl_show_terminate_903.rs`. The abort *path* they exercise is in
    /// turn pinned deterministically by `graphus-cypher`'s `constraint_ddl_transaction_903.rs`, which
    /// drives a pre-cancelled token with no threads at all.
    #[test]
    fn a_constraint_ddl_always_retires_its_live_transaction_entry_903() {
        let mut eng = engine();
        assert!(
            eng.transactions().is_empty(),
            "non-vacuity: the registry starts empty, so anything observed below is the DDL's"
        );

        // The success path.
        let s = eng.begin(AccessMode::Write).expect("begin setup");
        create_person(&mut eng, s, "a");
        create_person(&mut eng, s, "b");
        eng.commit(s).expect("commit setup");
        eng.constraint_ddl(create_unique("u_email", "P", "email"))
            .expect("distinct values, so the constraint holds");
        assert!(
            eng.transactions().is_empty(),
            "a committed constraint DDL must retire its entry"
        );

        // The refusal path: a committed duplicate under a second constraint on the same property.
        let d = eng.begin(AccessMode::Write).expect("begin dup");
        write(&mut eng, d, "CREATE (:Q {tag: 'x'})", vec![]);
        write(&mut eng, d, "CREATE (:Q {tag: 'x'})", vec![]);
        eng.commit(d).expect("commit dup");
        let refused = eng.constraint_ddl(create_unique("u_tag", "Q", "tag"));
        assert!(
            refused.is_err(),
            "non-vacuity: the duplicate must really refuse the constraint"
        );
        assert!(
            eng.transactions().is_empty(),
            "a REFUSED constraint DDL must retire its entry too — the RAII guard runs on every path"
        );

        // A `SHOW CONSTRAINTS` decides nothing and reads no user data, so it registers no entry at all.
        let _ = eng
            .constraint_ddl(ConstraintCommand::Show {
                filter: ConstraintTypeFilter::All,
                tail: None,
            })
            .expect("show constraints");
        assert!(
            eng.transactions().is_empty(),
            "a SHOW must not appear as a live transaction"
        );
    }

    /// The **relationship** twin of [`constraint_declared_while_an_older_reader_is_open_903`], over
    /// `REQUIRE r.tag IS UNIQUE`. It is not a duplicate of the node case: the DDL's relationship
    /// footprint is a different marker family (`RelType` + `RelEquality`), announced against a write
    /// path whose own footprint is announced by different code with a schema-reachability gate on it
    /// (`IndexSet::rel_equality_marker_possible`). A node-only guard would leave that half unpinned.
    #[test]
    fn relationship_constraint_declared_while_an_older_reader_is_open_903() {
        let mut eng = engine();

        // 1. R opens and stays idle.
        let r = eng.begin(AccessMode::Write).expect("begin r");

        // 2. W commits the first ':LINK {tag: "a"}' AFTER R's snapshot.
        let w = eng.begin(AccessMode::Write).expect("begin w");
        write(&mut eng, w, "CREATE (:A)-[:LINK {tag: 'a'}]->(:B)", vec![]);
        eng.commit(w).expect("w commits");

        // 3. Exactly one live ':LINK' carries 'a', so the constraint is accepted.
        eng.constraint_ddl(ConstraintCommand::Create(CreateConstraint {
            name: "u_tag".to_owned(),
            entity: ConstraintEntity::Relationship {
                rel_type: "LINK".to_owned(),
            },
            properties: vec!["tag".to_owned()],
            kind: ConstraintCreateKind::Unique,
            if_not_exists: false,
            or_replace: false,
        }))
        .expect("the relationship constraint holds over the committed graph");

        // 4. R writes a duplicate that its own snapshot hides from it.
        let admitted = match eng.run(
            r,
            "CREATE (:A)-[:LINK {tag: 'a'}]->(:B)",
            vec![],
            false,
            None,
        ) {
            Err(_) => false,
            Ok(mut reply) => loop {
                match reply.rows.next() {
                    Ok(Some(_)) => {}
                    Ok(None) => break true,
                    Err(_) => break false,
                }
            },
        };
        assert!(
            admitted,
            "non-vacuity: R's write path must ADMIT the duplicate relationship, because W's edge is \
             invisible to R's snapshot"
        );

        // 5. R tries to commit.
        let committed = eng.commit(r).is_ok();

        let t = eng.begin(AccessMode::Read).expect("begin counter");
        let mut reply = eng
            .run(
                t,
                "MATCH ()-[l:LINK {tag: 'a'}]->() RETURN count(l) AS c",
                vec![],
                false,
                None,
            )
            .expect("count runs");
        let mut live = 0;
        while let Ok(Some(row)) = reply.rows.next() {
            if let Some(MaterializedValue::Value(Value::Integer(n))) = row.first() {
                live = *n;
            }
        }
        let _ = eng.commit(t);

        assert_eq!(
            live, 1,
            "a live relationship IS UNIQUE must not admit a second committed 'a' (rmp #903); R \
             committed = {committed}, found {live}"
        );
    }

    /// The isolating control for [`constraint_declared_while_an_older_reader_is_open_903`]: with the
    /// constraint **already in force** before `R` opens, the identical interleaving must abort `R`
    /// through the ordinary write-path machinery. It pins the claim that the mechanism under test is
    /// the DDL's *own* predicate footprint and not some other change in the same interleaving — if this
    /// control ever fails, the #903 test above is measuring the wrong thing. It carries the same
    /// no-mid-scenario-probe discipline, for the same reason.
    #[test]
    fn constraint_already_in_force_aborts_the_older_writer_control() {
        let mut eng = engine();

        eng.constraint_ddl(create_unique("u_email", "P", "email"))
            .expect("declare the constraint over an empty graph");

        let r = eng.begin(AccessMode::Write).expect("begin r");

        let w = eng.begin(AccessMode::Write).expect("begin w");
        create_person(&mut eng, w, "a");
        eng.commit(w).expect("w commits");

        let admitted = try_create_person(&mut eng, r, "a");
        assert!(
            admitted,
            "control non-vacuity: R's write path must ADMIT the duplicate (W's row is invisible to R), \
             so that the abort under test is the SSI one and not the write-path check"
        );
        let committed = eng.commit(r).is_ok();

        let live = count_persons(&mut eng, "a");
        assert_eq!(
            live, 1,
            "control: an already-live IS UNIQUE must not admit a second committed 'a'; R committed = \
             {committed}, found {live}"
        );
    }

    /// The `SET` variant of the relationship reproduction, and the one that proves the DDL's
    /// **per-value** markers are load-bearing rather than a refinement of the coarse one.
    ///
    /// A relationship already carries `tag = 'z'`; `W` commits a second one carrying `'a'` after `R`'s
    /// snapshot; the constraint is declared over the two distinct values and accepted; `R` then
    /// *changes* its visible `'z'` to `'a'` — a duplicate that `R`'s own snapshot hides from it.
    ///
    /// # Why only the value marker closes this one
    ///
    /// `RecordStoreGraph::note_rel_property_predicate_write` — the `SET r.p = v` form — announces
    /// **only** `RelEquality{T, p, v}` for the key it changed, never the `[AnyRel, RelType]` pair that
    /// a `create_rel` announces. A DDL holding only `RelType(LINK)` therefore forms no edge with this
    /// writer at all. Measured, by disabling
    /// `TxnCoordinator::note_constraint_value_read` and re-running this scenario against the fixed
    /// coordinator: with the value markers the write is admitted and `R` is **aborted** (one live
    /// `'a'`); with only the coarse marker `R` **commits**, leaving two committed `'a'`s under a live
    /// relationship `IS UNIQUE`. The two `CREATE`-shaped reproductions above are closed by the coarse
    /// marker alone, so without this scenario the per-value half of the footprint would be untested.
    #[test]
    fn relationship_constraint_vs_a_concurrent_property_update_903() {
        let mut eng = engine();

        // A committed :LINK carrying 'z' — the relationship R will later re-point at 'a'.
        let s0 = eng.begin(AccessMode::Write).expect("begin s0");
        write(&mut eng, s0, "CREATE (:A)-[:LINK {tag: 'z'}]->(:B)", vec![]);
        eng.commit(s0).expect("s0 commits");

        // 1. R opens and stays idle.
        let r = eng.begin(AccessMode::Write).expect("begin r");

        // 2. W commits a second :LINK carrying 'a', after R's snapshot.
        let w = eng.begin(AccessMode::Write).expect("begin w");
        write(&mut eng, w, "CREATE (:A)-[:LINK {tag: 'a'}]->(:B)", vec![]);
        eng.commit(w).expect("w commits");

        // 3. The two live values are distinct, so the constraint is accepted.
        eng.constraint_ddl(ConstraintCommand::Create(CreateConstraint {
            name: "u_tag".to_owned(),
            entity: ConstraintEntity::Relationship {
                rel_type: "LINK".to_owned(),
            },
            properties: vec!["tag".to_owned()],
            kind: ConstraintCreateKind::Unique,
            if_not_exists: false,
            or_replace: false,
        }))
        .expect("the relationship constraint holds over the committed graph");

        // 4. R updates its visible 'z' to 'a'. W's 'a' is invisible to R, so the duplicate check passes.
        let admitted = match eng.run(
            r,
            "MATCH ()-[l:LINK {tag: 'z'}]->() SET l.tag = 'a'",
            vec![],
            false,
            None,
        ) {
            Err(_) => false,
            Ok(mut reply) => loop {
                match reply.rows.next() {
                    Ok(Some(_)) => {}
                    Ok(None) => break true,
                    Err(_) => break false,
                }
            },
        };
        assert!(
            admitted,
            "non-vacuity: R's SET must be ADMITTED, because W's 'a' is invisible to R's snapshot"
        );

        // 5. R tries to commit.
        let committed = eng.commit(r).is_ok();

        let t = eng.begin(AccessMode::Read).expect("begin counter");
        let mut reply = eng
            .run(
                t,
                "MATCH ()-[l:LINK {tag: 'a'}]->() RETURN count(l) AS c",
                vec![],
                false,
                None,
            )
            .expect("count runs");
        let mut live = 0;
        while let Ok(Some(row)) = reply.rows.next() {
            if let Some(MaterializedValue::Value(Value::Integer(n))) = row.first() {
                live = *n;
            }
        }
        let _ = eng.commit(t);

        assert_eq!(
            live, 1,
            "a live relationship IS UNIQUE must not admit a second committed 'a' through a concurrent \
             SET (rmp #903); R committed = {committed}, found {live}"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // A transaction must never be left NEITHER committed NOR rolled back (rmp #955)
    // ---------------------------------------------------------------------------------------------
    //
    // The store-level windows of this defect are pinned deterministically in
    // `crate::rollback_undo_fault`, which drives a bare `RecordStore` so a fault can be placed between
    // two exactly-known steps. What only the engine can show is the CONSEQUENCE of a failure that
    // reaches a real command dispatch: every commit call site surrenders the transaction's ticket
    // BEFORE it commits, so a commit that fails at the store level (rather than as an SSI abort) used
    // to leave a transaction no client `ROLLBACK`, no inactivity sweep and no shutdown drain could
    // ever reach — permanently holding the rmp #902 constraint-DDL guard closed and permanently
    // pinning the GC watermark.

    /// A durable auto-commit write whose commit fails at the STORE level must be rolled back by the
    /// engine, not orphaned.
    ///
    /// The one-shot device I/O error is armed immediately before the commit, and the transaction has
    /// interned enough property keys that its catalog no longer fits one metadata page — so the
    /// commit's `checkpoint_meta` must grow the metadata chain, which is the first home write it
    /// performs and therefore where the fault lands. What is asserted is the state the engine is left
    /// in: no open transaction, the rmp #902 guard re-opened (a `CREATE CONSTRAINT` is accepted), and
    /// the failed write absent.
    ///
    /// Fails against the pre-#955 code: the transaction stayed open forever and the DDL was refused
    /// for the rest of the process's life, naming a transaction that no longer had a ticket.
    #[test]
    fn a_store_level_commit_failure_orphans_no_transaction_955() {
        let mut eng = engine();

        let seed = eng.begin(AccessMode::Write).expect("begin seed");
        create_person(&mut eng, seed, "a");
        eng.commit(seed).expect("seed commits");

        // Precondition: with nothing open the DDL is accepted, so a refusal later is attributable.
        // Over a DIFFERENT property, so this probe does not itself become the equivalent-schema
        // conflict that would mask the guard's answer later.
        eng.constraint_ddl(create_unique("u_probe", "P", "name"))
            .expect("the DDL must be accepted over a quiet, committed graph");

        let w = eng.begin(AccessMode::Write).expect("begin w");
        create_person(&mut eng, w, "b");
        // Intern enough distinct property keys that the catalog no longer fits one metadata page, so
        // the commit's `checkpoint_meta` must GROW the metadata chain — a fresh page allocation and a
        // home write. That is what puts a guaranteed *device write* inside `commit_prepare`, where the
        // armed one-shot I/O error can land; without it the whole commit stays in the buffer pool and
        // the fault never fires (which the `fault_surfaced` assertion below is what detects).
        write(&mut eng, w, &wide_property_create(), vec![]);
        assert!(
            eng.constraint_ddl(create_unique("u_email", "P", "email"))
                .is_err(),
            "precondition (rmp #902): an OPEN writer refuses the DDL — without this the assertion \
             after the fault would prove nothing"
        );

        eng.with_device_mut(MemBlockDevice::arm_io_error)
            .expect("the engine is live, so the device seam must be reachable");
        let commit = eng.commit(w);
        let fault_surfaced = commit
            .as_ref()
            .err()
            .is_some_and(|e| e.to_string().contains("injected I/O error"));
        assert!(
            fault_surfaced,
            "non-vacuity: the armed I/O error must actually fail the commit; got {commit:?}"
        );

        assert_eq!(
            eng.status_open_txns().expect("status"),
            0,
            "a commit that failed at the store level must leave NO open transaction: its ticket is \
             already gone, so nothing else would ever roll it back (rmp #955)"
        );
        eng.constraint_ddl(create_unique("u_email", "P", "email"))
            .expect(
                "the rmp #902 guard must re-open once the failed commit's transaction is rolled \
                 back — before rmp #955 it stayed shut for the life of the process",
            );
        assert_eq!(
            count_persons(&mut eng, "b"),
            0,
            "the failed commit's row must be gone: the transaction was rolled back, not left \
             half-applied"
        );
        assert_eq!(
            count_persons(&mut eng, "a"),
            1,
            "the previously committed row must be untouched — the rollback undid the failed \
             transaction and nothing else"
        );
        assert!(
            !eng.is_degraded(),
            "a commit failure whose rollback SUCCEEDED is an ordinary aborted transaction: the \
             database must stay in service, or every transient I/O error would take it down"
        );
    }

    /// An explicit `ROLLBACK` whose durable undo panics must flag the engine degraded and keep the
    /// engine alive — never unwind the engine thread, and never quietly carry on over a store whose
    /// undo did not complete.
    ///
    /// Fails against the pre-#955 code twice over: the panic escaped `rollback_tx` (which had no
    /// recovery boundary at all, so the engine thread died — the `engine_gone` failure rmp #386
    /// closed for statements but not for this command), and the store had already dropped the
    /// transaction's active-set entry before the WAL undo it panicked in.
    #[test]
    fn a_rollback_whose_undo_panics_degrades_the_engine_955() {
        let fail_sync = Arc::new(AtomicBool::new(false));
        let device = MemBlockDevice::new(0);
        let sink = RollbackFaultSink {
            inner: MemLogSink::new(),
            fail_sync: Arc::clone(&fail_sync),
        };
        let wal = WalManager::create(sink).expect("create wal");
        let store = RecordStore::create(device, wal, 64, 1).expect("create store");
        let mut eng: LocalEngine<MemBlockDevice, RollbackFaultSink> =
            LocalEngine::new(TxnCoordinator::new(store), Arc::new(SharedClock::new(0)));

        let seed = eng.begin(AccessMode::Write).expect("begin seed");
        let mut reply = eng
            .run(seed, "CREATE (:P {email: 'a'})", vec![], false, None)
            .expect("seed write runs");
        while let Ok(Some(_)) = reply.rows.next() {}
        eng.commit(seed).expect("seed commits");
        assert!(
            !eng.is_degraded(),
            "precondition: a healthy engine, so the degradation below is caused by the fault"
        );

        let w = eng.begin(AccessMode::Write).expect("begin w");
        let mut reply = eng
            .run(w, "CREATE (:P {email: 'b'})", vec![], false, None)
            .expect("write runs");
        while let Ok(Some(_)) = reply.rows.next() {}

        fail_sync.store(true, Ordering::SeqCst);
        let rolled_back = eng.rollback(w);
        fail_sync.store(false, Ordering::SeqCst);

        assert!(
            rolled_back.is_err(),
            "a rollback whose WAL fdatasync failed must report failure, not success"
        );
        assert!(
            eng.is_degraded(),
            "the engine must be flagged DEGRADED: the undo did not complete, so the transaction's \
             writes are still on the page with nothing left to remove them (rmp #955). Reaching this \
             assertion at all is the other half of the fix — before it, the fsyncgate panic unwound \
             the engine thread instead of being caught"
        );
        assert!(
            eng.begin(AccessMode::Write).is_err(),
            "a degraded engine must refuse further work pending a controlled restart (rmp #409/#414)"
        );
    }

    /// The WAL sink used by [`a_rollback_whose_undo_panics_degrades_the_engine_955`]: its `fdatasync`
    /// can be armed to fail, which `WalManager::harden` turns into the controlled fsyncgate panic.
    /// Structurally identical to `crate::rollback_undo_fault`'s, and deliberately declared again here
    /// rather than shared: that module's is private to it, and a fault sink is the one thing a fault
    /// scenario should be able to read in full without following a re-export.
    struct RollbackFaultSink {
        inner: MemLogSink,
        fail_sync: Arc<AtomicBool>,
    }

    impl graphus_wal::LogSink for RollbackFaultSink {
        fn append(&mut self, bytes: &[u8]) {
            self.inner.append(bytes);
        }
        fn sync(&mut self) -> graphus_core::error::Result<()> {
            if self.fail_sync.load(Ordering::SeqCst) {
                return Err(graphus_core::error::GraphusError::Storage(
                    "injected WAL fdatasync failure during undo (rmp #955)".to_owned(),
                ));
            }
            self.inner.sync()
        }
        fn begin_harden(&mut self) -> graphus_core::error::Result<graphus_wal::FsyncJob> {
            self.inner.begin_harden()
        }
        fn complete_harden(&mut self, target_len: u64) {
            self.inner.complete_harden(target_len);
        }
        fn durable_len(&self) -> u64 {
            self.inner.durable_len()
        }
        fn buffered_len(&self) -> u64 {
            self.inner.buffered_len()
        }
        fn read_durable(&self, from: u64, into: &mut Vec<u8>) -> graphus_core::error::Result<()> {
            self.inner.read_durable(from, into)
        }
        fn read_bounded(
            &self,
            from: u64,
            to: u64,
            into: &mut Vec<u8>,
        ) -> graphus_core::error::Result<()> {
            self.inner.read_bounded(from, to, into)
        }
        fn reclaim(&mut self, from: u64, up_to: u64) -> graphus_core::error::Result<()> {
            self.inner.reclaim(from, up_to)
        }
        fn reclaimed_floor(&self) -> u64 {
            self.inner.reclaimed_floor()
        }
    }
}
