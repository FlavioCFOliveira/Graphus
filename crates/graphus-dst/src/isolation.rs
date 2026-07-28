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

    use graphus_core::Value;
    use graphus_cypher::MaterializedValue;
    use graphus_elle::{Op, Transaction, check};
    use graphus_io::MemBlockDevice;
    use graphus_server::engine::command::AccessMode;
    use graphus_server::engine::{
        ConstraintCommand, ConstraintCreateKind, ConstraintEntity, ConstraintTypeFilter,
        CreateConstraint, LocalEngine, TxTicket,
    };
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
}
