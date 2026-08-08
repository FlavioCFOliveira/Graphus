//! `rmp` #972 — **statement-level isolation**: the `command_id` on the undo delta, and the
//! [`View`] that decides whether a read sees its own current statement's writes.
//!
//! This is the storage half of the guarantee. It asserts the mechanism directly, at the layer that
//! owns it, so that a defect here is caught without going through the planner — which matters
//! because the planner has a *second*, independent Halloween defence (the openCypher `Eager`
//! barrier), and two mechanisms that mask each other is exactly how `rmp` #967's
//! retired-mechanism defect happened.
//!
//! Every scenario is **deterministic**: a single-threaded store over the DST substrate
//! (`MemBlockDevice` + `MemLogSink`), driven by an explicit statement interleaving. Concurrency is
//! expressed as *ordering*, never as threads, so a failure reproduces byte-for-byte.
//!
//! # The rule under test
//!
//! A delta written by command `c` of the reader's **own** transaction is undone when
//! `c > current` (`View::New`) or `c >= current` (`View::Old`) — Memgraph's `ApplyDeltasForRead`
//! (`/data/refsrc/memgraph/src/storage/v2/mvcc.hpp:72-94`), where the entire difference between the
//! two views is `<=` versus `<`. PostgreSQL says the same with `cmin < curcid`
//! (`heapam_visibility.c:965`).
//!
//! # The four axes, because the chain versions four different things
//!
//! A property, a label, an adjacency entry and the entity's own existence all live on the **same**
//! undo chain but reach the reader through **different** functions. A command-granularity bug can
//! therefore hide in one axis while the others are correct, and every axis is asserted here:
//!
//! 1. properties — `decision_scan_node_properties`;
//! 2. labels — `label_bitmap_at`;
//! 3. existence (create and delete) — `entity_visible_at`;
//! 4. and the cross-transaction rules, which must be **unchanged**: no view of ours may leak one
//!    transaction's uncommitted work into another.
//!
//! Run with `cargo test -p graphus-storage --test command_isolation_972`.

use graphus_core::{CommandId, TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{RecordStore, StoreKind};
use graphus_txn::{CommitRegistry, Snapshot, View};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// The property key every scenario writes.
const KEY: u32 = 7;
/// The label bit every scenario flips.
const LABEL: u32 = 3;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 256, 1).expect("create store")
}

/// The snapshot `txn` reads with at its **current** statement, on `view`.
///
/// Deliberately built from `store.command_of(txn)` rather than from a remembered number: the store
/// is the single source of truth for the counter, and a test that carried its own copy would keep
/// passing if `begin_command` stopped advancing it.
fn snap(s: &Store, txn: TxnId, view: View) -> Snapshot {
    Snapshot::at_command(txn, s.snapshot_ts(), s.command_of(txn), view)
}

/// The value `snapshot` reads for `node`'s [`KEY`], or `None` if the key is absent to it.
fn value_at(s: &Store, node: u64, snapshot: Snapshot) -> Option<Value> {
    let decided = s
        .decision_scan_node_properties(node, snapshot)
        .expect("decision-polarity property read");
    let seen = decided.visible_version(KEY)?;
    Some(
        s.decode_property_value(seen.type_tag, seen.value_inline)
            .expect("decode the visible value"),
    )
}

/// Whether `snapshot` sees [`LABEL`] on `node`.
fn has_label_at(s: &Store, node: u64, snapshot: Snapshot) -> bool {
    let rec = s.node(node).expect("read node record");
    let bitmap = s
        .label_bitmap_at(node, rec.labels, rec.mvcc.undo_ptr, snapshot)
        .expect("label bitmap at snapshot");
    bitmap & (1u64 << LABEL) != 0
}

/// Whether `snapshot` sees `node` at all.
fn exists_at(s: &Store, node: u64, snapshot: Snapshot, registry: &CommitRegistry) -> bool {
    let rec = s.node(node).expect("read node record");
    s.entity_visible_at(StoreKind::Node, node, rec.mvcc, snapshot, registry)
        .expect("existence at snapshot")
}

/// Commits one node carrying `KEY = value` and [`LABEL`], and returns its physical id.
fn seed_committed_node(s: &mut Store, txn: u64, value: i64) -> u64 {
    let t = TxnId(txn);
    s.begin(t);
    let (n, _) = s.create_node(t).expect("create node");
    s.set_node_property_value(t, n, KEY, &Value::Integer(value))
        .expect("seed property");
    s.set_node_labels(t, n, &[LABEL]).expect("seed label");
    s.commit(t).expect("commit seed");
    n
}

// =================================================================================================
// 1. The counter itself
// =================================================================================================

/// The counter starts at "no statement", advances one per statement, and is per transaction.
///
/// `NONE` is not a placeholder: it is what a delta written outside any statement carries (recovery,
/// a maintenance pass, the catalog), and it must sort below every real command so that no `OLD`
/// view ever undoes such a write.
#[test]
fn the_command_counter_is_per_transaction_and_advances_once_per_statement() {
    let mut s = fresh();
    let (a, b) = (TxnId(1), TxnId(2));
    s.begin(a);
    s.begin(b);

    assert_eq!(
        s.command_of(a),
        CommandId::NONE,
        "a transaction that has opened no statement is at NONE, not at FIRST"
    );
    assert_eq!(s.begin_command(a), CommandId::FIRST);
    assert_eq!(s.begin_command(a), CommandId(2));
    assert_eq!(
        s.command_of(b),
        CommandId::NONE,
        "another transaction's statements must not move this one's counter"
    );
    assert_eq!(s.begin_command(b), CommandId::FIRST);
    assert_eq!(s.command_of(a), CommandId(2));

    // An unknown transaction is NONE rather than a panic: the maintenance paths read this.
    assert_eq!(s.command_of(TxnId(99)), CommandId::NONE);
}

/// The delta actually carries the command that wrote it. Without this the whole rule is inert —
/// every delta would read back as `NONE` and `OLD` would be indistinguishable from `NEW`.
#[test]
fn a_delta_carries_the_command_that_wrote_it() {
    let mut s = fresh();
    let n = seed_committed_node(&mut s, 1, 10);

    let t = TxnId(2);
    s.begin(t);
    s.begin_command(t); // command 1
    s.begin_command(t); // command 2 — the one that writes
    s.set_node_property_value(t, n, KEY, &Value::Integer(20))
        .expect("overwrite");

    let head = s
        .read_mvcc_for_test(StoreKind::Node, n)
        .expect("node header")
        .undo_ptr;
    let delta = s
        .read_delta_for_test(head)
        .expect("read the chain head")
        .expect("the head is a live delta");
    assert_eq!(
        delta.command_id, 2,
        "the delta must be stamped with the statement that produced it, not with 0"
    );
}

// =================================================================================================
// 2. Properties — the Halloween axis
// =================================================================================================

/// **The Halloween guarantee, on the property axis.** A statement that writes a property must not
/// observe its own write; a *later* statement of the same transaction must.
#[test]
fn a_statement_does_not_observe_its_own_property_write_but_the_next_one_does() {
    let mut s = fresh();
    let n = seed_committed_node(&mut s, 1, 10);

    let t = TxnId(2);
    s.begin(t);
    s.begin_command(t); // statement 1
    s.set_node_property_value(t, n, KEY, &Value::Integer(20))
        .expect("statement 1 writes");

    assert_eq!(
        value_at(&s, n, snap(&s, t, View::New)),
        Some(Value::Integer(20)),
        "NEW is read-your-own-writes in full — the write path depends on it"
    );
    assert_eq!(
        value_at(&s, n, snap(&s, t, View::Old)),
        Some(Value::Integer(10)),
        "OLD is the state as the statement found it: its own write is undone"
    );

    s.begin_command(t); // statement 2
    assert_eq!(
        value_at(&s, n, snap(&s, t, View::Old)),
        Some(Value::Integer(20)),
        "an EARLIER statement's write is part of the state statement 2 started from"
    );

    s.set_node_property_value(t, n, KEY, &Value::Integer(30))
        .expect("statement 2 writes");
    assert_eq!(
        value_at(&s, n, snap(&s, t, View::Old)),
        Some(Value::Integer(20)),
        "statement 2's OLD view holds at 20 across its own write"
    );
    assert_eq!(
        value_at(&s, n, snap(&s, t, View::New)),
        Some(Value::Integer(30))
    );
    s.commit(t).expect("commit");
}

/// Repeated writes **within one statement** all belong to that statement, so `OLD` stays pinned to
/// the value the statement started from no matter how many times the statement overwrites.
///
/// This is the shape that a naive "undo one delta" implementation gets wrong: the chain holds three
/// of our own deltas at the same command, and every one of them must be undone.
#[test]
fn old_stays_pinned_across_many_writes_of_the_same_statement() {
    let mut s = fresh();
    let n = seed_committed_node(&mut s, 1, 10);

    let t = TxnId(2);
    s.begin(t);
    s.begin_command(t);
    for v in [20, 30, 40] {
        s.set_node_property_value(t, n, KEY, &Value::Integer(v))
            .expect("overwrite within one statement");
        assert_eq!(
            value_at(&s, n, snap(&s, t, View::Old)),
            Some(Value::Integer(10)),
            "every write of this statement is undone by its own OLD view"
        );
    }
    assert_eq!(
        value_at(&s, n, snap(&s, t, View::New)),
        Some(Value::Integer(40))
    );
    s.commit(t).expect("commit");
}

/// A property the statement **creates** must read as absent to its own `OLD` view — not as some
/// other value, and not as an error.
///
/// The distinction matters because the "was absent" payload is encoded as `type_tag == 0`
/// (`05 §12.2`), which is also the value a zeroed field takes: a decoder that lost the delta would
/// answer "absent" for the wrong reason. So the same read is asserted to be `Some` at `NEW`.
#[test]
fn a_property_first_set_by_this_statement_is_absent_to_its_own_old_view() {
    let mut s = fresh();
    let t1 = TxnId(1);
    s.begin(t1);
    let (n, _) = s.create_node(t1).expect("create node");
    s.commit(t1).expect("commit the bare node");

    let t = TxnId(2);
    s.begin(t);
    s.begin_command(t);
    s.set_node_property_value(t, n, KEY, &Value::Integer(1))
        .expect("first ever value for this key");

    assert_eq!(
        value_at(&s, n, snap(&s, t, View::Old)),
        None,
        "the key did not exist when the statement started"
    );
    assert_eq!(
        value_at(&s, n, snap(&s, t, View::New)),
        Some(Value::Integer(1)),
        "and it does exist to the statement that wrote it"
    );
    s.commit(t).expect("commit");
}

// =================================================================================================
// 3. Labels — the same rule on a different reader
// =================================================================================================

/// Labels reach the reader through `label_bitmap_at`, not through the property fold, so the rule
/// has to be asserted independently: a bug can be fixed in one walk and missed in the other.
#[test]
fn a_statement_does_not_observe_its_own_label_change_but_the_next_one_does() {
    let mut s = fresh();
    let n = seed_committed_node(&mut s, 1, 10);

    let t = TxnId(2);
    s.begin(t);
    s.begin_command(t); // statement 1 removes the label
    s.set_node_labels(t, n, &[]).expect("remove the label");

    assert!(
        !has_label_at(&s, n, snap(&s, t, View::New)),
        "NEW sees the removal it just performed"
    );
    assert!(
        has_label_at(&s, n, snap(&s, t, View::Old)),
        "OLD sees the label the statement started with — this is what stops a `REMOVE n:L` from \
         changing which rows its own `MATCH (n:L)` yields"
    );

    s.begin_command(t); // statement 2
    assert!(
        !has_label_at(&s, n, snap(&s, t, View::Old)),
        "statement 1's removal is part of what statement 2 started from"
    );
    s.commit(t).expect("commit");
}

/// **The creator gate, narrowed.** A node created by an *earlier* statement of the same transaction
/// and labelled by *this* one must still have its label versioned.
///
/// `link_label_deltas` skips linking a delta for a node its own transaction created, because no
/// reader can ask what such a node's labels were before. Statement isolation makes that justification
/// hold only **within the creating statement**: statement 2's `OLD` view *does* see a node statement
/// 1 created, so if the gate still fired the read would fall through to the live word and report a
/// label statement 2 had just added.
///
/// The gate's fast path is asserted alongside it, so narrowing the condition cannot be mistaken for
/// removing it: a node created **and** labelled by one statement still links no label delta.
#[test]
fn a_node_created_by_an_earlier_statement_has_its_labels_versioned() {
    let mut s = fresh();

    let t = TxnId(1);
    s.begin(t);
    s.begin_command(t); // statement 1 creates the node, unlabelled
    let (n, _) = s.create_node(t).expect("create node");
    let deltas_after_creation = s.live_undo_delta_count().expect("census");

    s.begin_command(t); // statement 2 labels it
    s.set_node_labels(t, n, &[LABEL]).expect("label it");
    assert!(
        s.live_undo_delta_count().expect("census") > deltas_after_creation,
        "the label change of a LATER statement must be versioned; the creator gate may not fire"
    );
    assert!(
        has_label_at(&s, n, snap(&s, t, View::New)),
        "the statement that added the label sees it"
    );
    assert!(
        !has_label_at(&s, n, snap(&s, t, View::Old)),
        "and its own OLD view does not — this is the read the gate used to answer wrongly"
    );
    s.commit(t).expect("commit");

    // The fast path the gate exists for is intact: one statement that creates AND labels links no
    // label delta, because no view of any statement can ask what came before.
    let mut s2 = fresh();
    let t2 = TxnId(1);
    s2.begin(t2);
    s2.begin_command(t2);
    let (m, _) = s2.create_node(t2).expect("create node");
    let before = s2.live_undo_delta_count().expect("census");
    s2.set_node_labels(t2, m, &[LABEL]).expect("label it");
    assert_eq!(
        s2.live_undo_delta_count().expect("census"),
        before,
        "a node created and labelled by the SAME statement still links no label delta — narrowing \
         the gate must not have removed it"
    );
    s2.commit(t2).expect("commit");
}

// =================================================================================================
// 4. Existence — the axis the record header alone cannot answer
// =================================================================================================

/// **The Halloween guarantee, on the existence axis** — the one that makes `MATCH () CREATE ()`
/// terminate without any planner barrier.
///
/// The record header records *which transaction* created the node and never *which statement of
/// it*, so `graphus_txn::is_visible` cannot answer this: it says "own in-flight write, visible" and
/// stops. The answer lives on the undo chain, in the `DeleteObject` delta the creation wrote.
#[test]
fn a_node_created_by_this_statement_does_not_exist_to_its_own_old_view() {
    let mut s = fresh();
    let registry = s.commit_registry_snapshot();

    let t = TxnId(1);
    s.begin(t);
    s.begin_command(t); // statement 1 creates
    let (n, _) = s.create_node(t).expect("create node");

    assert!(
        exists_at(&s, n, snap(&s, t, View::New), &registry),
        "NEW sees the node it just created — CREATE, SET and DELETE all depend on this"
    );
    assert!(
        !exists_at(&s, n, snap(&s, t, View::Old), &registry),
        "OLD does not: the node was not there when the statement started, which is exactly why a \
         scan cannot re-scan what it is creating"
    );

    s.begin_command(t); // statement 2
    assert!(
        exists_at(&s, n, snap(&s, t, View::Old), &registry),
        "an earlier statement's creation is part of what statement 2 started from"
    );
    s.commit(t).expect("commit");
}

/// The mirror case: a node this statement **deleted** is still there to its own `OLD` view, which
/// is what lets an undirected expansion yield both of its rows before either delete lands.
#[test]
fn a_node_deleted_by_this_statement_still_exists_to_its_own_old_view() {
    let mut s = fresh();
    let n = seed_committed_node(&mut s, 1, 10);
    let registry = s.commit_registry_snapshot();

    let t = TxnId(2);
    s.begin(t);
    s.begin_command(t); // statement 1 deletes
    s.delete_node(t, n).expect("delete node");

    assert!(
        !exists_at(&s, n, snap(&s, t, View::New), &registry),
        "NEW sees its own deletion"
    );
    assert!(
        exists_at(&s, n, snap(&s, t, View::Old), &registry),
        "OLD still sees the node the statement started with"
    );

    s.begin_command(t); // statement 2
    assert!(
        !exists_at(&s, n, snap(&s, t, View::Old), &registry),
        "statement 1's deletion is settled as far as statement 2 is concerned"
    );
    s.commit(t).expect("commit");
}

/// A node created **and** deleted inside one statement is absent under both views, and neither read
/// errors: the chain holds a `RecreateObject` over a `DeleteObject` and the two must compose.
#[test]
fn a_node_created_and_deleted_in_one_statement_is_absent_under_both_views() {
    let mut s = fresh();
    let registry = s.commit_registry_snapshot();

    let t = TxnId(1);
    s.begin(t);
    s.begin_command(t);
    let (n, _) = s.create_node(t).expect("create node");
    s.delete_node(t, n).expect("delete it again");

    assert!(!exists_at(&s, n, snap(&s, t, View::New), &registry));
    assert!(
        !exists_at(&s, n, snap(&s, t, View::Old), &registry),
        "undoing the deletion restores a node that undoing the creation then removes again"
    );
    s.commit(t).expect("commit");
}

// =================================================================================================
// 5. The cross-transaction rules must be UNCHANGED
// =================================================================================================

/// Neither view may leak one transaction's uncommitted work into another. `OLD` weakens what a
/// transaction sees of **itself**; it must not strengthen what it sees of anyone else, and `NEW`
/// must not have become "see everything".
///
/// This is the negative control for the whole feature: the command comparison is reached only after
/// the writer is established to be the reader itself, so a mis-ordered match arm would show up here
/// and nowhere else.
#[test]
fn neither_view_changes_what_another_transaction_sees() {
    let mut s = fresh();
    let n = seed_committed_node(&mut s, 1, 10);
    let registry = s.commit_registry_snapshot();

    let writer = TxnId(2);
    s.begin(writer);
    s.begin_command(writer);
    s.set_node_property_value(writer, n, KEY, &Value::Integer(20))
        .expect("uncommitted overwrite");
    s.set_node_labels(writer, n, &[])
        .expect("uncommitted removal");

    let reader = TxnId(3);
    s.begin(reader);
    s.begin_command(reader);
    for view in [View::New, View::Old] {
        let r = snap(&s, reader, view);
        assert_eq!(
            value_at(&s, n, r),
            Some(Value::Integer(10)),
            "{view:?}: another transaction's uncommitted property write is invisible"
        );
        assert!(
            has_label_at(&s, n, r),
            "{view:?}: another transaction's uncommitted label removal is invisible"
        );
        assert!(
            exists_at(&s, n, r, &registry),
            "{view:?}: the committed node is there for the reader"
        );
    }

    // And the reader's own high command number must not make the writer's deltas look like its own.
    for _ in 0..5 {
        s.begin_command(reader);
    }
    let r = snap(&s, reader, View::Old);
    assert_eq!(
        value_at(&s, n, r),
        Some(Value::Integer(10)),
        "command ids are compared only within one transaction; they are not a global clock"
    );
    s.commit(writer).expect("commit the writer");
}

/// A write made **outside any statement** — recovery, a maintenance pass, the catalog — belongs to
/// the transaction's baseline, and no later statement's `OLD` view may undo it.
///
/// This scenario is why [`graphus_txn::command_hides_own_write`] carves `CommandId::NONE` out
/// explicitly: with the plain `writer >= current` rule, a maintenance transaction that then ran a
/// statement would find its own earlier work erased from its `OLD` reads.
#[test]
fn a_statementless_write_survives_a_later_statements_old_view() {
    let mut s = fresh();
    let n = seed_committed_node(&mut s, 1, 10);

    let t = TxnId(2);
    s.begin(t); // no begin_command yet: this is the maintenance shape
    s.set_node_property_value(t, n, KEY, &Value::Integer(20))
        .expect("write with no statement open");
    assert_eq!(s.command_of(t), CommandId::NONE);
    assert_eq!(
        value_at(&s, n, snap(&s, t, View::New)),
        Some(Value::Integer(20)),
        "the baseline write is of course visible to its own author"
    );

    s.begin_command(t); // and now a statement opens on top of it
    assert_eq!(
        value_at(&s, n, snap(&s, t, View::Old)),
        Some(Value::Integer(20)),
        "the baseline write precedes every statement, so the statement's OLD view keeps it"
    );
    s.set_node_property_value(t, n, KEY, &Value::Integer(30))
        .expect("the statement's own write");
    assert_eq!(
        value_at(&s, n, snap(&s, t, View::Old)),
        Some(Value::Integer(20)),
        "and the statement's own write is still undone, so the carve-out has not swallowed the rule"
    );
    s.commit(t).expect("commit");
}

// =================================================================================================
// 6. What the mechanism must NOT cost
// =================================================================================================

/// The `NEW` view — the default, and what every read took before `rmp` #972 — must reach the same
/// answer as the pre-#972 engine did, on every axis, for a transaction reading its own writes.
///
/// Stated as a test rather than as a comment because "the default is unchanged" is the claim the
/// whole no-regression argument rests on.
#[test]
fn the_default_view_is_exactly_read_your_own_writes() {
    let mut s = fresh();
    let registry = s.commit_registry_snapshot();
    let n = seed_committed_node(&mut s, 1, 10);

    let t = TxnId(2);
    s.begin(t);
    for (i, v) in [20, 30, 40].into_iter().enumerate() {
        s.begin_command(t);
        s.set_node_property_value(t, n, KEY, &Value::Integer(v))
            .expect("write");
        assert_eq!(
            value_at(&s, n, snap(&s, t, View::New)),
            Some(Value::Integer(v)),
            "statement {} reads back exactly what it wrote",
            i + 1
        );
    }
    s.begin_command(t);
    let (fresh_node, _) = s.create_node(t).expect("create");
    assert!(
        exists_at(&s, fresh_node, snap(&s, t, View::New), &registry),
        "and a freshly created node is there for its creator"
    );
    s.commit(t).expect("commit");
}
