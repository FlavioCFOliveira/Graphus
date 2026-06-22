//! `loom` model-check of the **`rmp` #341** concurrency-ready SSI read-marker path: per-reader
//! deferred [`SsiReadBuffer`] + single-writer [`SsiTracker::merge_read_buffer`].
//!
//! ## What this proves
//!
//! Under `rmp` #341 a read-only transaction does **not** touch the shared [`SsiTracker`] while it
//! runs. It accumulates its SIREAD markers into a thread-local [`SsiReadBuffer`] (a plain owned
//! `Vec` pair — no shared lock, no `Rc`/`Arc`) and **hands the buffer back** to the single
//! writer/coordinator thread, which replays it through `merge_read_buffer`. The tracker is mutated on
//! exactly one thread, so it is **never shared across threads**; the only cross-thread artefact is
//! the buffer handoff (a `Send` move over a channel). That asymmetry is the whole point — these
//! models therefore keep the `SsiTracker` a **plain local on the coordinator thread** (no `Mutex`,
//! exactly as production keeps it `Rc<RefCell>` on one thread) and let `loom` explore only the
//! handoff.
//!
//! `loom` exhaustively explores every legal interleaving of:
//! * **L1** — two reader threads each buffer a SIREAD marker (the two halves of a write-skew) and
//!   hand off; the coordinator drains both buffers in whatever order the channel yields them, applies
//!   the two writes that close the pivot, then detects. The dangerous structure MUST be present at
//!   detection on every interleaving, and the abort victim MUST be the deterministic lowest-id pivot
//!   regardless of which buffer arrived first (the commutativity `merge_read_buffer`'s sort
//!   guarantees).
//! * **L2** — two reader threads on **disjoint** keys: no spurious edge, no pivot, no panic, on any
//!   interleaving (independent reads never manufacture a conflict).
//! * **L3** — the buffer handoff over a loom `mpsc` channel: every marker a reader buffered is fully
//!   visible to the coordinator after delivery. Falsifiable: the handed-off read is one of the two
//!   edges of a write-skew pivot, so a lost/half-seen marker would leave the reader a non-pivot and
//!   flip `detect_pivot_abort` from `Some(reader)` to `None`. This is the Release-on-send /
//!   Acquire-on-recv contract Slice 3 (`rmp` #336) will honour when it retires a reader thread.
//!
//! The SSI core is unchanged: `merge_read_buffer` replays through the existing `record_read` /
//! `record_predicate_read`, and `detect_pivot_abort` is byte-identical. This model only asserts that
//! moving the *recording* off-thread (buffer + handoff) cannot change the conflict graph or victim.
//!
//! Run with:
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo test -p graphus-txn --test loom_ssi --release
//! ```
//!
//! `--release` is recommended because loom explores an exponential interleaving space; the models are
//! kept deliberately tiny (2 reader threads, ≤2 keys) so they terminate quickly.

#![cfg(loom)]

use graphus_core::{Timestamp, TxnId};
use graphus_txn::{SsiReadBuffer, SsiTracker};

use loom::sync::mpsc;

fn ts(n: u64) -> Timestamp {
    Timestamp(n)
}

/// Spawns the two reader threads of a model and returns the buffers they handed off, drained in
/// channel-delivery order.
///
/// Each reader builds its OWN [`SsiReadBuffer`] (thread-local — no shared state) and sends it back;
/// the coordinator (the calling thread) drains the channel into a `Vec` AFTER the readers join. The
/// readers never touch the tracker — the asymmetry `rmp` #341 exploits — so there is nothing shared
/// to lock. `r1_key` / `r2_key` are the keys each reader SIREAD-marks.
fn drain_two_readers(r1_key: u64, r2_key: u64) -> Vec<SsiReadBuffer> {
    let (tx, rx) = mpsc::channel::<SsiReadBuffer>();

    let tx1 = tx.clone();
    let r1 = loom::thread::spawn(move || {
        let mut buf = SsiReadBuffer::new(TxnId(1));
        buf.record_read(r1_key);
        tx1.send(buf).unwrap();
    });

    let r2 = loom::thread::spawn(move || {
        let mut buf = SsiReadBuffer::new(TxnId(2));
        buf.record_read(r2_key);
        tx.send(buf).unwrap();
    });

    r1.join().unwrap();
    r2.join().unwrap();

    // Receive EXACTLY the two buffers we sent, in interleaving-dependent order. (We recv a known
    // count rather than looping until the channel closes: loom does not model `recv()` on an
    // all-senders-dropped channel as a clean disconnect, so a drain-until-`Err` loop would register
    // as a deadlock. Both sends have happened-before the joins above, so both recvs succeed.)
    let first = rx.recv().expect("first handed-off buffer");
    let second = rx.recv().expect("second handed-off buffer");
    vec![first, second]
}

/// **L1** — two concurrent readers form the two halves of a write-skew; the coordinator merges both
/// buffers (either arrival order) and applies the writes that close the pivot. The structure MUST be
/// present at detection on every interleaving, and the victim MUST be the deterministic lowest-id
/// pivot.
///
/// Faithful to the serial `write_skew_forms_a_pivot_and_aborts` unit test: T1 reads X(=100) + writes
/// Y(=200); T2 reads Y(=200) + writes X(=100). The **reads** are what #341 buffers off-thread; the
/// **writes** stay on the single coordinator thread. Whichever buffer the channel delivers first,
/// `merge_read_buffer` sorts+dedups, so the resulting graph and `detect_pivot_abort`'s `.min()`
/// victim are identical.
#[test]
fn loom_l1_two_readers_write_skew_pivot_and_deterministic_victim() {
    loom::model(|| {
        // T1 reads X(100), T2 reads Y(200) — buffered off-thread, handed off.
        let buffers = drain_two_readers(100, 200);

        // Coordinator (this thread): a PLAIN local tracker — never shared with a reader thread.
        let mut t = SsiTracker::new();
        t.register(TxnId(1), ts(1));
        t.register(TxnId(2), ts(1));
        for buf in buffers {
            t.merge_read_buffer(buf);
        }
        t.record_write(TxnId(1), 200); // T1 writes Y -> T2 (read Y) --rw--> T1
        t.record_write(TxnId(2), 100); // T2 writes X -> T1 (read X) --rw--> T2

        assert!(t.is_pivot(TxnId(1)), "T1 must be a pivot (in+out rw-edge)");
        assert!(t.is_pivot(TxnId(2)), "T2 must be a pivot (in+out rw-edge)");

        // The dangerous structure is present at detection on EVERY interleaving, and the victim is
        // the deterministic lowest-id pivot — independent of which reader buffer arrived first.
        assert_eq!(
            t.detect_pivot_abort(TxnId(1)),
            Some(TxnId(1)),
            "first committer (T1) aborts itself; the .min() tie-break is interleaving-independent"
        );
    });
}

/// **L2** — two concurrent readers on **disjoint** keys: merging both buffers forms NO edge and never
/// panics, on any interleaving. No write touches either read key, so neither reader has any rw-edge.
#[test]
fn loom_l2_disjoint_readers_no_spurious_edge() {
    loom::model(|| {
        // Disjoint keys 10 and 20; no writes at all.
        let buffers = drain_two_readers(10, 20);

        let mut t = SsiTracker::new();
        t.register(TxnId(1), ts(1));
        t.register(TxnId(2), ts(1));
        for buf in buffers {
            t.merge_read_buffer(buf);
        }

        assert!(!t.is_pivot(TxnId(1)));
        assert!(!t.is_pivot(TxnId(2)));
        assert_eq!(t.detect_pivot_abort(TxnId(1)), None);
        assert_eq!(t.detect_pivot_abort(TxnId(2)), None);
    });
}

/// **L3** — the buffer handoff over a loom `mpsc`: every marker a reader buffered is fully visible to
/// the coordinator after delivery. Falsifiable via a write-skew whose ONE half is the handed-off
/// read: if that marker were lost or half-seen across the handoff, the reader would not become a
/// pivot and `detect_pivot_abort` would return `None` instead of `Some(reader)`.
///
/// T1 (the off-thread reader) buffers reads of X(100) **and** Z(300) and hands the buffer off; the
/// coordinator merges it, records T2 reading Y(200) inline (the peer, on the coordinator thread),
/// then applies T1 writes Y / T2 writes X. The T1↔T2 pivot closes only if T1's handed-off read of X
/// survived intact.
#[test]
fn loom_l3_handoff_marker_fully_visible_closes_pivot() {
    loom::model(|| {
        let (tx, rx) = mpsc::channel::<SsiReadBuffer>();

        // The off-thread reader buffers MULTIPLE markers (so the handoff must carry the whole Vec),
        // then hands the buffer back.
        let reader = loom::thread::spawn(move || {
            let mut buf = SsiReadBuffer::new(TxnId(1));
            buf.record_read(100); // X — the load-bearing half of the pivot
            buf.record_read(300); // Z — an extra marker that must also survive
            tx.send(buf).unwrap();
        });
        reader.join().unwrap();

        let mut t = SsiTracker::new();
        t.register(TxnId(1), ts(1)); // the off-thread reader
        t.register(TxnId(2), ts(1)); // a concurrent peer

        // Receive + merge the handed-off buffer (the Acquire side of the handoff).
        let buf = rx.recv().expect("the handed-off buffer is delivered");
        assert_eq!(
            buf.reader(),
            TxnId(1),
            "the buffer's owner id survives the handoff"
        );
        t.merge_read_buffer(buf);

        // T2's read of Y is recorded inline (the peer running on the coordinator thread).
        t.record_read(TxnId(2), 200);
        // Close the structure: T1 writes Y (T2 read Y -> T2 --rw--> T1), T2 writes X (T1 read X ->
        // T1 --rw--> T2). The T1->T2 edge EXISTS iff T1's handed-off read of X is visible.
        t.record_write(TxnId(1), 200);
        t.record_write(TxnId(2), 100);

        assert!(
            t.is_pivot(TxnId(1)),
            "T1 is a pivot only if its handed-off read of X is fully visible post-handoff"
        );
        assert!(t.is_pivot(TxnId(2)));
        assert_eq!(
            t.detect_pivot_abort(TxnId(1)),
            Some(TxnId(1)),
            "the handoff delivered every marker: the write-skew pivot closes and T1 is the victim"
        );
    });
}
