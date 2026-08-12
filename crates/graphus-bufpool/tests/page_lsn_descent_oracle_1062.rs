//! **The `rmp` #1062 oracle, tested against itself.**
//!
//! # Why this file exists
//!
//! [`ConcurrentBufferPool::page_lsn_descents`] is the single instrument every #1062 assertion rests
//! on: `graphus-dst`'s `page_log_apply_order_1062` battery asserts it reads **zero**, and so does any
//! future battery that wants to say "this workload took its page changes in log order". An
//! always-zero counter satisfies all of them. Delete the `fetch_add`, invert the comparison, or move
//! the call out from under the frame write latch, and every one of those suites goes permanently
//! green — for exactly the reason the defect was invisible in the first place: nothing about a
//! *result* changes when a page applies its changes in the wrong order, so only the instrument can
//! tell, and an instrument nobody calibrates is not evidence.
//!
//! The ablation run recorded in `page_log_apply_order_1062`'s module note proves the counter fires,
//! but a measurement written into a doc comment is a claim about one afternoon. This file is the
//! part that gets re-run.
//!
//! # What is asserted
//!
//! * [`a_descending_stamp_is_counted`] — the positive direction. Stamp a page at LSN 10, then at
//!   LSN 5, and require the count to go `0 -> 1`. This is the assertion that fails if the increment
//!   is removed or the comparison inverted.
//! * [`an_ascending_stamp_is_not_counted`] — the negative direction, which is what stops the test
//!   above from being satisfied by a counter that increments unconditionally. An equal stamp is
//!   included: `page_lsn` is a claim of the form "this image reflects every change logged at or below
//!   this LSN", so re-stating the same LSN is not a descent.
//! * [`the_declining_variant_counts_only_when_it_writes`] — `with_page_mut_lsn_if` stamps only when
//!   its closure reports a write (`rmp` #1028), so it must count only then too. A refused write that
//!   incremented the counter would make every future battery flaky in the one direction nobody would
//!   investigate: a failure that is not a real defect.
//! * [`the_counter_is_per_pool`] — the count belongs to the pool it was measured on, so two suites
//!   running concurrently in one process cannot contaminate each other's verdict.
//!
//! # Running it
//!
//! ```text
//! cargo test -p graphus-bufpool --test page_lsn_descent_oracle_1062
//! ```

use graphus_bufpool::{ConcurrentBufferPool, page};
use graphus_core::Lsn;
use graphus_io::MemBlockDevice;

/// Frames in the test pool. Two, so [`the_counter_is_per_pool`] can hold a page in each of two pools
/// without either evicting.
const POOL_FRAMES: usize = 2;

/// A byte offset well inside the page body, past the header, used as the payload the stamps carry.
const PAYLOAD_OFF: usize = 128;

/// A pool over a fresh in-memory device, plus one allocated, initialised, still-pinned page.
///
/// The page is `flush_unlogged`-ed exactly as the store does for a freshly grown page, so it starts
/// life with a valid checksum and `page_lsn == 0` — the same starting state a real logged write
/// stamps over.
fn pool_with_one_page() -> (
    ConcurrentBufferPool<MemBlockDevice>,
    graphus_bufpool::PinnedFrame,
) {
    let pool = ConcurrentBufferPool::new(MemBlockDevice::new(0), POOL_FRAMES);
    let (frame, _id) = pool.new_page().expect("allocate a page");
    pool.flush_unlogged(frame).expect("seed the page checksum");
    (pool, frame)
}

/// **The property this file exists for.** A stamp below the page's current `page_lsn` is counted.
///
/// LSN 10 then LSN 5 is the shape of the defect in miniature: two records entered the log as 5 then
/// 10 (LSNs are minted in append order), and the page took 10 before 5. ARIES replays 5 then 10, so
/// the recovered image is record 10's and the live image is record 5's — two internally consistent
/// images that are not the same image.
#[test]
fn a_descending_stamp_is_counted() {
    let (pool, frame) = pool_with_one_page();
    assert_eq!(
        pool.page_lsn_descents(),
        0,
        "a freshly allocated page has been stamped by nobody, so the count must start at zero"
    );

    pool.with_page_mut_lsn(frame, Lsn(10), |p| p[PAYLOAD_OFF] = 0xAA);
    assert_eq!(
        pool.page_lsn_descents(),
        0,
        "the FIRST stamp of a page whose `page_lsn` is 0 ascends, so it must not be counted"
    );

    pool.with_page_mut_lsn(frame, Lsn(5), |p| p[PAYLOAD_OFF] = 0xBB);
    assert_eq!(
        pool.page_lsn_descents(),
        1,
        "a page carrying `page_lsn` 10 was stamped with 5 and the descent was NOT counted, so \
         `ConcurrentBufferPool::page_lsn_descents` cannot detect out-of-log-order application and \
         every `rmp` #1062 battery that reads it is vacuous"
    );

    // The stamp itself is a maximum (`rmp` #1029), so the descent is counted and NOT obeyed. Both
    // halves matter: counting it is what makes the defect visible, and refusing to obey it is what
    // keeps WAL-before-data sound while the defect exists.
    let lsn = pool.with_page(frame, page::page_lsn);
    assert_eq!(
        lsn,
        Lsn(10),
        "`set_page_lsn` must be monotone (`rmp` #1029): the counted descent may not lower the header"
    );
}

/// **The negative direction.** An ascending — or repeated — stamp is not counted.
///
/// Without this, [`a_descending_stamp_is_counted`] would also pass against a counter that increments
/// on every stamp, which would report a descent on every page write and make the invariant
/// unassertable.
#[test]
fn an_ascending_stamp_is_not_counted() {
    let (pool, frame) = pool_with_one_page();
    for lsn in [1u64, 2, 3, 100, 101] {
        pool.with_page_mut_lsn(frame, Lsn(lsn), |p| p[PAYLOAD_OFF] = lsn as u8);
    }
    // Equal, not below: `page_lsn` claims "every change logged at or below this LSN is reflected
    // here", so re-stating the current value asserts nothing new and reverses nothing.
    pool.with_page_mut_lsn(frame, Lsn(101), |p| p[PAYLOAD_OFF] = 0xEE);
    assert_eq!(
        pool.page_lsn_descents(),
        0,
        "stamps that ascend, or that repeat the current `page_lsn`, are in log order and must not be \
         counted — a counter that fires on them would report a descent on every page write"
    );
}

/// **The declining variant.** `with_page_mut_lsn_if` counts only on the stamps it actually applies.
///
/// A compare-and-publish that finds the word already changed writes nothing, stamps nothing
/// (`rmp` #1028: advancing `page_lsn` without a write is corruption, not over-approximation) and
/// must therefore count nothing — even when the LSN it was offered is below the page's.
#[test]
fn the_declining_variant_counts_only_when_it_writes() {
    let (pool, frame) = pool_with_one_page();
    pool.with_page_mut_lsn(frame, Lsn(10), |p| p[PAYLOAD_OFF] = 0xAA);

    let declined = pool.with_page_mut_lsn_if(frame, Lsn(5), |_p| None::<()>);
    assert!(
        declined.is_none(),
        "the closure declined, so nothing was written"
    );
    assert_eq!(
        pool.page_lsn_descents(),
        0,
        "a DECLINED write applies no change and stamps no LSN, so it cannot have applied one out of \
         order; counting it would make every `rmp` #1062 battery fail on a run with no defect in it"
    );

    let wrote = pool.with_page_mut_lsn_if(frame, Lsn(5), |p| {
        p[PAYLOAD_OFF] = 0xBB;
        Some(())
    });
    assert!(
        wrote.is_some(),
        "the closure wrote, so the stamp was applied"
    );
    assert_eq!(
        pool.page_lsn_descents(),
        1,
        "an ACCEPTED write stamped 5 over a `page_lsn` of 10 and was not counted"
    );
}

/// **The count belongs to its pool.** Two pools in one process do not contaminate each other.
///
/// The #1062 batteries read the counter off the store under test while the rest of the suite runs in
/// the same process; a process-global counter would make their verdict depend on what else happened
/// to be running.
#[test]
fn the_counter_is_per_pool() {
    let (offender, offender_frame) = pool_with_one_page();
    let (clean, clean_frame) = pool_with_one_page();

    offender.with_page_mut_lsn(offender_frame, Lsn(10), |p| p[PAYLOAD_OFF] = 0xAA);
    offender.with_page_mut_lsn(offender_frame, Lsn(5), |p| p[PAYLOAD_OFF] = 0xBB);
    clean.with_page_mut_lsn(clean_frame, Lsn(10), |p| p[PAYLOAD_OFF] = 0xCC);
    clean.with_page_mut_lsn(clean_frame, Lsn(20), |p| p[PAYLOAD_OFF] = 0xDD);

    assert_eq!(
        offender.page_lsn_descents(),
        1,
        "the offending pool counts its own descent"
    );
    assert_eq!(
        clean.page_lsn_descents(),
        0,
        "a pool that took every stamp in order must read zero regardless of what another pool in \
         this process did"
    );
}
