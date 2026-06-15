//! Red-team security tests for `graphus-io` block-device arithmetic on attacker-controlled
//! page identifiers.
//!
//! Threat model: a `page_id` (`u64`) decoded from a WAL record or store header is **fully
//! attacker-controlled** (the WAL CRC32C is unkeyed, so a tampered log frame still parses). During
//! crash recovery `DeviceTarget::ensure` (graphus-storage) turns that id into
//! `FileBlockDevice::extend(additional)` and `FileBlockDevice::write_page`, both of which multiply a
//! `u64` page count by `PAGE_SIZE` **without `checked_mul`** (`file.rs:49`, `file.rs:98`).
//!
//! These tests stay entirely inside a tmpdir and never touch real data. They are **regression
//! tests for SEC-211**: `FileBlockDevice::extend` and `FileBlockDevice::offset` now use
//! `checked_mul` plus a sane `MAX_PAGE_COUNT` cap, so an attacker-chosen page count / page id whose
//! `* PAGE_SIZE` would wrap `u64` is rejected with a clean `Err` — never a silent truncation
//! (release) and never an overflow panic (debug). Before the fix this was CWE-190 → CWE-787/125
//! (out-of-position I/O, silent DB corruption) or a startup DoS.

use graphus_io::{BlockDevice, FileBlockDevice, PAGE_SIZE};

fn temp_path(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("graphus-sec-io-{}-{tag}-{n}.blk", std::process::id()))
}

/// The exact arithmetic performed by `FileBlockDevice::extend` (`new_count * PAGE_SIZE as u64`) and
/// `FileBlockDevice::offset` (`page.0 * PAGE_SIZE as u64`). A page count just above
/// `u64::MAX / PAGE_SIZE` overflows the multiplication.
const OVERFLOW_PAGE_COUNT: u64 = (u64::MAX / PAGE_SIZE as u64) + 1;

/// Regression: SEC-211 — `extend` rejects (clean `Err`, no panic, no wrap, no truncation) a page
/// count whose `* PAGE_SIZE` overflows `u64`.
#[test]
fn extend_with_overflowing_page_count_returns_err_not_wrap() {
    // Sanity on the chosen boundary: the product genuinely overflows, so a `wrapping_mul` would
    // yield a tiny byte length — the exact silent-truncation footgun the fix must prevent.
    assert!(
        OVERFLOW_PAGE_COUNT.checked_mul(PAGE_SIZE as u64).is_none(),
        "the page-count * PAGE_SIZE product must be a genuine overflow for this test to be valid"
    );

    let path = temp_path("extend");
    let mut dev = FileBlockDevice::open(&path).expect("open device");
    dev.extend(1).expect("baseline grow by one page");
    assert_eq!(dev.page_count(), 1);

    let before_len = std::fs::metadata(&path).map(|m| m.len()).expect("metadata");

    // Attacker-chosen huge growth. Run inside catch_unwind so that, were the fix ever regressed
    // back to an unchecked `*`, a debug-build overflow panic surfaces as a test failure here
    // instead of aborting the process: we assert a clean Err, never a panic, never an Ok wrap.
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dev.extend(OVERFLOW_PAGE_COUNT)));

    match result {
        Ok(Err(_e)) => { /* SECURE: rejected with a clean error, as required. */ }
        Ok(Ok(())) => panic!(
            "REGRESSION (SEC-211): extend accepted an overflowing page count instead of erroring \
             — silent truncation / metadata desync"
        ),
        Err(_panic) => panic!(
            "REGRESSION (SEC-211): extend panicked on overflow instead of returning Err — \
             unchecked multiplication reintroduced (DoS)"
        ),
    }

    // The on-disk file must be byte-for-byte untouched by the rejected extend (no truncation, no
    // growth), and the in-memory page_count must NOT have been bumped to the wrapped value.
    let after_len = std::fs::metadata(&path).map(|m| m.len()).expect("metadata");
    assert_eq!(
        after_len, before_len,
        "a rejected extend must not change the file length"
    );
    assert_eq!(
        dev.page_count(),
        1,
        "a rejected extend must leave page_count unchanged (no metadata desync)"
    );

    std::fs::remove_file(&path).ok();
}

/// Regression: SEC-211 — a positioned access at an overflowing / out-of-cap page id is rejected
/// with a clean `Err` rather than seeking to a wrapped, in-bounds-looking byte offset.
///
/// `offset()` is private; its security contract is observed through the public `read_page` /
/// `write_page`, which must refuse a `page_id` so large that its `* PAGE_SIZE` would wrap. (The
/// range check `page_id >= page_count` already fires first for these ids, which is exactly the
/// secured outcome: no wrapped seek ever reaches the syscall.)
#[test]
fn positioned_access_at_overflowing_page_id_returns_err_not_wrapped_seek() {
    assert!(
        OVERFLOW_PAGE_COUNT.checked_mul(PAGE_SIZE as u64).is_none(),
        "offset product must overflow for this test to be valid"
    );

    let path = temp_path("offset");
    let mut dev = FileBlockDevice::open(&path).expect("open device");
    dev.extend(1).expect("one real page");

    let evil = graphus_core::PageId(OVERFLOW_PAGE_COUNT);
    let mut buf = [0u8; PAGE_SIZE];

    let read = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dev.read_page(evil, &mut buf)));
    assert!(
        matches!(read, Ok(Err(_))),
        "REGRESSION (SEC-211): read_page at an overflowing page id must return Err, not panic or \
         seek to a wrapped offset"
    );

    let page = [0u8; PAGE_SIZE];
    let write = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dev.write_page(evil, &page)));
    assert!(
        matches!(write, Ok(Err(_))),
        "REGRESSION (SEC-211): write_page at an overflowing page id must return Err, not panic or \
         write out of position"
    );

    std::fs::remove_file(&path).ok();
}
