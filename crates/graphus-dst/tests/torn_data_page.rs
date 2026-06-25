//! Targeted torn-DATA-page fault test (`specification/04-technical-design.md` §11.5: torn write of a
//! home data page; `05 §3` / `04 §4.5` doublewrite buffer).
//!
//! A power loss can tear a **home data page** mid-write: some device sectors hold the new image,
//! some the old. Its CRC32C page checksum (`04 §3.2`) then fails, and — critically — its `page_lsn`
//! header is garbage, so ARIES redo, which gates each change on `record.lsn > page_lsn`, could
//! *skip* the redo and serve the corrupt page. The fix is the **doublewrite buffer**: every dirty
//! page is written to a durable doublewrite copy *before* its home write, and recovery restores any
//! torn home page from that copy **before** redo (`graphus_storage::recovery::recover_device_with_dwb`).
//!
//! This test drives the full `RecordStore` engine through the DST harness with the
//! [`FaultKind::TornDataPage`] fault. The harness:
//!
//! 1. runs a seeded workload and flushes dirty pages home **under doublewrite protection**
//!    ([`graphus_storage::RecordStore::flush_protected`]);
//! 2. snapshots the on-disk home image while **tearing one home data page** (asserting the tear is
//!    real: the page fails its checksum before recovery, so the scenario is never vacuous);
//! 3. recovers with the doublewrite-aware recovery, which repairs the torn page from the doublewrite
//!    buffer before redo;
//! 4. checks all four invariants — including the page-checksum integrity invariant, which would fail
//!    loudly if the tear had *not* been repaired.
//!
//! A pass across many seeds is direct evidence the doublewrite buffer closes the torn-home-page
//! durability hole that was previously recorded as a deferred fault.

use graphus_core::PageId;
use graphus_dst::{DetRng, FaultKind, run_with_fault};
use graphus_io::{BlockDevice, MemBlockDevice, PAGE_SIZE, TORN_SECTOR_SIZE, sector_torn_image};

/// Across many seeds, a torn home data page is repaired from the doublewrite buffer before redo, and
/// every invariant (durability, atomicity, integrity incl. page checksums) still holds.
#[test]
fn torn_data_page_is_repaired_from_the_doublewrite_buffer() {
    let mut saw_commit = false;

    for seed in 1..=150u64 {
        let mut rng = DetRng::new(seed);
        let report = run_with_fault(seed, FaultKind::TornDataPage, &mut rng);

        assert!(
            report.passed(),
            "seed {seed} [torn-data-page] violated an invariant: {:?}\n\
             reproduce by constructing run_with_fault(seed, TornDataPage, ..)\n\
             a BadChecksum failure here means the torn home page was NOT repaired from the DWB \
             before redo (the durability hole reopened)",
            report.result
        );

        saw_commit |= report.ledger.acknowledged_commits() > 0;
    }

    assert!(
        saw_commit,
        "no acknowledged commits across any seed — the durability side of the check is vacuous"
    );
}

/// The torn-data-page run is deterministic: the same seed tears the same page at the same point and
/// recovers to the same state (the fault's page choice and tear seed are seed-derived).
#[test]
fn torn_data_page_is_deterministic() {
    for seed in [5u64, 23, 71, 144] {
        let a = run_with_fault(seed, FaultKind::TornDataPage, &mut DetRng::new(seed));
        let b = run_with_fault(seed, FaultKind::TornDataPage, &mut DetRng::new(seed));
        assert_eq!(a, b, "seed {seed}: torn-data-page is not deterministic");
    }
}

/// Regression gate for rmp #433: the torn-write fault tears at **sector** granularity, producing the
/// realistic power-loss image of a valid OLD header sector over a NEW body sector (a state a coarse
/// byte-prefix tear could never reach), and that mix is (a) sector-wise — not a byte prefix, (b)
/// deterministic per seed, and (c) still flagged by the whole-page CRC32C checksum (`04 §3.2`).
///
/// This exercises the device fault directly (the same `arm_torn_write_sectors` /
/// `sector_torn_image` the [`FaultKind::TornDataPage`] harness drives) with a *real* page header so
/// the "valid header in an old sector" property is concrete, not abstract.
#[test]
fn sector_torn_write_yields_old_header_over_new_body_detectable_by_crc() {
    use graphus_bufpool::page::{stored_checksum, verify_checksum, write_checksum};

    assert_eq!(
        PAGE_SIZE % TORN_SECTOR_SIZE,
        0,
        "the sector model needs the sector size to divide the page size"
    );
    let sectors = PAGE_SIZE / TORN_SECTOR_SIZE;
    assert!(sectors >= 2, "need >= 2 sectors for a header/body split");

    // OLD durable image: a fully valid page (its CRC32C header lives in sector 0).
    let mut old = [0xA0u8; PAGE_SIZE];
    write_checksum(&mut old);
    assert!(verify_checksum(&old), "old image must be self-consistent");
    // NEW image being written when power is lost: different content, its own valid checksum.
    let mut new = [0x0Bu8; PAGE_SIZE];
    write_checksum(&mut new);
    assert!(verify_checksum(&new), "new image must be self-consistent");

    // Drive the fault through the device exactly as the harness does.
    let run = |seed: u64| {
        let mut dev = MemBlockDevice::new(1);
        dev.write_page(PageId(0), &old).unwrap();
        dev.sync_all().unwrap(); // OLD image durable
        dev.arm_torn_write_sectors(PageId(0), seed);
        dev.write_page(PageId(0), &new).unwrap(); // torn at sector granularity
        let mut buf = [0u8; PAGE_SIZE];
        dev.read_page(PageId(0), &mut buf).unwrap();
        buf
    };

    // Find a seed yielding the canonical "OLD header sector + NEW body sector" image. The fault is a
    // pure function of `sector_torn_image`, so we can predict the device output exactly.
    let seed = (0..1024u64)
        .find(|&s| {
            let t = sector_torn_image(&old, &new, s);
            t[..TORN_SECTOR_SIZE] == old[..TORN_SECTOR_SIZE]
                && t[TORN_SECTOR_SIZE..2 * TORN_SECTOR_SIZE]
                    == new[TORN_SECTOR_SIZE..2 * TORN_SECTOR_SIZE]
        })
        .expect("a seed yielding an OLD-header / NEW-body sector tear must exist");

    let torn_a = run(seed);
    let torn_b = run(seed);

    // (b) Determinism: same seed reproduces the identical torn image byte for byte, and the device
    // output equals the predicted `sector_torn_image` (single source of truth).
    assert_eq!(
        torn_a, torn_b,
        "same seed must reproduce the identical torn image"
    );
    assert_eq!(
        torn_a,
        sector_torn_image(&old, &new, seed),
        "the device fault must equal the predicted sector image (harness can predict tears)"
    );

    // (a) Sector-wise mix in the canonical #433 shape: OLD header sector over NEW body sector — a
    // valid old header sitting over a new body, which a byte-prefix tear (new bytes always at the
    // front) could never produce.
    assert_eq!(
        torn_a[..TORN_SECTOR_SIZE],
        old[..TORN_SECTOR_SIZE],
        "header sector must retain the OLD (valid-header) bytes"
    );
    assert_eq!(
        torn_a[TORN_SECTOR_SIZE..2 * TORN_SECTOR_SIZE],
        new[TORN_SECTOR_SIZE..2 * TORN_SECTOR_SIZE],
        "body sector must carry the NEW bytes"
    );
    assert_ne!(torn_a, old, "torn image must differ from the old page");
    assert_ne!(torn_a, new, "torn image must differ from the new page");

    // (c) The whole-page CRC32C still flags the torn page as corrupt — the stored checksum (now the
    // OLD header's, computed over the OLD body) no longer matches the torn body. Detection is intact
    // even though the header sector itself is a self-consistent OLD sector: this is exactly the
    // realistic state where a coarse body-only check could be fooled but the whole-page checksum is
    // not.
    assert!(
        !verify_checksum(&torn_a),
        "the whole-page CRC32C must still flag the sector-torn page as corrupt"
    );
    assert_ne!(
        stored_checksum(&torn_a),
        graphus_bufpool::page::compute_checksum(&torn_a),
        "torn body must not match the (old-header) stored checksum"
    );
}
