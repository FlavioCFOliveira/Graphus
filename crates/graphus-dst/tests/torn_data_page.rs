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

use graphus_dst::{DetRng, FaultKind, run_with_fault};

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
/// recovers to the same state (the fault's page choice and tear prefix are seed-derived).
#[test]
fn torn_data_page_is_deterministic() {
    for seed in [5u64, 23, 71, 144] {
        let a = run_with_fault(seed, FaultKind::TornDataPage, &mut DetRng::new(seed));
        let b = run_with_fault(seed, FaultKind::TornDataPage, &mut DetRng::new(seed));
        assert_eq!(a, b, "seed {seed}: torn-data-page is not deterministic");
    }
}
