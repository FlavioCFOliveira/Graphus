//! Integration test (rmp #87): the **residual-risk bound** for the bare-zero read path of the
//! [`EncryptedBlockDevice`].
//!
//! Context. A never-written page is stored as an all-zero physical slot and read back as a zero page
//! *without* AEAD verification (required for the never-written-page-reads-zeros contract that
//! crash-recovery's read-modify-write relies on; see `device::read_page`). The documented residual
//! gap, **outside** the at-rest stolen-disk *confidentiality* threat model, is that an *active*
//! attacker with write access to the live disk could zero a **real** page's slot and have it read
//! back as a zero page, bypassing the AEAD tag.
//!
//! These tests prove that gap is **defeated in practice for the real consumer**: the storage layer
//! never reads a page without verifying that page's own CRC32C header
//! (`graphus_bufpool::BufferPool::fetch`), and an all-zero page fails that check — so a zeroed-out
//! real page is rejected before use. We drive the *actual* `BufferPool::fetch` gate (not a re-derived
//! CRC) so the bound is verified at the precise seam the `device` docs cite.
//!
//! This is the empirical complement to the in-`device.rs` unit tests
//! (`never_written_page_reads_back_as_zeros`, `tamper_with_a_slot_is_detected_on_read`,
//! `reopen_recovers_when_extend_outlived_a_crash_before_header_sync`): those pin the device's own
//! behaviour; this pins the *consumer's* fail-closed behaviour on the one substitution AEAD cannot
//! catch.

use graphus_bufpool::BufferPool;
use graphus_bufpool::page;
use graphus_core::PageId;
use graphus_crypto::{
    EncryptedBlockDevice, HEADER_SLOTS, KEY_LEN, Keyring, MemRawSlots, RawSlots, SALT_LEN,
    SLOT_SIZE,
};
use graphus_io::{BlockDevice, PAGE_SIZE, Page};

const SALT: [u8; SALT_LEN] = [0x7E; SALT_LEN];

type EncMem = EncryptedBlockDevice<MemRawSlots>;

fn keyring() -> Keyring {
    Keyring::from_key_file_bytes(&[0x42u8; KEY_LEN], &SALT).expect("keyring")
}

fn fresh_device() -> EncMem {
    EncryptedBlockDevice::create(MemRawSlots::new(0), &keyring(), SALT).expect("create device")
}

/// Builds a realistic record page exactly as the storage layer would: a valid self-referential page
/// id and a correct CRC32C in the header (what `new_page` + `write_back` stamp before a page is
/// written home).
fn checksummed_page(page_id: u64, marker: u8) -> Page {
    let mut p: Page = [0u8; PAGE_SIZE];
    page::set_page_id(&mut p, page_id);
    // Some body content so the page is not trivially all-zero even before the checksum is stamped.
    p[page::HEADER_SIZE..page::HEADER_SIZE + 8].copy_from_slice(&[marker; 8]);
    page::write_checksum(&mut p);
    assert!(page::verify_checksum(&p), "constructed page must be valid");
    p
}

/// A fresh encrypted device with one real, checksummed, hardened page at `target`.
fn device_with_one_real_page(target: PageId) -> EncMem {
    let mut device = fresh_device();
    device.extend(target.0 + 1).expect("extend");
    device
        .write_page(target, &checksummed_page(target.0, 0xAB))
        .expect("write real page");
    device.sync_all().expect("sync");
    device
}

#[test]
fn a_valid_real_page_loads_through_the_storage_consumer() {
    // Control: a genuine, checksummed page loads cleanly through the real consumer
    // (`BufferPool::fetch` verifies the CRC32C on load). This is the positive case the bound below
    // contrasts with.
    let target = PageId(1);
    let device = device_with_one_real_page(target);
    let mut pool = BufferPool::new(device, 4);
    let f = pool
        .fetch(target)
        .expect("a valid checksummed page loads through the consumer");
    assert!(
        page::verify_checksum(pool.page(f)),
        "the loaded page is checksum-valid"
    );
    pool.unpin(f);
}

#[test]
fn storage_rejects_a_zeroed_out_real_page_via_crc32c() {
    let target = PageId(1);
    let device = device_with_one_real_page(target);

    // The active attacker zeros that real page's encrypted slot on the live disk, then it is
    // hardened. Logical page `p` lives at physical slot `p + HEADER_SLOTS`.
    let mut backing = device.into_backing();
    backing
        .write_slot(target.0 + HEADER_SLOTS, &[0u8; SLOT_SIZE])
        .expect("zero the real page's slot");
    backing.sync_all().expect("harden the zeroing");
    let device =
        EncryptedBlockDevice::open(backing, &keyring()).expect("reopen over zeroed backing");

    // The device itself, by the documented bare-zero contract, now reads the slot back as a zero page
    // WITHOUT failing AEAD (this is the gap — intentional, for never-written pages).
    {
        let mut buf = [0xFFu8; PAGE_SIZE];
        device
            .read_page(target, &mut buf)
            .expect("the zeroed slot reads back as a zero page at the device level (the gap)");
        assert_eq!(
            buf, [0u8; PAGE_SIZE],
            "the zeroed real slot reads back as all zeros at the device level"
        );
    }

    // THE BOUND: the real storage-layer consumer rejects the zeroed page on its CRC32C check, because
    // an all-zero page body has a non-zero CRC32C while the stored checksum field is 0.
    let mut pool = BufferPool::new(device, 4);
    let err = pool
        .fetch(target)
        .expect_err("the storage layer must reject the zeroed-out real page");
    let msg = err.to_string();
    assert!(
        msg.contains("failed checksum verification"),
        "the consumer must reject via CRC32C, got: {msg}"
    );
}

#[test]
fn an_all_zero_page_fails_the_storage_crc32c_check() {
    // The crisp underlying fact the bound rests on: an all-zero page does NOT pass CRC32C
    // verification, so the storage layer never trusts an all-zero slot it reads from the device.
    let zero: Page = [0u8; PAGE_SIZE];
    assert!(
        !page::verify_checksum(&zero),
        "an all-zero page must fail CRC32C verification (stored=0, computed!=0)"
    );

    // And a genuinely never-written page reads back as zeros at the device level — the legitimate
    // contract — yet would be caught by the same CRC32C gate were it ever loaded as a real page.
    let mut device = fresh_device();
    device.extend(1).expect("extend");
    let mut buf = [0xFFu8; PAGE_SIZE];
    device
        .read_page(PageId(0), &mut buf)
        .expect("never-written page reads back as zeros");
    assert_eq!(buf, [0u8; PAGE_SIZE]);
    assert!(
        !page::verify_checksum(&buf),
        "the pristine zero page also fails CRC32C — which is exactly why the storage layer builds a \
         fresh page in memory (with a valid checksum) on allocation rather than reading the bare slot"
    );
}
