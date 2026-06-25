//! `rmp` #408 regression: on the **encrypted** device, doublewrite recovery
//! ([`graphus_storage::Dwb::recover_home`]) must distinguish a **transient** home-read I/O error
//! from a **genuine torn** (AEAD-tag-failed) home page.
//!
//! Before the fix, the encrypted device's `read_page` returned `Err` for *both* a genuine torn page
//! (AEAD tag failure) and a transient I/O error, and `recover_home` mapped *any* home-read `Err` to
//! "torn → repair from the doublewrite copy". So a fine-but-momentarily-unreadable home page with a
//! stale surviving doublewrite batch would be **clobbered** with the older image — a durability
//! violation (an older image written over a newer home page).
//!
//! The fix adds [`graphus_io::BlockDevice::read_page_classified`], which the encrypted device
//! overrides to report a genuine AES-GCM tag failure as [`graphus_io::PageReadOutcome::Torn`] while
//! **propagating** a transient backing-store read error as `Err`. `recover_home` then repairs only a
//! genuine tear and propagates a transient error instead of silently reverting a good page.
//!
//! Two companion tests pin both arms:
//!   1. a transient read error on a FINE home page with a STALE doublewrite batch → `recover_home`
//!      returns `Err` (propagated, never reverts) and the home page is left intact;
//!   2. a genuine AEAD-tag failure (a torn home slot) → `recover_home` repairs it from the copy.

use graphus_bufpool::page;
use graphus_core::{Lsn, PageId};
use graphus_crypto::{EncryptedBlockDevice, HEADER_SLOTS, KEY_LEN, Keyring, MemRawSlots, SALT_LEN};
use graphus_io::{BlockDevice, PAGE_SIZE, Page};
use graphus_storage::Dwb;

type EncMem = EncryptedBlockDevice<MemRawSlots>;

const SALT: [u8; SALT_LEN] = [0x5C; SALT_LEN];

fn keyring() -> Keyring {
    Keyring::from_key_file_bytes(&[0x42u8; KEY_LEN], &SALT).expect("keyring")
}

/// A fresh encrypted device over an empty in-memory backing with `pages` zero-extended logical pages.
fn fresh_encrypted(pages: u64) -> EncMem {
    let mut dev =
        EncryptedBlockDevice::create(MemRawSlots::new(0), &keyring(), SALT).expect("create device");
    if pages > 0 {
        dev.extend(pages).expect("extend");
    }
    dev
}

/// Builds a valid, checksummed page self-identifying as `id` with `page_lsn` and a body fill.
fn make_page(id: u64, lsn: u64, fill: u8) -> Page {
    let mut p = [fill; PAGE_SIZE];
    page::set_page_id(&mut p, id);
    page::set_page_lsn(&mut p, Lsn(lsn));
    page::write_checksum(&mut p);
    p
}

/// #408 arm 1 — a **transient** read error on a FINE home page must NOT be treated as torn: with a
/// stale doublewrite batch present, `recover_home` must propagate the error and leave the (newer,
/// intact) home page untouched, never reverting it to the older doublewrite image.
#[test]
fn transient_home_read_error_does_not_revert_a_fine_page_from_a_stale_dwb_copy() {
    let target = PageId(0);

    // The doublewrite buffer over its own encrypted device, holding a STALE (older) batch for `target`.
    let mut dwb = Dwb::new(fresh_encrypted(0)).expect("dwb");
    let stale = make_page(target.0, 10, 0xAA); // page_lsn 10 — the OLD image
    dwb.stage_batch(&[(target, &stale)]).expect("stage stale");

    // The home device holds a NEWER, fully-intact image of `target` (page_lsn 20).
    let mut home = fresh_encrypted(1);
    let fresh = make_page(target.0, 20, 0xBB); // page_lsn 20 — the live image
    home.write_page(target, &fresh).expect("write fresh home");
    home.sync_all().expect("sync home");

    // Arm a transient read error on the NEXT home read (the read `recover_home` issues for `target`).
    // `recover_home` reads the DWB header (on the *dwb* device) first, then reads the home page — so
    // arming one error on the HOME backing lands it exactly on the home read, modelling a
    // momentarily-unreadable-but-fine page. `backing_mut` arms it on the LIVE device (no re-open,
    // which would itself read the header slot and consume the one-shot fault).
    home.backing_mut().arm_read_io_errors(1);

    // recover_home must PROPAGATE the transient error, NOT silently revert the page.
    let result = dwb.recover_home(&mut home);
    assert!(
        result.is_err(),
        "a transient home-read error must propagate as Err, not be treated as a torn page"
    );

    // The home page must be UNTOUCHED — still the newer image, never clobbered by the stale DWB copy.
    let mut got: Page = [0u8; PAGE_SIZE];
    home.read_page(target, &mut got)
        .expect("home read succeeds once the transient error has cleared");
    assert_eq!(
        &got[..],
        &fresh[..],
        "the fine home page must be left intact (its newer image), never reverted to the stale DWB copy"
    );
    assert_eq!(
        page::page_lsn(&got),
        Lsn(20),
        "the home page must still carry the NEWER page_lsn 20, proving no stale revert"
    );
}

/// #408 arm 2 — a **genuine** AEAD-tag failure (a torn home slot) IS a tear and MUST be repaired from
/// the doublewrite copy. Proves the classified read still repairs the real torn-page case the DWB
/// exists for (no regression of the #384/#385 guarantee on the encrypted device).
#[test]
fn genuine_aead_tag_failure_is_repaired_from_the_dwb_copy() {
    let target = PageId(0);

    // The doublewrite buffer holds the GOOD image for `target` (the repair source).
    let mut dwb = Dwb::new(fresh_encrypted(0)).expect("dwb");
    let good = make_page(target.0, 30, 0xCD);
    dwb.stage_batch(&[(target, &good)]).expect("stage good");

    // Write the good image home, then TEAR the home slot: a torn write stores only a prefix of the
    // slot, so the AES-GCM tag no longer authenticates — a genuine torn page (PageReadOutcome::Torn).
    let mut home = fresh_encrypted(1);
    home.write_page(target, &good).expect("write home");
    home.sync_all().expect("sync home");

    let mut backing = home.into_backing();
    let phys = target.0 + HEADER_SLOTS; // logical page -> physical slot
    backing.arm_torn_write(phys, 64); // next write to this slot keeps only 64 bytes
    // Re-write the slot through the torn-armed backing so the stored slot is genuinely torn.
    let mut home = EncryptedBlockDevice::open(backing, &keyring()).expect("reopen home");
    home.write_page(target, &good).expect("torn re-write");
    home.sync_all().expect("sync torn");

    // Sanity: the torn home page now fails AEAD (read_page errors).
    let mut probe: Page = [0u8; PAGE_SIZE];
    assert!(
        home.read_page(target, &mut probe).is_err(),
        "precondition: the torn home slot must fail AEAD authentication"
    );

    // recover_home must classify it as torn and repair it from the DWB copy.
    let repaired = dwb.recover_home(&mut home).expect("recover");
    assert_eq!(repaired, 1, "the genuinely torn home page must be repaired");

    let mut got: Page = [0u8; PAGE_SIZE];
    home.read_page(target, &mut got)
        .expect("home page authenticates after repair");
    assert_eq!(
        &got[..],
        &good[..],
        "the repaired home page must equal the doublewrite copy"
    );
}
