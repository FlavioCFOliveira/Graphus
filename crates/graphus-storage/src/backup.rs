//! Offline **backup / restore / verification** of a [`RecordStore`] (`rmp` task #23:
//! "Backups restore to a consistent state; verification detects a tampered backup"; serves
//! `CLAUDE.md`'s inviolable *never corrupt* mandate and `04-technical-design.md` §2.1 on-disk file
//! organisation, §3.2 page header + CRC32C, §4.7 consistent checkpoint-based snapshots).
//!
//! # What this module provides
//!
//! * [`backup_store`] — produce a self-describing backup artifact (a `Vec<u8>`) capturing a
//!   **consistent snapshot** of a store. It is **read-only** with respect to the source store's
//!   *graph* (it appends a clean fuzzy checkpoint, but mutates no record and frees nothing).
//! * [`restore`] — materialise a fresh in-memory device from an artifact and
//!   [`open`](RecordStore::open) a [`RecordStore`] over it, **after** running the consistency
//!   checker so a backup that would restore to an inconsistent state is rejected.
//! * [`restore_onto`] — the device-agnostic restore primitive, so a file-backed restore is a thin
//!   wrapper that supplies its own [`BlockDevice`] (see [`restore`] for the in-memory path).
//! * [`verify_backup`] — validate an artifact's structure and integrity digest **without** a full
//!   restore: it detects a flipped byte, a truncation, a corrupt header, a per-page checksum
//!   failure, and a misplaced page.
//!
//! # The "offline / consistent snapshot" guarantee (`04 §4.7`)
//!
//! "Offline" here means the store is **quiesced and hardened** before the snapshot is taken, so the
//! durable image is internally consistent with no in-flight torn state:
//!
//! 1. [`RecordStore::flush`] writes every dirty page home; the buffer pool enforces the WAL rule on
//!    each write-back (the log is durable through each page's `page_lsn`, `04 §4.3`), and the device
//!    is `sync`'d, so the durable image reflects every committed change.
//! 2. A fuzzy **checkpoint** is appended (`04 §4.7`): it marks the durable image as a clean,
//!    recoverable point. Because the snapshot is taken after a full flush, the captured pages are a
//!    complete and mutually consistent image — exactly the property the post-restore consistency
//!    check then re-proves.
//!
//! There is no online/incremental backup here; that is explicitly a later task (see the module-level
//! note in the crate docs). This module is the **offline** path and is fully deterministic, so it
//! runs unchanged over the in-memory DST device and over a file device (`04 §11`).
//!
//! # The artifact format (frozen here; mirrors `04 §2.1`, `05 §6`)
//!
//! All multi-byte integers are **little-endian**, matching the on-disk format (`04 §2.1`). The
//! artifact is three contiguous sections:
//!
//! ```text
//!  ┌──────────────────────────── header (44 bytes) ────────────────────────────┐
//!  │ magic        : [u8; 8]  = b"GRPHBKUP"      (artifact identity)             │
//!  │ format_ver   : u32      = BACKUP_FORMAT_VERSION                            │
//!  │ page_size    : u32      = PAGE_SIZE (asserted equal on restore/verify)     │
//!  │ creation_mark: u128     = the store's element-id-next at snapshot time     │
//!  │ page_count   : u64      = number of pages in the page section              │
//!  ├──────────────────────────── page section ─────────────────────────────────┤
//!  │ repeated page_count times, in ascending device-page order:                 │
//!  │   page_id : u64                                                            │
//!  │   bytes   : [u8; PAGE_SIZE]   (the full durable page, incl. its own CRC32C)│
//!  ├──────────────────────────── trailer (4 bytes) ────────────────────────────┤
//!  │ digest : u32 = CRC32C over every byte before this field                    │
//!  └────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! Two layers of integrity protection compose (`04 §4.6`): each page carries its **own** CRC32C in
//! its page header (so torn/bit-rot of any page body is caught), and the artifact carries a
//! **whole-payload CRC32C** trailer (so tampering *anywhere* — header, page ids, or the framing
//! between pages — is caught even when an attacker re-computes a per-page checksum).

use graphus_bufpool::page;
use graphus_core::PageId;
use graphus_core::error::{GraphusError, Result};
use graphus_io::{BlockDevice, MemBlockDevice, PAGE_SIZE, Page};
use graphus_wal::{LogSink, WalManager};

use crate::check::{IndexAgreement, verify_on_open};
use crate::store::RecordStore;

/// The artifact magic identifying a Graphus offline backup (ASCII `"GRPHBKUP"`).
pub const BACKUP_MAGIC: [u8; 8] = *b"GRPHBKUP";

/// The backup artifact format version, bumped on any incompatible artifact-layout change. Distinct
/// from [`graphus_core::constants::FORMAT_VERSION`] (the on-disk page format): the artifact frames
/// on-disk pages, so the two version axes are independent.
pub const BACKUP_FORMAT_VERSION: u32 = 1;

/// Byte length of the fixed artifact header: magic(8) + format_ver(4) + page_size(4) +
/// creation_mark(16) + page_count(8).
const HEADER_LEN: usize = 8 + 4 + 4 + 16 + 8;

/// Byte length of the per-page record in the page section: page_id(8) + the page bytes.
const PAGE_ENTRY_LEN: usize = 8 + PAGE_SIZE;

/// Byte length of the trailing whole-payload digest.
const DIGEST_LEN: usize = 4;

/// Produces a self-describing **offline backup artifact** for `store`, capturing a consistent
/// snapshot (`04 §4.7`).
///
/// The store is quiesced first — every dirty page is flushed home under the WAL rule and the device
/// is synced ([`RecordStore::flush`]) — then a clean fuzzy checkpoint is appended so the durable
/// image is a recoverable point. The artifact then frames **every durable page** of the store (the
/// metadata page plus every allocated record-store page, in ascending device-page order) with its
/// own page CRC32C intact, and appends a whole-payload CRC32C trailer (see the module docs for the
/// exact layout).
///
/// This is read-only with respect to the graph: it writes no record, frees no id, and interns no
/// token. The only durable side effect is the checkpoint marker, which is benign (it never changes
/// query-visible state).
///
/// # Errors
/// Returns a storage error if the flush, the checkpoint, or reading a durable page back through the
/// pool (which re-verifies its CRC32C, `04 §4.6`) fails — the last of which would mean the *source*
/// store is already corrupt, in which case the backup is correctly refused rather than propagating
/// corruption.
///
/// # Panics
/// Panics if the checkpoint's `fdatasync` fails (`04 §4.9`), inherited from
/// [`WalManager::checkpoint`].
pub fn backup_store<D: BlockDevice, S: LogSink>(store: &mut RecordStore<D, S>) -> Result<Vec<u8>> {
    // 1. Quiesce: flush every dirty page home (WAL rule enforced on each write-back) and sync.
    store.flush()?;
    // 2. Mark a clean, recoverable point. The snapshot is taken after a full flush, so no page is
    //    in-flight; an empty dirty-page table is therefore truthful here.
    store.with_wal(|w| w.checkpoint(&[]));

    // 3. Frame the durable image. `mapped_pages` is the authoritative durable set: the metadata
    //    page plus every allocated record-store page (`04 §2.1`). Sort + dedup so the page section
    //    is canonical (ascending device-page order) and verifiable position-by-position.
    let mut pages = store.mapped_pages();
    pages.sort_unstable();
    pages.dedup();

    let mut out = Vec::with_capacity(HEADER_LEN + pages.len() * PAGE_ENTRY_LEN + DIGEST_LEN);
    out.extend_from_slice(&BACKUP_MAGIC);
    out.extend_from_slice(&BACKUP_FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
    out.extend_from_slice(&store.element_id_next().to_le_bytes());
    out.extend_from_slice(&(pages.len() as u64).to_le_bytes());

    for p in &pages {
        // `read_device_page` goes through the pool's `fetch`, which verifies the on-disk CRC32C;
        // a corrupt source page surfaces here as an `Err`, refusing to back up corruption.
        let bytes = store.read_device_page(*p)?;
        out.extend_from_slice(&p.0.to_le_bytes());
        out.extend_from_slice(bytes.as_slice());
    }

    let digest = crc32c::crc32c(&out);
    out.extend_from_slice(&digest.to_le_bytes());
    Ok(out)
}

/// A structurally-validated view of a backup artifact, produced by [`parse`] and consumed by
/// [`verify_backup`] and the restore path. Borrows the artifact bytes; no page is copied.
#[derive(Debug)]
struct ParsedBackup<'a> {
    /// The creation marker (the store's element-id-next at snapshot time).
    creation_mark: u128,
    /// The framed pages, in artifact order: `(page_id, page_bytes)`.
    pages: Vec<(u64, &'a [u8])>,
}

/// Parses and structurally validates an artifact's framing **without** verifying the digest or the
/// per-page checksums (those are layered on by [`verify_backup`]). Checks: minimum length, magic,
/// format version, page size, and that the declared `page_count` exactly accounts for the bytes
/// between the header and the 4-byte digest trailer.
fn parse(artifact: &[u8]) -> Result<ParsedBackup<'_>> {
    if artifact.len() < HEADER_LEN + DIGEST_LEN {
        return Err(GraphusError::Storage(format!(
            "backup artifact too short: {} bytes (need at least {})",
            artifact.len(),
            HEADER_LEN + DIGEST_LEN
        )));
    }
    if artifact[0..8] != BACKUP_MAGIC {
        return Err(GraphusError::Storage(
            "backup artifact has a bad magic (not a Graphus backup)".to_owned(),
        ));
    }
    let format_ver = u32::from_le_bytes(artifact[8..12].try_into().expect("4-byte slice"));
    if format_ver != BACKUP_FORMAT_VERSION {
        return Err(GraphusError::Storage(format!(
            "unsupported backup format version {format_ver} (this build supports {BACKUP_FORMAT_VERSION})"
        )));
    }
    let page_size = u32::from_le_bytes(artifact[12..16].try_into().expect("4-byte slice")) as usize;
    if page_size != PAGE_SIZE {
        return Err(GraphusError::Storage(format!(
            "backup page size {page_size} does not match this build's page size {PAGE_SIZE}"
        )));
    }
    let creation_mark = u128::from_le_bytes(artifact[16..32].try_into().expect("16-byte slice"));
    let page_count =
        u64::from_le_bytes(artifact[32..40].try_into().expect("8-byte slice")) as usize;

    // The page section must exactly fill the gap between the header and the digest trailer.
    let body = artifact
        .len()
        .checked_sub(DIGEST_LEN)
        .and_then(|n| n.checked_sub(HEADER_LEN))
        .ok_or_else(|| GraphusError::Storage("backup artifact truncated".to_owned()))?;
    let expected = page_count.checked_mul(PAGE_ENTRY_LEN).ok_or_else(|| {
        GraphusError::Storage("backup page count overflows the addressable range".to_owned())
    })?;
    if body != expected {
        return Err(GraphusError::Storage(format!(
            "backup page section is {body} bytes but its header declares {page_count} page(s) ({expected} bytes)"
        )));
    }

    let mut pages = Vec::with_capacity(page_count);
    let mut cur = HEADER_LEN;
    for _ in 0..page_count {
        let page_id = u64::from_le_bytes(
            artifact[cur..cur + 8]
                .try_into()
                .expect("8-byte slice (bounds checked by section length)"),
        );
        let start = cur + 8;
        let end = start + PAGE_SIZE;
        pages.push((page_id, &artifact[start..end]));
        cur = end;
    }
    Ok(ParsedBackup {
        creation_mark,
        pages,
    })
}

/// Verifies a backup artifact's **structural validity and integrity** without performing a restore
/// (`rmp` task #23 verification). Detects, in order:
///
/// 1. a too-short artifact, a bad magic, an unsupported format version, a wrong page size, or a
///    page section whose length contradicts the declared page count (structural framing);
/// 2. a tampered whole-payload digest — any flipped byte anywhere before the trailer (the artifact's
///    CRC32C no longer matches);
/// 3. a per-page integrity fault — a framed page whose own page-header CRC32C fails (`04 §4.6`), or
///    a page whose self-referential `page_id` header (`05 §6`) disagrees with the `page_id` it is
///    framed under (a page written to / restored at the wrong slot).
///
/// A backup that passes this is structurally sound and has not been tampered with; whether it
/// *restores to a consistent graph* is additionally proven by the consistency check inside
/// [`restore`].
///
/// # Errors
/// Returns [`GraphusError::Storage`] describing the first fault found.
pub fn verify_backup(artifact: &[u8]) -> Result<()> {
    let parsed = parse(artifact)?;

    // Whole-payload digest: recompute over everything before the 4-byte trailer.
    let body_len = artifact.len() - DIGEST_LEN;
    let stored = u32::from_le_bytes(
        artifact[body_len..]
            .try_into()
            .expect("4-byte trailer (length checked by parse)"),
    );
    let computed = crc32c::crc32c(&artifact[..body_len]);
    if stored != computed {
        return Err(GraphusError::Storage(format!(
            "backup integrity digest mismatch: stored {stored:#010x}, computed {computed:#010x} (artifact tampered or truncated)"
        )));
    }

    // Per-page integrity: each framed page must pass its own CRC32C and sit at the page id its
    // header claims. This catches a page-body corruption that survived the digest only if the digest
    // were *also* re-faked, and a page restored to the wrong device slot.
    for (page_id, bytes) in &parsed.pages {
        let page: &Page = (*bytes)
            .try_into()
            .expect("page slice is exactly PAGE_SIZE (framed by parse)");
        if !page::verify_checksum(page) {
            return Err(GraphusError::Storage(format!(
                "backup page {page_id} failed its CRC32C (corrupt page body)"
            )));
        }
        let stored_id = page::page_id(page);
        if stored_id != *page_id {
            return Err(GraphusError::Storage(format!(
                "backup page framed as {page_id} carries header page_id {stored_id} (misplaced page)"
            )));
        }
    }
    Ok(())
}

/// Writes the pages of a **verified** backup artifact onto `device`, growing it as needed, then
/// hardens it. The device must be addressable from page `0`; pages are written at the device id each
/// was framed under, so the restored image is byte-identical to the source's durable image.
///
/// This is the device-agnostic restore primitive: pass a fresh [`MemBlockDevice`] (see [`restore`])
/// or a [`graphus_io::FileBlockDevice`] for a file-backed restore. It does **not** open or check the
/// store — callers that want the full safety guarantee use [`restore`], which also runs the
/// consistency checker.
///
/// # Errors
/// Returns a storage error if `verify_backup` fails or a device write/sync fails.
pub fn restore_onto<D: BlockDevice>(artifact: &[u8], device: &mut D) -> Result<()> {
    verify_backup(artifact)?;
    let parsed = parse(artifact)?;

    let max_id = parsed.pages.iter().map(|(id, _)| *id).max();
    if let Some(max_id) = max_id {
        let needed = max_id + 1;
        if device.page_count() < needed {
            device.extend(needed - device.page_count())?;
        }
    }
    for (page_id, bytes) in &parsed.pages {
        let page: &Page = (*bytes)
            .try_into()
            .expect("page slice is exactly PAGE_SIZE (framed by parse)");
        device.write_page(PageId(*page_id), page)?;
    }
    device.sync_all()?;
    Ok(())
}

/// Restores a backup artifact to a fresh in-memory store and **proves it is consistent** before
/// returning it (`rmp` task #23: "Backups restore to a consistent state").
///
/// The artifact is verified ([`verify_backup`]), its pages are written onto a fresh
/// [`MemBlockDevice`] ([`restore_onto`]), a [`RecordStore`] is opened over the device with a fresh
/// (empty) WAL, and finally [`verify_on_open`] runs the full consistency pass — so a backup that
/// somehow framed an internally-inconsistent image (e.g. a record corrupted in a way that still
/// passed the per-page and whole-payload digests) is **rejected** rather than served (`04 §4.6`).
///
/// `pool_capacity` sizes the restored store's buffer pool; `wal` is a freshly-created WAL for the
/// restored store (the backup captures the **data** image at a clean checkpoint, so no WAL replay is
/// needed — the restored device is already at a consistent point).
///
/// # Errors
/// Returns a storage error if verification, the device restore, opening the store, or the post-
/// restore consistency check fails.
pub fn restore<S: LogSink>(
    artifact: &[u8],
    wal: WalManager<S>,
    pool_capacity: usize,
) -> Result<RecordStore<MemBlockDevice, S>> {
    let mut device = MemBlockDevice::new(0);
    restore_onto(artifact, &mut device)?;
    let mut store = RecordStore::open(device, wal, pool_capacity)?;
    let indexes: &[IndexAgreement] = &[];
    verify_on_open(&mut store, indexes)?;
    Ok(store)
}

/// The element-id-next creation marker embedded in a backup artifact (the value the source store
/// would next allocate, `04 §2.2`), recovered without a restore. Useful for an operator to confirm
/// which snapshot an artifact is.
///
/// # Errors
/// Returns a storage error if the artifact is structurally invalid.
pub fn backup_creation_marker(artifact: &[u8]) -> Result<u128> {
    Ok(parse(artifact)?.creation_mark)
}

#[cfg(test)]
mod tests {
    //! Unit tests for the pure parse/verify surface; the heavy round-trip and tamper-detection
    //! tests (which build real stores) live in `tests/backup.rs`.
    use super::*;

    /// A minimal, well-formed artifact: header + zero pages + a correct digest.
    fn empty_artifact() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&BACKUP_MAGIC);
        out.extend_from_slice(&BACKUP_FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
        out.extend_from_slice(&7u128.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        let digest = crc32c::crc32c(&out);
        out.extend_from_slice(&digest.to_le_bytes());
        out
    }

    #[test]
    fn empty_artifact_parses_and_verifies() {
        let a = empty_artifact();
        let p = parse(&a).expect("parse");
        assert_eq!(p.creation_mark, 7);
        assert!(p.pages.is_empty());
        verify_backup(&a).expect("verify");
        assert_eq!(backup_creation_marker(&a).unwrap(), 7);
    }

    #[test]
    fn too_short_artifact_is_rejected() {
        assert!(parse(&[0u8; 4]).is_err());
        assert!(verify_backup(&[0u8; 4]).is_err());
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut a = empty_artifact();
        a[0] ^= 0xFF;
        // The digest still matches the (now wrong-magic) bytes, so the magic check is what fires.
        let digest = crc32c::crc32c(&a[..a.len() - DIGEST_LEN]);
        let n = a.len() - DIGEST_LEN;
        a[n..].copy_from_slice(&digest.to_le_bytes());
        let err = verify_backup(&a).unwrap_err().to_string();
        assert!(err.contains("magic"), "got: {err}");
    }

    #[test]
    fn wrong_format_version_is_rejected() {
        let mut a = empty_artifact();
        a[8..12].copy_from_slice(&(BACKUP_FORMAT_VERSION + 1).to_le_bytes());
        assert!(parse(&a).is_err());
    }

    #[test]
    fn wrong_page_size_is_rejected() {
        let mut a = empty_artifact();
        a[12..16].copy_from_slice(&((PAGE_SIZE as u32) + 1).to_le_bytes());
        assert!(parse(&a).is_err());
    }

    #[test]
    fn declared_page_count_must_match_section_length() {
        let mut a = empty_artifact();
        // Claim one page while the section is empty.
        a[32..40].copy_from_slice(&1u64.to_le_bytes());
        let err = parse(&a).unwrap_err().to_string();
        assert!(err.contains("page section"), "got: {err}");
    }

    #[test]
    fn flipped_digest_byte_is_caught() {
        let mut a = empty_artifact();
        let last = a.len() - 1;
        a[last] ^= 0x01;
        let err = verify_backup(&a).unwrap_err().to_string();
        assert!(err.contains("digest"), "got: {err}");
    }
}
