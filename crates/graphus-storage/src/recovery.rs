//! Crash recovery wiring: replaying the WAL onto the raw device (`04-technical-design.md` §4.8).
//!
//! After an unclean shutdown the WAL holds the only durable record of committed work (no-force)
//! and possibly stolen, uncommitted pages (steal). [`recover_device`] runs the WAL's three-phase
//! ARIES recovery ([`graphus_wal::recover`]) against a [`DeviceTarget`] that applies redo/undo
//! intra-page patches directly to the [`BlockDevice`], reading each page's `page_lsn` from its
//! header to guard redo (`record.lsn > page_lsn`). After it returns, the device's pages — the
//! metadata page included — are at the last durable committed-or-nothing state, and
//! [`crate::RecordStore::open`] reloads the in-memory catalog from them.
//!
//! Recovery operates on the **raw device**, not the buffer pool, because (a) there is no
//! concurrency during recovery, (b) it must read each page's `page_lsn` to guard redo, and (c)
//! keeping the pool out avoids a self-referential WAL borrow through the pool's WAL rule.

use graphus_bufpool::page;
use graphus_core::error::Result;
use graphus_core::{Lsn, PageId};
use graphus_io::{BlockDevice, PAGE_SIZE, Page};
use graphus_wal::{ApplyTarget, LogSink, RecoveryReport, WalManager, recover, recover_from};

/// An [`ApplyTarget`] that applies WAL redo/undo intra-page patches directly to a
/// [`BlockDevice`].
///
/// On `apply` it reads the page, patches it, re-stamps its `page_lsn` and the page header
/// checksum, and writes it back (the write becomes durable on the final [`DeviceTarget::sync`]).
/// `page_lsn` reads the page header so redo can skip changes already reflected on a page
/// (no-force after a partial flush).
pub struct DeviceTarget<'a, D: BlockDevice> {
    device: &'a mut D,
}

impl<'a, D: BlockDevice> DeviceTarget<'a, D> {
    /// Wraps a device as a recovery apply target.
    pub fn new(device: &'a mut D) -> Self {
        Self { device }
    }

    /// Grows the device with zero pages until `page` is addressable (no-force redo can reference a
    /// page the device was not flushed up to), returning the (possibly grown) page index.
    fn ensure(&mut self, page: PageId) -> Result<()> {
        if page.0 >= self.device.page_count() {
            let additional = page.0 - self.device.page_count() + 1;
            self.device.extend(additional)?;
        }
        Ok(())
    }

    /// Hardens every applied page durably.
    ///
    /// # Errors
    /// Returns a storage error if the device sync fails.
    pub fn sync(&mut self) -> Result<()> {
        self.device.sync_all()
    }
}

impl<D: BlockDevice> ApplyTarget for DeviceTarget<'_, D> {
    fn page_lsn(&self, page: PageId) -> Lsn {
        if page.0 >= self.device.page_count() {
            return Lsn(0);
        }
        let mut buf: Page = [0u8; PAGE_SIZE];
        // A read failure OR a failed page checksum means the page's stored `page_lsn` cannot be trusted;
        // treat its lsn as `0` so redo replays every change for it (idempotent: physiological redo
        // overwrites the region with the post-image anyway, rebuilding the page from the log).
        //
        // The checksum check is load-bearing (`rmp` #592, F A-#1). Recovery's OWN redo/undo page writes
        // bypass the doublewrite buffer (they are a buffered `pwrite` deferred to the final `sync()`), so
        // a torn writeback of a recovered page + a second crash before that `sync` leaves the page torn.
        // On the next recovery the doublewrite `recover_home` does NOT name it (recovery never staged it),
        // and — for an unencrypted device — the torn page READS SUCCESSFULLY with a large, intact header
        // `page_lsn`: without verifying the checksum, `rec.lsn > page_lsn` would be false, redo would be
        // SKIPPED, and the tear would survive recovery (committed data left inaccessible until a restore).
        // Verifying the checksum here makes redo re-apply every record for a torn page, healing it.
        // (The encrypted device is already safe: an AEAD read of a torn page fails, so `read_page` errors
        // and the first guard fires — this second guard closes the plaintext gap.)
        if self.device.read_page(page, &mut buf).is_err() || !page::verify_checksum(&buf) {
            return Lsn(0);
        }
        page::page_lsn(&buf)
    }

    fn apply(&mut self, page: PageId, lsn: Lsn, image: &[u8]) -> Result<()> {
        self.ensure(page)?;
        let mut buf: Page = [0u8; PAGE_SIZE];
        self.device.read_page(page, &mut buf)?;
        crate::paging::apply_patch(&mut buf, image)?;
        // The page is REBUILT here, not amended: a page that failed its checksum reports an LSN of
        // `0` above so redo replays every record for it, and a monotone stamp would retain the torn
        // header's garbage LSN and skip the whole rebuild (`rmp` #1029). See `reset_page_lsn`.
        page::reset_page_lsn(&mut buf, lsn);
        page::set_page_id(&mut buf, page.0);
        page::write_checksum(&mut buf);
        self.device.write_page(page, &buf)
    }
}

/// Runs three-phase ARIES recovery of `wal` onto `device`, leaving its pages at the last durable
/// committed-or-nothing state. Hardens the device before returning.
///
/// # Errors
/// Propagates a WAL read, apply, or device sync failure.
///
/// # Panics
/// Panics if hardening the CLRs written during undo fails (`04 §4.9`).
pub fn recover_device<S: LogSink, D: BlockDevice>(
    wal: &mut WalManager<S>,
    device: &mut D,
) -> Result<RecoveryReport> {
    let mut target = DeviceTarget::new(device);
    let report = recover(wal, &mut target)?;
    target.sync()?;
    Ok(report)
}

/// Like [`recover_device`], but first repairs any **torn home page** from the doublewrite buffer
/// (`05 §3`, `04 §4.5`) **before** ARIES redo runs.
///
/// This closes the torn-data-page durability hole: a power loss mid-write can leave a home page
/// half-old/half-new, whose header — and therefore its `page_lsn` — is garbage. ARIES redo gates each
/// change on that `page_lsn` ([`recover`]: `record.lsn > page_lsn`), so a torn page reading a
/// junk-but-large `page_lsn` would have its redo **skipped** and the corrupt page served. Running the
/// DWB repair first restores every torn home page from its intact doublewrite copy, so redo reads a
/// trustworthy `page_lsn` from every page.
///
/// Ordering is the crux: the DWB copy was made durable *before* the home write began
/// ([`crate::dwb::Dwb::stage_batch`]), so at the crash point one intact copy of each in-flight page
/// always exists, and a page that fails its home checksum is repaired from the DWB before any redo
/// decision depends on its header.
///
/// # Errors
/// Propagates a DWB read/repair failure (including an unrepairable double fault, surfaced never
/// hidden, `04 §4.6`), or an [`ApplyTarget::apply`]/sink/sync failure from the subsequent recovery.
///
/// # Panics
/// Panics if hardening the CLRs written during undo fails (`04 §4.9`).
pub fn recover_device_with_dwb<S: LogSink, D: BlockDevice, W: BlockDevice>(
    wal: &mut WalManager<S>,
    device: &mut D,
    dwb: &mut crate::dwb::Dwb<W>,
) -> Result<RecoveryReport> {
    // Phase 0: torn-write repair from the doublewrite buffer, before any redo reads a `page_lsn`.
    dwb.recover_home(device)?;
    recover_device(wal, device)
}

/// Like [`recover_device`], but begins the WAL analysis scan at `scan_start` instead of right after
/// the header ([`graphus_wal::recover_from`]). Used by the backup-chain point-in-time restore
/// (`rmp` task #71), whose reconstructed logical WAL has its first record at the chain's `base_lsn`,
/// with an unscanned gap in `[HEADER_LEN, base_lsn)`. For a normal crash recovery use
/// [`recover_device`].
///
/// # Errors
/// Propagates a WAL read, apply, or device sync failure.
///
/// # Panics
/// Panics if hardening the CLRs written during undo fails (`04 §4.9`).
pub fn recover_device_from<S: LogSink, D: BlockDevice>(
    wal: &mut WalManager<S>,
    device: &mut D,
    scan_start: Lsn,
) -> Result<RecoveryReport> {
    let mut target = DeviceTarget::new(device);
    let report = recover_from(wal, &mut target, scan_start)?;
    target.sync()?;
    Ok(report)
}

/// **Resolves the catalogue's pending-DDL block against the log that decides it, on the device**
/// (`rmp` #1083) — for a restore that replays a WAL onto a device and then **discards** it.
///
/// # Why a restore must do this and a crash recovery must not
///
/// The block (`crate::meta::PendingSchema`) names the transaction whose commit wrote the catalogue
/// image, and `RecordStore::open` applies it only if it finds that transaction's `COMMIT` record —
/// **defaulting to drop**. That decision is only meaningful against the log the image was written
/// against. A crash recovery reopens over that same log, so `open` decides correctly and nothing
/// else is needed.
///
/// An **incremental / point-in-time restore does not**. Its increments are raw WAL bytes, so redo
/// re-materialises the metadata page exactly as it stood — block included — and the restored
/// database is then opened over a *fresh, empty* WAL. `committed_txns` would be empty, the block
/// would be dropped, and a **committed** `CREATE CONSTRAINT` at the tail of the restored chain would
/// be gone. That is silent loss of committed schema, so the decision is taken HERE, while the
/// deciding log is still in hand, and written down.
///
/// # What it writes
///
/// The resolved catalogue, over the existing metadata-page chain, with no WAL record. That is sound
/// because it is not a transactional change: it replaces an image with the image that same log says
/// it means, at a point where the device is quiescent and the log is about to be thrown away.
///
/// The re-encoded payload is never longer than the one it replaces — folding moves the block's
/// schema into the committed half and drops the (duplicate) block, and dropping removes it outright
/// — so the existing chain always has room, and chunks past the new end are written empty exactly as
/// [`RecordStore::checkpoint_meta`](crate::RecordStore) writes them.
///
/// A no-op when the image carries no block, which is every image written outside a DDL commit.
///
/// # Errors
/// Propagates a device read/write failure, or a storage error if the metadata chain is unreadable,
/// cyclic, or decodes to a catalogue this build cannot read.
pub fn resolve_pending_ddl_on_device<S: LogSink, D: BlockDevice>(
    wal: &WalManager<S>,
    device: &mut D,
) -> Result<()> {
    let (mut meta, chain) = read_device_meta(device)?;
    let Some(pending) = meta.pending_ddl.take() else {
        return Ok(());
    };
    // The same predicate `RecordStore::open` applies, against the log that is about to be discarded.
    let committed = wal
        .recovered_transactions()?
        .commits
        .iter()
        .any(|&(txn, _, _)| txn.0 == pending.txn);
    if committed {
        meta.statistics.adopt_schema_from(pending.schema);
    }
    write_device_meta(device, &chain, &meta.encode()?)?;
    device.sync_all()
}

/// Reads and decodes the catalogue by walking the metadata-page chain **directly on the device**,
/// returning it with the page ids it spans (head first).
///
/// The buffer-pool twin is `RecordStore::read_meta`; this exists because a restore holds a bare
/// device and no pool. The framing is the same: `len: u32 | next: u64 | chunk` at
/// [`page::HEADER_SIZE`], with bit 31 of `len` the format tripwire rather than a length.
fn read_device_meta<D: BlockDevice>(device: &mut D) -> Result<(crate::meta::Meta, Vec<PageId>)> {
    let mut payload = Vec::new();
    let mut chain = vec![PageId(0)];
    let mut page = PageId(0);
    let mut buf = Box::new([0u8; PAGE_SIZE]);
    loop {
        device.read_page(page, &mut buf)?;
        let framed = u32::from_le_bytes(
            buf[page::HEADER_SIZE..page::HEADER_SIZE + 4]
                .try_into()
                .expect("4-byte slice"),
        );
        let chunk_len = (framed & 0x7fff_ffff) as usize;
        let next = u64::from_le_bytes(
            buf[page::HEADER_SIZE + 4..page::HEADER_SIZE + 12]
                .try_into()
                .expect("8-byte slice"),
        );
        let start = page::HEADER_SIZE + 12;
        if start + chunk_len > buf.len() {
            return Err(graphus_core::GraphusError::Storage(
                "metadata chunk runs past the page".to_owned(),
            ));
        }
        payload.extend_from_slice(&buf[start..start + chunk_len]);
        if next == 0 {
            break;
        }
        let next = PageId(next);
        // The same cycle guard `RecordStore::read_meta` applies, for the same reason: a damaged
        // chain must fail rather than loop for ever.
        if chain.contains(&next) {
            return Err(graphus_core::GraphusError::Storage(
                "metadata chain is cyclic or points at the head page".to_owned(),
            ));
        }
        chain.push(next);
        page = next;
    }
    Ok((crate::meta::Meta::decode(&payload)?, chain))
}

/// Writes `payload` back over the metadata-page `chain`, preserving each page's header and the head
/// page's format tripwire, and stamping a fresh checksum.
///
/// # Errors
/// Returns a storage error if `payload` does not fit the chain it was given — which cannot happen
/// for the shrinking rewrite [`resolve_pending_ddl_on_device`] performs, and is checked rather than
/// assumed because writing a truncated catalogue would be unrecoverable.
fn write_device_meta<D: BlockDevice>(
    device: &mut D,
    chain: &[PageId],
    payload: &[u8],
) -> Result<()> {
    /// Bytes of catalogue one metadata page carries (mirrors `store::META_CHUNK_CAP`).
    const CHUNK_CAP: usize = PAGE_SIZE - page::HEADER_SIZE - 12;
    /// Bit 31 of the framed length: the format tripwire on the head page (`store::META_FORMAT_V2_FLAG`).
    const FORMAT_FLAG: u32 = 0x8000_0000;

    if payload.len() > chain.len() * CHUNK_CAP {
        return Err(graphus_core::GraphusError::Storage(format!(
            "the resolved catalogue is {} bytes but its {} metadata page(s) hold {}; refusing to \
             write a truncated catalogue (`rmp` #1083)",
            payload.len(),
            chain.len(),
            chain.len() * CHUNK_CAP
        )));
    }
    let mut buf = Box::new([0u8; PAGE_SIZE]);
    for (i, &page_id) in chain.iter().enumerate() {
        // Read-modify-write: the page's own header (type, id, `page_lsn`) must survive untouched.
        device.read_page(page_id, &mut buf)?;
        let lo = (i * CHUNK_CAP).min(payload.len());
        let hi = ((i + 1) * CHUNK_CAP).min(payload.len());
        let chunk = &payload[lo..hi];
        let next = chain.get(i + 1).map_or(0, |p| p.0);
        let framed = if i == 0 {
            chunk.len() as u32 | FORMAT_FLAG
        } else {
            chunk.len() as u32
        };
        let at = page::HEADER_SIZE;
        buf[at..at + 4].copy_from_slice(&framed.to_le_bytes());
        buf[at + 4..at + 12].copy_from_slice(&next.to_le_bytes());
        buf[at + 12..at + 12 + chunk.len()].copy_from_slice(chunk);
        page::write_checksum(&mut buf);
        device.write_page(page_id, &buf)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_io::MemBlockDevice;
    use graphus_wal::MemLogSink;

    #[test]
    fn device_target_applies_a_patch_and_stamps_lsn() {
        let mut dev = MemBlockDevice::new(1);
        {
            let mut t = DeviceTarget::new(&mut dev);
            let patch = crate::paging::encode_patch(100, &[1, 2, 3, 4]);
            t.apply(PageId(0), Lsn(42), &patch).unwrap();
            t.sync().unwrap();
        }
        let mut buf = [0u8; PAGE_SIZE];
        dev.read_page(PageId(0), &mut buf).unwrap();
        assert_eq!(&buf[100..104], &[1, 2, 3, 4]);
        assert_eq!(page::page_lsn(&buf), Lsn(42));
        assert!(page::verify_checksum(&buf));
    }

    /// `rmp` #592 (sprint-52 F A-#1): a page torn during recovery (a valid, intact header `page_lsn`
    /// but a body that fails the checksum) must report `page_lsn == 0`, so recovery redo re-applies every
    /// record for it (healing the tear) instead of trusting the stale header lsn and SKIPPING redo. Before
    /// the checksum check the torn page read back successfully and `page_lsn` returned its (large) stored
    /// lsn, so `rec.lsn > page_lsn` was false and the tear survived recovery.
    #[test]
    fn page_lsn_of_a_torn_page_is_zero_so_recovery_redo_reapplies_it() {
        let mut dev = MemBlockDevice::new(1);
        {
            let mut t = DeviceTarget::new(&mut dev);
            let patch = crate::paging::encode_patch(100, &[1, 2, 3, 4]);
            t.apply(PageId(0), Lsn(100), &patch).unwrap();
            t.sync().unwrap();
        }
        // A checksum-valid page reports its stored lsn (redo correctly SKIPS it when already applied).
        assert_eq!(DeviceTarget::new(&mut dev).page_lsn(PageId(0)), Lsn(100));

        // Tear it: flip a body byte in place, leaving the now-stale checksum and the intact header
        // `page_lsn` — exactly a torn writeback of a recovered page (recovery's writes bypass the DWB).
        let mut buf = [0u8; PAGE_SIZE];
        dev.read_page(PageId(0), &mut buf).unwrap();
        assert!(page::verify_checksum(&buf));
        buf[101] ^= 0xFF; // corrupt the body; deliberately do NOT recompute the checksum
        assert!(
            !page::verify_checksum(&buf),
            "the tear must break the checksum"
        );
        assert_eq!(
            page::page_lsn(&buf),
            Lsn(100),
            "but the header lsn is still intact"
        );
        dev.write_page(PageId(0), &buf).unwrap();

        assert_eq!(
            DeviceTarget::new(&mut dev).page_lsn(PageId(0)),
            Lsn(0),
            "#592: a torn page (bad checksum) must report lsn 0 so recovery redo re-applies it"
        );
    }

    #[test]
    fn device_target_grows_for_an_out_of_range_page() {
        let mut dev = MemBlockDevice::new(1);
        {
            let mut t = DeviceTarget::new(&mut dev);
            let patch = crate::paging::encode_patch(0, &[9]);
            t.apply(PageId(3), Lsn(1), &patch).unwrap(); // page 3 does not exist yet
            t.sync().unwrap();
        }
        assert!(dev.page_count() >= 4);
    }

    #[test]
    fn recover_on_empty_log_is_a_noop() {
        let wal = WalManager::create(MemLogSink::new()).unwrap();
        let sink = wal.sink().clone();
        let mut wal2 = WalManager::open(sink).unwrap();
        let mut dev = MemBlockDevice::new(1);
        let report = recover_device(&mut wal2, &mut dev).unwrap();
        assert_eq!(report.redo_applied, 0);
        assert_eq!(report.losers, 0);
    }
}
