//! [`EncryptedBlockDevice`]: a [`graphus_io::BlockDevice`] that stores each logical page as one
//! authenticated-encryption slot, transparent to everything above the seam (buffer pool,
//! checkpoint, recovery, consistency checker).
//!
//! ## Layout
//!
//! Physical slot 0 holds the [`Header`] (magic, version, salt, KCV) and is written **once, at
//! create**. Logical page `p` is stored at physical slot `p + HEADER_SLOTS`. Each page slot is
//! `nonce(12) || tag(16) || ciphertext(8192)` (see [`crate::slot`]). The logical page count is **not**
//! persisted in the header; it is derived from the backing slot count
//! (`backing.slot_count() - HEADER_SLOTS`), the single source of truth (see the crash-consistency
//! note below).
//!
//! ## Nonce and AAD
//!
//! Every `write_page` draws a **fresh random 96-bit nonce** from the OS CSPRNG and stores it in the
//! slot. With a random nonce the only way to reuse a (key, nonce) pair is a 96-bit birthday
//! collision; standard guidance is to rotate the key well before ~2^32 writes per key (random-nonce
//! GCM keeps the collision probability negligible up to that order of magnitude). **Key rotation is
//! sub-task #86.** The AEAD **associated data** is the 8-byte little-endian `page_id`, so the
//! authentication tag binds the ciphertext to its offset: a slot moved to another page's offset
//! fails to authenticate (a page cannot be silently relocated).
//!
//! ## Crash-consistency
//!
//! A page's whole encrypted record is one slot written with a single positioned write, so a torn or
//! partial physical write corrupts exactly one slot and is **detected** by AEAD verification on read
//! (the tag will not validate) — the same one-page blast radius and fail-closed behaviour as the
//! plaintext device's per-page CRC. `sync_data`/`sync_all` forward unchanged to the backing, so the
//! durability ordering the buffer pool relies on (the WAL rule) is preserved exactly.
//!
//! ### Page count is derived, not stored
//!
//! The logical page count is **not** persisted in the header — it is always
//! `backing.slot_count() - HEADER_SLOTS`, the single source of truth. This deliberately avoids a
//! crash-consistency divergence: `extend` grows the file with `set_len` (an `i_size` metadata change),
//! and on a common filesystem (e.g. ext4 `data=ordered`) that metadata change can become durable while
//! a buffered header rewrite is lost on a crash before the next sync. Were the count also stored in the
//! header, the durable `set_len` and the stale header would then disagree, and a strict equality check
//! at open would refuse to open a store the WAL/recovery layer could otherwise recover. By deriving the
//! count from the backing, the durable slot count is authoritative: any extra slots a crashed `extend`
//! left behind simply read back as pristine zero pages (the never-written-page contract), exactly as a
//! zero-`extend`ed-but-unwritten page does on the plaintext device. Recovery's read-modify-write then
//! re-initialises them. The header is therefore written exactly once (at create) and never again, which
//! also removes a latent whole-store-corruption risk: a torn write to slot 0 (magic/salt/KCV — needed
//! to open the *whole* store) on every `extend`.
//!
//! This derived-page-count invariant is exactly **why the bare-zero read path in [`read_page`] is
//! retained** (rmp #87): because a crash mid-`extend` can leave durable-but-all-zero slots that the
//! count includes and recovery's read-modify-write must read back as zeros (not fail closed), the
//! all-zero slot cannot be made a real AEAD slot without either syncing inside `extend` (unacceptable)
//! or redesigning the crash-consistency model. Writing `enc(zero-page)` on `extend` would re-open that
//! crash window (the `set_len` is durable before the content writes are synced) while adding ~2x write
//! amplification per allocation — so it is *not* done. The residual integrity gap (an active live-disk
//! attacker zeroing a real slot reads back as zeros, bypassing the tag) is **outside** the at-rest
//! (stolen-disk *confidentiality*) threat model and is **defeated in practice** for the real consumer:
//! the storage layer verifies each page's CRC32C header on read, which an all-zero page fails. See the
//! KNOWN LIMITATION block in [`read_page`] for the full bound and the regression tests that pin it.

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use graphus_core::PageId;
use graphus_core::error::{GraphusError, Result};
use graphus_io::{BlockDevice, Page};

use crate::header::{HEADER_SLOTS, Header};
use crate::keyring::Keyring;
use crate::raw::RawSlots;
use crate::slot::{self, NONCE_LEN, SLOT_SIZE, Slot, TAG_LEN};

/// A [`BlockDevice`] that encrypts each logical page into one authenticated slot of its backing
/// [`RawSlots`].
///
/// Construct it with [`EncryptedBlockDevice::create`] (writes a fresh header) or
/// [`EncryptedBlockDevice::open`] (validates the header + KCV against the keyring, failing closed on
/// a wrong/missing key or a non-encrypted file).
pub struct EncryptedBlockDevice<R: RawSlots> {
    backing: R,
    cipher: Aes256Gcm,
    /// Number of **logical** pages (excludes the header slot). This is an in-memory cache of the
    /// authoritative value, which is always `backing.slot_count() - HEADER_SLOTS`; `open` seeds it
    /// from the backing and `extend` advances it in step. The header does **not** store it (see the
    /// crash-consistency note in the module docs).
    page_count: u64,
}

impl<R: RawSlots> std::fmt::Debug for EncryptedBlockDevice<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedBlockDevice")
            .field("page_count", &self.page_count)
            .finish_non_exhaustive()
    }
}

impl<R: RawSlots> EncryptedBlockDevice<R> {
    /// Creates a **fresh** encrypted device on an empty backing: writes the header slot **once**
    /// (magic, version, a freshly-generated salt, and the keyring's KCV), with zero logical pages. The
    /// header is never rewritten after this — the logical page count is derived from the backing slot
    /// count, not stored (see the module's crash-consistency note).
    ///
    /// The keyring passed in is assumed to have been derived with the salt this call generates; in
    /// the production path the caller derives the keyring *from* this salt (see the server wiring),
    /// so create takes the salt explicitly to keep that single source of truth.
    ///
    /// # Errors
    /// [`GraphusError::Storage`] if the backing is non-empty or a raw write/sync fails;
    /// [`GraphusError::Security`] if the KCV cannot be computed.
    pub fn create(
        mut backing: R,
        keyring: &Keyring,
        salt: [u8; crate::keyring::SALT_LEN],
    ) -> Result<Self> {
        if backing.slot_count() != 0 {
            return Err(GraphusError::Storage(
                "EncryptedBlockDevice::create requires an empty backing".to_owned(),
            ));
        }
        let kcv = keyring.compute_store_kcv()?;
        let header = Header { salt, kcv };
        // Reserve and write the header slot, then make it durable before the device is usable.
        backing.extend(HEADER_SLOTS)?;
        backing.write_slot(0, &header.encode())?;
        backing.sync_all()?;
        Ok(Self {
            backing,
            cipher: keyring.store_cipher(),
            page_count: 0,
        })
    }

    /// **Opens** an existing encrypted device: reads + validates the header, generates the cipher
    /// from the keyring, and verifies the persisted KCV against the keyring **before any page read**
    /// — a wrong or missing key fails closed here.
    ///
    /// Returns both the device and the header's salt, so a caller that needs to re-derive a keyring
    /// from the stored salt can do so. In the production path the keyring is derived from the salt
    /// *before* calling open (the header read on a probe pass supplies it); see the server wiring.
    ///
    /// The logical page count is taken from the backing slot count
    /// (`slot_count - HEADER_SLOTS`), the single source of truth — the header does not store it, so a
    /// crash mid-`extend` that left the file grown but a header rewrite unsynced can never make a
    /// recoverable store refuse to open (see the module's crash-consistency note). Any slots an
    /// interrupted `extend` left behind read back as pristine zero pages until written.
    ///
    /// # Errors
    /// [`GraphusError::Security`] if the file is not an encrypted Graphus store (wrong magic) or the
    /// key is wrong (KCV mismatch); [`GraphusError::Storage`] on an unsupported version/cipher,
    /// corrupt header, or a raw I/O failure.
    pub fn open(backing: R, keyring: &Keyring) -> Result<Self> {
        let slot_count = backing.slot_count();
        if slot_count < HEADER_SLOTS {
            return Err(GraphusError::Storage(
                "encrypted device is too small to contain a header".to_owned(),
            ));
        }
        let mut header_slot = [0u8; SLOT_SIZE];
        backing.read_slot(0, &mut header_slot)?;
        let header = Header::decode(&header_slot)?;
        // Fail closed on a wrong/missing key BEFORE reading any page (defence in depth: a page read
        // would also fail the AEAD tag, but the KCV gives an immediate, unambiguous error).
        keyring.verify_store_kcv(&header.kcv)?;

        // The backing slot count is authoritative for the logical page count. There is intentionally
        // no header/slot-count equality check: a count stored in the header could diverge from a
        // durable `set_len` on a crash mid-`extend` and would then falsely reject a recoverable store.
        Ok(Self {
            backing,
            cipher: keyring.store_cipher(),
            page_count: slot_count - HEADER_SLOTS,
        })
    }

    /// Reads the header slot of `backing` and returns its [`Header`] (for the production probe pass
    /// that needs the salt to derive the keyring before [`open`](Self::open)).
    ///
    /// # Errors
    /// As [`Header::decode`], plus [`GraphusError::Storage`] on a raw read failure or a too-small
    /// backing.
    pub fn read_header(backing: &R) -> Result<Header> {
        if backing.slot_count() < HEADER_SLOTS {
            return Err(GraphusError::Storage(
                "encrypted device is too small to contain a header".to_owned(),
            ));
        }
        let mut header_slot = [0u8; SLOT_SIZE];
        backing.read_slot(0, &mut header_slot)?;
        Header::decode(&header_slot)
    }

    /// Consumes the device and returns its raw backing (so a caller can reopen it with a different
    /// keyring — e.g. to assert a wrong key fails closed).
    #[must_use]
    pub fn into_backing(self) -> R {
        self.backing
    }

    /// The associated data for `page`: its 8-byte little-endian id, binding the ciphertext to its
    /// offset.
    fn aad(page: PageId) -> [u8; 8] {
        page.0.to_le_bytes()
    }
}

impl<R: RawSlots> BlockDevice for EncryptedBlockDevice<R> {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        if page.0 >= self.page_count {
            return Err(GraphusError::Storage(format!(
                "read out of range: page {} of {}",
                page.0, self.page_count
            )));
        }
        let mut s: Slot = [0u8; SLOT_SIZE];
        self.backing.read_slot(page.0 + HEADER_SLOTS, &mut s)?;

        // A never-written page is a zero-filled slot: it reads back as a zero page, exactly as on
        // the plaintext device (a freshly `extend`ed page is zero bytes there too). This is the
        // analogue the storage/recovery layer relies on — `extend` zero-fills, and recovery's
        // read-modify-write (`DeviceTarget::apply`) reads a page before patching it, so a page that
        // was zero-extended but never written must read back as zeros rather than fail closed.
        //
        // This does NOT weaken integrity: a genuine encrypted slot is never all-zero. Every real
        // `write_page` draws a fresh random 96-bit nonce and produces a 128-bit GCM tag, so the
        // probability a real slot is all-zero is at most 2^-96 (the nonce alone) — negligible. A
        // torn or partial write of a *real* page leaves a non-zero slot (the old or new bytes
        // disagree with the tag), so it still fails AEAD verification below. Only the genuinely
        // pristine zero slot takes this path.
        //
        // KNOWN LIMITATION (documented + bounded, rmp #87; outside the at-rest threat model):
        // because an all-zero slot is read as a zero page WITHOUT AEAD verification, an *active*
        // attacker with write access to the live disk could overwrite a real page's slot with zeros
        // and have it read back as a zero page — the tag is bypassed for an all-zero slot, so AEAD
        // does not detect this *one* substitution (zeroing). This is explicitly out of scope for the
        // documented at-rest (stolen-disk *confidentiality*) threat model, which assumes an attacker
        // who can read but not actively tamper with the live disk.
        //
        // Residual-risk bound — it is *defeated in practice for the real consumer*: the storage layer
        // never reads a page through this device without verifying that page's own CRC32C header
        // (`graphus_bufpool::BufferPool::fetch` / `ConcurrentBufferPool::load_into`). An all-zero
        // page fails that check, because `crc32c` of an all-zero page body is `0xfc1c38a5` (non-zero)
        // while the stored checksum field of a zero page is `0` — so a zeroed-out *real* page is
        // rejected as "page N failed checksum verification" before any use. (The encrypted-crate
        // regression `storage_rejects_a_zeroed_out_real_page_via_crc32c` proves exactly this.) The
        // only slot that legitimately reaches this bare-zero path is a genuinely pristine
        // never-written page, whose CRC the storage layer never trusts (allocation builds a fresh
        // page in memory with a valid checksum; it does not read the bare slot).
        //
        // Why we do NOT replace this with `enc(zero-page)`-on-extend (which would seem to remove the
        // bare-zero slot entirely): it cannot, and it would cost ~2x write amplification on every
        // page allocation for no security gain. `RawSlots::write_slot` rejects out-of-range indices,
        // so writing `enc(zero-page)` for a new page first requires `backing.extend` (a `set_len`).
        // That `set_len` (file `i_size` growth) becomes durable INDEPENDENTLY of the buffered content
        // writes, which `extend` must NOT sync (durability/perf). The logical page count is DERIVED
        // (`backing.slot_count() - HEADER_SLOTS`), deliberately not stored (see the module's
        // crash-consistency note). So a crash after `extend` returns but before the content writes are
        // synced leaves the slot_count durably grown with the new slots still ALL-ZERO; on reopen
        // those durable-but-zero slots are counted and read — and recovery's read-modify-write
        // (`DeviceTarget::apply`, which reads a page before patching it) would fail AEAD on them if
        // the bare-zero path were removed. The bare-zero path is therefore load-bearing for
        // crash-consistency: it is exactly what makes a crash mid-`extend` recoverable (regression
        // `reopen_recovers_when_extend_outlived_a_crash_before_header_sync`). `enc(zero-page)` would
        // re-open that crash window unless `extend` synced (unacceptable) or the derived-page-count
        // model were redesigned — so it adds I/O without closing the hole.
        if s.iter().all(|&b| b == 0) {
            buf.fill(0);
            return Ok(());
        }

        let v = slot::view(&s);
        let nonce = Nonce::from(*v.nonce);
        let tag = Tag::from(*v.tag);
        let aad = Self::aad(page);
        // Decrypt in place: copy the ciphertext region into the caller's buffer (GCM ciphertext
        // length equals plaintext length, both exactly `PAGE_SIZE`) and authenticate-decrypt it
        // against the detached tag. This is byte-identical to the attached `decrypt` of
        // `ciphertext || tag` but avoids the `combined` concatenation Vec and the result Vec.
        buf.copy_from_slice(v.ciphertext);
        self.cipher
            .decrypt_in_place_detached(&nonce, &aad, buf.as_mut_slice(), &tag)
            .map_err(|_| {
                // A tag failure is the unified signal for: wrong key, tamper, torn/partial write, or
                // a relocated page (AAD mismatch). Fail closed exactly like a CRC failure.
                GraphusError::Storage(format!(
                    "authenticated decryption failed for page {} (wrong key, corruption, a torn \
                     write, or a relocated page)",
                    page.0
                ))
            })?;
        Ok(())
    }

    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        if page.0 >= self.page_count {
            return Err(GraphusError::Storage(format!(
                "write out of range: page {} of {}",
                page.0, self.page_count
            )));
        }
        // Fresh random nonce per write (no GCM nonce reuse under a key; see module docs).
        let nonce_bytes = random_nonce();
        let nonce = Nonce::from(nonce_bytes);
        let aad = Self::aad(page);
        // Encrypt in place: build the slot, copy the plaintext into its ciphertext region, then
        // seal that region in place to obtain the detached tag. The detached API produces a
        // byte-identical ciphertext and tag to the attached `encrypt` of `plaintext`, but writes
        // the ciphertext directly into the slot — no result Vec, no split.
        let mut s: Slot = [0u8; SLOT_SIZE];
        s[slot::CIPHERTEXT_OFFSET..].copy_from_slice(buf.as_slice());
        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce, &aad, &mut s[slot::CIPHERTEXT_OFFSET..])
            .map_err(|_| {
                GraphusError::Storage(format!(
                    "authenticated encryption failed for page {}",
                    page.0
                ))
            })?;
        // `tag` is the 16-byte GCM authentication tag (`TAG_LEN`); place nonce and tag in their
        // header regions to complete the `nonce || tag || ciphertext` slot layout.
        debug_assert_eq!(tag.len(), TAG_LEN);
        s[slot::NONCE_OFFSET..slot::NONCE_OFFSET + NONCE_LEN].copy_from_slice(&nonce_bytes);
        s[slot::TAG_OFFSET..slot::TAG_OFFSET + TAG_LEN].copy_from_slice(tag.as_ref());
        self.backing.write_slot(page.0 + HEADER_SLOTS, &s)
    }

    fn sync_data(&mut self) -> Result<()> {
        self.backing.sync_data()
    }

    fn sync_all(&mut self) -> Result<()> {
        self.backing.sync_all()
    }

    fn page_count(&self) -> u64 {
        self.page_count
    }

    fn extend(&mut self, additional: u64) -> Result<()> {
        let new_count = self
            .page_count
            .checked_add(additional)
            .ok_or_else(|| GraphusError::Storage("page count overflow".to_owned()))?;
        // Grow the backing first (zero-filled slots). Newly-extended logical pages are zero slots
        // until written; the storage layer always writes a page before reading it (it initialises
        // pages on allocation), exactly as on the plaintext device where a fresh page is zero bytes.
        //
        // COST (rmp #87, on the record here): this is an O(1) `set_len` (one `i_size` metadata
        // change) regardless of `additional` — it does NOT write `additional` slots of content. The
        // alternative considered and rejected — writing `enc(zero-page)` for each extended page so no
        // slot is ever a bare zero — would be O(additional) authenticated 8 KiB slot writes per
        // allocation, i.e. roughly 2x write amplification on page allocation (one `enc(zero-page)`
        // write now, then the real `write_page` later), and would still NOT close the active-tamper
        // hole (see `read_page`'s KNOWN LIMITATION: a crash after this `set_len` but before those
        // content writes are synced re-creates the durable-but-zero slots, which the derived
        // page-count model counts and reads on reopen). So the cheap `set_len` is also the correct
        // choice for crash-consistency, not merely for performance.
        //
        // The header is NOT rewritten here: the backing slot count is the single source of truth for
        // the logical page count, so a reopen derives the count from the backing. This is what closes
        // the crash window — a durable `set_len` with an unsynced header rewrite can no longer make a
        // recoverable store refuse to open (see the module's crash-consistency note).
        self.backing.extend(additional)?;
        self.page_count = new_count;
        Ok(())
    }
}

/// Draws a fresh random 96-bit nonce from the OS CSPRNG.
fn random_nonce() -> [u8; NONCE_LEN] {
    use aes_gcm::aead::OsRng;
    use aes_gcm::aead::rand_core::RngCore;
    let mut n = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut n);
    n
}

/// A convenience for the common production case: the file-backed encrypted device.
pub type EncryptedFileDevice = EncryptedBlockDevice<crate::raw::FileRawSlots>;

impl EncryptedFileDevice {
    /// Creates a fresh encrypted file-backed device at `path` (the file must be empty or absent).
    ///
    /// # Errors
    /// As [`EncryptedBlockDevice::create`], plus a file-open error.
    pub fn create_file<P: AsRef<std::path::Path>>(
        path: P,
        keyring: &Keyring,
        salt: [u8; crate::keyring::SALT_LEN],
    ) -> Result<Self> {
        let backing = crate::raw::FileRawSlots::open(path)?;
        Self::create(backing, keyring, salt)
    }

    /// Opens an existing encrypted file-backed device at `path`, validating the header + KCV.
    ///
    /// # Errors
    /// As [`EncryptedBlockDevice::open`], plus a file-open error.
    pub fn open_file<P: AsRef<std::path::Path>>(path: P, keyring: &Keyring) -> Result<Self> {
        let backing = crate::raw::FileRawSlots::open(path)?;
        Self::open(backing, keyring)
    }

    /// Reads only the header of the encrypted file at `path` (the salt-probe pass that lets the
    /// server derive the keyring from the stored salt before opening).
    ///
    /// # Errors
    /// As [`EncryptedBlockDevice::read_header`], plus a file-open error.
    pub fn read_file_header<P: AsRef<std::path::Path>>(path: P) -> Result<Header> {
        let backing = crate::raw::FileRawSlots::open(path)?;
        Self::read_header(&backing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::{KEY_LEN, SALT_LEN};
    use crate::raw::MemRawSlots;
    use graphus_io::PAGE_SIZE;

    fn keyring(salt: &[u8; SALT_LEN]) -> Keyring {
        Keyring::from_key_file_bytes(&[0x5Cu8; KEY_LEN], salt).expect("keyring")
    }

    fn page_of(byte: u8) -> Page {
        [byte; PAGE_SIZE]
    }

    #[test]
    fn create_write_read_roundtrip() {
        let salt = [0xA1; SALT_LEN];
        let kr = keyring(&salt);
        let mut dev = EncryptedBlockDevice::create(MemRawSlots::new(0), &kr, salt).expect("create");
        dev.extend(2).expect("extend");
        assert_eq!(dev.page_count(), 2);
        dev.write_page(PageId(1), &page_of(0xCD)).expect("write");
        let mut buf = [0u8; PAGE_SIZE];
        dev.read_page(PageId(1), &mut buf).expect("read");
        assert_eq!(buf, page_of(0xCD));
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let salt = [0xA2; SALT_LEN];
        let kr = keyring(&salt);
        let mut dev = EncryptedBlockDevice::create(MemRawSlots::new(0), &kr, salt).expect("create");
        dev.extend(1).expect("extend");
        // A recognisable plaintext marker.
        let mut p = [0u8; PAGE_SIZE];
        p[..8].copy_from_slice(b"SECRET!!");
        dev.write_page(PageId(0), &p).expect("write");
        // The raw stored slot must not contain the marker, and must look high-entropy.
        let raw = dev.backing.raw_slot(HEADER_SLOTS).expect("raw slot");
        assert!(
            !raw.windows(8).any(|w| w == b"SECRET!!"),
            "plaintext marker leaked into the ciphertext"
        );
        // The header slot must not contain it either.
        let header_raw = dev.backing.raw_slot(0).expect("header slot");
        assert!(!header_raw.windows(8).any(|w| w == b"SECRET!!"));
    }

    #[test]
    fn wrong_key_fails_at_open_via_kcv() {
        let salt = [0xA3; SALT_LEN];
        let mut dev = EncryptedBlockDevice::create(MemRawSlots::new(0), &keyring(&salt), salt)
            .expect("create");
        dev.extend(1).expect("extend");
        dev.write_page(PageId(0), &page_of(1)).expect("write");
        dev.sync_all().expect("sync");
        let backing = dev.backing; // take the durable backing
        // A different key must fail closed at open (KCV mismatch), before any page read.
        let wrong = Keyring::from_key_file_bytes(&[0x00u8; KEY_LEN], &salt).expect("wrong key");
        let err = EncryptedBlockDevice::open(backing, &wrong).expect_err("wrong key must fail");
        assert!(matches!(err, GraphusError::Security(_)));
    }

    #[test]
    fn tamper_with_a_slot_is_detected_on_read() {
        let salt = [0xA4; SALT_LEN];
        let kr = keyring(&salt);
        let mut dev = EncryptedBlockDevice::create(MemRawSlots::new(0), &kr, salt).expect("create");
        dev.extend(1).expect("extend");
        dev.write_page(PageId(0), &page_of(0x11)).expect("write");
        // Flip one ciphertext byte.
        dev.backing.flip_byte(HEADER_SLOTS, slot::CIPHERTEXT_OFFSET);
        let mut buf = [0u8; PAGE_SIZE];
        assert!(
            dev.read_page(PageId(0), &mut buf).is_err(),
            "a flipped ciphertext byte must fail AEAD verification"
        );
    }

    #[test]
    fn relocating_a_page_is_detected_via_aad() {
        let salt = [0xA5; SALT_LEN];
        let kr = keyring(&salt);
        let mut dev = EncryptedBlockDevice::create(MemRawSlots::new(0), &kr, salt).expect("create");
        dev.extend(2).expect("extend");
        dev.write_page(PageId(0), &page_of(0x22)).expect("write 0");
        dev.write_page(PageId(1), &page_of(0x33)).expect("write 1");
        // Swap the two physical page slots: each is now at the other's offset. The AAD (page_id) no
        // longer matches, so both reads must fail.
        dev.backing.swap_slots(HEADER_SLOTS, HEADER_SLOTS + 1);
        let mut buf = [0u8; PAGE_SIZE];
        assert!(dev.read_page(PageId(0), &mut buf).is_err());
        assert!(dev.read_page(PageId(1), &mut buf).is_err());
    }

    #[test]
    fn torn_write_is_detected() {
        let salt = [0xA6; SALT_LEN];
        let kr = keyring(&salt);
        let mut dev = EncryptedBlockDevice::create(MemRawSlots::new(0), &kr, salt).expect("create");
        dev.extend(1).expect("extend");
        dev.write_page(PageId(0), &page_of(0x44)).expect("write");
        dev.sync_all().expect("sync");
        // Arm a torn write: only a prefix of the next slot write lands.
        dev.backing.arm_torn_write(HEADER_SLOTS, 100);
        dev.write_page(PageId(0), &page_of(0x55))
            .expect("write torn");
        let mut buf = [0u8; PAGE_SIZE];
        assert!(
            dev.read_page(PageId(0), &mut buf).is_err(),
            "a torn slot write must fail AEAD verification"
        );
    }

    #[test]
    fn reopen_after_sync_recovers_pages() {
        let salt = [0xA7; SALT_LEN];
        let kr = keyring(&salt);
        let mut dev = EncryptedBlockDevice::create(MemRawSlots::new(0), &kr, salt).expect("create");
        dev.extend(3).expect("extend");
        dev.write_page(PageId(2), &page_of(0x77)).expect("write");
        dev.sync_all().expect("sync");
        let backing = dev.backing;
        let dev2 = EncryptedBlockDevice::open(backing, &kr).expect("reopen");
        assert_eq!(dev2.page_count(), 3);
        let mut buf = [0u8; PAGE_SIZE];
        dev2.read_page(PageId(2), &mut buf)
            .expect("read after reopen");
        assert_eq!(buf, page_of(0x77));
    }

    #[test]
    fn reopen_recovers_when_extend_outlived_a_crash_before_header_sync() {
        // Regression for the crash-consistency divergence: `extend` grows the backing (a durable
        // `set_len`/`i_size` change on a real filesystem) but no page writes for the new slots, and
        // historically a header page-count rewrite, may have been lost on a crash before the next
        // sync. The post-crash durable state therefore has MORE physical slots than a stale header
        // would have claimed. Backing-as-source-of-truth must recover this rather than fail closed.
        let salt = [0xAB; SALT_LEN];
        let kr = keyring(&salt);
        let mut dev = EncryptedBlockDevice::create(MemRawSlots::new(0), &kr, salt).expect("create");

        // Real, durably-synced pages first.
        dev.extend(2).expect("extend");
        dev.write_page(PageId(0), &page_of(0x10)).expect("write 0");
        dev.write_page(PageId(1), &page_of(0x20)).expect("write 1");
        dev.sync_all().expect("sync");

        // Now model the crash window: `extend`'s slot growth became durable, but the new pages were
        // never written (and pre-fix, the header page-count rewrite was lost). For `MemRawSlots`,
        // `extend` mutates the persisted (durable) vector directly, so a bare `backing.extend`
        // reproduces exactly "durable slot_count grew, new slots are pristine zeros, header untouched".
        let mut backing = dev.into_backing();
        backing
            .extend(3)
            .expect("extend backing past the header's view");
        assert_eq!(backing.slot_count(), HEADER_SLOTS + 5);

        // Before the fix, `open` computed physical_pages = 5 but read a stale header page_count = 2
        // and failed the strict equality check. It must now succeed.
        let dev2 =
            EncryptedBlockDevice::open(backing, &kr).expect("reopen must recover, not reject");
        assert_eq!(
            dev2.page_count(),
            5,
            "page count reflects the durable backing, not a stale header"
        );

        // Previously-written pages still read back correctly.
        let mut buf = [0u8; PAGE_SIZE];
        dev2.read_page(PageId(0), &mut buf).expect("read 0");
        assert_eq!(buf, page_of(0x10));
        dev2.read_page(PageId(1), &mut buf).expect("read 1");
        assert_eq!(buf, page_of(0x20));

        // The never-written extended pages read back as pristine zero pages (the zero-slot path),
        // exactly what recovery's read-modify-write relies on.
        for p in 2..5 {
            let mut z = [0xFFu8; PAGE_SIZE];
            dev2.read_page(PageId(p), &mut z)
                .expect("never-written extended page reads back");
            assert_eq!(
                z, [0u8; PAGE_SIZE],
                "extended-but-unwritten page reads zeros"
            );
        }
    }

    #[test]
    fn extend_and_page_count_exclude_the_header() {
        let salt = [0xA8; SALT_LEN];
        let kr = keyring(&salt);
        let mut dev = EncryptedBlockDevice::create(MemRawSlots::new(0), &kr, salt).expect("create");
        assert_eq!(dev.page_count(), 0);
        assert_eq!(dev.backing.slot_count(), HEADER_SLOTS); // header only
        dev.extend(5).expect("extend");
        assert_eq!(dev.page_count(), 5);
        assert_eq!(dev.backing.slot_count(), HEADER_SLOTS + 5);
    }

    #[test]
    fn never_written_page_reads_back_as_zeros() {
        // A page that was zero-`extend`ed but never written must read back as a zero page (the
        // analogue of the plaintext device, which recovery's read-modify-write relies on). A
        // pristine zero slot is NOT treated as corruption.
        let salt = [0xAA; SALT_LEN];
        let kr = keyring(&salt);
        let mut dev = EncryptedBlockDevice::create(MemRawSlots::new(0), &kr, salt).expect("create");
        dev.extend(2).expect("extend");
        let mut buf = [0xFFu8; PAGE_SIZE];
        dev.read_page(PageId(0), &mut buf)
            .expect("never-written page reads back, not an error");
        assert_eq!(buf, [0u8; PAGE_SIZE], "a pristine page reads back as zeros");
        // Writing then reading still works (the zero-slot fast path does not shadow real reads).
        dev.write_page(PageId(0), &page_of(0x5A)).expect("write");
        let mut buf2 = [0u8; PAGE_SIZE];
        dev.read_page(PageId(0), &mut buf2).expect("read");
        assert_eq!(buf2, page_of(0x5A));
    }

    #[test]
    fn create_rejects_a_non_empty_backing() {
        let salt = [0xA9; SALT_LEN];
        let kr = keyring(&salt);
        let backing = MemRawSlots::new(3); // already has slots
        assert!(matches!(
            EncryptedBlockDevice::create(backing, &kr, salt),
            Err(GraphusError::Storage(_))
        ));
    }
}
