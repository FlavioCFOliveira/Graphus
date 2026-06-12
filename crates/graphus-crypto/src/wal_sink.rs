//! [`EncryptedLogSink`]: a length-preserving, authenticated-encryption wrapper around any
//! [`graphus_wal::LogSink`], so the write-ahead log is encrypted at rest while the WAL manager,
//! recovery, and the byte-offset == LSN invariant above the seam stay byte-identical (rmp #88).
//!
//! ## The hard constraint: logical byte offsets are LSNs
//!
//! In Graphus the WAL byte offset **is** the LSN (`graphus_wal::WalManager::next_lsn` reads the
//! sink's `buffered_len`), and `page_lsn`s stamped into store pages reference these offsets. The
//! encrypted sink therefore presents a **logical plaintext stream** upward —
//! [`durable_len`](LogSink::durable_len) / [`buffered_len`](LogSink::buffered_len) /
//! [`read_durable`](LogSink::read_durable) are all in plaintext byte offsets, byte-identical to a
//! plaintext sink for the same logical writes — while storing larger **authenticated frames** in
//! the backing sink. Above the seam nothing changes: the same WAL records, the same LSNs.
//!
//! ## Physical layout in the backing sink
//!
//! ```text
//!   [sink header]  [frame 0]  [frame 1]  ...  [frame N]
//! ```
//!
//! - **Sink header** (at physical offset 0, written once at create, never rewritten): magic
//!   (`"GRAPHUSW"`), version, cipher id, and a WAL **Key-Check-Value** (a GCM seal of a fixed
//!   constant under the WAL subkey). On open the magic is checked (wrong magic → fail closed) and
//!   the KCV verified constant-time against the keyring (wrong/missing key → fail closed) **before
//!   any frame is read**. There is **no salt** in this header: the WAL subkey is derived from the
//!   master key + the *store's* salt (passed in by the caller), so the WAL and store share one
//!   salt source. The header logically maps physical offset `0` to logical offset `0` (the WAL
//!   manager's own header sits at logical `0`, inside the first frame).
//! - **Frame** (one per [`sync`](LogSink::sync) that has pending bytes):
//!   ```text
//!     phys_len(8) || logical_len(8) || nonce(12) || ciphertext(logical_len) || tag(16)
//!   ```
//!   `phys_len` is the whole frame length on disk (so a forward scan steps frame-to-frame and a
//!   torn tail is caught when the claimed length runs past the durable bytes). `nonce` is a fresh
//!   random 96-bit value per frame. **AAD = the frame's logical start offset (8-byte LE)**, so a
//!   frame cannot be reordered, duplicated, or spliced to another logical position without failing
//!   authentication. GCM ciphertext length equals plaintext length, so `ciphertext` is exactly
//!   `logical_len` bytes.
//!
//! ## Crash / torn-tail semantics (ACID-preserving)
//!
//! Each [`sync`](LogSink::sync) seals all pending plaintext into **one** frame, appends it to the
//! backing, then forwards `sync()` (the backing's single write + `fdatasync` — group commit is
//! preserved: one frame, one fsync). A frame is therefore either **fully durable** or, after a
//! crash mid-write, a **torn tail**. On [`open`](EncryptedLogSink::open) the frames are scanned
//! forward and authenticated one by one; the logical durable length is the end of the **last fully
//! valid frame**. A short, truncated, or AEAD-failing tail frame is **dropped** — exactly the
//! plaintext sink's "un-synced tail is lost" crash semantics. Because the WAL manager only treats
//! bytes inside a synced (hence whole, authenticated) frame as durable, dropping a torn tail can
//! never lose committed work: a group commit's frame is fully durable before `commit` returns.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Nonce};
use graphus_core::error::{GraphusError, Result};
use graphus_wal::LogSink;

use crate::keyring::Keyring;
use crate::slot::{NONCE_LEN, TAG_LEN};

/// Magic bytes identifying an encrypted Graphus **WAL** sink (`"GRAPHUSW"` — Graphus WAL). Distinct
/// from the store's `"GRAPHUSE"` so the two encrypted formats can never be confused.
pub const WAL_SINK_MAGIC: [u8; 8] = *b"GRAPHUSW";

/// The encrypted-WAL sink format version. Bumped on any incompatible header/frame layout change, or
/// any change to how the persisted WAL KCV bytes are computed. Bumped in lock-step with the store's
/// [`crate::HEADER_VERSION`].
///
/// - **v1**: WAL KCV sealed under the *WAL* frame-encryption subkey.
/// - **v2** (rmp #87): WAL KCV sealed under a dedicated, independent *WAL-KCV* subkey (the fixed KCV
///   nonce now shares no nonce space with frame encryption). This changes the persisted WAL KCV
///   bytes; a v1 sink fails closed at open on the version check. No migration is needed (pre-1.0,
///   no persisted production encrypted WALs).
pub const WAL_SINK_VERSION: u32 = 2;

/// Cipher identifier for AES-256-GCM with a 96-bit nonce and 128-bit tag (matches the store).
pub const WAL_CIPHER_AES_256_GCM: u32 = 1;

// --- sink header layout (all multi-byte integers little-endian) ----------------------------------
// magic(8) || version(4) || cipher(4) || kcv_len(4) || kcv(kcv_len)
const HDR_OFF_MAGIC: usize = 0;
const HDR_OFF_VERSION: usize = 8;
const HDR_OFF_CIPHER: usize = 12;
const HDR_OFF_KCV_LEN: usize = 16;
const HDR_OFF_KCV: usize = 20;

/// The fixed-size header prefix preceding the variable-length KCV.
const HDR_PREFIX_LEN: usize = HDR_OFF_KCV;

// --- frame layout (all multi-byte integers little-endian) ----------------------------------------
// phys_len(8) || logical_len(8) || nonce(12) || ciphertext(logical_len) || tag(16)
const FR_OFF_PHYS_LEN: usize = 0;
const FR_OFF_LOGICAL_LEN: usize = 8;
const FR_OFF_NONCE: usize = 16;
const FR_OFF_CIPHERTEXT: usize = FR_OFF_NONCE + NONCE_LEN;

/// The fixed frame overhead: the two length fields, the nonce, and the trailing tag. The on-disk
/// frame length is `FRAME_OVERHEAD + logical_len`.
const FRAME_OVERHEAD: usize = 8 + 8 + NONCE_LEN + TAG_LEN;

/// One frame's physical layout: where its plaintext begins logically, and where it sits physically.
#[derive(Debug, Clone, Copy)]
struct FrameLoc {
    /// The logical (plaintext) start offset this frame covers.
    logical_offset: u64,
    /// The plaintext length this frame carries.
    logical_len: u64,
    /// The physical start offset of the frame in the backing sink.
    phys_offset: u64,
    /// The whole physical frame length in the backing sink.
    phys_len: u64,
}

/// A [`LogSink`] that encrypts every synced batch of WAL bytes into one authenticated frame in a
/// backing `LogSink`, while presenting plaintext logical byte offsets upward (so LSNs are
/// unchanged).
///
/// Construct it with [`create`](Self::create) (writes a fresh sink header on an empty backing) or
/// [`open`](Self::open) (validates the header + WAL KCV against the keyring, then scans + decrypts
/// the frame index, dropping a torn tail). Works over `FileLogSink` in production and `MemLogSink`
/// for Deterministic Simulation Testing.
pub struct EncryptedLogSink<S: LogSink> {
    backing: S,
    cipher: Aes256Gcm,
    /// The frame index, in logical order, covering `[0, logical_durable_len)`.
    frames: Vec<FrameLoc>,
    /// The sum of synced frame plaintext lengths (the logical durable length).
    logical_durable_len: u64,
    /// Buffered plaintext appended but not yet sealed into a frame (mirrors the backing sinks'
    /// `pending`).
    pending: Vec<u8>,
}

impl<S: LogSink> std::fmt::Debug for EncryptedLogSink<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedLogSink")
            .field("frames", &self.frames.len())
            .field("logical_durable_len", &self.logical_durable_len)
            .field("pending", &self.pending.len())
            .finish_non_exhaustive()
    }
}

impl<S: LogSink> EncryptedLogSink<S> {
    /// Creates a **fresh** encrypted WAL sink on an empty backing: writes the sink header (magic,
    /// version, cipher, WAL KCV) and hardens it, leaving zero logical bytes durable.
    ///
    /// The keyring's WAL subkey is assumed to have been derived from the store's salt (the caller
    /// shares one salt source between the store device and the WAL — see the module docs).
    ///
    /// # Errors
    /// [`GraphusError::Storage`] if the backing is non-empty or a backing write/sync fails;
    /// [`GraphusError::Security`] if the WAL KCV cannot be computed.
    pub fn create(mut backing: S, keyring: &Keyring) -> Result<Self> {
        if backing.buffered_len() != 0 {
            return Err(GraphusError::Storage(
                "EncryptedLogSink::create requires an empty backing".to_owned(),
            ));
        }
        let kcv = keyring.compute_wal_kcv()?;
        let header = encode_sink_header(&kcv);
        backing.append(&header);
        backing.sync()?;
        Ok(Self {
            backing,
            cipher: keyring.wal_cipher(),
            frames: Vec::new(),
            logical_durable_len: 0,
            pending: Vec::new(),
        })
    }

    /// **Opens** an existing encrypted WAL sink: reads + validates the sink header (wrong magic →
    /// fail closed; wrong key → WAL KCV mismatch fail closed, **before** any frame is decrypted),
    /// then scans frames forward from the end of the header, AEAD-authenticating each. The logical
    /// durable length is the end of the last fully-valid frame; a torn/short/AEAD-failing tail is
    /// **dropped** (the plaintext sink's un-synced-tail-lost crash semantics — see the module docs).
    ///
    /// # Errors
    /// [`GraphusError::Security`] if the backing is not an encrypted Graphus WAL (wrong magic) or
    /// the key is wrong (WAL KCV mismatch); [`GraphusError::Storage`] on an unsupported
    /// version/cipher, a corrupt header, or a backing read failure.
    pub fn open(backing: S, keyring: &Keyring) -> Result<Self> {
        // Read the whole durable backing once (recovery's hot read is `from = 0` anyway). The header
        // is validated before any frame byte is interpreted.
        let mut physical = Vec::new();
        backing.read_durable(0, &mut physical)?;
        let header_len = parse_and_verify_sink_header(&physical, keyring)?;

        let cipher = keyring.wal_cipher();
        let mut frames = Vec::new();
        let mut logical_durable_len: u64 = 0;
        let mut cursor = header_len;

        // Forward scan: step frame-to-frame. The first frame that is short, claims a length running
        // past the durable bytes, or fails AEAD authentication is a torn/garbage tail — stop there,
        // dropping it and everything after (there is nothing after a synced frame but a torn tail).
        while cursor < physical.len() {
            let Some((loc, plaintext_ok)) =
                decode_and_authenticate_frame(&physical, cursor, logical_durable_len, &cipher)
            else {
                break;
            };
            if !plaintext_ok {
                break;
            }
            cursor = (loc.phys_offset + loc.phys_len) as usize;
            logical_durable_len += loc.logical_len;
            frames.push(loc);
        }

        Ok(Self {
            backing,
            cipher,
            frames,
            logical_durable_len,
            pending: Vec::new(),
        })
    }

    /// Consumes the sink and returns its backing (so a test can reopen it with a different keyring,
    /// or a DST test can `crash()` it). Mirrors the store device's `into_backing`.
    #[must_use]
    pub fn into_backing(self) -> S {
        self.backing
    }

    /// Borrows the backing sink (test/inspection helper).
    #[must_use]
    pub fn backing(&self) -> &S {
        &self.backing
    }

    /// Mutably borrows the backing sink (test helper: e.g. to `crash()` a `MemLogSink` backing for a
    /// DST power-loss scenario).
    #[must_use]
    pub fn backing_mut(&mut self) -> &mut S {
        &mut self.backing
    }

    /// The AAD for a frame at logical offset `off`: its 8-byte little-endian value, binding the
    /// ciphertext to its logical position (a frame cannot be relocated/reordered).
    fn aad(off: u64) -> [u8; 8] {
        off.to_le_bytes()
    }

    /// Seals `plaintext` into a frame at logical offset `logical_offset` and returns the framed
    /// bytes ready to append to the backing.
    fn seal_frame(&self, logical_offset: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = random_nonce();
        let nonce = Nonce::from(nonce_bytes);
        let aad = Self::aad(logical_offset);
        let sealed = self
            .cipher
            .encrypt(
                &nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                GraphusError::Storage("authenticated encryption of a WAL frame failed".to_owned())
            })?;
        // GCM output is ciphertext || tag; ciphertext length equals plaintext length.
        if sealed.len() != plaintext.len() + TAG_LEN {
            return Err(GraphusError::Storage(format!(
                "sealed WAL frame has length {} (expected {})",
                sealed.len(),
                plaintext.len() + TAG_LEN
            )));
        }
        let logical_len = plaintext.len() as u64;
        let phys_len = (FRAME_OVERHEAD + plaintext.len()) as u64;
        let mut frame = Vec::with_capacity(phys_len as usize);
        frame.extend_from_slice(&phys_len.to_le_bytes());
        frame.extend_from_slice(&logical_len.to_le_bytes());
        frame.extend_from_slice(&nonce_bytes);
        frame.extend_from_slice(&sealed); // ciphertext || tag
        debug_assert_eq!(frame.len() as u64, phys_len);
        Ok(frame)
    }
}

impl<S: LogSink> LogSink for EncryptedLogSink<S> {
    fn append(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
    }

    fn sync(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            // Forward the sync so the backing's fsync still runs (a no-op `sync` must still harden
            // anything the backing buffered, and keeps the group-commit contract uniform).
            return self.backing.sync();
        }
        let logical_offset = self.logical_durable_len;
        // `seal_frame` does not borrow `self.pending` mutably, but we must not hold an immutable
        // borrow of `pending` across the `append`; take the pending bytes out first.
        let pending = std::mem::take(&mut self.pending);
        let frame = match self.seal_frame(logical_offset, &pending) {
            Ok(f) => f,
            Err(e) => {
                // Restore pending so the caller can retry; nothing was appended to the backing.
                self.pending = pending;
                return Err(e);
            }
        };
        let phys_offset = self.backing.buffered_len();
        let phys_len = frame.len() as u64;
        self.backing.append(&frame);
        // One backing write + one fdatasync hardens the whole frame (group commit preserved).
        self.backing.sync()?;
        self.frames.push(FrameLoc {
            logical_offset,
            logical_len: pending.len() as u64,
            phys_offset,
            phys_len,
        });
        self.logical_durable_len += pending.len() as u64;
        Ok(())
    }

    fn durable_len(&self) -> u64 {
        self.logical_durable_len
    }

    fn buffered_len(&self) -> u64 {
        self.logical_durable_len + self.pending.len() as u64
    }

    fn read_durable(&self, from: u64, into: &mut Vec<u8>) -> Result<()> {
        into.clear();
        if from >= self.logical_durable_len {
            return Ok(());
        }
        // Read the whole physical backing once; slice + decrypt the frames covering
        // `[from, logical_durable_len)`. The common case is `from = 0` (recovery reads the whole
        // log), so this is the same single bulk read the plaintext sink does.
        let mut physical = Vec::new();
        self.backing.read_durable(0, &mut physical)?;

        for loc in &self.frames {
            let frame_end = loc.logical_offset + loc.logical_len;
            if frame_end <= from {
                continue; // entirely before the requested range
            }
            // This frame overlaps `[from, durable)`; decrypt it.
            let plaintext = self.decrypt_frame_at(&physical, loc)?;
            // Slice off any prefix before `from` (only ever the first overlapping frame).
            let start = from.saturating_sub(loc.logical_offset) as usize;
            if start < plaintext.len() {
                into.extend_from_slice(&plaintext[start..]);
            }
        }
        Ok(())
    }
}

impl<S: LogSink> EncryptedLogSink<S> {
    /// Decrypts and authenticates the frame described by `loc` from the physical bytes, returning
    /// its plaintext. Used by [`read_durable`](LogSink::read_durable) (the frame index was already
    /// validated at open, so a failure here is genuine on-disk corruption discovered late).
    ///
    /// # Errors
    /// [`GraphusError::Storage`] if the physical bytes are too short for the frame, or
    /// [`GraphusError::Security`] if AEAD authentication fails (tamper/corruption after open).
    fn decrypt_frame_at(&self, physical: &[u8], loc: &FrameLoc) -> Result<Vec<u8>> {
        let phys_offset = loc.phys_offset as usize;
        let phys_len = loc.phys_len as usize;
        let end = phys_offset
            .checked_add(phys_len)
            .ok_or_else(|| GraphusError::Storage("WAL frame offset overflow".to_owned()))?;
        if end > physical.len() {
            return Err(GraphusError::Storage(
                "WAL frame runs past the durable backing (truncated after open)".to_owned(),
            ));
        }
        let frame = &physical[phys_offset..end];
        let nonce_bytes: [u8; NONCE_LEN] = frame[FR_OFF_NONCE..FR_OFF_NONCE + NONCE_LEN]
            .try_into()
            .expect("INVARIANT: nonce region is exactly NONCE_LEN bytes by frame construction");
        let nonce = Nonce::from(nonce_bytes);
        // ciphertext || tag is everything after the nonce.
        let ct_and_tag = &frame[FR_OFF_CIPHERTEXT..];
        let aad = Self::aad(loc.logical_offset);
        let plaintext = self
            .cipher
            .decrypt(
                &nonce,
                aes_gcm::aead::Payload {
                    msg: ct_and_tag,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                GraphusError::Security(
                    "authenticated decryption of a WAL frame failed (wrong key, corruption, a torn \
                     write, or a relocated frame)"
                        .to_owned(),
                )
            })?;
        if plaintext.len() as u64 != loc.logical_len {
            return Err(GraphusError::Storage(format!(
                "decrypted WAL frame has length {} (expected {})",
                plaintext.len(),
                loc.logical_len
            )));
        }
        Ok(plaintext)
    }
}

/// Encodes the sink header (magic, version, cipher, KCV) into a single fixed-shape byte block.
fn encode_sink_header(kcv: &[u8]) -> Vec<u8> {
    let mut hdr = Vec::with_capacity(HDR_PREFIX_LEN + kcv.len());
    hdr.extend_from_slice(&WAL_SINK_MAGIC); // HDR_OFF_MAGIC
    hdr.extend_from_slice(&WAL_SINK_VERSION.to_le_bytes()); // HDR_OFF_VERSION
    hdr.extend_from_slice(&WAL_CIPHER_AES_256_GCM.to_le_bytes()); // HDR_OFF_CIPHER
    hdr.extend_from_slice(&(kcv.len() as u32).to_le_bytes()); // HDR_OFF_KCV_LEN
    hdr.extend_from_slice(kcv); // HDR_OFF_KCV
    debug_assert_eq!(hdr.len(), HDR_PREFIX_LEN + kcv.len());
    hdr
}

/// Parses and validates the sink header at the start of `physical`, verifying the WAL KCV against
/// `keyring` constant-time. Returns the header length (where the first frame begins).
///
/// # Errors
/// [`GraphusError::Security`] on a magic mismatch (not an encrypted Graphus WAL) or a KCV mismatch
/// (wrong/missing key); [`GraphusError::Storage`] on an unsupported version/cipher or a corrupt /
/// too-short header.
fn parse_and_verify_sink_header(physical: &[u8], keyring: &Keyring) -> Result<usize> {
    if physical.len() < HDR_PREFIX_LEN {
        return Err(GraphusError::Storage(
            "encrypted WAL is too short to contain a sink header".to_owned(),
        ));
    }
    if physical[HDR_OFF_MAGIC..HDR_OFF_MAGIC + 8] != WAL_SINK_MAGIC {
        return Err(GraphusError::Security(
            "not an encrypted Graphus WAL (sink header magic mismatch): refusing to open. A \
             plaintext WAL cannot be opened as encrypted, nor vice versa"
                .to_owned(),
        ));
    }
    let version = u32::from_le_bytes(read4(physical, HDR_OFF_VERSION));
    if version != WAL_SINK_VERSION {
        return Err(GraphusError::Storage(format!(
            "unsupported encrypted-WAL format version {version} (this build supports \
             {WAL_SINK_VERSION})"
        )));
    }
    let cipher = u32::from_le_bytes(read4(physical, HDR_OFF_CIPHER));
    if cipher != WAL_CIPHER_AES_256_GCM {
        return Err(GraphusError::Storage(format!(
            "unsupported cipher id {cipher} in encrypted-WAL header (this build supports \
             AES-256-GCM = {WAL_CIPHER_AES_256_GCM})"
        )));
    }
    let kcv_len = u32::from_le_bytes(read4(physical, HDR_OFF_KCV_LEN)) as usize;
    let kcv_end = HDR_OFF_KCV.checked_add(kcv_len).ok_or_else(|| {
        GraphusError::Storage("corrupt encrypted-WAL header: KCV length".to_owned())
    })?;
    if kcv_end > physical.len() {
        return Err(GraphusError::Storage(
            "corrupt encrypted-WAL header: KCV length runs past the backing".to_owned(),
        ));
    }
    // Fail closed on a wrong/missing key BEFORE reading any frame (defence in depth: a frame
    // decrypt would also fail the AEAD tag, but the KCV gives an immediate, unambiguous error).
    keyring.verify_wal_kcv(&physical[HDR_OFF_KCV..kcv_end])?;
    Ok(kcv_end)
}

/// Decodes the frame starting at physical offset `cursor` and authenticates it against the running
/// `logical_offset` (the AAD). Returns `Some((loc, true))` on a fully valid frame, or `None`/`(_,
/// false)` when the frame is short, claims an impossible length, or fails AEAD — signalling a torn
/// tail to drop.
fn decode_and_authenticate_frame(
    physical: &[u8],
    cursor: usize,
    logical_offset: u64,
    cipher: &Aes256Gcm,
) -> Option<(FrameLoc, bool)> {
    // Need at least the two length fields to read the claimed physical length.
    if cursor + FR_OFF_NONCE > physical.len() {
        return None;
    }
    let phys_len = u64::from_le_bytes(read8(physical, cursor + FR_OFF_PHYS_LEN));
    let logical_len = u64::from_le_bytes(read8(physical, cursor + FR_OFF_LOGICAL_LEN));
    // The claimed physical length must be consistent (overhead + logical_len) and within bounds.
    let expected_phys = (FRAME_OVERHEAD as u64).checked_add(logical_len)?;
    if phys_len != expected_phys {
        return None; // inconsistent header → torn/garbage tail
    }
    let end = cursor.checked_add(phys_len as usize)?;
    if end > physical.len() {
        return None; // claimed length runs past the durable bytes → torn tail
    }
    let frame = &physical[cursor..end];
    let nonce_bytes: [u8; NONCE_LEN] = frame[FR_OFF_NONCE..FR_OFF_NONCE + NONCE_LEN]
        .try_into()
        .ok()?;
    let nonce = Nonce::from(nonce_bytes);
    let ct_and_tag = &frame[FR_OFF_CIPHERTEXT..];
    let aad = logical_offset.to_le_bytes();
    match cipher.decrypt(
        &nonce,
        aes_gcm::aead::Payload {
            msg: ct_and_tag,
            aad: &aad,
        },
    ) {
        Ok(plaintext) if plaintext.len() as u64 == logical_len => Some((
            FrameLoc {
                logical_offset,
                logical_len,
                phys_offset: cursor as u64,
                phys_len,
            },
            true,
        )),
        // Either AEAD failed (torn/tampered tail) or the decrypted length disagrees → drop the tail.
        _ => None,
    }
}

fn read4(b: &[u8], off: usize) -> [u8; 4] {
    let mut out = [0u8; 4];
    out.copy_from_slice(&b[off..off + 4]);
    out
}

fn read8(b: &[u8], off: usize) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&b[off..off + 8]);
    out
}

/// Draws a fresh random 96-bit nonce from the OS CSPRNG (per frame; no GCM nonce reuse under a key).
fn random_nonce() -> [u8; NONCE_LEN] {
    use aes_gcm::aead::OsRng;
    use aes_gcm::aead::rand_core::RngCore;
    let mut n = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut n);
    n
}

/// A convenience for the common production case: the file-backed encrypted WAL sink.
pub type EncryptedFileLogSink = EncryptedLogSink<graphus_wal::FileLogSink>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::{KEY_LEN, SALT_LEN};
    use graphus_wal::MemLogSink;

    const SALT: [u8; SALT_LEN] = [0x3C; SALT_LEN];

    fn keyring(byte: u8) -> Keyring {
        Keyring::from_key_file_bytes(&[byte; KEY_LEN], &SALT).expect("keyring")
    }

    /// A fresh encrypted sink over an empty in-memory backing.
    fn fresh(kr: &Keyring) -> EncryptedLogSink<MemLogSink> {
        EncryptedLogSink::create(MemLogSink::new(), kr).expect("create encrypted sink")
    }

    #[test]
    fn logical_offsets_match_a_plaintext_sink() {
        // For the same logical writes, the encrypted sink's logical durable/buffered lengths must be
        // byte-identical to a plaintext MemLogSink's (the LSN == byte-offset invariant).
        let kr = keyring(0x01);
        let mut enc = fresh(&kr);
        let mut plain = MemLogSink::new();

        let writes: &[&[u8]] = &[b"hello ", b"world", b"!!!"];
        for w in writes {
            enc.append(w);
            plain.append(w);
            assert_eq!(enc.buffered_len(), plain.buffered_len());
            enc.sync().expect("enc sync");
            plain.sync().expect("plain sync");
            assert_eq!(enc.durable_len(), plain.durable_len());
            assert_eq!(enc.buffered_len(), plain.buffered_len());
        }

        // read_durable(0) must return the exact concatenated plaintext.
        let mut e = Vec::new();
        let mut p = Vec::new();
        enc.read_durable(0, &mut e).expect("enc read");
        plain.read_durable(0, &mut p).expect("plain read");
        assert_eq!(e, p);
        assert_eq!(e, b"hello world!!!");
    }

    #[test]
    fn append_is_not_durable_until_sync() {
        let kr = keyring(0x02);
        let mut enc = fresh(&kr);
        enc.append(b"pending");
        assert_eq!(enc.buffered_len(), 7);
        assert_eq!(enc.durable_len(), 0);
        enc.sync().expect("sync");
        assert_eq!(enc.durable_len(), 7);
    }

    #[test]
    fn raw_physical_bytes_contain_no_plaintext() {
        let kr = keyring(0x03);
        let mut enc = fresh(&kr);
        enc.append(b"SUPER-SECRET-MARKER");
        enc.sync().expect("sync");
        let backing = enc.into_backing();
        let raw = backing.durable_bytes();
        assert!(
            !raw.windows(b"SUPER-SECRET-MARKER".len())
                .any(|w| w == b"SUPER-SECRET-MARKER"),
            "the plaintext marker leaked into the encrypted WAL backing"
        );
    }

    #[test]
    fn round_trips_across_reopen() {
        let kr = keyring(0x04);
        let mut enc = fresh(&kr);
        enc.append(b"alpha");
        enc.sync().expect("sync 1");
        enc.append(b"beta");
        enc.sync().expect("sync 2");

        let backing = enc.into_backing();
        let reopened = EncryptedLogSink::open(backing, &kr).expect("reopen");
        assert_eq!(reopened.durable_len(), 9);
        let mut out = Vec::new();
        reopened.read_durable(0, &mut out).expect("read");
        assert_eq!(out, b"alphabeta");
    }

    #[test]
    fn wrong_key_fails_closed_at_open() {
        let kr = keyring(0x05);
        let mut enc = fresh(&kr);
        enc.append(b"data");
        enc.sync().expect("sync");
        let backing = enc.into_backing();

        let wrong = keyring(0xFF);
        let err = EncryptedLogSink::open(backing, &wrong).expect_err("wrong key must fail closed");
        assert!(matches!(err, GraphusError::Security(_)));
    }

    #[test]
    fn wrong_magic_fails_closed_at_open() {
        // A plaintext (non-encrypted) backing must be rejected with a clear error.
        let kr = keyring(0x06);
        let mut plain = MemLogSink::new();
        plain.append(b"this is not an encrypted WAL header at all");
        plain.sync().expect("sync");
        let err = EncryptedLogSink::open(plain, &kr).expect_err("wrong magic must fail closed");
        assert!(matches!(err, GraphusError::Security(_)));
    }

    #[test]
    fn flipped_ciphertext_byte_fails_decryption() {
        let kr = keyring(0x07);
        let mut enc = fresh(&kr);
        enc.append(b"authentic");
        enc.sync().expect("sync");
        let mut backing = enc.into_backing();

        // Flip a byte inside the (only) frame's ciphertext region. The header is HDR length; the
        // frame's ciphertext begins after the frame header (phys_len + logical_len + nonce).
        let mut bytes = backing.durable_bytes().to_vec();
        let header_len = HDR_OFF_KCV + kcv_len_of(&bytes);
        let ct_pos = header_len + FR_OFF_CIPHERTEXT;
        bytes[ct_pos] ^= 0xFF;
        // Rebuild a backing holding the tampered bytes.
        backing = MemLogSink::new();
        backing.append(&bytes);
        backing.sync().expect("sync tampered");

        // The single frame now fails AEAD, so it is dropped as a torn/tampered tail → 0 durable.
        let reopened = EncryptedLogSink::open(backing, &kr).expect("open still succeeds (KCV ok)");
        assert_eq!(
            reopened.durable_len(),
            0,
            "a tampered frame must be dropped (treated as a torn tail)"
        );
    }

    #[test]
    fn crash_drops_unsynced_tail_but_keeps_synced_prefix() {
        // Append + sync a frame (durable), append more WITHOUT sync, then "crash" the backing
        // (drop its un-synced tail). The synced prefix survives; the un-synced frame is gone.
        let kr = keyring(0x08);
        let mut enc = fresh(&kr);
        enc.append(b"committed");
        enc.sync().expect("sync committed");
        enc.append(b"-uncommitted");
        // No sync: the pending bytes were never sealed/appended to the backing.

        // Model power loss: the backing drops its un-synced cache (there is none beyond the synced
        // header+frame here), and the encrypted sink's own pending is discarded on reopen.
        let mut backing = enc.into_backing();
        backing.crash();

        let reopened = EncryptedLogSink::open(backing, &kr).expect("reopen");
        assert_eq!(
            reopened.durable_len(),
            9,
            "only the synced prefix is durable"
        );
        let mut out = Vec::new();
        reopened.read_durable(0, &mut out).expect("read");
        assert_eq!(out, b"committed");
    }

    #[test]
    fn torn_last_frame_is_dropped_on_open() {
        // Two synced frames, then truncate the backing's durable bytes mid-second-frame: the torn
        // last frame must be dropped, leaving the first frame's logical length durable.
        let kr = keyring(0x59);
        let mut enc = fresh(&kr);
        enc.append(b"first");
        enc.sync().expect("sync 1");
        enc.append(b"second-and-longer");
        enc.sync().expect("sync 2");

        let backing = enc.into_backing();
        let mut bytes = backing.durable_bytes().to_vec();
        // Truncate a few bytes off the end → the second frame is now short/torn.
        bytes.truncate(bytes.len() - 5);
        let mut torn = MemLogSink::new();
        torn.append(&bytes);
        torn.sync().expect("sync torn");

        let reopened = EncryptedLogSink::open(torn, &kr).expect("reopen");
        assert_eq!(
            reopened.durable_len(),
            5,
            "the torn second frame is dropped; only 'first' remains"
        );
        let mut out = Vec::new();
        reopened.read_durable(0, &mut out).expect("read");
        assert_eq!(out, b"first");
    }

    #[test]
    fn read_durable_from_within_a_frame_returns_the_suffix() {
        // Multi-frame log; read from an offset in the MIDDLE of the first frame and assert the
        // returned plaintext is the correct logical suffix.
        let kr = keyring(0x5A);
        let mut enc = fresh(&kr);
        enc.append(b"ABCDE"); // frame 0: logical [0,5)
        enc.sync().expect("sync 1");
        enc.append(b"FGHIJ"); // frame 1: logical [5,10)
        enc.sync().expect("sync 2");

        // from = 3 lands inside frame 0; expect "DE" + "FGHIJ".
        let mut out = Vec::new();
        enc.read_durable(3, &mut out).expect("read from 3");
        assert_eq!(out, b"DEFGHIJ");

        // from at a frame boundary.
        let mut out2 = Vec::new();
        enc.read_durable(5, &mut out2).expect("read from 5");
        assert_eq!(out2, b"FGHIJ");

        // from in the middle of the second frame.
        let mut out3 = Vec::new();
        enc.read_durable(7, &mut out3).expect("read from 7");
        assert_eq!(out3, b"HIJ");

        // from == durable_len → empty.
        let mut out4 = Vec::new();
        enc.read_durable(10, &mut out4).expect("read from end");
        assert!(out4.is_empty());
    }

    #[test]
    fn empty_sync_forwards_to_backing_and_is_a_noop() {
        let kr = keyring(0x5B);
        let mut enc = fresh(&kr);
        // Sync with nothing pending: must not create a frame, must not change durable_len.
        enc.sync().expect("empty sync");
        assert_eq!(enc.durable_len(), 0);
        assert!(enc.frames.is_empty());
    }

    #[test]
    fn create_rejects_a_non_empty_backing() {
        let kr = keyring(0x5D);
        let mut backing = MemLogSink::new();
        backing.append(b"pre-existing");
        backing.sync().expect("sync");
        assert!(matches!(
            EncryptedLogSink::create(backing, &kr),
            Err(GraphusError::Storage(_))
        ));
    }

    /// Reads the KCV length out of an encoded sink header (test helper for byte-poking).
    fn kcv_len_of(bytes: &[u8]) -> usize {
        u32::from_le_bytes(read4(bytes, HDR_OFF_KCV_LEN)) as usize
    }
}
