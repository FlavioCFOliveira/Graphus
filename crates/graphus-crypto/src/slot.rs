//! The physical **slot** layout for one encrypted logical page.
//!
//! Each logical 8192-byte page is stored in exactly one atomic physical slot of
//!
//! ```text
//!   nonce(12) || tag(16) || ciphertext(8192)   =  8220 bytes
//! ```
//!
//! ## Why one slot, one positioned write (the crash-consistency argument)
//!
//! The whole encrypted record of a page — its nonce, its GCM authentication tag, and its
//! ciphertext — lives in a single contiguous slot written with **one** positioned write
//! (`write_all_at`). A torn or partial physical write therefore corrupts **exactly one slot** and
//! is caught by AEAD verification on the next read (the tag will not validate). This is the same
//! one-page blast radius as today's per-page CRC: a torn page is *detected*, never silently
//! accepted. A split layout (a ciphertext region plus a separate tag region) would need two writes
//! and so has a crash window where the tag and ciphertext disagree — we deliberately avoid it.
//!
//! GCM ciphertext length equals plaintext length, so the ciphertext is exactly [`PAGE_SIZE`]
//! (8192) bytes; the 16-byte authentication tag is stored separately, alongside the 12-byte nonce.

use graphus_io::PAGE_SIZE;

/// AES-GCM nonce length in bytes (96-bit, the standard GCM nonce size).
pub const NONCE_LEN: usize = 12;

/// AES-GCM authentication tag length in bytes (128-bit).
pub const TAG_LEN: usize = 16;

/// The size of one physical slot: `nonce || tag || ciphertext`.
pub const SLOT_SIZE: usize = NONCE_LEN + TAG_LEN + PAGE_SIZE;

/// Byte offset of the nonce within a slot.
pub const NONCE_OFFSET: usize = 0;
/// Byte offset of the tag within a slot.
pub const TAG_OFFSET: usize = NONCE_LEN;
/// Byte offset of the ciphertext within a slot.
pub const CIPHERTEXT_OFFSET: usize = NONCE_LEN + TAG_LEN;

/// Exactly one physical slot worth of bytes.
pub type Slot = [u8; SLOT_SIZE];

/// A borrowed view of the three regions of a slot for reading.
pub struct SlotView<'a> {
    /// The 12-byte nonce.
    pub nonce: &'a [u8; NONCE_LEN],
    /// The 16-byte authentication tag.
    pub tag: &'a [u8; TAG_LEN],
    /// The 8192-byte ciphertext.
    pub ciphertext: &'a [u8; PAGE_SIZE],
}

/// Splits a slot into its `(nonce, tag, ciphertext)` regions for decryption.
#[must_use]
pub fn view(slot: &Slot) -> SlotView<'_> {
    // The slices below are all in-bounds by `SLOT_SIZE`'s definition; the `try_into`/`unwrap`s are
    // infallible because the lengths are compile-time constants matching the array types.
    let nonce: &[u8; NONCE_LEN] = slot[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN]
        .try_into()
        .expect("INVARIANT: nonce region is exactly NONCE_LEN bytes by SLOT_SIZE construction");
    let tag: &[u8; TAG_LEN] = slot[TAG_OFFSET..TAG_OFFSET + TAG_LEN]
        .try_into()
        .expect("INVARIANT: tag region is exactly TAG_LEN bytes by SLOT_SIZE construction");
    let ciphertext: &[u8; PAGE_SIZE] = slot[CIPHERTEXT_OFFSET..CIPHERTEXT_OFFSET + PAGE_SIZE]
        .try_into()
        .expect(
            "INVARIANT: ciphertext region is exactly PAGE_SIZE bytes by SLOT_SIZE construction",
        );
    SlotView {
        nonce,
        tag,
        ciphertext,
    }
}

/// Assembles a slot from its `(nonce, tag, ciphertext)` regions for writing.
#[must_use]
pub fn assemble(
    nonce: &[u8; NONCE_LEN],
    tag: &[u8; TAG_LEN],
    ciphertext: &[u8; PAGE_SIZE],
) -> Slot {
    let mut slot = [0u8; SLOT_SIZE];
    slot[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN].copy_from_slice(nonce);
    slot[TAG_OFFSET..TAG_OFFSET + TAG_LEN].copy_from_slice(tag);
    slot[CIPHERTEXT_OFFSET..CIPHERTEXT_OFFSET + PAGE_SIZE].copy_from_slice(ciphertext);
    slot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_size_is_the_sum_of_regions() {
        assert_eq!(SLOT_SIZE, 12 + 16 + 8192);
        assert_eq!(SLOT_SIZE, 8220);
    }

    #[test]
    fn assemble_then_view_roundtrips() {
        let nonce = [7u8; NONCE_LEN];
        let tag = [9u8; TAG_LEN];
        let mut ct = [0u8; PAGE_SIZE];
        ct[0] = 1;
        ct[PAGE_SIZE - 1] = 2;
        let slot = assemble(&nonce, &tag, &ct);
        let v = view(&slot);
        assert_eq!(v.nonce, &nonce);
        assert_eq!(v.tag, &tag);
        assert_eq!(v.ciphertext, &ct);
    }
}
