//! The Bolt **legacy 4-slot handshake** (`04-technical-design.md` §8.1; `06-bolt-and-error-shapes.md`
//! §1, which **pins Bolt 5.4** and makes this handshake mandatory).
//!
//! Before any message flows, the client opens with the 4-byte magic preamble `60 60 B0 17`, then
//! **four** big-endian 32-bit version proposals. The server replies with the single chosen
//! [`Version`] (4 bytes) or `00 00 00 00` to reject (`04 §8.1`, `06 §1`).
//!
//! ## Version encoding (range-encoded since Bolt 4.3)
//!
//! Each 32-bit proposal is big-endian `[00, range, minor, major]` (verified against the Neo4j Bolt
//! handshake spec, 2026-06):
//!
//! - byte 0 is reserved (`00`);
//! - byte 1 is the **range** — how many consecutive minors *below* `minor` are also acceptable;
//! - byte 2 is the **minor**;
//! - byte 3 is the **major**.
//!
//! So `00 00 04 05` proposes exactly 5.4, and `00 02 04 05` proposes 5.2–5.4 (a span of three
//! minors).
//!
//! ## The Manifest-v1 handshake (`06 §1.2`; rmp #95)
//!
//! A modern driver can ask for **Manifest-v1** negotiation instead of the legacy fixed reply: it
//! substitutes the special proposal `00 00 01 FF` for one of its four slots (the other three being
//! `00 00 00 00` or further legacy proposals — see the Neo4j Bolt handshake-manifest-v1 spec). The
//! first transmission is still the 20-byte magic + 4 slots; the manifest exchange is then a **second
//! round**:
//!
//! 1. the server replies with the manifest acknowledgment `00 00 01 FF`, then a **varint** count of
//!    supported version ranges, then each range in the same `[00, range, minor, major]` form, then a
//!    **varint** capabilities bitmask (`0` = no extra capabilities);
//! 2. the client sends back its **chosen 4-byte version** followed by a **varint** of the
//!    capabilities it accepts;
//! 3. the connection proceeds at the chosen version exactly as the legacy path would.
//!
//! The varint is the Bolt LEB128 form: 7 bits per byte, least-significant group first, the high bit
//! of each byte a continuation flag. Graphus advertises **one** range (5.0–5.4) and **no**
//! capabilities, so its manifest is short and constant; both handshake forms negotiate the *same*
//! version window. [`detect_manifest_request`], [`encode_server_manifest`] and
//! [`parse_manifest_choice`] are the manifest primitives; the legacy path
//! ([`parse_client_handshake`] / [`negotiate`] / [`server_reply`]) is unchanged.
//!
//! ## What Graphus negotiates
//!
//! Graphus pins **5.4 as the maximum** (`06 §1`) and negotiates **down to any 5.0–5.4 minor** a
//! client requests within that window. [`negotiate`] picks the **highest** mutually-supported minor
//! across the four proposals (drivers list their preference highest-first; choosing the highest
//! offered minor that we support is the standard, driver-friendly rule).

use crate::error::{BoltError, BoltResult};

/// The 4-byte Bolt magic preamble that opens every connection (`04 §8.1`).
pub const MAGIC: [u8; 4] = [0x60, 0x60, 0xB0, 0x17];

/// The number of version proposal slots in the legacy handshake (`04 §8.1`).
pub const PROPOSAL_SLOTS: usize = 4;

/// The Bolt major version Graphus speaks.
pub const SUPPORTED_MAJOR: u8 = 5;
/// The lowest Bolt 5.x minor Graphus accepts (the 5.0 baseline, `06 §1`).
pub const MIN_MINOR: u8 = 0;
/// The highest Bolt 5.x minor Graphus accepts and certifies (pinned to 5.4, `06 §1`).
pub const MAX_MINOR: u8 = 4;

/// A negotiated or proposed Bolt protocol version (`major.minor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// The major version.
    pub major: u8,
    /// The minor version.
    pub minor: u8,
}

impl Version {
    /// Constructs a version.
    #[must_use]
    pub const fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    /// The wire bytes for a **single** (non-range) version: `[00, 00, minor, major]`.
    ///
    /// This is the form the server uses to reply with the chosen version, and a client uses to
    /// propose exactly one version.
    #[must_use]
    pub fn to_wire(self) -> [u8; 4] {
        [0x00, 0x00, self.minor, self.major]
    }

    /// Decodes a **single** (non-range, range byte ignored) version from 4 big-endian bytes.
    #[must_use]
    pub fn from_wire(bytes: [u8; 4]) -> Self {
        Self {
            major: bytes[3],
            minor: bytes[2],
        }
    }

    /// Whether Graphus supports this exact version (major 5, minor `0..=4`).
    #[must_use]
    pub fn is_supported(self) -> bool {
        self.major == SUPPORTED_MAJOR && (MIN_MINOR..=MAX_MINOR).contains(&self.minor)
    }
}

/// The all-zero version that the server returns to **reject** every proposal (`04 §8.1`).
pub const REJECTION: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// A single range-encoded version proposal: a top minor plus how many minors below it are also
/// offered (`04 §8.1`, range-encoded since 4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proposal {
    /// The major version proposed.
    pub major: u8,
    /// The highest minor in the proposed span.
    pub minor: u8,
    /// How many consecutive minors *below* `minor` are also acceptable (`minor - range ..= minor`).
    pub range: u8,
}

impl Proposal {
    /// A proposal for an exact single version (range 0).
    #[must_use]
    pub const fn exact(major: u8, minor: u8) -> Self {
        Self {
            major,
            minor,
            range: 0,
        }
    }

    /// A proposal spanning `minor - range ..= minor`.
    #[must_use]
    pub const fn range(major: u8, minor: u8, range: u8) -> Self {
        Self {
            major,
            minor,
            range,
        }
    }

    /// The wire bytes `[00, range, minor, major]`.
    #[must_use]
    pub fn to_wire(self) -> [u8; 4] {
        [0x00, self.range, self.minor, self.major]
    }

    /// Decodes a proposal from 4 big-endian bytes.
    #[must_use]
    pub fn from_wire(bytes: [u8; 4]) -> Self {
        Self {
            major: bytes[3],
            minor: bytes[2],
            range: bytes[1],
        }
    }

    /// The highest minor in this proposal that Graphus supports, if any.
    ///
    /// Walks the proposed span from its top (`minor`) downward to `minor - range` (saturating at 0)
    /// and returns the first minor that is within Graphus's supported window. Returning the highest
    /// is what makes [`negotiate`] pick the best mutually-supported version.
    fn best_supported_minor(self) -> Option<u8> {
        if self.major != SUPPORTED_MAJOR {
            return None;
        }
        let lowest = self.minor.saturating_sub(self.range);
        // Iterate from the top of the span downward.
        for minor in (lowest..=self.minor).rev() {
            if (MIN_MINOR..=MAX_MINOR).contains(&minor) {
                return Some(minor);
            }
        }
        None
    }
}

/// Parses the client's handshake opening: the magic preamble followed by exactly four 4-byte
/// proposals (16 bytes), for a 20-byte total.
///
/// # Errors
/// [`BoltError::Handshake`] if the input is not 20 bytes or the magic preamble is wrong.
pub fn parse_client_handshake(bytes: &[u8]) -> BoltResult<[Proposal; PROPOSAL_SLOTS]> {
    const EXPECTED_LEN: usize = MAGIC.len() + PROPOSAL_SLOTS * 4;
    if bytes.len() != EXPECTED_LEN {
        return Err(BoltError::Handshake(format!(
            "handshake must be {EXPECTED_LEN} bytes (magic + 4 proposals), got {}",
            bytes.len()
        )));
    }
    if bytes[..MAGIC.len()] != MAGIC {
        return Err(BoltError::Handshake(format!(
            "bad magic preamble {:02x?}, expected {:02x?}",
            &bytes[..MAGIC.len()],
            MAGIC
        )));
    }
    let mut proposals = [Proposal::exact(0, 0); PROPOSAL_SLOTS];
    for (i, slot) in proposals.iter_mut().enumerate() {
        let off = MAGIC.len() + i * 4;
        let b: [u8; 4] = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
        *slot = Proposal::from_wire(b);
    }
    Ok(proposals)
}

/// Chooses the version Graphus will speak from the client's four proposals (`04 §8.1`, `06 §1`).
///
/// Returns the **highest** Bolt 5.x minor (within `5.0..=5.4`) that any proposal offers; `None` if
/// no proposal overlaps Graphus's supported window. A `00 00 00 00` unused slot decodes to major 0
/// and is naturally unsupported, so empty slots are ignored.
#[must_use]
pub fn negotiate(proposals: &[Proposal]) -> Option<Version> {
    proposals
        .iter()
        .filter_map(|p| p.best_supported_minor())
        .max()
        .map(|minor| Version::new(SUPPORTED_MAJOR, minor))
}

/// The 4 wire bytes the server sends in reply: the chosen version, or [`REJECTION`].
#[must_use]
pub fn server_reply(chosen: Option<Version>) -> [u8; 4] {
    chosen.map_or(REJECTION, Version::to_wire)
}

// ---- Manifest-v1 handshake (`06 §1.2`; rmp #95) ------------------------------------------------

/// The special 4-byte slot a client sends to request **Manifest-v1** negotiation: two reserved
/// bytes, the manifest version (`01`), and the manifest marker (`FF`) (Neo4j Bolt
/// handshake-manifest-v1 spec).
pub const MANIFEST_V1_REQUEST: [u8; 4] = [0x00, 0x00, 0x01, 0xFF];

/// Whether any of the client's legacy proposals is the Manifest-v1 request marker.
///
/// A manifest-aware client substitutes [`MANIFEST_V1_REQUEST`] for one of its four 32-bit slots; the
/// other slots are unused (`00 00 00 00`) or further legacy proposals. Seeing the marker means the
/// server must run the manifest exchange ([`encode_server_manifest`] then [`parse_manifest_choice`])
/// rather than reply with a single legacy version.
#[must_use]
pub fn detect_manifest_request(proposals: &[Proposal]) -> bool {
    proposals.iter().any(|p| p.to_wire() == MANIFEST_V1_REQUEST)
}

/// Appends a Bolt LEB128 varint of `value` to `out` (7 bits per byte, least-significant group first,
/// the high bit a continuation flag; `0` encodes as the single byte `0x00`).
fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = u8::try_from(value & 0x7F).unwrap_or(0);
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Reads a Bolt LEB128 varint from `bytes` starting at `*pos`, advancing `*pos` past it.
///
/// # Errors
/// [`BoltError::Handshake`] if the bytes end mid-varint or the value would overflow `u64`.
fn read_varint(bytes: &[u8], pos: &mut usize) -> BoltResult<u64> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        let &byte = bytes.get(*pos).ok_or_else(|| {
            BoltError::Handshake("truncated manifest varint (unexpected end of input)".to_owned())
        })?;
        *pos += 1;
        let payload = u64::from(byte & 0x7F);
        // 64-bit varints never need more than ten 7-bit groups; reject an over-long encoding rather
        // than silently shifting bits off the top.
        if shift >= 64 || (shift == 63 && payload > 1) {
            return Err(BoltError::Handshake(
                "manifest varint overflows u64".to_owned(),
            ));
        }
        value |= payload << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

/// Encodes the server's Manifest-v1 reply: the acknowledgment `00 00 01 FF`, a varint range count,
/// each supported version range (`[00, range, minor, major]`), then a varint capabilities bitmask
/// (Neo4j Bolt handshake-manifest-v1 spec).
///
/// `ranges` are advertised in the order given (drivers read them highest-first); `capabilities` is
/// the server's bitmask of vendor amendments (Graphus advertises `0` — none).
#[must_use]
pub fn encode_server_manifest(ranges: &[Proposal], capabilities: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(MANIFEST_V1_REQUEST.len() + ranges.len() * 4 + 2);
    out.extend_from_slice(&MANIFEST_V1_REQUEST);
    // The advertised-range count fits a u64 on every supported platform.
    write_varint(&mut out, u64::try_from(ranges.len()).unwrap_or(u64::MAX));
    for range in ranges {
        out.extend_from_slice(&range.to_wire());
    }
    write_varint(&mut out, capabilities);
    out
}

/// Graphus's advertised manifest range: the single 5.0–5.4 window (`MIN_MINOR..=MAX_MINOR`),
/// encoded as one [`Proposal`] (top minor `MAX_MINOR`, spanning down to `MIN_MINOR`).
#[must_use]
pub fn supported_manifest_range() -> Proposal {
    Proposal::range(SUPPORTED_MAJOR, MAX_MINOR, MAX_MINOR - MIN_MINOR)
}

/// The server's full Manifest-v1 reply bytes for Graphus's supported window and no capabilities.
#[must_use]
pub fn graphus_manifest() -> Vec<u8> {
    encode_server_manifest(&[supported_manifest_range()], 0)
}

/// The client's chosen version + accepted capabilities, sent after the server's manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestChoice {
    /// The 4-byte version the client picked (decoded as a single, non-range version).
    pub version: Version,
    /// The capabilities the client accepts (a bitmask varint; `0` = none).
    pub capabilities: u64,
}

/// Encodes a client's post-manifest response: the chosen 4-byte version followed by a varint of the
/// accepted capabilities (the inverse of [`parse_manifest_choice`]; used by clients and tests).
#[must_use]
pub fn encode_manifest_choice(choice: ManifestChoice) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&choice.version.to_wire());
    write_varint(&mut out, choice.capabilities);
    out
}

/// Parses the client's post-manifest response: a 4-byte chosen version followed by a varint of the
/// capabilities the client accepts (Neo4j Bolt handshake-manifest-v1 spec).
///
/// # Errors
/// [`BoltError::Handshake`] if fewer than 4 version bytes are present or the trailing capabilities
/// varint is truncated/overflowing.
pub fn parse_manifest_choice(bytes: &[u8]) -> BoltResult<ManifestChoice> {
    let version_bytes: [u8; 4] =
        bytes
            .get(..4)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| {
                BoltError::Handshake(format!(
                    "manifest choice must start with a 4-byte version, got {} bytes",
                    bytes.len()
                ))
            })?;
    let mut pos = 4;
    let capabilities = read_varint(bytes, &mut pos)?;
    Ok(ManifestChoice {
        version: Version::from_wire(version_bytes),
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds the 20-byte client handshake from four proposals.
    fn client_bytes(proposals: [Proposal; 4]) -> Vec<u8> {
        let mut v = Vec::with_capacity(20);
        v.extend_from_slice(&MAGIC);
        for p in proposals {
            v.extend_from_slice(&p.to_wire());
        }
        v
    }

    #[test]
    fn exact_54_proposal_is_accepted() {
        let bytes = client_bytes([
            Proposal::exact(5, 4),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
        ]);
        // 00 00 04 05 in slot 1.
        assert_eq!(&bytes[4..8], &[0x00, 0x00, 0x04, 0x05]);
        let proposals = parse_client_handshake(&bytes).unwrap();
        let chosen = negotiate(&proposals).unwrap();
        assert_eq!(chosen, Version::new(5, 4));
        assert_eq!(server_reply(Some(chosen)), [0x00, 0x00, 0x04, 0x05]);
    }

    #[test]
    fn unsupported_version_is_rejected() {
        // A client speaking only 6.0 and 4.x (below our 5.0 floor in major terms).
        let bytes = client_bytes([
            Proposal::exact(6, 0),
            Proposal::exact(4, 4),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
        ]);
        let proposals = parse_client_handshake(&bytes).unwrap();
        assert_eq!(negotiate(&proposals), None);
        assert_eq!(server_reply(None), REJECTION);
    }

    #[test]
    fn range_encoded_proposal_negotiates_highest_supported() {
        // Proposes 5.2..=5.6 (top 5.6, range 4). We cap at 5.4, so we must pick 5.4.
        let bytes = client_bytes([
            Proposal::range(5, 6, 4),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
        ]);
        // 00 04 06 05.
        assert_eq!(&bytes[4..8], &[0x00, 0x04, 0x06, 0x05]);
        let proposals = parse_client_handshake(&bytes).unwrap();
        assert_eq!(negotiate(&proposals), Some(Version::new(5, 4)));
    }

    #[test]
    fn range_below_our_floor_is_rejected() {
        // Proposes 4.0..=4.4 — major 5 mismatch, no overlap.
        let bytes = client_bytes([
            Proposal::range(4, 4, 4),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
        ]);
        let proposals = parse_client_handshake(&bytes).unwrap();
        assert_eq!(negotiate(&proposals), None);
    }

    #[test]
    fn highest_across_slots_wins() {
        // Slot 1 offers 5.1, slot 2 offers 5.3: pick 5.3.
        let bytes = client_bytes([
            Proposal::exact(5, 1),
            Proposal::exact(5, 3),
            Proposal::exact(5, 0),
            Proposal::exact(0, 0),
        ]);
        let proposals = parse_client_handshake(&bytes).unwrap();
        assert_eq!(negotiate(&proposals), Some(Version::new(5, 3)));
    }

    #[test]
    fn range_spanning_into_our_window_picks_top_of_overlap() {
        // Proposes 5.3..=5.9 — overlap with our window is just 5.3 and 5.4; pick 5.4.
        let proposals = [Proposal::range(5, 9, 6)];
        assert_eq!(negotiate(&proposals), Some(Version::new(5, 4)));
        // Proposes only 5.0 exactly.
        assert_eq!(
            negotiate(&[Proposal::exact(5, 0)]),
            Some(Version::new(5, 0))
        );
    }

    #[test]
    fn bad_magic_and_bad_length_error() {
        let mut bad = client_bytes([Proposal::exact(5, 4); 4]);
        bad[0] = 0x00;
        assert!(matches!(
            parse_client_handshake(&bad),
            Err(BoltError::Handshake(_))
        ));
        assert!(matches!(
            parse_client_handshake(&[0x60, 0x60, 0xB0, 0x17]),
            Err(BoltError::Handshake(_))
        ));
    }

    #[test]
    fn version_wire_round_trips() {
        let v = Version::new(5, 4);
        assert_eq!(Version::from_wire(v.to_wire()), v);
        assert!(v.is_supported());
        assert!(!Version::new(5, 5).is_supported());
        assert!(!Version::new(4, 4).is_supported());
    }

    // ---- Manifest-v1 handshake (rmp #95) ------------------------------------------------------

    #[test]
    fn varint_round_trips_across_boundaries() {
        for value in [0u64, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 1_851_775, u64::MAX] {
            let mut buf = Vec::new();
            write_varint(&mut buf, value);
            let mut pos = 0;
            assert_eq!(
                read_varint(&buf, &mut pos).unwrap(),
                value,
                "value {value:#x}"
            );
            assert_eq!(pos, buf.len(), "varint fully consumed for {value:#x}");
        }
        // Zero is a single 0x00 byte (capabilities "none").
        let mut zero = Vec::new();
        write_varint(&mut zero, 0);
        assert_eq!(zero, [0x00]);
        // The spec's worked example FF 82 71 decodes to 1,851,775.
        let mut pos = 0;
        assert_eq!(
            read_varint(&[0xFF, 0x82, 0x71], &mut pos).unwrap(),
            1_851_775
        );
    }

    #[test]
    fn truncated_or_overlong_varint_errors() {
        // A dangling continuation bit with no following byte.
        let mut pos = 0;
        assert!(matches!(
            read_varint(&[0x80], &mut pos),
            Err(BoltError::Handshake(_))
        ));
        // Eleven 0x80 bytes (more than ten 7-bit groups) overflows u64.
        let overlong = [0x80u8; 11];
        let mut pos = 0;
        assert!(matches!(
            read_varint(&overlong, &mut pos),
            Err(BoltError::Handshake(_))
        ));
    }

    #[test]
    fn detect_manifest_request_in_any_slot() {
        let proposals = parse_client_handshake(&client_bytes([
            Proposal::exact(0, 0),
            Proposal::from_wire(MANIFEST_V1_REQUEST),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
        ]))
        .unwrap();
        assert!(detect_manifest_request(&proposals));

        // A purely legacy handshake is not a manifest request.
        let legacy = parse_client_handshake(&client_bytes([
            Proposal::exact(5, 4),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
        ]))
        .unwrap();
        assert!(!detect_manifest_request(&legacy));
    }

    #[test]
    fn server_manifest_advertises_the_5_0_to_5_4_window() {
        let manifest = graphus_manifest();
        // Acknowledgment, then varint count = 1, then the single range, then varint capabilities = 0.
        assert_eq!(&manifest[..4], &MANIFEST_V1_REQUEST, "manifest ack");
        assert_eq!(manifest[4], 0x01, "one advertised range");
        // The range is 5.4 spanning down to 5.0: [00, range=4, minor=4, major=5].
        assert_eq!(&manifest[5..9], &[0x00, 0x04, 0x04, 0x05]);
        assert_eq!(manifest[9], 0x00, "no extra capabilities");
        assert_eq!(manifest.len(), 10);

        // The advertised range negotiates exactly Graphus's legacy window.
        let range = supported_manifest_range();
        assert_eq!(negotiate(&[range]), Some(Version::new(5, 4)));
        assert_eq!(range.best_supported_minor(), Some(4));
    }

    #[test]
    fn parse_manifest_choice_reads_version_and_capabilities() {
        // Client picks 5.4 and accepts no capabilities.
        let choice = parse_manifest_choice(&[0x00, 0x00, 0x04, 0x05, 0x00]).unwrap();
        assert_eq!(choice.version, Version::new(5, 4));
        assert_eq!(choice.capabilities, 0);

        // A multi-byte capabilities varint after the version.
        let choice = parse_manifest_choice(&[0x00, 0x00, 0x02, 0x05, 0x80, 0x01]).unwrap();
        assert_eq!(choice.version, Version::new(5, 2));
        assert_eq!(choice.capabilities, 128);
    }

    #[test]
    fn manifest_choice_too_short_errors() {
        // Only 3 version bytes.
        assert!(matches!(
            parse_manifest_choice(&[0x00, 0x00, 0x04]),
            Err(BoltError::Handshake(_))
        ));
        // 4 version bytes but no capabilities varint.
        assert!(matches!(
            parse_manifest_choice(&[0x00, 0x00, 0x04, 0x05]),
            Err(BoltError::Handshake(_))
        ));
    }

    #[test]
    fn both_handshake_forms_negotiate_the_same_version() {
        // Legacy: a 5.0..=5.4 range proposal negotiates 5.4.
        let legacy = negotiate(&[Proposal::range(5, 4, 4)]);
        assert_eq!(legacy, Some(Version::new(5, 4)));

        // Manifest: the server advertises its window, the client picks 5.4 from it. The negotiated
        // version is identical to the legacy outcome.
        let manifest = graphus_manifest();
        // Confirm the server's advertised top is 5.4 (the byte the manifest carries).
        assert_eq!(&manifest[5..9], &Proposal::range(5, 4, 4).to_wire());
        let choice = parse_manifest_choice(&[0x00, 0x00, 0x04, 0x05, 0x00]).unwrap();
        assert_eq!(choice.version, legacy.unwrap());
        assert!(choice.version.is_supported());
    }
}
