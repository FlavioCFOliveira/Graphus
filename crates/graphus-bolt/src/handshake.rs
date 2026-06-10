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
//! minors). The Manifest-v1 handshake (client proposes `00 00 01 FF`) is **deferred to Phase 2**
//! (`06 §1.2`); this module implements the legacy handshake only.
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
}
