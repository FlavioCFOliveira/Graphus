//! **Incremental backup chains + point-in-time recovery (PITR)** for a [`RecordStore`] (`rmp` task
//! #71; builds on the offline full backup of [`crate::backup`], `rmp` task #23).
//!
//! Phase-1 backup is a single, self-contained *full* artifact ([`backup_store`]). Production needs
//! two more properties that a full-only scheme cannot give:
//!
//! 1. **Incremental backup** — ship only the *changes* since the last backup, so the steady-state
//!    backup cost is proportional to the write rate, not to the database size.
//! 2. **Point-in-time recovery (PITR)** — restore to any *committed* point in the past (a chosen
//!    LSN or commit timestamp), so the recovery-point objective is bounded by the increment cadence,
//!    not pinned to whole-backup boundaries.
//!
//! Both are achieved by a **backup chain**: one *base* full artifact plus an ordered list of
//! *increments*, each capturing the WAL bytes appended since the previous link, tied together by a
//! CRC-protected [`ChainManifest`]. Restore = lay down the base, then replay the chain's WAL up to
//! the target point through the **existing recovery machinery** — PITR is *recovery over a WAL
//! truncated at the target*, which is exactly why a restored state is always a consistent committed
//! state (see [`restore_to`]).
//!
//! # Why this is sound (and reuses the proven machinery)
//!
//! This module **adds a layer** over the frozen, audited primitives; it forks none of them:
//!
//! * the base is a [`backup_store`] artifact, verified by [`verify_backup`] and laid down by
//!   [`restore_onto`](crate::restore_onto) — byte-for-byte the Phase-1 path;
//! * an increment is a verbatim slice of the durable WAL byte stream (`[from_lsn, to_lsn)`), and the
//!   LSN *is* the byte offset (`04 §4.1`), so increments concatenate into a contiguous logical WAL
//!   with no re-encoding;
//! * replay is the standard three-phase ARIES [`recover`](graphus_wal::recover) against the storage
//!   [`DeviceTarget`](crate::recovery::DeviceTarget) — redo repeats history, undo rolls back every
//!   transaction not committed by the cut. PITR is implemented purely by **pre-truncating the
//!   concatenated WAL bytes** at the target; `recover` itself is untouched.
//!
//! # Chain anatomy
//!
//! ```text
//!   base (full artifact)                 increments (WAL byte ranges)
//!   ┌───────────────────┐   ┌──────────────────┐ ┌──────────────────┐
//!   │ backup_store image │   │ WAL [L0 .. L1)   │ │ WAL [L1 .. L2)   │  ...
//!   │  + base_lsn = L0   │   │  crc, len        │ │  crc, len        │
//!   └───────────────────┘   └──────────────────┘ └──────────────────┘
//!         link 0                   link 1                link 2
//!
//!   base_lsn == L0,  increments contiguous:  from_lsn[k] == to_lsn[k-1]  (== base_lsn for k=1)
//! ```
//!
//! The [`ChainManifest`] records, in order: the base's creation marker and `base_lsn`, then each
//! increment's `(from_lsn, to_lsn, crc32c, len)`, plus a 128-bit `chain_id` and a format version.
//! The manifest is itself CRC-protected. [`verify_chain`] re-proves the whole chain: the base
//! verifies, every increment's CRC matches its bytes, and the LSN ranges are **contiguous from
//! `base_lsn` onward with no gap and no overlap** — a corrupt link, a broken CRC, or a missing link
//! is detected and located precisely.
//!
//! # Encryption integration (no dependency cycle)
//!
//! `graphus-storage` must **not** depend on `graphus-crypto` (the dependency runs the other way:
//! `graphus-crypto -> graphus-storage`). So this module never calls `seal_backup`/`open_backup`
//! directly; instead it is generic over a [`LinkCodec`] seam. The default [`Plain`] codec is the
//! identity (an unencrypted chain). The server wires an *encrypting* codec backed by
//! `graphus_crypto::{seal_backup, open_backup}` when a master key is configured (the adapter +
//! its end-to-end test live in `graphus-crypto`, which already has both crates in scope). Each link
//! — the base artifact and every increment — is sealed independently, so:
//!
//! * a sealed chain leaks no page content or WAL content without the key (AES-256-GCM
//!   confidentiality);
//! * tamper is caught twice over — the AEAD tag fails first for a sealed chain, and the per-link
//!   CRC catches it for an unencrypted chain (and is re-checked on the *opened* plaintext anyway);
//! * [`verify_chain`] and [`restore_to`] **open each link first**, so verification and restore run
//!   over plaintext exactly as in the unencrypted case.
//!
//! # RPO / RTO model
//!
//! * **RPO (recovery-point objective)** — bounded by the **increment cadence**: any committed work
//!   written *after* the most recent increment was captured is not in the chain and would be lost in
//!   a restore-from-chain. Taking increments every `T` seconds bounds the worst-case data loss to
//!   `T` seconds of commits. (The live WAL on the source host, if it survives, is a separate, finer
//!   recovery source; the chain is the *shippable* backup.)
//! * **RTO (recovery-time objective)** — base-restore time (write every page image of the base,
//!   `O(base size)`) plus WAL-replay-to-target time (redo + undo over the truncated chain,
//!   `O(replayed log bytes)`). It is independent of how *many* increments there are — they
//!   concatenate into one logical log.
//! * **Granularity** — PITR stops at any **committed-transaction boundary**: an [`LSN`](graphus_core::Lsn)
//!   cut, or a commit-timestamp cut (just after the last transaction that committed at or before the
//!   target timestamp). Anything not committed by the cut is a loser and is undone, so the restored
//!   state equals the live state at that exact point.

use graphus_core::error::{GraphusError, Result};
use graphus_core::{Lsn, Timestamp};
use graphus_io::BlockDevice;
use graphus_wal::{
    HEADER_LEN as WAL_HEADER_LEN, LogRecord, LogSink, RecordType, WAL_MAGIC, WAL_VERSION,
    WalManager,
};

use crate::backup::{backup_creation_marker, backup_store, verify_backup};
use crate::recovery::recover_device_from;
use crate::store::RecordStore;

/// The chain manifest format version, bumped on any incompatible manifest-layout change. Distinct
/// from [`crate::BACKUP_FORMAT_VERSION`] (the full-artifact layout): a chain frames full artifacts
/// and WAL ranges, so the two version axes are independent.
pub const CHAIN_FORMAT_VERSION: u32 = 1;

/// One increment's bookkeeping in a [`ChainManifest`]: the half-open WAL byte range it captured and
/// the integrity facts needed to re-prove it without the bytes in hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementMeta {
    /// The first WAL byte offset (LSN) this increment captured (inclusive).
    pub from_lsn: Lsn,
    /// One past the last WAL byte offset (LSN) this increment captured (exclusive).
    pub to_lsn: Lsn,
    /// CRC32C over the increment's WAL bytes (catches bit-rot / truncation of the link).
    pub crc: u32,
    /// The increment's byte length (`to_lsn - from_lsn`); stored redundantly so the manifest can be
    /// validated against the link bytes without arithmetic ambiguity.
    pub len: u64,
}

/// The ordered description of a backup chain: the base watermark plus every increment, with a chain
/// id and a self-protecting CRC. Encoded little-endian (matching the on-disk and artifact formats).
///
/// A manifest is the *index* of a chain; the actual bytes live in the **links** ([`ChainLinks`]).
/// Keeping them separable lets an operator store/ship the (small) manifest independently of the
/// (large) link bytes, and lets [`verify_chain`] re-prove integrity given both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainManifest {
    /// Identifies this chain (so links of different chains cannot be mixed). Set from the base's
    /// creation marker at [`begin_chain`] time.
    pub chain_id: u128,
    /// The full-backup creation marker embedded in the base artifact (operator-facing identity of
    /// which snapshot the base is; cross-checked against the base on [`verify_chain`]).
    pub base_creation_mark: u128,
    /// The WAL `durable_len` captured at base time: everything `< base_lsn` is already in the base's
    /// page images, so the first increment starts here.
    pub base_lsn: Lsn,
    /// The increments, in capture order. Contiguous by construction (asserted on append and on
    /// [`verify_chain`]).
    pub increments: Vec<IncrementMeta>,
}

/// Magic identifying an encoded [`ChainManifest`] (`"GRPHCHN\0"` — Graphus CHaiN).
const MANIFEST_MAGIC: [u8; 8] = *b"GRPHCHN\0";

/// Encoded manifest header length: magic(8) + version(4) + chain_id(16) + base_creation_mark(16) +
/// base_lsn(8) + increment_count(8).
const MANIFEST_HEADER_LEN: usize = 8 + 4 + 16 + 16 + 8 + 8;

/// Encoded length of one increment entry: from_lsn(8) + to_lsn(8) + crc(4) + len(8).
const MANIFEST_INCREMENT_LEN: usize = 8 + 8 + 4 + 8;

/// Trailing whole-manifest CRC32C length.
const MANIFEST_DIGEST_LEN: usize = 4;

impl ChainManifest {
    /// The WAL watermark the chain currently extends to: the last increment's `to_lsn`, or
    /// `base_lsn` if there are no increments yet. The next increment must start exactly here.
    #[must_use]
    pub fn tip_lsn(&self) -> Lsn {
        self.increments
            .last()
            .map_or(self.base_lsn, |inc| inc.to_lsn)
    }

    /// Serialises the manifest to a self-describing, CRC-protected byte vector (little-endian).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            MANIFEST_HEADER_LEN
                + self.increments.len() * MANIFEST_INCREMENT_LEN
                + MANIFEST_DIGEST_LEN,
        );
        out.extend_from_slice(&MANIFEST_MAGIC);
        out.extend_from_slice(&CHAIN_FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.base_creation_mark.to_le_bytes());
        out.extend_from_slice(&self.base_lsn.0.to_le_bytes());
        out.extend_from_slice(&(self.increments.len() as u64).to_le_bytes());
        for inc in &self.increments {
            out.extend_from_slice(&inc.from_lsn.0.to_le_bytes());
            out.extend_from_slice(&inc.to_lsn.0.to_le_bytes());
            out.extend_from_slice(&inc.crc.to_le_bytes());
            out.extend_from_slice(&inc.len.to_le_bytes());
        }
        let digest = crc32c::crc32c(&out);
        out.extend_from_slice(&digest.to_le_bytes());
        out
    }

    /// Parses a manifest from its [`encode`](Self::encode)d form, validating the magic, version, the
    /// declared increment count against the byte length, and the trailing whole-manifest CRC.
    ///
    /// # Errors
    /// Returns [`GraphusError::Storage`] for a too-short buffer, a bad magic, an unsupported version,
    /// a length that contradicts the declared increment count, or a CRC mismatch (a tampered or
    /// truncated manifest).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MANIFEST_HEADER_LEN + MANIFEST_DIGEST_LEN {
            return Err(GraphusError::Storage(format!(
                "chain manifest too short: {} bytes (need at least {})",
                bytes.len(),
                MANIFEST_HEADER_LEN + MANIFEST_DIGEST_LEN
            )));
        }
        if bytes[0..8] != MANIFEST_MAGIC {
            return Err(GraphusError::Storage(
                "chain manifest has a bad magic (not a Graphus backup chain)".to_owned(),
            ));
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().expect("4-byte slice"));
        if version != CHAIN_FORMAT_VERSION {
            return Err(GraphusError::Storage(format!(
                "unsupported chain manifest version {version} (this build supports \
                 {CHAIN_FORMAT_VERSION})"
            )));
        }
        let chain_id = u128::from_le_bytes(bytes[12..28].try_into().expect("16-byte slice"));
        let base_creation_mark =
            u128::from_le_bytes(bytes[28..44].try_into().expect("16-byte slice"));
        let base_lsn = Lsn(u64::from_le_bytes(
            bytes[44..52].try_into().expect("8-byte slice"),
        ));
        let count = u64::from_le_bytes(bytes[52..60].try_into().expect("8-byte slice")) as usize;

        let body = bytes
            .len()
            .checked_sub(MANIFEST_DIGEST_LEN)
            .and_then(|n| n.checked_sub(MANIFEST_HEADER_LEN))
            .ok_or_else(|| GraphusError::Storage("chain manifest truncated".to_owned()))?;
        let expected = count.checked_mul(MANIFEST_INCREMENT_LEN).ok_or_else(|| {
            GraphusError::Storage("chain manifest increment count overflows".to_owned())
        })?;
        if body != expected {
            return Err(GraphusError::Storage(format!(
                "chain manifest body is {body} bytes but declares {count} increment(s) \
                 ({expected} bytes)"
            )));
        }

        let digest_off = bytes.len() - MANIFEST_DIGEST_LEN;
        let stored = u32::from_le_bytes(bytes[digest_off..].try_into().expect("4-byte trailer"));
        let computed = crc32c::crc32c(&bytes[..digest_off]);
        if stored != computed {
            return Err(GraphusError::Storage(format!(
                "chain manifest CRC mismatch: stored {stored:#010x}, computed {computed:#010x} \
                 (manifest tampered or truncated)"
            )));
        }

        let mut increments = Vec::with_capacity(count);
        let mut cur = MANIFEST_HEADER_LEN;
        for _ in 0..count {
            let from_lsn = Lsn(u64::from_le_bytes(
                bytes[cur..cur + 8].try_into().expect("8-byte slice"),
            ));
            let to_lsn = Lsn(u64::from_le_bytes(
                bytes[cur + 8..cur + 16].try_into().expect("8-byte slice"),
            ));
            let crc =
                u32::from_le_bytes(bytes[cur + 16..cur + 20].try_into().expect("4-byte slice"));
            let len =
                u64::from_le_bytes(bytes[cur + 20..cur + 28].try_into().expect("8-byte slice"));
            increments.push(IncrementMeta {
                from_lsn,
                to_lsn,
                crc,
                len,
            });
            cur += MANIFEST_INCREMENT_LEN;
        }
        Ok(Self {
            chain_id,
            base_creation_mark,
            base_lsn,
            increments,
        })
    }
}

/// The actual byte payloads of a chain: the (possibly sealed) base artifact, and the (possibly
/// sealed) WAL bytes of each increment in order. Paired with a [`ChainManifest`] for verification
/// and restore.
///
/// `base` and `increments[k]` are stored exactly as produced by the active [`LinkCodec`]: identity
/// bytes for an unencrypted chain ([`Plain`]), or sealed envelopes for an encrypted one. Nothing in
/// this struct assumes which — the codec is supplied at verify/restore time and must be the same one
/// the chain was written with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainLinks {
    /// The base full-backup link (a [`backup_store`] artifact, then run through the codec).
    pub base: Vec<u8>,
    /// The increment links, in capture order (WAL byte ranges, then run through the codec).
    pub increments: Vec<Vec<u8>>,
}

/// The encode/decode seam for a chain link, so encryption is injectable **without** a
/// `graphus-storage -> graphus-crypto` dependency (which would be a cycle — crypto depends on
/// storage). `seal` is applied when a link is *written*; `open` recovers its plaintext when a link
/// is *verified or restored*.
///
/// The default [`Plain`] codec is the identity (an unencrypted chain). The server supplies an
/// encrypting codec backed by `graphus_crypto::{seal_backup, open_backup}` when a master key is
/// configured; that adapter lives in `graphus-crypto`, where both crates are in scope.
pub trait LinkCodec {
    /// Transforms a plaintext link into its stored form (identity, or a sealed envelope).
    ///
    /// # Errors
    /// Returns an error if sealing fails (e.g. an AEAD encrypt error).
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Recovers a stored link's plaintext (identity, or AEAD-authenticated decryption).
    ///
    /// # Errors
    /// Returns an error if opening fails (wrong key, or a tampered/corrupt envelope).
    fn open(&self, stored: &[u8]) -> Result<Vec<u8>>;
}

/// The identity [`LinkCodec`]: a stored link *is* its plaintext (an unencrypted chain).
#[derive(Debug, Default, Clone, Copy)]
pub struct Plain;

impl LinkCodec for Plain {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(plaintext.to_vec())
    }

    fn open(&self, stored: &[u8]) -> Result<Vec<u8>> {
        Ok(stored.to_vec())
    }
}

/// Starts a new backup chain from `store`: captures the **base** full artifact and the WAL watermark
/// at base time, sealing the base through `codec`.
///
/// The returned `(manifest, base_link)` is the chain at its origin (zero increments). The `base_lsn`
/// recorded in the manifest is the WAL `durable_len` *after* [`backup_store`] has flushed and
/// checkpointed, so every change `< base_lsn` is already captured in the base's page images and the
/// first increment will begin exactly at `base_lsn` (`04 §4.7`).
///
/// # Errors
/// Returns a storage error if the base backup fails (which also means the *source* store is corrupt,
/// see [`backup_store`]), or if `codec.seal` fails.
pub fn begin_chain<D: BlockDevice, S: LogSink, C: LinkCodec>(
    store: &mut RecordStore<D, S>,
    codec: &C,
) -> Result<(ChainManifest, Vec<u8>)> {
    // `backup_store` flushes + checkpoints first; the resulting WAL `durable_len` is the watermark
    // at and after which the incremental WAL capture begins. Order matters: read the watermark
    // *after* the backup so the base and base_lsn are coherent.
    let artifact = backup_store(store)?;
    let base_lsn = store.with_wal(|w| w.durable_len());
    let base_creation_mark = backup_creation_marker(&artifact)?;

    let manifest = ChainManifest {
        // The base's creation marker doubles as the chain id: it is unique to this snapshot and lets
        // links of different chains be told apart on restore.
        chain_id: base_creation_mark,
        base_creation_mark,
        base_lsn: Lsn(base_lsn),
        increments: Vec::new(),
    };
    let base_link = codec.seal(&artifact)?;
    Ok((manifest, base_link))
}

/// Captures the **next increment**: the WAL bytes appended since the chain's current tip
/// (`manifest.tip_lsn()`) up to `store`'s current `durable_len`, sealing them through `codec` and
/// appending the increment's metadata to `manifest`.
///
/// Returns the sealed increment link to append to [`ChainLinks::increments`]. If no WAL bytes have
/// been appended since the tip (`durable_len == tip_lsn`), this is a no-op that returns an **empty**
/// link with a zero-length [`IncrementMeta`] (`from_lsn == to_lsn`); a caller may skip storing it, or
/// store it as a benign marker. The increment is **contiguous** with the chain by construction:
/// `from_lsn == manifest.tip_lsn()`.
///
/// # Errors
/// Returns a storage error if reading the durable WAL fails, if the WAL has somehow gone *backwards*
/// (a `durable_len < tip_lsn` — an impossible state that indicates a misuse / corrupt chain), or if
/// `codec.seal` fails.
pub fn capture_increment<D: BlockDevice, S: LogSink, C: LinkCodec>(
    store: &mut RecordStore<D, S>,
    manifest: &mut ChainManifest,
    codec: &C,
) -> Result<Vec<u8>> {
    let from_lsn = manifest.tip_lsn();
    let to = store.with_wal(|w| w.durable_len());
    if to < from_lsn.0 {
        return Err(GraphusError::Storage(format!(
            "WAL durable_len {to} is behind the chain tip {} — a backup chain cannot capture a \
             negative range",
            from_lsn.0
        )));
    }
    // `read_durable(from, ..)` yields exactly the bytes `[from, durable_len)`; slice to `to` in case
    // a concurrent commit advanced `durable_len` between the two reads (we capture a coherent prefix
    // up to the `to` we sampled).
    let mut bytes = Vec::new();
    store.with_wal(|w| w.read_durable(from_lsn, &mut bytes))?;
    let span = (to - from_lsn.0) as usize;
    bytes.truncate(span);

    let crc = crc32c::crc32c(&bytes);
    manifest.increments.push(IncrementMeta {
        from_lsn,
        to_lsn: Lsn(to),
        crc,
        len: bytes.len() as u64,
    });
    codec.seal(&bytes)
}

/// Re-proves a backup chain end-to-end (`rmp` task #71 integrity AC). Given the `manifest` and its
/// `links`, with the `codec` the chain was written with, checks — in order — that:
///
/// 1. the link count matches the manifest's increment count;
/// 2. every link **opens** under `codec` (for a sealed chain: the AEAD tag authenticates; for a
///    [`Plain`] chain this is the identity);
/// 3. the opened **base** verifies as a full artifact ([`verify_backup`]) and its embedded creation
///    marker matches the manifest's `base_creation_mark`;
/// 4. every opened **increment**'s CRC32C matches the manifest's recorded `crc` and its length
///    matches `len` and `to_lsn - from_lsn`;
/// 5. the LSN ranges are **contiguous from `base_lsn` onward** — `increments[0].from_lsn ==
///    base_lsn`, and each `increments[k].from_lsn == increments[k-1].to_lsn`, with every range
///    non-decreasing (`from_lsn <= to_lsn`). A gap or overlap is rejected with the offending index.
///
/// A corrupt base, a broken increment CRC, a tampered/garbled sealed link, a wrong key, a gap, or an
/// overlap is detected and reported precisely.
///
/// # Errors
/// Returns [`GraphusError::Storage`] (integrity faults) or whatever `codec.open` returns (a
/// [`GraphusError::Security`] for a sealed chain with a wrong key / tampered link), describing the
/// first fault found.
pub fn verify_chain<C: LinkCodec>(
    manifest: &ChainManifest,
    links: &ChainLinks,
    codec: &C,
) -> Result<()> {
    if links.increments.len() != manifest.increments.len() {
        return Err(GraphusError::Storage(format!(
            "chain has {} increment link(s) but the manifest declares {}",
            links.increments.len(),
            manifest.increments.len()
        )));
    }

    // 2 + 3: open and verify the base.
    let base_plain = codec.open(&links.base)?;
    verify_backup(&base_plain)?;
    let base_mark = backup_creation_marker(&base_plain)?;
    if base_mark != manifest.base_creation_mark {
        return Err(GraphusError::Storage(format!(
            "base artifact creation marker {base_mark} does not match the manifest's \
             {} (wrong base for this chain)",
            manifest.base_creation_mark
        )));
    }

    // 4 + 5: open each increment, check its CRC/len, and check contiguity.
    let mut expected_from = manifest.base_lsn;
    for (i, (meta, sealed)) in manifest
        .increments
        .iter()
        .zip(links.increments.iter())
        .enumerate()
    {
        if meta.from_lsn != expected_from {
            return Err(GraphusError::Storage(format!(
                "chain increment {i} starts at LSN {} but the previous link ends at {} \
                 (a gap or overlap in the WAL range)",
                meta.from_lsn.0, expected_from.0
            )));
        }
        if meta.to_lsn < meta.from_lsn {
            return Err(GraphusError::Storage(format!(
                "chain increment {i} has to_lsn {} before from_lsn {} (inverted range)",
                meta.to_lsn.0, meta.from_lsn.0
            )));
        }
        let plain = codec.open(sealed)?;
        let declared_span = meta.to_lsn.0 - meta.from_lsn.0;
        if plain.len() as u64 != meta.len || meta.len != declared_span {
            return Err(GraphusError::Storage(format!(
                "chain increment {i} length mismatch: bytes {}, manifest len {}, range span {}",
                plain.len(),
                meta.len,
                declared_span
            )));
        }
        let crc = crc32c::crc32c(&plain);
        if crc != meta.crc {
            return Err(GraphusError::Storage(format!(
                "chain increment {i} CRC mismatch: stored {:#010x}, computed {crc:#010x} \
                 (corrupt or tampered increment)",
                meta.crc
            )));
        }
        expected_from = meta.to_lsn;
    }
    Ok(())
}

/// The point a [`restore_to`] should recover to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreTarget {
    /// The end of the whole chain (every captured, committed transaction).
    Latest,
    /// A specific WAL LSN (byte offset): replay up to and including the record ending at `Lsn`,
    /// cutting the log there. Anything not committed by the cut is undone.
    Lsn(Lsn),
    /// A commit timestamp: replay up to and including the last transaction that committed at or
    /// before this timestamp; anything committed later (or never) is undone.
    Timestamp(Timestamp),
}

/// **Point-in-time restore** of a backup chain onto `device` (`rmp` task #71). Lays down the base,
/// then replays the chain's WAL — truncated at `target` — through the proven recovery machinery, so
/// the device is left at exactly the consistent committed state of `target`.
///
/// # The PITR-via-truncated-recovery argument (why this is a consistent committed state)
///
/// 1. [`restore_onto`](crate::restore_onto) writes the base's page images, leaving `device` at the
///    consistent checkpoint snapshot the base captured — i.e. at WAL position `base_lsn`.
/// 2. The increments are decrypted and **concatenated in order** into one contiguous byte buffer
///    that *is* the logical WAL from `base_lsn` onward (the LSN is the byte offset, and the chain is
///    verified contiguous). Prepending a synthetic WAL header makes it a complete log a fresh
///    [`WalManager`] can open and scan.
/// 3. The log is **truncated at the target** *before* recovery runs:
///    * [`RestoreTarget::Lsn(l)`](RestoreTarget::Lsn) cuts the buffer at byte `l` (records wholly
///      before `l` survive; a record straddling `l` is dropped as a torn tail);
///    * [`RestoreTarget::Timestamp(t)`](RestoreTarget::Timestamp) scans forward and cuts **just
///      after** the last `COMMIT` record whose `commit_ts <= t`;
///    * [`RestoreTarget::Latest`] keeps the whole buffer.
/// 4. The standard three-phase [`recover`](graphus_wal::recover) then runs over the *truncated* log
///    against the storage [`DeviceTarget`](crate::recovery::DeviceTarget): redo repeats history up
///    to the cut, and undo rolls back every transaction with no `COMMIT` at or before the cut. By the
///    correctness of ARIES recovery — which this reuses verbatim — the result is the unique
///    committed-or-nothing state as of the cut. A transaction whose `COMMIT` lies *after* the cut is
///    a loser and is fully undone; one whose `COMMIT` is at or before the cut is fully redone. **That
///    is precisely the live state at the target point**, which is why a chain restore is always a
///    consistent committed state — PITR inherits the recovery layer's proven semantics rather than
///    inventing new ones.
///
/// A base alone (zero increments) at [`Latest`](RestoreTarget::Latest) restores byte-identical to a
/// full [`restore_onto`](crate::restore_onto) of that base: the concatenated WAL is empty, so
/// recovery is a no-op over an empty log and only the base page images land on the device.
///
/// `device` should be a fresh device addressable from page `0` (typically a
/// [`MemBlockDevice`](graphus_io::MemBlockDevice) or a file device); it is grown as needed and
/// hardened before returning.
///
/// # Errors
/// Returns a storage error (or a `codec.open` security error) if the chain fails [`verify_chain`],
/// if laying down the base fails, or if WAL replay fails.
pub fn restore_to<D: BlockDevice, C: LinkCodec>(
    manifest: &ChainManifest,
    links: &ChainLinks,
    target: RestoreTarget,
    device: &mut D,
    codec: &C,
) -> Result<()> {
    // Re-prove integrity (and authenticate sealed links) before touching the device.
    verify_chain(manifest, links, codec)?;

    // 1. Lay down the base page images: the device is now at WAL position `base_lsn`.
    let base_plain = codec.open(&links.base)?;
    crate::restore_onto(&base_plain, device)?;

    // 2. Build the contiguous logical WAL from base_lsn onward. The WAL header occupies
    //    `[0, HEADER_LEN)` and the first increment's `from_lsn == base_lsn`, so a complete log is a
    //    `base_lsn`-length zero-prefix (never scanned: recovery starts at `HEADER_LEN`, and the redo
    //    start is at or after `base_lsn >= HEADER_LEN`) followed by the concatenated increment bytes.
    //    We reconstruct it as a real WAL byte image so a fresh `WalManager` can open + scan it.
    let mut wal_bytes = build_logical_wal(manifest, links, codec)?;

    // 3. Truncate the logical WAL at the target *before* recovery.
    truncate_at_target(&mut wal_bytes, manifest.base_lsn, target);

    // 4. Replay through the proven three-phase recovery against the device, beginning the analysis
    //    scan at `base_lsn` (the chain's records start there; `[HEADER_LEN, base_lsn)` is an
    //    unscanned gap). Recovery's redo + undo then yield the consistent committed state at the cut.
    let sink = SliceLogSink::new(wal_bytes);
    let mut wal = WalManager::open(sink)?;
    recover_device_from(&mut wal, device, manifest.base_lsn)?;
    Ok(())
}

/// Reconstructs the full logical WAL byte image for a chain: a valid WAL header, a zero gap covering
/// `[HEADER_LEN, base_lsn)` (never scanned — see [`restore_to`]), then every increment's opened bytes
/// concatenated in order. The result is a byte stream whose record at offset `L` is the chain's
/// record with LSN `L`, exactly as the source WAL had it.
fn build_logical_wal<C: LinkCodec>(
    manifest: &ChainManifest,
    links: &ChainLinks,
    codec: &C,
) -> Result<Vec<u8>> {
    let base = manifest.base_lsn.0 as usize;
    let mut total = base;
    for inc in &manifest.increments {
        total += inc.len as usize;
    }
    let mut out = vec![0u8; base];
    // Stamp a valid WAL header so `WalManager::open` accepts the reconstructed log. The bytes in
    // `[HEADER_LEN, base_lsn)` are never decoded (recovery's forward scan starts at `HEADER_LEN`
    // but the redo start is `>= base_lsn`, and analysis only *reads* records, applying nothing
    // before the checkpoint — all the chain's committed work lives at `>= base_lsn`).
    write_wal_header(&mut out);
    out.reserve(total.saturating_sub(out.len()));
    for sealed in &links.increments {
        let plain = codec.open(sealed)?;
        out.extend_from_slice(&plain);
    }
    Ok(out)
}

/// Writes a minimal valid WAL header (`magic || version`, both `u32` LE) into the first
/// [`WAL_HEADER_LEN`](graphus_wal::HEADER_LEN) bytes of `buf`. Mirrors [`WalManager::create`]'s
/// header so the reconstructed log opens cleanly.
fn write_wal_header(buf: &mut [u8]) {
    let hdr_len = WAL_HEADER_LEN as usize;
    if buf.len() < hdr_len {
        // A base_lsn shorter than a header is impossible for a real chain (the source WAL always has
        // a header), but guard rather than index out of bounds.
        return;
    }
    buf[0..4].copy_from_slice(&WAL_MAGIC.to_le_bytes());
    buf[4..8].copy_from_slice(&WAL_VERSION.to_le_bytes());
}

/// Truncates the logical WAL `bytes` in place at `target` (see [`restore_to`] step 3). `base_lsn` is
/// where the chain's records start; the scan never decodes the pre-`base_lsn` gap.
fn truncate_at_target(bytes: &mut Vec<u8>, base_lsn: Lsn, target: RestoreTarget) {
    let cut = match target {
        RestoreTarget::Latest => return,
        RestoreTarget::Lsn(l) => {
            // Cut at byte `l`. A record straddling `l` is dropped by `recover`'s torn-tail handling;
            // a record ending exactly at `l` survives. Never cut before the WAL header / base_lsn.
            (l.0 as usize).max(base_lsn.0 as usize).min(bytes.len())
        }
        RestoreTarget::Timestamp(t) => commit_cut_for_timestamp(bytes, base_lsn, t),
    };
    bytes.truncate(cut);
}

/// Finds the byte offset just **after** the last `COMMIT` record whose `commit_ts <= t`, scanning the
/// chain's records forward from `base_lsn`. Returns `base_lsn` if no such commit exists (restore to
/// the base only — every later transaction is a loser and is undone).
///
/// Cutting *after* a commit record (rather than at its start) keeps that transaction a winner: its
/// `COMMIT` is in the truncated log, so redo applies it and undo leaves it alone. The very next
/// record — the first byte of a later, now-excluded transaction's work — and everything after it is
/// gone, so those transactions have no `COMMIT` in the log and are undone.
fn commit_cut_for_timestamp(bytes: &[u8], base_lsn: Lsn, t: Timestamp) -> usize {
    let mut cursor = base_lsn.0 as usize;
    let mut cut = base_lsn.0 as usize;
    while cursor < bytes.len() {
        match LogRecord::decode(&bytes[cursor..]) {
            Ok((rec, n)) => {
                let end = cursor + n;
                if rec.rec_type == RecordType::Commit {
                    if let Some(ts) = rec.commit_ts() {
                        if ts <= t {
                            // This commit is in-window; keep everything up to and including it.
                            cut = end;
                        }
                    }
                }
                cursor = end;
            }
            // A torn/short tail ends the scan, exactly like recovery's forward scan.
            Err(_) => break,
        }
    }
    cut
}

/// A read-only [`LogSink`] over a fixed, already-durable WAL byte image, for driving recovery during
/// a chain restore. Every byte is "durable" (the chain's increments are the *committed* WAL of the
/// source); nothing is ever appended (recovery's CLR/END writes during undo go through `append` +
/// `sync`, which append to the in-memory buffer and are harmless — they are never persisted, since
/// the restore target is the *device*, not this throwaway log).
///
/// This exists so [`restore_to`] can reuse [`WalManager`] + [`recover`](graphus_wal::recover)
/// unchanged: recovery only ever *reads* the durable prefix to rebuild state, and the sink presents
/// the whole chain as that durable prefix.
#[derive(Debug, Clone)]
struct SliceLogSink {
    /// The durable WAL image (header + concatenated increments, truncated at the target).
    durable: Vec<u8>,
    /// Recovery appends CLR/END records during undo; they accumulate here and are discarded with the
    /// sink. They never affect the restored *device*, which is the actual restore output.
    appended: Vec<u8>,
}

impl SliceLogSink {
    fn new(durable: Vec<u8>) -> Self {
        Self {
            durable,
            appended: Vec::new(),
        }
    }
}

impl LogSink for SliceLogSink {
    fn append(&mut self, bytes: &[u8]) {
        self.appended.extend_from_slice(bytes);
    }

    fn sync(&mut self) -> Result<()> {
        // The appended undo records become "durable" only in the sense that recovery considers them
        // written; they live in a throwaway in-memory log and are never persisted.
        self.durable.append(&mut self.appended);
        Ok(())
    }

    fn durable_len(&self) -> u64 {
        self.durable.len() as u64
    }

    fn buffered_len(&self) -> u64 {
        (self.durable.len() + self.appended.len()) as u64
    }

    fn read_durable(&self, from: u64, into: &mut Vec<u8>) -> Result<()> {
        into.clear();
        let from = from as usize;
        if from <= self.durable.len() {
            into.extend_from_slice(&self.durable[from..]);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Pure unit tests for the manifest codec, contiguity/CRC checks, and the timestamp cut. The
    //! heavy chain round-trip / PITR / encryption tests (which drive real stores) live in
    //! `tests/incremental.rs`.
    use super::*;

    fn sample_manifest() -> ChainManifest {
        ChainManifest {
            chain_id: 0xDEAD_BEEF,
            base_creation_mark: 42,
            base_lsn: Lsn(8),
            increments: vec![
                IncrementMeta {
                    from_lsn: Lsn(8),
                    to_lsn: Lsn(40),
                    crc: 0x1111_1111,
                    len: 32,
                },
                IncrementMeta {
                    from_lsn: Lsn(40),
                    to_lsn: Lsn(100),
                    crc: 0x2222_2222,
                    len: 60,
                },
            ],
        }
    }

    #[test]
    fn manifest_round_trips() {
        let m = sample_manifest();
        let bytes = m.encode();
        let got = ChainManifest::decode(&bytes).expect("decode");
        assert_eq!(got, m);
        assert_eq!(got.tip_lsn(), Lsn(100));
    }

    #[test]
    fn empty_chain_manifest_round_trips() {
        let m = ChainManifest {
            chain_id: 7,
            base_creation_mark: 7,
            base_lsn: Lsn(8),
            increments: Vec::new(),
        };
        let bytes = m.encode();
        let got = ChainManifest::decode(&bytes).expect("decode");
        assert_eq!(got, m);
        assert_eq!(got.tip_lsn(), Lsn(8)); // no increments -> tip is base_lsn
    }

    #[test]
    fn manifest_too_short_is_rejected() {
        assert!(ChainManifest::decode(&[0u8; 4]).is_err());
    }

    #[test]
    fn manifest_bad_magic_is_rejected() {
        let mut bytes = sample_manifest().encode();
        bytes[0] ^= 0xFF;
        let err = ChainManifest::decode(&bytes).unwrap_err().to_string();
        assert!(err.contains("magic"), "got: {err}");
    }

    #[test]
    fn manifest_flipped_byte_breaks_crc() {
        let mut bytes = sample_manifest().encode();
        // Flip a byte in the body (an increment's CRC field).
        let pos = MANIFEST_HEADER_LEN + 17;
        bytes[pos] ^= 0xFF;
        let err = ChainManifest::decode(&bytes).unwrap_err().to_string();
        assert!(err.contains("CRC"), "got: {err}");
    }

    #[test]
    fn manifest_declared_count_must_match_length() {
        let mut bytes = sample_manifest().encode();
        // Claim three increments while only two are encoded.
        bytes[52..60].copy_from_slice(&3u64.to_le_bytes());
        // The CRC now also mismatches, but the length check fires first.
        assert!(ChainManifest::decode(&bytes).is_err());
    }

    #[test]
    fn verify_chain_detects_a_gap() {
        // Two empty (len-0) increments so the only possible fault is the contiguity check. Increment
        // 0 is `[8, 8)` (== base_lsn, contiguous); increment 1 is `[41, 41)`, which leaves a gap
        // after increment 0's `to_lsn` of 8.
        let empty_crc = crc32c::crc32c(&[]);
        let m = ChainManifest {
            chain_id: 42,
            base_creation_mark: 42,
            base_lsn: Lsn(8),
            increments: vec![
                IncrementMeta {
                    from_lsn: Lsn(8),
                    to_lsn: Lsn(8),
                    crc: empty_crc,
                    len: 0,
                },
                IncrementMeta {
                    from_lsn: Lsn(41), // should be 8 to be contiguous -> gap
                    to_lsn: Lsn(41),
                    crc: empty_crc,
                    len: 0,
                },
            ],
        };
        let links = ChainLinks {
            base: minimal_base_artifact(),
            increments: vec![Vec::new(), Vec::new()],
        };
        let err = verify_chain(&m, &links, &Plain).unwrap_err().to_string();
        assert!(err.contains("gap or overlap"), "got: {err}");
    }

    /// A minimal, well-formed full-backup artifact (header + zero pages + correct digest), matching
    /// `backup.rs`'s framing, so the base-verification step inside `verify_chain` passes and the
    /// increment-level checks are reached.
    fn minimal_base_artifact() -> Vec<u8> {
        use graphus_io::PAGE_SIZE;
        let mut out = Vec::new();
        out.extend_from_slice(&crate::BACKUP_MAGIC);
        out.extend_from_slice(&crate::BACKUP_FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
        out.extend_from_slice(&42u128.to_le_bytes()); // creation mark == base_creation_mark
        out.extend_from_slice(&0u64.to_le_bytes()); // zero pages
        let digest = crc32c::crc32c(&out);
        out.extend_from_slice(&digest.to_le_bytes());
        out
    }

    #[test]
    fn verify_chain_detects_a_crc_mismatch() {
        let mut m = ChainManifest {
            chain_id: 42,
            base_creation_mark: 42,
            base_lsn: Lsn(8),
            increments: vec![IncrementMeta {
                from_lsn: Lsn(8),
                to_lsn: Lsn(11),
                crc: 0xBAD_C0DE,
                len: 3,
            }],
        };
        let links = ChainLinks {
            base: minimal_base_artifact(),
            increments: vec![vec![1, 2, 3]],
        };
        // The real CRC of [1,2,3] won't equal 0xBAD_C0DE.
        let err = verify_chain(&m, &links, &Plain).unwrap_err().to_string();
        assert!(err.contains("CRC mismatch"), "got: {err}");
        // Fix the CRC -> now it verifies.
        m.increments[0].crc = crc32c::crc32c(&[1, 2, 3]);
        verify_chain(&m, &links, &Plain).expect("now valid");
    }

    #[test]
    fn verify_chain_detects_link_count_mismatch() {
        let m = sample_manifest();
        let links = ChainLinks {
            base: minimal_base_artifact(),
            increments: vec![Vec::new()], // 1 link, manifest declares 2
        };
        assert!(verify_chain(&m, &links, &Plain).is_err());
    }

    #[test]
    fn plain_codec_is_identity() {
        let data = b"some link bytes".to_vec();
        let sealed = Plain.seal(&data).unwrap();
        assert_eq!(sealed, data);
        assert_eq!(Plain.open(&sealed).unwrap(), data);
    }
}
