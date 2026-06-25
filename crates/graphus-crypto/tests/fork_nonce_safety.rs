//! Real-`fork(2)` regression for the fork-safe nonce source (rmp #393).
//!
//! # What this proves
//!
//! The buffered userspace ChaCha20 nonce CSPRNG (rmp #378) is seeded once at sink construction. A
//! `fork(2)` clones the parent's address space — including that CSPRNG state — so without a reseed
//! the parent and child would emit the **identical** nonce stream. Both then write under the
//! **identical** WAL encryption subkey (they share the open `EncryptedLogSink`), producing
//! `(key, nonce)` reuse, which is catastrophic for AES-256-GCM (plaintext-XOR leak + GHASH
//! authentication-subkey recovery → universal forgery).
//!
//! The fix (rmp #393) PID-stamps the nonce source and reseeds on a PID change. This test exercises
//! that through the **public** [`EncryptedLogSink`] API with a real `fork`: a sink is created in the
//! parent (seeding the CSPRNG), the process forks, and **both** the parent and the child seal a
//! batch of frames into their (independent, copy-on-write) sinks. Each frame stores its 96-bit GCM
//! nonce in the clear at a fixed wire offset; the child ships its nonces to the parent over a pipe,
//! and the parent asserts the two nonce sets are **disjoint**. They can only be disjoint if the
//! child reseeded after the fork.
//!
//! This lives in a separate test crate (not in `src/`) on purpose: `graphus-crypto` is
//! `#![forbid(unsafe_code)]`, and the raw `fork`/`pipe` FFI requires `unsafe`. Keeping the unsafe
//! out of the library preserves that invariant. The deterministic, injected-PID unit tests in
//! `nonce_source.rs` (`pid_change_reseeds_so_streams_never_collide`, etc.) are the primary,
//! fork-free gate; this is the belt-and-braces real-`fork` confirmation.

#![cfg(unix)]
#![allow(unsafe_code)] // raw fork(2)/pipe(2) FFI, isolated to this test crate (see module docs)

use std::collections::HashSet;
use std::io::Read;

use graphus_crypto::{EncryptedLogSink, KEY_LEN, Keyring, NONCE_LEN, SALT_LEN};
use graphus_wal::{LogSink, MemLogSink};

/// WAL frame wire layout (see `wal_sink.rs`, v4): the 96-bit nonce begins at byte 36, after
/// magic(4) || phys_len(8) || logical_offset(8) || logical_len(8) || write_count(8).
const FR_OFF_NONCE: usize = 36;
const FRAME_MAGIC: [u8; 4] = *b"GWFR";

const N_FRAMES: usize = 200;

/// Extracts every frame's nonce from the encrypted sink's durable backing image.
fn collect_frame_nonces(sink: &EncryptedLogSink<MemLogSink>) -> Vec<[u8; NONCE_LEN]> {
    // The header precedes the frames; reading from 0 and walking by `phys_len` (LE u64 at offset 4)
    // is robust to the header length without depending on private constants.
    let mut bytes = Vec::new();
    sink.backing()
        .read_durable(0, &mut bytes)
        .expect("read durable backing");

    let mut nonces = Vec::new();
    let mut cursor = 0usize;
    while cursor + FR_OFF_NONCE + NONCE_LEN <= bytes.len() {
        if bytes[cursor..cursor + 4] != FRAME_MAGIC {
            // Not at a frame boundary yet (header / padding): advance one byte and resync.
            cursor += 1;
            continue;
        }
        let phys_len = u64::from_le_bytes(
            bytes[cursor + 4..cursor + 12]
                .try_into()
                .expect("phys_len is 8 bytes"),
        ) as usize;
        if phys_len < FR_OFF_NONCE + NONCE_LEN || cursor + phys_len > bytes.len() {
            cursor += 1;
            continue;
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[cursor + FR_OFF_NONCE..cursor + FR_OFF_NONCE + NONCE_LEN]);
        nonces.push(nonce);
        cursor += phys_len;
    }
    nonces
}

fn keyring() -> Keyring {
    let salt = [0x3C_u8; SALT_LEN];
    Keyring::from_key_file_bytes(&[0xABu8; KEY_LEN], &salt).expect("keyring")
}

#[test]
fn real_fork_child_never_replays_parent_nonces() {
    // Sink created BEFORE the fork: this is the hazardous case (#393). Both processes inherit the
    // SAME seeded nonce CSPRNG. Only a post-fork reseed can make the two nonce streams disjoint.
    let kr = keyring();
    let mut sink =
        EncryptedLogSink::create(MemLogSink::new(), &kr).expect("create encrypted WAL sink");

    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a 2-int array exactly as pipe(2) requires; we check the return code.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe(2) failed");
    let (read_fd, write_fd) = (fds[0], fds[1]);

    // SAFETY: single-threaded test (cargo runs each test fn on a worker, but no locks/Tokio are
    // held across this point); fork is the only call between here and the child's _exit/exec-free
    // path, and the child touches only its own copied sink + the pipe write fd.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork(2) failed");

    if pid == 0 {
        // ---------- Child ----------
        // SAFETY: close the read end the child does not use.
        unsafe { libc::close(read_fd) };

        // The child seals its own batch of frames into its (copy-on-write) sink.
        for i in 0..N_FRAMES {
            sink.append(format!("child-frame-{i}").as_bytes());
            if sink.sync().is_err() {
                // SAFETY: terminate the forked child on error without unwinding the harness.
                unsafe { libc::_exit(2) };
            }
        }
        let nonces = collect_frame_nonces(&sink);
        if nonces.len() != N_FRAMES {
            unsafe { libc::_exit(3) };
        }

        // Ship the child's nonces to the parent: N_FRAMES * NONCE_LEN bytes, contiguous.
        let mut out = Vec::with_capacity(N_FRAMES * NONCE_LEN);
        for n in &nonces {
            out.extend_from_slice(n);
        }
        let mut remaining = out.as_slice();
        while !remaining.is_empty() {
            // SAFETY: write_fd is the valid write end; remaining points to `out`'s live bytes.
            let w = unsafe { libc::write(write_fd, remaining.as_ptr().cast(), remaining.len()) };
            if w <= 0 {
                unsafe { libc::_exit(4) };
            }
            remaining = &remaining[w as usize..];
        }
        // SAFETY: close the write end and terminate the child cleanly (no destructors/harness).
        unsafe {
            libc::close(write_fd);
            libc::_exit(0);
        }
    }

    // ---------- Parent ----------
    // SAFETY: close the write end the parent does not use.
    unsafe { libc::close(write_fd) };

    // Parent seals its own batch from the SAME pre-fork CSPRNG seed.
    for i in 0..N_FRAMES {
        sink.append(format!("parent-frame-{i}").as_bytes());
        sink.sync().expect("parent sync");
    }
    let parent_nonces: HashSet<[u8; NONCE_LEN]> = collect_frame_nonces(&sink).into_iter().collect();
    assert_eq!(
        parent_nonces.len(),
        N_FRAMES,
        "parent produced duplicate nonces within its own stream"
    );

    // Read the child's nonces back over the pipe.
    // SAFETY: wrap the read end in a File for buffered reads; we own this fd.
    let mut reader = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(read_fd) };
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).expect("read child nonces");

    // Reap the child and assert clean exit.
    let mut status = 0i32;
    // SAFETY: standard waitpid on our known child pid.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let exited_ok = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
    assert!(exited_ok, "child did not exit cleanly (status {status})");

    assert_eq!(
        buf.len(),
        N_FRAMES * NONCE_LEN,
        "child sent the wrong number of nonce bytes"
    );

    // The core assertion: NOT ONE child nonce may equal a parent nonce. Equality would mean the
    // child replayed the inherited stream under the same subkey — the catastrophic (key, nonce)
    // reuse rmp #393 prevents.
    for chunk in buf.chunks_exact(NONCE_LEN) {
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(chunk);
        assert!(
            !parent_nonces.contains(&nonce),
            "child replayed a parent nonce under the same WAL subkey — fork reseed FAILED (rmp #393)"
        );
    }
}
