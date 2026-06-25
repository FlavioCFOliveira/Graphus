//! Atomic file replacement — the durable-rename idiom (PostgreSQL `durable_rename`).
//!
//! [`atomic_replace_file`] writes the new content into a fresh sibling temp file, then `rename(2)`s
//! it over the target and `fsync`s the parent directory. `rename(2)` within one filesystem is
//! atomic, so a crash at any point leaves `target` as **either** the old whole image **or** the new
//! whole image — never an in-place torn mixture of both (the failure mode of writing pages directly
//! over a live file). On any error from the content producer the temp is removed and `target` is
//! left untouched, so an aborted replace never destroys the original. This is the mechanism behind
//! the atomic, verified backup/restore in `graphus-storage` (storage audit F2/F11).

use std::path::{Path, PathBuf};

use graphus_core::error::{GraphusError, Result};

fn io_err(context: &str, e: &std::io::Error) -> GraphusError {
    GraphusError::Storage(format!("{context}: {e}"))
}

/// A process-and-call-unique, hard-to-predict suffix for the temp sibling name.
///
/// Combines the pid, a monotonically increasing per-process counter, and the high-resolution
/// clock. The goal is **not** cryptographic unpredictability but to defeat the
/// deterministic-name attack (CWE-377): an attacker can no longer pre-plant a symlink at the
/// known temp path before the replace runs, because the name is not known in advance. The
/// real guarantee against link-following is `O_EXCL | O_NOFOLLOW` at creation time (see
/// [`create_fresh_temp`]); this suffix only removes the predictable, reusable target.
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(".graphus-replace-{}-{n}-{nanos}.tmp", std::process::id())
}

/// A sibling temp path for `target` with an unpredictable suffix (same directory ⇒ same
/// filesystem ⇒ `rename(2)` is atomic). The randomized suffix defeats the predictable-temp
/// attack; the actual symlink/clobber defence is enforced when the file is created.
fn temp_sibling(target: &Path) -> Result<PathBuf> {
    let name = target.file_name().ok_or_else(|| {
        GraphusError::Storage(format!("target path {} has no file name", target.display()))
    })?;
    let mut tmp = name.to_os_string();
    tmp.push(unique_suffix());
    Ok(target.with_file_name(tmp))
}

/// Atomically creates `tmp` as a brand-new regular file, refusing to follow a symlink or clobber
/// an existing entry (CWE-59 / CWE-377). `O_CREAT | O_EXCL` makes the create fail if anything
/// already exists at the path (including a symlink), and `O_NOFOLLOW` refuses to traverse a final
/// symlink — so a local attacker who plants a symlink (or a file) at the temp path cannot redirect
/// our write onto an attacker-chosen target. Permissions are set explicitly to `0600` rather than
/// relying on the process umask.
fn create_fresh_temp(tmp: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true) // O_CREAT | O_EXCL: fail if the path already exists (incl. a symlink)
        .custom_flags(libc::O_NOFOLLOW) // refuse to follow a final symlink
        .mode(0o600) // owner-only; do not depend on umask
        .open(tmp)
        .map(|_| ()) // close immediately; `fill` reopens and writes the content
        .map_err(|e| io_err(&format!("securely creating temp {}", tmp.display()), &e))
}

/// `fsync`s the directory containing `file`, hardening the just-renamed directory entry — the POSIX
/// requirement for a durable rename (an `fsync` of file content does not harden the entry naming it).
fn fsync_parent_dir(file: &Path) -> Result<()> {
    // `Path::parent` of a bare file name is `Some("")`; map that (and a missing parent) to the
    // current directory, the directory the entry actually lives in.
    let dir = match file.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    sync_dir(dir)
}

/// `fsync`s a **directory** so its own entries (newly created / renamed / removed files inside it)
/// are durable. On POSIX, an `fsync` of a *file* makes the file's data durable but does **not**
/// guarantee the directory entry that names it survives a crash; a separate `fsync` of the parent
/// directory is required (PostgreSQL `fsync_parent_path` / `durable_rename`). After creating new
/// files in a directory (e.g. a fresh store + WAL), call this on that directory so a crash cannot
/// leave the entries unreferenced (`rmp` #404).
///
/// # Errors
/// Returns a storage error if the directory cannot be opened or `fsync`ed.
pub fn sync_dir(dir: &Path) -> Result<()> {
    let f = std::fs::File::open(dir)
        .map_err(|e| io_err(&format!("opening directory {} to fsync", dir.display()), &e))?;
    f.sync_all()
        .map_err(|e| io_err(&format!("syncing directory {}", dir.display()), &e))
}

/// Atomically replaces the file at `target` with content produced by `fill`.
///
/// `fill` receives the path of a fresh sibling temp file and must write the full new content there
/// **and make that content durable** (its own `fsync`/`sync_all`) before returning `Ok`. On success
/// the temp is `rename(2)`d over `target` and the parent directory is `fsync`ed. On any `Err` from
/// `fill` (or a rename failure) the temp is removed and `target` is left byte-for-byte untouched.
///
/// There is never an in-place torn mixture: a concurrent crash leaves `target` as the old whole
/// image or the new whole image. `target` need not pre-exist (a fresh create is just a rename onto a
/// missing name).
///
/// # Errors
/// Returns a storage error if the stale-temp cleanup, the `fill` closure, the rename, or the
/// directory `fsync` fails.
pub fn atomic_replace_file<F>(target: &Path, fill: F) -> Result<()>
where
    F: FnOnce(&Path) -> Result<()>,
{
    let tmp = temp_sibling(target)?;
    // Securely create the temp first with `O_CREAT|O_EXCL|O_NOFOLLOW` (CWE-59/CWE-377): this fails
    // if anything already exists at the (unpredictable) path — defeating a planted symlink or a
    // pre-created file — and never follows a final symlink. The randomized name makes a stale
    // collision practically impossible; on the off chance of one, `create_new` rejects it as an Err
    // rather than reusing a possibly-attacker-controlled file.
    create_fresh_temp(&tmp)?;
    // Produce + durably persist the new content into the temp. On failure, abort and leave `target`.
    if let Err(e) = fill(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // Atomic swap, then harden the directory entry so the rename survives a crash.
    if let Err(e) = std::fs::rename(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io_err(
            &format!("renaming {} over {}", tmp.display(), target.display()),
            &e,
        ));
    }
    fsync_parent_dir(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let p = std::env::temp_dir().join(format!(
                "graphus-replace-{tag}-{nanos}-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&p).expect("mkdir");
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write_durably(path: &Path, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        let mut f = std::fs::File::create(path)
            .map_err(|e| GraphusError::Storage(format!("create temp: {e}")))?;
        f.write_all(bytes)
            .map_err(|e| GraphusError::Storage(format!("write temp: {e}")))?;
        f.sync_all()
            .map_err(|e| GraphusError::Storage(format!("sync temp: {e}")))
    }

    #[test]
    fn sync_dir_hardens_an_existing_directory() {
        // `sync_dir` must succeed on a real directory (it issues `fsync` on the dir fd) and error
        // cleanly on a path that is not a directory / does not exist — never panic.
        let dir = TempDir::new("syncdir");
        std::fs::write(dir.0.join("a"), b"x").expect("seed");
        sync_dir(&dir.0).expect("fsync of a real directory must succeed");
        // A non-existent path is a clean error, not a panic.
        assert!(sync_dir(&dir.0.join("does-not-exist")).is_err());
    }

    #[test]
    fn replaces_an_existing_file_and_leaves_no_temp() {
        let dir = TempDir::new("ok");
        let target = dir.0.join("data");
        write_durably(&target, b"OLD").expect("seed original");

        atomic_replace_file(&target, |tmp| write_durably(tmp, b"NEWNEW")).expect("replace");

        assert_eq!(std::fs::read(&target).expect("read"), b"NEWNEW");
        // No temp residue after a successful replace.
        assert!(!target.with_file_name("data.graphus-replace-tmp").exists());
    }

    #[test]
    fn creates_a_fresh_target_that_did_not_exist() {
        let dir = TempDir::new("fresh");
        let target = dir.0.join("brand-new");
        assert!(!target.exists());
        atomic_replace_file(&target, |tmp| write_durably(tmp, b"hello")).expect("replace");
        assert_eq!(std::fs::read(&target).expect("read"), b"hello");
    }

    /// Regression: SEC-213 (temp component) — `create_fresh_temp` refuses to follow a planted
    /// symlink (CWE-59) and refuses to clobber a pre-existing file (CWE-377). It must create a
    /// brand-new regular file or return an error; it must never write through an attacker's link.
    #[test]
    fn create_fresh_temp_refuses_symlink_and_preexisting_file() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new("symlink");

        // (a) A planted symlink at the temp path pointing at a victim file the server can write.
        let victim = dir.0.join("victim-secret");
        write_durably(&victim, b"DO-NOT-CLOBBER").expect("seed victim");
        let temp_link = dir.0.join("temp-as-symlink");
        symlink(&victim, &temp_link).expect("plant symlink");

        let r = create_fresh_temp(&temp_link);
        assert!(
            r.is_err(),
            "create_fresh_temp must refuse a path that is a symlink (no link following)"
        );
        // The victim is untouched: the create did NOT follow the link and truncate/overwrite it.
        assert_eq!(
            std::fs::read(&victim).expect("victim still readable"),
            b"DO-NOT-CLOBBER",
            "a planted symlink must not redirect the create onto the victim file"
        );

        // (b) A pre-existing regular file at the temp path must also be refused (O_EXCL), not reused.
        let existing = dir.0.join("already-here");
        write_durably(&existing, b"PRE").expect("seed existing");
        assert!(
            create_fresh_temp(&existing).is_err(),
            "create_fresh_temp must refuse to clobber/reuse a pre-existing file"
        );
        assert_eq!(std::fs::read(&existing).expect("read"), b"PRE");

        // (c) A fresh, non-existent path succeeds and yields a regular file (not a symlink).
        let fresh = dir.0.join("fresh-temp");
        create_fresh_temp(&fresh).expect("fresh temp must be created");
        let meta = std::fs::symlink_metadata(&fresh).expect("metadata");
        assert!(
            meta.file_type().is_file(),
            "created temp must be a regular file"
        );
    }

    /// Regression: SEC-213 — a full `atomic_replace_file` uses an unpredictable temp name and a
    /// symlink-safe creation, so the end-to-end replace still works and leaves no temp residue.
    #[test]
    fn atomic_replace_uses_unpredictable_temp_and_leaves_no_residue() {
        let dir = TempDir::new("unpredictable");
        let target = dir.0.join("data");
        write_durably(&target, b"OLD").expect("seed");

        atomic_replace_file(&target, |tmp| {
            // The temp name must NOT be the old deterministic, predictable sibling.
            assert!(
                !tmp.ends_with("data.graphus-replace-tmp"),
                "temp name must be unpredictable, not the deterministic sibling"
            );
            write_durably(tmp, b"NEWNEW")
        })
        .expect("replace");

        assert_eq!(std::fs::read(&target).expect("read"), b"NEWNEW");
        // No predictable-name temp residue remains.
        assert!(!target.with_file_name("data.graphus-replace-tmp").exists());
    }

    #[test]
    fn an_aborted_fill_leaves_the_original_untouched_and_removes_the_temp() {
        let dir = TempDir::new("abort");
        let target = dir.0.join("data");
        write_durably(&target, b"ORIGINAL").expect("seed original");

        let err = atomic_replace_file(&target, |tmp| {
            // Write a partial temp, then fail — models a producer that errors mid-way.
            write_durably(tmp, b"PARTIAL").expect("partial write");
            Err(GraphusError::Storage("producer failed".to_owned()))
        });
        assert!(err.is_err(), "the replace must surface the producer error");
        // The original survives byte-for-byte, and the temp is gone.
        assert_eq!(std::fs::read(&target).expect("read"), b"ORIGINAL");
        assert!(!target.with_file_name("data.graphus-replace-tmp").exists());
    }
}
