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

/// The sibling temp path for `target` (same directory ⇒ same filesystem ⇒ `rename(2)` is atomic).
fn temp_sibling(target: &Path) -> Result<PathBuf> {
    let name = target.file_name().ok_or_else(|| {
        GraphusError::Storage(format!("target path {} has no file name", target.display()))
    })?;
    let mut tmp = name.to_os_string();
    tmp.push(".graphus-replace-tmp");
    Ok(target.with_file_name(tmp))
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
    // Clear any stale temp left by a previously-aborted replace, so `fill` starts from a clean slate.
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(io_err(
                &format!("removing stale temp {}", tmp.display()),
                &e,
            ));
        }
    }
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
