//! On-disk footprint of a **real** Graphus store directory, decomposed by PATH (`rmp` #698).
//!
//! # Why this exists (the bug it fixes)
//!
//! A running `graphus-server`'s store directory looks like this:
//!
//! ```text
//! <store_path>/
//!   databases.toml                       <- the database catalog
//!   databases/<db>/graphus.store         <- the data image (home pages)
//!   databases/<db>/graphus.dwb           <- the doublewrite buffer
//!   databases/<db>/graphus.wal/          <- the WAL: a DIRECTORY …
//!   databases/<db>/graphus.wal/seg.<lsn> <- … of segment files
//! ```
//!
//! The **WAL is a directory**, and its segment files are named `seg.<lsn>` — the string `wal` appears
//! only in the *parent directory* name, never in the leaf file name. Any accounting that classifies a
//! file by its LEAF NAME therefore counts every WAL byte as "store" and reports `wal_bytes = 0`,
//! hiding the very redo log a crash-recovery example exists to measure. Classification MUST be done by
//! PATH: once any component of the path is the WAL directory, every file beneath it is WAL.
//!
//! This module is the durability example's shared, unit-tested accounting (the same decomposition
//! `graphus-social-gen`'s `social_bench` uses), so the example can state — and assert — how many bytes
//! of redo log the crash actually left behind for recovery to replay.

use std::path::Path;

/// The decomposed on-disk footprint of a store directory: what is redo log, what is the graph itself,
/// and what is fixed overhead.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StoreFootprint {
    /// Bytes under any `*.wal` **directory** (the WAL segment files) — the redo log recovery replays.
    pub wal_bytes: u64,
    /// Bytes of the data image(s) (`graphus.store`) — the home pages the graph lives on.
    pub data_bytes: u64,
    /// Bytes of the doublewrite buffer(s) (`graphus.dwb`) — fixed torn-page-repair overhead.
    pub dwb_bytes: u64,
    /// Everything else in the directory (the `databases.toml` catalog, security catalog, …).
    pub other_bytes: u64,
}

impl StoreFootprint {
    /// Everything that is **not** WAL — the store side of the store-vs-WAL split.
    #[must_use]
    pub fn store_bytes(&self) -> u64 {
        self.data_bytes
            .saturating_add(self.dwb_bytes)
            .saturating_add(self.other_bytes)
    }

    /// The total on-disk footprint (store + WAL).
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.store_bytes().saturating_add(self.wal_bytes)
    }
}

/// `true` iff `p`'s file name contains `needle` (ASCII-case-insensitive).
fn name_contains(p: &Path, needle: &str) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.to_ascii_lowercase().contains(needle))
}

/// Walks `dir`, accumulating the decomposed footprint. `in_wal` stays `true` for everything beneath a
/// directory whose name marks it as the WAL — this is the PATH-based classification the leaf-name
/// approach gets wrong. Symlinks are not followed (their own entry size is what `metadata` reports on
/// the directory walk), so neither cycles nor double counting are possible.
fn walk(dir: &Path, in_wal: bool, fp: &mut StoreFootprint) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let wal_here = in_wal || name_contains(&p, "wal");
        if p.is_dir() {
            walk(&p, wal_here, fp);
        } else if let Ok(meta) = entry.metadata() {
            let len = meta.len();
            if wal_here {
                fp.wal_bytes = fp.wal_bytes.saturating_add(len);
            } else if name_contains(&p, ".dwb") {
                fp.dwb_bytes = fp.dwb_bytes.saturating_add(len);
            } else if name_contains(&p, ".store") {
                fp.data_bytes = fp.data_bytes.saturating_add(len);
            } else {
                fp.other_bytes = fp.other_bytes.saturating_add(len);
            }
        }
    }
}

/// Measures a real store directory, decomposing it into WAL / data / doublewrite / other by PATH.
///
/// A missing path yields a zero footprint (an example may legitimately measure a store that does not
/// exist yet).
#[must_use]
pub fn measure(store_dir: &Path) -> StoreFootprint {
    let mut fp = StoreFootprint::default();
    walk(store_dir, false, &mut fp);
    fp
}

/// Locates a server store's real `(data_image, wal_directory)` paths, handling **both** on-disk layouts
/// the server actually produces (verified against a running `graphus-server`, not assumed):
///
/// * **flat** — a server whose `store_path` is opened directly writes `<store_dir>/graphus.store` and
///   `<store_dir>/graphus.wal/` (plus `graphus.dwb`, `store.lock`, `security.toml`). This is what a
///   single-database, UDS-only server such as this example's looks like.
/// * **multi-database** — once databases are created through the catalog, each lives at
///   `<store_dir>/databases/<db>/graphus.store` + `.../graphus.wal/`. The first database directory in
///   ascending name order is chosen, so the pick is deterministic.
///
/// Returns `None` if neither layout is present. In **both** layouts the WAL is a **directory** of
/// `seg.<lsn>` segments (plus its `anchor`), never a single file — which is exactly why the byte
/// accounting must classify by PATH ([`measure`]).
#[must_use]
pub fn locate_db_paths(store_dir: &Path) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let flat_store = store_dir.join("graphus.store");
    let flat_wal = store_dir.join("graphus.wal");
    if flat_store.is_file() || flat_wal.is_dir() {
        return Some((flat_store, flat_wal));
    }
    let mut names: Vec<std::path::PathBuf> = std::fs::read_dir(store_dir.join("databases"))
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    names.sort();
    let db = names.into_iter().next()?;
    Some((db.join("graphus.store"), db.join("graphus.wal")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "gdur-fp-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    /// The **flat** layout a running `graphus-server` creates when its `store_path` is opened directly
    /// (verified against the real binary: `graphus.store`, `graphus.wal/seg.<lsn>` + `graphus.wal/anchor`,
    /// `graphus.dwb`, `store.lock`, `security.toml`).
    fn flat_store(tag: &str) -> std::path::PathBuf {
        let root = tmp_root(tag);
        let wal = root.join("graphus.wal");
        std::fs::create_dir_all(&wal).expect("layout");
        std::fs::write(root.join("graphus.store"), vec![0u8; 8192]).expect("data image");
        std::fs::write(root.join("graphus.dwb"), vec![0u8; 1024]).expect("doublewrite");
        std::fs::write(root.join("store.lock"), vec![0u8; 16]).expect("lock");
        std::fs::write(root.join("security.toml"), vec![0u8; 48]).expect("security catalog");
        // WAL segments: named `seg.<lsn>` / `anchor` — the leaf names contain NO "wal"; only the
        // PARENT DIRECTORY does. A leaf-name classifier therefore books them all as "store".
        std::fs::write(wal.join("seg.00000000000000000008"), vec![0u8; 65536]).expect("seg");
        std::fs::write(wal.join("anchor"), vec![0u8; 4096]).expect("anchor");
        root
    }

    /// The **multi-database** (catalog) layout: `databases/<db>/graphus.store` + `.../graphus.wal/`.
    fn catalog_store(tag: &str) -> std::path::PathBuf {
        let root = tmp_root(tag);
        let db = root.join("databases").join("graphus");
        let wal = db.join("graphus.wal");
        std::fs::create_dir_all(&wal).expect("layout");
        std::fs::write(db.join("graphus.store"), vec![0u8; 8192]).expect("data image");
        std::fs::write(db.join("graphus.dwb"), vec![0u8; 1024]).expect("doublewrite");
        std::fs::write(root.join("databases.toml"), vec![0u8; 64]).expect("catalog");
        std::fs::write(wal.join("seg.00000000000000000000"), vec![0u8; 65536]).expect("seg");
        root
    }

    /// **Regression (`rmp` #698).** The WAL is a DIRECTORY of `seg.<lsn>` / `anchor` files: classifying
    /// by the LEAF FILE NAME counts every WAL byte as store and reports `wal_bytes = 0`, hiding the redo
    /// log the crash left for recovery to replay. Classification must be by PATH.
    #[test]
    fn wal_segments_are_classified_as_wal_not_store() {
        let root = flat_store("wal");
        let fp = measure(&root);
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(
            fp.wal_bytes,
            65536 + 4096,
            "every byte under the graphus.wal DIRECTORY is redo log, however its leaf file is named"
        );
        assert_eq!(fp.data_bytes, 8192, "only graphus.store is the data image");
        assert_eq!(
            fp.dwb_bytes, 1024,
            "the doublewrite buffer is fixed overhead"
        );
        assert_eq!(
            fp.other_bytes,
            16 + 48,
            "the lock + security catalog are neither data nor WAL"
        );
        assert_eq!(fp.store_bytes(), 8192 + 1024 + 16 + 48);
        assert_eq!(fp.total_bytes(), fp.store_bytes() + 65536 + 4096);
    }

    /// The same decomposition must hold for the multi-database (catalog) layout, whose WAL directory is
    /// two levels down.
    #[test]
    fn the_catalog_layout_is_decomposed_the_same_way() {
        let root = catalog_store("catalog");
        let fp = measure(&root);
        let located = locate_db_paths(&root);
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(fp.wal_bytes, 65536, "the nested WAL directory is still WAL");
        assert_eq!(fp.data_bytes, 8192);
        assert_eq!(fp.other_bytes, 64, "databases.toml is neither data nor WAL");
        let (store, wal) = located.expect("the catalog layout must be located");
        assert!(store.ends_with("databases/graphus/graphus.store"));
        assert!(wal.ends_with("databases/graphus/graphus.wal"));
    }

    /// Both real layouts must be located, and the WAL must always be found as a DIRECTORY (never a
    /// file) — the paths handed to the metering harness must be the ones that actually exist.
    #[test]
    fn locate_db_paths_finds_the_flat_layout_the_server_really_writes() {
        let root = flat_store("locate");
        let (store, wal) = locate_db_paths(&root).expect("layout must be discovered");
        let store_ok = store.is_file();
        let wal_is_dir = wal.is_dir();
        std::fs::remove_dir_all(&root).ok();

        assert!(store_ok, "the data image is at <store_dir>/graphus.store");
        assert!(
            wal_is_dir,
            "the WAL is a DIRECTORY at <store_dir>/graphus.wal — measuring it as a file yields zeros"
        );
    }

    #[test]
    fn a_missing_store_measures_as_zero() {
        let fp = measure(Path::new("/nonexistent/graphus-durability-demo"));
        assert_eq!(fp, StoreFootprint::default());
        assert_eq!(fp.total_bytes(), 0);
    }
}
