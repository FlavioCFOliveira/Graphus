//! On-disk footprint accounting for a **real** `graphus-server` database directory — decomposed, and
//! classified by **path**, not by leaf file name.
//!
//! # The trap this module exists to avoid (`rmp` #694)
//!
//! A Graphus database on disk looks like this:
//!
//! ```text
//! <store_path>/
//!   databases.toml                       <- the database catalog
//!   databases/<db>/
//!     graphus.store                      <- the data image (the graph itself)
//!     graphus.dwb                        <- the doublewrite buffer (a FIXED preallocation)
//!     graphus.wal/                       <- the WAL is a DIRECTORY…
//!       seg.00000000000000000008         <- …of segments whose leaf names contain no "wal" at all
//!       seg.00000000000000000009
//! ```
//!
//! Any code that decides "is this a WAL byte?" from the **leaf file name** therefore classifies every
//! single WAL segment as store, and reports `wal_bytes = 0` — the exact failure that made this
//! example's earlier storage numbers untrustworthy. Classification must carry the "inside the WAL
//! directory" fact down the walk. [`measure`] does that.
//!
//! # Why a decomposition, not a lumped total
//!
//! A single `du -s` number is misleading here. The doublewrite buffer is a **fixed preallocation per
//! database** (it does not grow with the graph), and the catalog is constant overhead, so lumping them
//! into "store bytes" inflates the store and deflates every ratio derived from it — most importantly
//! the WAL/store ratio this example reports. The four buckets are kept apart so each ratio can name
//! exactly which bytes it divides by.

use std::fs;
use std::path::Path;

/// The decomposed on-disk footprint of one Graphus database directory.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StoreFootprint {
    /// `graphus.store` — the data image: the graph itself (pages of node/rel/property records).
    pub data_bytes: u64,
    /// `graphus.dwb` — the doublewrite buffer. A **fixed preallocation** per database (torn-write
    /// protection), so it is overhead that does not scale with the graph and must not be counted as
    /// graph data.
    pub dwb_bytes: u64,
    /// Everything under a `*wal*` **directory**: the segmented write-ahead log (`seg.<lsn>` files).
    pub wal_bytes: u64,
    /// Anything else in the tree (e.g. `databases.toml`, key files) — constant catalog overhead.
    pub other_bytes: u64,
}

impl StoreFootprint {
    /// Everything that is **not** WAL: the durable store image plus its fixed overheads.
    #[must_use]
    pub fn store_bytes(&self) -> u64 {
        self.data_bytes
            .saturating_add(self.dwb_bytes)
            .saturating_add(self.other_bytes)
    }

    /// The full on-disk footprint (store + WAL).
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.store_bytes().saturating_add(self.wal_bytes)
    }

    /// The **WAL/store ratio**: durable WAL bytes per byte of the data image (`graphus.store`).
    ///
    /// Divided by the DATA image, not by `store_bytes()`: the doublewrite buffer and the catalog are
    /// fixed overheads whose inclusion would silently deflate the ratio on a small database. `None`
    /// when there is no data image to divide by (nothing was written).
    #[must_use]
    pub fn wal_to_data_ratio(&self) -> Option<f64> {
        (self.data_bytes > 0).then(|| self.wal_bytes as f64 / self.data_bytes as f64)
    }
}

/// Walks `root` and decomposes every regular file into one of the [`StoreFootprint`] buckets.
///
/// A missing / unreadable `root` yields a zero footprint (not an error): callers use this to sample a
/// live server's store directory, where a transient read failure must never abort the workload. The
/// walk does **not** follow symlinks (`fs::read_dir` + `Path::is_dir` on the entry path is enough for
/// a directory tree the server itself owns).
#[must_use]
pub fn measure(root: impl AsRef<Path>) -> StoreFootprint {
    let mut fp = StoreFootprint::default();
    walk(root.as_ref(), false, &mut fp);
    fp
}

/// Every WAL **segment** currently on disk under `root`, as `path -> length`.
///
/// Needed because the residual on-disk WAL badly understates the WAL volume a run actually wrote: a
/// checkpoint DELETES the sealed segments below the reclaim floor, so by the end of a churn run most of
/// the bytes the engine wrote are simply gone. A caller that merges these maps across ticks, keeping the
/// MAXIMUM length ever seen per segment path, recovers the cumulative WAL bytes written — sound because
/// a WAL segment is append-only, so its length only ever grows until it is reclaimed.
#[must_use]
pub fn wal_segments(root: impl AsRef<Path>) -> Vec<(std::path::PathBuf, u64)> {
    let mut out = Vec::new();
    collect_wal(root.as_ref(), false, &mut out);
    out
}

fn collect_wal(dir: &Path, in_wal: bool, out: &mut Vec<(std::path::PathBuf, u64)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let wal_here = in_wal || leaf_contains(&path, "wal");
        if path.is_dir() {
            collect_wal(&path, wal_here, out);
        } else if wal_here {
            if let Ok(meta) = entry.metadata() {
                out.push((path, meta.len()));
            }
        }
    }
}

/// True when the path's own leaf name contains `needle` (ASCII-case-insensitively).
fn leaf_contains(p: &Path, needle: &str) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.to_ascii_lowercase().contains(needle))
}

/// Recursive walk. `in_wal` is the load-bearing bit: once we have descended into a `*wal*` directory,
/// EVERY file below it is WAL — regardless of its own leaf name (`seg.<lsn>` contains no "wal").
fn walk(dir: &Path, in_wal: bool, fp: &mut StoreFootprint) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let wal_here = in_wal || leaf_contains(&path, "wal");
        if path.is_dir() {
            walk(&path, wal_here, fp);
        } else if let Ok(meta) = entry.metadata() {
            let len = meta.len();
            if wal_here {
                fp.wal_bytes = fp.wal_bytes.saturating_add(len);
            } else if leaf_contains(&path, ".dwb") {
                fp.dwb_bytes = fp.dwb_bytes.saturating_add(len);
            } else if leaf_contains(&path, ".store") {
                fp.data_bytes = fp.data_bytes.saturating_add(len);
            } else {
                fp.other_bytes = fp.other_bytes.saturating_add(len);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds the REAL server layout in a temp dir and proves each byte lands in the right bucket.
    /// The load-bearing case is the WAL: its segments are named `seg.<lsn>` and live inside a
    /// `graphus.wal/` DIRECTORY, so a leaf-name classifier reports `wal_bytes = 0` and folds every WAL
    /// byte into the store. This test fails on such an implementation.
    #[test]
    fn classifies_the_real_server_layout_by_path_not_by_leaf_name() {
        let root = std::env::temp_dir().join(format!(
            "giot-footprint-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&root);
        let db = root.join("databases").join("iotdb");
        let wal = db.join("graphus.wal");
        fs::create_dir_all(&wal).expect("layout");

        fs::write(db.join("graphus.store"), vec![0u8; 40_960]).expect("data image");
        fs::write(db.join("graphus.dwb"), vec![0u8; 8_192]).expect("doublewrite");
        fs::write(root.join("databases.toml"), vec![0u8; 128]).expect("catalog");
        // WAL segments: NO "wal" in the leaf name — only in the parent directory.
        fs::write(wal.join("seg.00000000000000000008"), vec![0u8; 16_384]).expect("seg8");
        fs::write(wal.join("seg.00000000000000000009"), vec![0u8; 512]).expect("seg9");

        let fp = measure(&root);
        let _ = fs::remove_dir_all(&root);

        assert_eq!(
            fp.wal_bytes,
            16_384 + 512,
            "every byte under the graphus.wal DIRECTORY is WAL, whatever the segment file is called"
        );
        assert_eq!(
            fp.data_bytes, 40_960,
            "only graphus.store holds the graph itself"
        );
        assert_eq!(
            fp.dwb_bytes, 8_192,
            "the doublewrite buffer is a fixed preallocation, not graph data"
        );
        assert_eq!(
            fp.other_bytes, 128,
            "the database catalog is neither data nor WAL"
        );
        assert_eq!(fp.store_bytes(), 40_960 + 8_192 + 128);
        assert_eq!(fp.total_bytes(), 40_960 + 8_192 + 128 + 16_384 + 512);
        // The ratio divides by the DATA image, never by the dwb-inflated store total.
        let ratio = fp.wal_to_data_ratio().expect("a data image exists");
        assert!(
            (ratio - (16_896.0 / 40_960.0)).abs() < 1e-9,
            "wal_to_data_ratio must divide WAL by graphus.store, got {ratio}"
        );
    }

    #[test]
    fn a_missing_root_is_a_zero_footprint_not_a_panic() {
        let fp = measure("/nonexistent/graphus/store/path");
        assert_eq!(fp, StoreFootprint::default());
        assert_eq!(fp.total_bytes(), 0);
        assert!(
            fp.wal_to_data_ratio().is_none(),
            "no data image => the ratio is NOT MEASURED (None), never a fabricated 0.0"
        );
    }
}
