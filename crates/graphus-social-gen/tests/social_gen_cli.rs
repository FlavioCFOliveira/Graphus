//! Integration tests for the `social_gen` binary's CLI surface — specifically the `--format csv`
//! mode and the `--users`/`--articles`/`--friend-min`/`--friend-max`/`--avg-likes`/`--seed` profile
//! overrides added for `rmp` task #521 (the network bulk-import validation against a live remote
//! instance, which needed a
//! way to request a custom-scale dataset without inventing a new named profile). The override /
//! validation logic lives only in the binary (`src/bin/social_gen.rs`), not in the library, so it is
//! exercised here by spawning the compiled binary rather than by calling `graphus_social_gen`
//! directly (mirroring how `tests/determinism.rs` covers the library's own generation contract).

use std::path::{Path, PathBuf};
use std::process::Command;

/// A fresh, unique temp directory for one test, removed on drop so the suite leaves no artifacts —
/// mirrors `tests/load_fast.rs`'s `TempDir` (this crate deliberately has no `tempfile` dependency).
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "graphus-social-gen-cli-test-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_social_gen"))
}

fn read_header(path: &Path) -> String {
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    content.lines().next().unwrap_or_default().to_string()
}

fn count_data_rows(path: &Path) -> usize {
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    content.lines().count().saturating_sub(1)
}

#[test]
fn csv_format_writes_four_files_with_correct_headers_and_counts() {
    let dir = TempDir::new("csv-writes-four");
    let out = dir.path.as_path();

    let status = bin()
        .args([
            "--profile",
            "huge",
            "--format",
            "csv",
            "--out-dir",
            out.to_str().unwrap(),
            "--users",
            "300",
            "--articles",
            "40",
            "--friend-min",
            "4",
            "--friend-max",
            "10",
            "--avg-likes",
            "3",
        ])
        .status()
        .expect("spawn social_gen");
    assert!(status.success(), "social_gen --format csv should succeed");

    assert_eq!(
        read_header(&out.join("users.csv")),
        ":ID,:LABEL,id:string,name:string,registered:long"
    );
    assert_eq!(
        read_header(&out.join("articles.csv")),
        ":ID,:LABEL,id:string,name:string,registered:long"
    );
    assert_eq!(
        read_header(&out.join("friends.csv")),
        ":START_ID,:END_ID,:TYPE,since:long"
    );
    assert_eq!(
        read_header(&out.join("likes.csv")),
        ":START_ID,:END_ID,:TYPE,date:long"
    );

    // Node counts are exact (fixed by --users/--articles); FRIEND/LIKE counts are only bounded by
    // construction (configuration-model degree band, uniform-in-[0, 2*avg] like sampling) — assert
    // the invariants the generator itself guarantees rather than exact counts.
    assert_eq!(count_data_rows(&out.join("users.csv")), 300);
    assert_eq!(count_data_rows(&out.join("articles.csv")), 40);
    let friend_rows = count_data_rows(&out.join("friends.csv"));
    assert!(
        (300 * 4 / 2..=300 * 10 / 2 + 1).contains(&friend_rows),
        "friend edge count {friend_rows} outside the degree-band-implied range"
    );
}

#[test]
fn csv_and_cypher_formats_agree_on_realised_counts() {
    let dir = TempDir::new("csv-cypher-agree");
    let out = dir.path.as_path();

    let csv_out = out.join("csv");
    let status = bin()
        .args([
            "--profile",
            "fast",
            "--format",
            "csv",
            "--out-dir",
            csv_out.to_str().unwrap(),
        ])
        .status()
        .expect("spawn social_gen csv");
    assert!(status.success());

    let cypher_out = out.join("cypher");
    let output = bin()
        .args([
            "--profile",
            "fast",
            "--format",
            "cypher",
            "--out-dir",
            cypher_out.to_str().unwrap(),
        ])
        .output()
        .expect("spawn social_gen cypher");
    assert!(output.status.success());
    let summary = String::from_utf8_lossy(&output.stdout);
    let first_line = summary.lines().next().unwrap_or_default();

    // The `fast` profile's realised counts are pinned (rmp #307's committed baseline): both formats
    // must derive from the identical generator, so the printed summary and the CSV row counts agree.
    assert!(first_line.contains("users=2000"), "{first_line}");
    assert!(first_line.contains("articles=200"), "{first_line}");
    assert!(first_line.contains("friend_edges=15047"), "{first_line}");
    assert!(first_line.contains("like_edges=10020"), "{first_line}");
    assert_eq!(count_data_rows(&csv_out.join("users.csv")), 2000);
    assert_eq!(count_data_rows(&csv_out.join("articles.csv")), 200);
    assert_eq!(count_data_rows(&csv_out.join("friends.csv")), 15047);
    assert_eq!(count_data_rows(&csv_out.join("likes.csv")), 10020);
}

#[test]
fn csv_format_is_byte_identical_across_runs_with_a_custom_seed() {
    let dir = TempDir::new("csv-byte-identical");
    let a = dir.path.join("a");
    let b = dir.path.join("b");

    for out in [&a, &b] {
        let status = bin()
            .args([
                "--profile",
                "large",
                "--format",
                "csv",
                "--out-dir",
                out.to_str().unwrap(),
                "--users",
                "500",
                "--seed",
                "123456789",
            ])
            .status()
            .expect("spawn social_gen");
        assert!(status.success());
    }

    for name in ["users.csv", "articles.csv", "friends.csv", "likes.csv"] {
        let ca = std::fs::read(a.join(name)).unwrap();
        let cb = std::fs::read(b.join(name)).unwrap();
        assert_eq!(ca, cb, "{name} must be byte-identical across runs");
    }
}

#[test]
fn invalid_friend_band_is_rejected() {
    let dir = TempDir::new("invalid-friend-band");
    let output = bin()
        .args([
            "--profile",
            "fast",
            "--format",
            "csv",
            "--out-dir",
            dir.path.to_str().unwrap(),
            "--friend-min",
            "50",
            "--friend-max",
            "10",
        ])
        .output()
        .expect("spawn social_gen");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--friend-min") && stderr.contains("--friend-max"),
        "{stderr}"
    );
}

#[test]
fn unknown_format_is_rejected() {
    let dir = TempDir::new("unknown-format");
    let output = bin()
        .args([
            "--profile",
            "fast",
            "--format",
            "xml",
            "--out-dir",
            dir.path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn social_gen");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown format"), "{stderr}");
}
