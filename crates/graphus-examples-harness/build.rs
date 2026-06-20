//! Build script for `graphus-examples-harness`.
//!
//! Its sole job is to bake the `rustc` version into the binary as the `RUSTC_VERSION` environment
//! variable, so [`crate::host::HostInfo`](../src/host.rs) can report which toolchain produced the
//! evidence without shelling out at run time. This is *report metadata* (see `host.rs`), captured
//! cheaply at build time. If `rustc -V` cannot be run, the variable is simply not set and the field
//! degrades to `"unknown"`.

use std::process::Command;

fn main() {
    // Only re-run when the build script itself changes (the rustc version is otherwise stable for a
    // given toolchain, and Cargo already rebuilds on toolchain change).
    println!("cargo:rerun-if-changed=build.rs");

    let version = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string()))
        .arg("-V")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());

    if let Some(v) = version {
        println!("cargo:rustc-env=RUSTC_VERSION={v}");
    }
}
