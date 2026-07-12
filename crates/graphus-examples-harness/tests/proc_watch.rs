//! Integration tests for the `proc_watch` server-sampling binary (`rmp #717`).
//!
//! `proc_watch` is the seam every example uses to obtain SERVER evidence (CPU + RSS of the server's
//! own pid) from a driver that is not itself the server — a Node or Python client, or bash. Its whole
//! value is that the numbers are REAL, so the properties worth pinning are exactly the ones whose
//! violation would produce a *believable lie*:
//!
//! 1. a process that burned CPU must be reported as having burned CPU — **even if it exits before the
//!    watch window closes** (the regression below: the first cut read the CPU counters only *after*
//!    the sampling loop, so a pid that exited mid-watch could no longer be read, the code fell back to
//!    the baseline, and it published `mean_core_utilisation: 0.0` for a process that had just
//!    saturated a core — a fabricated zero of exactly the family `examples/README.md` forbids);
//! 2. a pid it cannot read must FAIL LOUDLY rather than emit a report full of zeros.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Spawns a child that spins (burning CPU) until it is killed.
fn spawn_cpu_burner() -> Child {
    Command::new("sh")
        .arg("-c")
        .arg("while : ; do : ; done")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn cpu burner")
}

/// Spawns a child that saturates a core **inside its own process** and then EXITS on its own — the
/// shape that produced the fabricated zero.
///
/// The loop is pure shell arithmetic: no `fork`, no `exec`, no `date`. That matters — a burner written
/// as `while [ $(date +%s) -lt $end ]` spends its life blocked in `fork`/`wait` while the CPU is
/// actually burned by short-lived `date` CHILDREN, so the monitored pid itself shows almost no CPU and
/// the test would be asserting on the wrong process. The iteration count is large enough to run for
/// several hundred milliseconds on any plausible host; the exact duration does not matter, only that
/// the process is CPU-bound and exits by itself.
fn spawn_self_exiting_burner() -> Child {
    Command::new("sh")
        .arg("-c")
        .arg("i=0; while [ $i -lt 2000000 ]; do i=$((i+1)); done")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn self-exiting burner")
}

#[test]
fn snapshot_reports_cumulative_counters_for_a_live_pid() {
    let mut child = spawn_cpu_burner();
    // Give it enough time to accrue at least one whole clock tick (10 ms on Linux).
    std::thread::sleep(Duration::from_millis(300));

    let out = Command::new(env!("CARGO_BIN_EXE_proc_watch"))
        .args(["--pid", &child.id().to_string(), "--snapshot"])
        .output()
        .expect("run proc_watch --snapshot");
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        out.status.success(),
        "snapshot of a live pid must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let json: serde_json::Value =
        serde_json::from_str(line.trim()).expect("snapshot is valid JSON");

    for key in ["pid", "rss_bytes", "user_secs", "system_secs"] {
        assert!(json.get(key).is_some(), "snapshot must carry `{key}`");
    }
    assert!(
        json["rss_bytes"].as_u64().expect("rss_bytes is a number") > 0,
        "a live process occupies memory; a 0 here would be a placeholder, not a measurement"
    );
    let cpu = json["user_secs"].as_f64().expect("user_secs")
        + json["system_secs"].as_f64().expect("system_secs");
    assert!(
        cpu > 0.0,
        "a process that spun for 300 ms has burned CPU; got {cpu} s"
    );
}

/// REGRESSION (`rmp #717`): a monitored process that EXITS DURING the watch window must still have its
/// CPU reported truthfully.
///
/// The first implementation read the CPU counters once, after the sampling loop. When the pid had
/// exited by then the read failed, the code silently fell back to the start-of-window baseline, and
/// the delta came out as exactly `0.0` — so a process that had just saturated a core for a full second
/// was published as `mean_core_utilisation: 0.0`. The fix reads the counters on every iteration and
/// keeps the last successful reading; this test is what proves it.
#[test]
fn watch_reports_real_cpu_even_when_the_monitored_pid_exits_mid_window() {
    let dir = std::env::temp_dir().join(format!("graphus-proc-watch-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let out_path = dir.join("watch.json");

    let mut child = spawn_self_exiting_burner();
    let pid = child.id().to_string();

    let status = Command::new(env!("CARGO_BIN_EXE_proc_watch"))
        .args([
            "--pid",
            &pid,
            "--watch",
            "--out",
            out_path.to_str().expect("utf-8 path"),
            "--interval-ms",
            "20",
            // Comfortably longer than the burner lives, so the watch ends because the PID EXITED —
            // which is precisely the path that used to fabricate the zero.
            "--max-secs",
            "10",
        ])
        .status()
        .expect("run proc_watch --watch");
    let _ = child.wait();
    assert!(status.success(), "watch over a live pid must succeed");

    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).expect("watch report exists"))
            .expect("watch report is valid JSON");
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        report["monitored_pid_exited"], true,
        "the burner exits on its own; the report must say the window closed because of that"
    );
    let total = report["cpu"]["total_secs"]
        .as_f64()
        .expect("cpu.total_secs");
    assert!(
        total > 0.1,
        "the burner was CPU-bound for its whole life, so the watch must report real CPU — a value of \
         {total} s is the fabricated zero this test exists to prevent"
    );
    // The decisive invariant: a process that spins in-process reports ~1.0 core. The bug reported
    // 0.0. The floor is deliberately loose (not ~1.0) so a heavily loaded CI host cannot make this
    // flaky, while still being nowhere near the zero it guards against.
    let cores = report["cpu"]["mean_core_utilisation"]
        .as_f64()
        .expect("mean_core_utilisation is measured");
    assert!(
        cores > 0.5,
        "a single-core burner must report ~1.0 mean core utilisation, got {cores}"
    );
    assert!(
        report["memory"]["peak_rss_bytes"]
            .as_u64()
            .expect("peak_rss_bytes")
            > 0,
        "a live process occupies memory"
    );
}

/// A pid that cannot be read must FAIL, not emit a report of zeros: a zero-filled report would flow
/// straight into an evidence file and read as "the server burned no CPU and held no memory".
#[test]
fn an_unreadable_pid_fails_loudly_instead_of_fabricating_zeros() {
    let out = Command::new(env!("CARGO_BIN_EXE_proc_watch"))
        // A pid that cannot exist (Linux's default pid_max is 4194304, and this is far past the
        // usual ceiling); if it somehow resolves, the assertion below simply does not fire.
        .args(["--pid", "4294967290", "--snapshot"])
        .output()
        .expect("run proc_watch --snapshot on a dead pid");

    assert!(
        !out.status.success(),
        "an unreadable pid must exit non-zero, not report zeros"
    );
    assert!(
        out.stdout.is_empty(),
        "an unreadable pid must print NOTHING on stdout (a caller parses stdout as the measurement)"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("cannot read"),
        "the failure must say why"
    );
}

/// The watch report must never be written for a pid that was unreadable from the start — an evidence
/// file that exists is an evidence file that will be believed.
#[test]
fn watch_writes_no_report_for_an_unreadable_pid() {
    let dir = std::env::temp_dir().join(format!("graphus-proc-watch-dead-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let out_path = dir.join("watch.json");

    let out = Command::new(env!("CARGO_BIN_EXE_proc_watch"))
        .args([
            "--pid",
            "4294967290",
            "--watch",
            "--out",
            out_path.to_str().expect("utf-8 path"),
            "--max-secs",
            "1",
        ])
        .output()
        .expect("run proc_watch --watch on a dead pid");

    assert!(
        !out.status.success(),
        "an unreadable pid must exit non-zero"
    );
    assert!(
        !out_path.exists(),
        "no report may be written for a pid that was never readable"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
