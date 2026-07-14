//! **`rmp` #745** — `graphus_wal_bytes_written_total` reports the EXACT WAL volume an engine wrote,
//! and it survives a **reclamation**.
//!
//! ## The problem this metric closes
//!
//! `examples/iot-timeseries` reconstructed the cumulative WAL bytes an engine wrote by polling the WAL
//! directory and summing the largest size it ever observed per segment path. That reconstruction
//! structurally UNDER-counts: a WAL segment can be created, filled, sealed **and reclaimed** entirely
//! between two samples, so it is never observed at its final length — and its bytes silently disappear
//! from the total. The error is one-sided (it can only under-count) and host-speed dependent (a faster
//! host reclaims more between polls, so it under-counts *more*), which makes the headline
//! write-amplification figure a floor rather than a measurement.
//!
//! The engine already knows the exact answer: a WAL byte offset **is** an LSN, the offset only ever
//! advances, and reclamation deletes segment *files* without moving it. `LogSink::durable_len` is that
//! offset. `graphus-wal/tests/wal_volume_survives_reclamation_750.rs` proves those sink-level
//! properties against ground truth; **this** test proves the whole pipeline — engine thread → `Metrics`
//! → the rendered `/metrics` text — reports them without losing or double-counting a byte.
//!
//! ## Ground truth (independent of the metric)
//!
//! The WAL's absolute byte offset is recoverable from the directory *without asking the engine*,
//! because a segment's **filename encodes its absolute base offset** (`seg.<base>`): the offset is
//! `max(base + file_len)`. That is a genuinely independent oracle — it is derived from the filesystem,
//! not from the counter under test — and it is exactly what an external observer CANNOT reconstruct
//! after the fact once the files are deleted, which is the whole point.
//!
//! The test drives the REAL threaded engine over a REAL file-backed store and WAL.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use graphus_core::capability::Clock;
use graphus_io::FileBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine};
use graphus_server::metrics::Metrics;
use graphus_storage::RecordStore;
use graphus_storage::recovery::recover_device;
use graphus_wal::{FileLogSink, WalManager};

/// Nodes written, each as its own acknowledged auto-commit transaction. Sized so the WAL grows past the
/// 1 MiB minimum segment seal threshold (`WAL_SEGMENT_MIN_TARGET_BYTES`) several times over, giving the
/// checkpoint sealed segments below the recovery floor that it can actually delete. The test ASSERTS
/// that a reclamation really happened, so an undersized workload fails loudly rather than passing
/// vacuously.
const WRITES: usize = 1500;

const DB: &str = "waldb";

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "graphus_wal750_srv_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).expect("create scratch dir");
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The WAL's **absolute durable byte offset**, read straight off the filesystem: the highest
/// `base + len` over the surviving `seg.<base>` files, or the anchor's length when no segment exists
/// yet. This is the independent oracle — it never consults the metric.
fn wal_offset_on_disk(wal_dir: &Path) -> u64 {
    let mut anchor_len = 0u64;
    let mut end = 0u64;
    for e in std::fs::read_dir(wal_dir).expect("read wal dir").flatten() {
        let Ok(meta) = e.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if name == "anchor" {
            anchor_len = meta.len();
        } else if let Some(base) = name.strip_prefix("seg.") {
            let base: u64 = base.parse().expect("segment base is numeric");
            end = end.max(base + meta.len());
        }
    }
    end.max(anchor_len)
}

/// The bytes **physically present** in the WAL directory right now — what a reclamation destroys, and
/// therefore the ceiling on anything an after-the-fact on-disk reconstruction could ever report.
fn wal_bytes_on_disk(wal_dir: &Path) -> u64 {
    std::fs::read_dir(wal_dir)
        .expect("read wal dir")
        .flatten()
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

/// The number of `seg.*` files present (used to prove a reclaim really deleted some).
fn segment_count(wal_dir: &Path) -> usize {
    std::fs::read_dir(wal_dir)
        .expect("read wal dir")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("seg."))
        .count()
}

/// Scrapes one unlabelled counter out of the rendered Prometheus text.
fn counter(text: &str, name: &str) -> u64 {
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix(name) {
            if let Some(v) = rest.strip_prefix(' ') {
                return v.trim().parse().expect("counter value parses");
            }
        }
    }
    panic!("counter {name} not present in /metrics output:\n{text}");
}

/// Scrapes one `{database="<db>"}`-labelled counter out of the rendered Prometheus text.
fn labelled(text: &str, name: &str, db: &str) -> u64 {
    let needle = format!("{name}{{database=\"{db}\"}} ");
    for line in text.lines() {
        if let Some(v) = line.strip_prefix(&needle) {
            return v.trim().parse().expect("counter value parses");
        }
    }
    panic!("series {name}{{database=\"{db}\"}} not present in /metrics output:\n{text}");
}

fn spawn(dir: &Path, metrics: Arc<Metrics>) -> Engine {
    let device_path = dir.join("graph.db");
    let wal_dir = dir.join("wal");
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(graphus_sim::SharedClock::new(0));
    spawn_engine::<FileBlockDevice, FileLogSink, _>(
        Arc::from(DB),
        move || {
            let device = FileBlockDevice::open(&device_path)?;
            let sink = FileLogSink::open(&wal_dir)?;
            let wal = WalManager::create(sink)?;
            let store = RecordStore::create(device, wal, 4096, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        4096,
        128,
        1,
        metrics,
        clock,
    )
    .expect("spawn file-backed engine")
}

/// **Reopens** the SAME store from its durable WAL (recover → open) — a `STOP`/`START DATABASE` cycle.
/// The `Metrics` registry is deliberately the SAME `Arc` the first incarnation used, exactly as a real
/// server's process-wide registry is, so the counter's behaviour across a restart is what is under test.
fn reopen(dir: &Path, metrics: Arc<Metrics>) -> Engine {
    let device_path = dir.join("graph.db");
    let wal_dir = dir.join("wal");
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(graphus_sim::SharedClock::new(0));
    spawn_engine::<FileBlockDevice, FileLogSink, _>(
        Arc::from(DB),
        move || {
            let mut device = FileBlockDevice::open(&device_path)?;
            let sink = FileLogSink::open(&wal_dir)?;
            let mut wal = WalManager::open(sink)?;
            recover_device(&mut wal, &mut device)?;
            let store = RecordStore::open(device, wal, 4096)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        4096,
        128,
        1,
        metrics,
        clock,
    )
    .expect("reopen file-backed engine")
}

/// Runs one auto-commit write to completion (acked => `fdatasync`-durable), draining its rows.
fn write(handle: &EngineHandle, stmt: &str) {
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Write)
        .expect("begin auto-commit");
    let mut reply = handle
        .run_blocking(ticket, stmt.to_owned(), vec![], true, None)
        .unwrap_or_else(|e| panic!("run {stmt:?}: {e:?}"));
    while reply.rows.next().expect("drain rows").is_some() {}
}

/// A **graceful** shutdown: `EngineCommand::Shutdown` drains, hardens the store (the final flush) and
/// exits. This is the path that exercises the `harden_store` → final-publish seam (`rmp` #745) — merely
/// dropping the handles would close the channel without ever running it.
fn shutdown(engine: Engine) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build shutdown runtime");
    rt.block_on(engine.handle.shutdown())
        .expect("graceful shutdown");
    engine.join.join().expect("engine thread joins");
}

/// **The certification.** Over a workload that seals WAL segments and then RECLAIMS them, the counter's
/// delta equals the WAL's true byte growth — measured independently from the segment filenames — to the
/// byte. And the on-disk reconstruction the metric replaces is shown, in the same run, to be short.
#[test]
fn wal_bytes_written_is_exact_across_a_reclamation() {
    let dir = TempDir::new("exact");
    let wal_dir = dir.path().join("wal");
    let metrics = Arc::new(Metrics::new());
    let engine = spawn(dir.path(), Arc::clone(&metrics));
    let handle = engine.handle.clone();

    // ---- The window OPENS here. The engine has just created the store; nothing has been written by us.
    let offset_at_open = wal_offset_on_disk(&wal_dir);
    let text = metrics.render_prometheus();
    assert_eq!(
        counter(&text, "graphus_wal_bytes_written_total"),
        0,
        "a freshly-opened engine has written nothing YET — the store-creation WAL it inherited must be \
         baselined out, not counted as bytes this process wrote"
    );

    // ---- The workload. Each write is its own acked auto-commit, so every byte is fdatasync-durable.
    for i in 0..WRITES {
        write(
            &handle,
            &format!(
                "CREATE (:Reading {{id: {i}, v: 'payload-{i}-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'}})"
            ),
        );
    }

    // The counter must be live DURING the run, not only at shutdown.
    let mid = counter(
        &metrics.render_prometheus(),
        "graphus_wal_bytes_written_total",
    );
    assert!(
        mid > 0,
        "the counter must advance as commits harden, not only at shutdown"
    );

    let segments_before = segment_count(&wal_dir);

    // ---- Force a reclamation: the operator checkpoint deletes every sealed segment below the floor.
    handle.checkpoint_blocking().expect("operator checkpoint");

    let segments_after = segment_count(&wal_dir);
    assert!(
        segments_before > segments_after,
        "TEETH: the checkpoint must have RECLAIMED sealed WAL segments ({segments_before} -> \
         {segments_after} segment files). Without a reclamation inside the window this test proves \
         nothing — raise WRITES."
    );

    // ---- The window CLOSES at shutdown, which also hardens the final flush (whose WAL bytes the
    // ---- Shutdown publish is there to capture — see `harden_store`).
    shutdown(engine);

    let offset_at_close = wal_offset_on_disk(&wal_dir);
    let truth = offset_at_close - offset_at_open;
    let text = metrics.render_prometheus();
    let reported = counter(&text, "graphus_wal_bytes_written_total");
    let reported_db = labelled(&text, "graphus_db_wal_bytes_written_total", DB);

    // THE ASSERTION. Exact, to the byte, across a segment seal AND a reclamation.
    assert_eq!(
        reported, truth,
        "graphus_wal_bytes_written_total ({reported}) must EXACTLY equal the WAL's true byte growth \
         over the window ({truth}), independently measured from the segment filenames — across a seal \
         and a reclamation"
    );
    assert_eq!(
        reported_db, truth,
        "the per-database series must carry the same exact figure"
    );
    assert!(
        truth > 0,
        "TEETH: the workload must actually have written WAL"
    );

    // ---- And the thing it replaces is, in this very same run, provably short. After the reclamation
    // ---- the bytes still on disk are FEWER than the bytes the window wrote — so no after-the-fact
    // ---- reconstruction from the surviving files can recover the true figure. It is not that the old
    // ---- approach was imprecise; it is that the evidence was deleted.
    let still_on_disk = wal_bytes_on_disk(&wal_dir);
    assert!(
        still_on_disk < truth,
        "the reclaimed WAL ({still_on_disk} bytes surviving) is smaller than what the window wrote \
         ({truth} bytes) — this is exactly the evidence an on-disk reconstruction loses, and exactly \
         what the counter retains"
    );
}

/// **The shutdown-drain seam.** A `STOP DATABASE` with a transaction still open makes the engine ROLL
/// IT BACK (`drain_inflight`) — which appends WAL (undo/CLR records) *after* the last commit's publish.
/// Those bytes must still be counted: if they were not, the next `START DATABASE` would re-baseline the
/// fold at the higher on-disk offset and they would be dropped from the counter FOREVER — a permanent,
/// silent, one-sided under-count, i.e. the exact disease this metric exists to cure.
///
/// This is the test that makes the `harden_store` → final-publish seam load-bearing. With that publish
/// removed, the counter falls short of ground truth here.
#[test]
fn wal_bytes_written_captures_the_shutdown_drain_of_an_open_transaction() {
    let dir = TempDir::new("drain");
    let wal_dir = dir.path().join("wal");
    let metrics = Arc::new(Metrics::new());
    let engine = spawn(dir.path(), Arc::clone(&metrics));
    let handle = engine.handle.clone();
    let offset_at_open = wal_offset_on_disk(&wal_dir);

    // Some committed traffic first, so the last commit publish lands well before shutdown.
    for i in 0..50 {
        write(&handle, &format!("CREATE (:A {{id: {i}}})"));
    }

    // Now leave an EXPLICIT transaction open, having written a lot inside it. Its updates are logged
    // (WAL-before-data), and the shutdown drain must roll it back — appending undo/CLR records after
    // the last commit's publish.
    let ticket = handle
        .begin_blocking(AccessMode::Write)
        .expect("begin explicit txn");
    for i in 0..400 {
        let mut reply = handle
            .run_blocking(
                ticket,
                format!(
                    "CREATE (:Doomed {{id: {i}, pad: 'yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy'}})"
                ),
                vec![],
                false, // explicit transaction: do NOT auto-commit — it must stay open for the drain
                None,
            )
            .expect("run inside explicit txn");
        while reply.rows.next().expect("drain rows").is_some() {}
    }
    // Deliberately NOT committed and NOT rolled back: the shutdown drain must do it.

    shutdown(engine);

    let offset_at_close = wal_offset_on_disk(&wal_dir);
    let truth = offset_at_close - offset_at_open;
    let reported = counter(
        &metrics.render_prometheus(),
        "graphus_wal_bytes_written_total",
    );
    assert_eq!(
        reported, truth,
        "the counter ({reported}) must include the WAL the SHUTDOWN DRAIN appended when it rolled back \
         the still-open transaction — ground truth from the segment filenames is {truth}"
    );
    assert!(truth > 0, "TEETH: the workload must have written WAL");
}

/// The counter is **continuous across a `STOP`/`START DATABASE` cycle**: the second incarnation neither
/// re-counts the WAL history it inherits (which would inflate the counter by the whole log) nor rewinds.
/// The sum over both incarnations equals the true total growth.
#[test]
fn wal_bytes_written_is_continuous_across_a_restart() {
    let dir = TempDir::new("restart");
    let wal_dir = dir.path().join("wal");
    // ONE `Metrics` across both incarnations — the server-lifetime registry, exactly as production has.
    let metrics = Arc::new(Metrics::new());

    // ---- Incarnation 1.
    let engine = spawn(dir.path(), Arc::clone(&metrics));
    let handle = engine.handle.clone();
    let offset_at_open = wal_offset_on_disk(&wal_dir);
    for i in 0..200 {
        write(&handle, &format!("CREATE (:A {{id: {i}}})"));
    }
    shutdown(engine);
    let after_first = counter(
        &metrics.render_prometheus(),
        "graphus_wal_bytes_written_total",
    );
    let offset_after_first = wal_offset_on_disk(&wal_dir);
    assert_eq!(
        after_first,
        offset_after_first - offset_at_open,
        "incarnation 1's bytes are exact (including the final flush the Shutdown publish captures)"
    );
    assert!(after_first > 0, "TEETH: incarnation 1 wrote WAL");

    // ---- Incarnation 2: reopen the SAME store from its durable WAL (recover → open).
    let engine = reopen(dir.path(), Arc::clone(&metrics));
    let handle = engine.handle.clone();

    // The instant it opens, the counter must be UNCHANGED: the WAL history it just inherited is
    // baselined out, never folded in. (A monotone-max design over the raw offset would be fine here but
    // would break on a DROP+CREATE; a design that folded the open offset as a delta would DOUBLE-COUNT
    // the whole log right here.)
    assert_eq!(
        counter(
            &metrics.render_prometheus(),
            "graphus_wal_bytes_written_total"
        ),
        after_first,
        "reopening a database must NOT re-count the WAL history it inherits"
    );

    for i in 200..400 {
        write(&handle, &format!("CREATE (:A {{id: {i}}})"));
    }
    shutdown(engine);

    let offset_at_close = wal_offset_on_disk(&wal_dir);
    let reported = counter(
        &metrics.render_prometheus(),
        "graphus_wal_bytes_written_total",
    );
    assert_eq!(
        reported,
        offset_at_close - offset_at_open,
        "across a STOP/START cycle the counter is CONTINUOUS: it equals the total WAL growth over both \
         incarnations, with no gap (bytes lost at shutdown) and no double count (history re-folded at \
         open)"
    );
    assert!(
        reported > after_first,
        "TEETH: incarnation 2 must have added bytes of its own"
    );
}
