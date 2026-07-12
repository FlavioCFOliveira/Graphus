//! Regression tests for the WAL on-disk write-amplification / reclamation bounds (`rmp` #556, #706).
//!
//! Two findings, two devices, two halves of this file:
//!
//! # `rmp` #556 — the reclaim CADENCE (guarded over `MemLogSink`)
//!
//! The on-disk WAL was 7–60x the store because the *only* reclaiming maintenance checkpoint fired at a
//! fixed 256 MiB threshold, independent of store size. #315 made reclamation *work*; #556 made its
//! *cadence* proportional to the store. The two `MemLogSink` tests below pin that: reclamation frees the
//! whole transient prefix, and the adaptive cadence keeps the retained-WAL/store ratio bounded. They run
//! over `MemLogSink` deliberately — it frees exact byte ranges, so it isolates the CADENCE logic from
//! any segment-granularity effect.
//!
//! # `rmp` #706 / #719 — the reclaim GRANULARITY (guarded over a FILE-BACKED WAL)
//!
//! The cadence being proportional was not enough: WAL disk is freed only in whole SEGMENT units, and the
//! active segment is never reclaimed, so nothing below the reclaim floor can be freed until a segment
//! **seals** — and a segment sealed at a fixed 64 MiB. So a small database's WAL climbed all the way to
//! 64 MiB (hundreds of times its store) before one byte came back. #706 makes the segment seal size
//! store-proportional ([`graphus_wal::segment_target_for_store`]); this file's file-backed guard proves
//! it, on the DEVICE THE SERVER ACTUALLY RUNS (a real `FileBlockDevice` + a real segmented `FileLogSink`
//! on disk), not over a `MemLogSink` that has no segments and so is structurally blind to the defect
//! (the exact reason `rmp` #719 exists).
//!
//! The guard is built like the one in `crates/graphus-iot-gen/src/wire_samples.rs`: a REAL run over a
//! file-backed WAL produces a plain [`WalAmpObservation`], and a PURE [`WalAmpObservation::gate`]
//! function encodes the physics. Because the gate is pure, the unit tests below can hand it a mutated
//! observation — a zeroed WAL, a fixed 64 MiB segment on a small store — and *prove* it fires the rule
//! it names, and equally prove it does NOT fire on an improvement (a gate that fails on a fix is worse
//! than no gate).

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::semantics::analyze;
use graphus_io::{BlockDevice, FileBlockDevice, MemBlockDevice};
use graphus_storage::RecordStore;
use graphus_wal::{
    FileLogSink, HEADER_LEN, LogRecord, LogSink, MemLogSink, RecordType,
    WAL_SEGMENT_MIN_TARGET_BYTES, WalManager, segment_target_for_store,
};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

type MemCoord = TxnCoordinator<MemBlockDevice, MemLogSink>;
type FileCoord = TxnCoordinator<FileBlockDevice, FileLogSink>;

// The production adaptive-cadence constants (graphus-server engine/mod.rs), replicated for the
// emulation below. Kept in sync by the shared #556 rationale; the production copy is authoritative.
const WAL_STORE_RATIO_TARGET: u64 = 4;
const MAINTENANCE_FLOOR: u64 = 8 * 1024 * 1024;
const MAINTENANCE_CAP: u64 = 256 * 1024 * 1024;

fn adaptive_interval(store_bytes: u64) -> u64 {
    WAL_STORE_RATIO_TARGET
        .saturating_mul(store_bytes)
        .clamp(MAINTENANCE_FLOOR, MAINTENANCE_CAP)
}

fn fresh_mem() -> MemCoord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut store = RecordStore::create(device, wal, 256, 1).expect("create store");
    // Disable the store-level redo-bounding auto-checkpoint (which never reclaims WAL disk on its own,
    // since only the GC freeze sweep settles `unfrozen_commit_lsn`) so the workload's RAW WAL is
    // measured; reclamation is then driven explicitly, exactly as the engine maintenance loop does.
    store.set_checkpoint_interval_bytes(0);
    TxnCoordinator::new(store)
}

/// Compiles `CREATE (:Account {id: $id, bal: 100})` once; each call binds a fresh `$id` and commits,
/// so a large workload is not dominated by re-planning the same statement N times.
struct NodeInserter {
    plan: PhysicalPlan,
}

impl NodeInserter {
    fn new() -> Self {
        let src = "CREATE (:Account {id: $id, bal: 100})";
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        Self {
            plan: plan_physical(&lower(&validated), &IndexCatalog::empty()),
        }
    }

    /// Binds `$id`, opens a serializable transaction, runs the compiled `CREATE`, and commits. Generic
    /// over the device / sink so the same workload drives both the in-memory (#556) and file-backed
    /// (#706) coordinators.
    fn insert_committed<D, S>(&self, coord: &mut TxnCoordinator<D, S>, id: i64)
    where
        D: BlockDevice + Send + Sync + 'static,
        S: LogSink + Send + Sync + 'static,
    {
        let params = Parameters::new().with("id", Value::Integer(id));
        let bound = bind_parameters(&self.plan, &params).expect("bind");
        let t = coord.begin_serializable();
        {
            let mut graph = coord.statement(t).expect("statement");
            let mut cursor = execute(&self.plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect");
            assert!(!graph.has_error(), "insert error: {:?}", graph.take_error());
        }
        coord.commit(t).expect("commit");
    }
}

// ============================================================================================
// #556 — the reclaim CADENCE, over MemLogSink (byte-exact, no segments).
// ============================================================================================

fn store_bytes(coord: &MemCoord) -> u64 {
    coord.store_byte_len()
}

fn wal_retained(coord: &MemCoord) -> usize {
    coord.with_store_mut(|s| s.with_wal(|w| w.sink().retained_bytes()))
}

fn wal_image(coord: &MemCoord) -> Vec<u8> {
    coord.with_store_mut(|s| s.with_wal(|w| w.sink().durable_bytes()))
}

/// (count, encoded_bytes) per record type in the durable WAL after the 8-byte header.
fn breakdown(bytes: &[u8]) -> BTreeMap<u8, (usize, usize)> {
    let mut cursor = HEADER_LEN as usize;
    let mut map: BTreeMap<u8, (usize, usize)> = BTreeMap::new();
    while cursor < bytes.len() {
        match LogRecord::decode(&bytes[cursor..]) {
            Ok((rec, n)) => {
                let e = map.entry(rec.rec_type as u8).or_insert((0, 0));
                e.0 += 1;
                e.1 += n;
                cursor += n;
            }
            Err(_) => break,
        }
    }
    map
}

fn type_name(b: u8) -> &'static str {
    RecordType::from_u8(b).map_or("??", |t| match t {
        RecordType::Begin => "Begin",
        RecordType::Update => "Update",
        RecordType::Insert => "Insert",
        RecordType::Delete => "Delete",
        RecordType::Commit => "Commit",
        RecordType::Abort => "Abort",
        RecordType::Clr => "Clr",
        RecordType::CheckpointBegin => "CheckpointBegin",
        RecordType::CheckpointEnd => "CheckpointEnd",
        RecordType::FullPageImage => "FullPageImage",
        RecordType::Alloc => "Alloc",
        RecordType::Free => "Free",
    })
}

/// The entire pre-checkpoint WAL is un-reclaimed transient: one checkpoint frees it back to the
/// anchor header. Guards the #315 reclamation property (a regression that stopped freeing the prefix
/// would silently reintroduce the unbounded on-disk WAL).
#[test]
fn reclamation_collapses_the_retained_wal() {
    let mut coord = fresh_mem();
    let inserter = NodeInserter::new();
    for i in 0..2000 {
        inserter.insert_committed(&mut coord, i);
    }

    let before = wal_retained(&coord);
    let store = store_bytes(&coord);
    let img = wal_image(&coord);
    let bd = breakdown(&img);
    let ratio_before = before as f64 / store as f64;
    eprintln!("pre-checkpoint: store={store} B, WAL retained={before} B, ratio={ratio_before:.2}x");
    for (k, (cnt, enc)) in &bd {
        eprintln!("  {:<8} count={cnt:>6}  enc_bytes={enc}", type_name(*k));
    }

    // The transient WAL genuinely dwarfs the store (documents the finding under test).
    assert!(
        ratio_before > 3.0,
        "expected a large transient WAL ratio, got {ratio_before:.2}x"
    );

    coord.checkpoint().expect("checkpoint");
    let after = wal_retained(&coord);
    eprintln!("post-checkpoint: WAL retained={after} B");

    // A single checkpoint frees essentially the whole WAL: what remains is only the small retained
    // head/tail (the anchor header + at most a sliver of live tail), independent of how much was
    // written. Assert it is both tiny in absolute terms and a negligible fraction of what it was.
    assert!(
        after < 64 * 1024,
        "checkpoint must free the WAL prefix; {after} B still retained"
    );
    assert!(
        (after as f64) < 0.02 * before as f64,
        "checkpoint freed too little: {after} B of {before} B still retained"
    );
}

/// The core #556 bound: under a sustained OLTP write stream, the adaptive `4×store` cadence keeps the
/// on-disk WAL/store ratio bounded, where the historical fixed 256 MiB cadence lets it grow unbounded.
#[test]
fn adaptive_cadence_bounds_the_wal_store_ratio() {
    // Enough inserts that the store grows past the 2 MiB point where `4×store` overtakes the 8 MiB
    // floor, so the RATIO bound (not the floor) governs — and enough total WAL that the fixed 256 MiB
    // cadence still never fires, reproducing the unbounded-transient finding.
    let n = 20_000i64;

    let run = |adaptive: bool| -> (f64, u64) {
        let mut coord = fresh_mem();
        let inserter = NodeInserter::new();
        let mut wal_at_last_ckpt = 0u64;
        let mut checkpoints = 0u64;
        for i in 0..n {
            inserter.insert_committed(&mut coord, i);
            let durable = coord.wal_durable_len();
            let interval = if adaptive {
                adaptive_interval(store_bytes(&coord))
            } else {
                MAINTENANCE_CAP // the historical fixed 256 MiB cadence
            };
            if durable.saturating_sub(wal_at_last_ckpt) >= interval {
                coord.checkpoint().expect("maintenance checkpoint");
                wal_at_last_ckpt = coord.wal_durable_len();
                checkpoints += 1;
            }
        }
        let ratio = wal_retained(&coord) as f64 / store_bytes(&coord) as f64;
        (ratio, checkpoints)
    };

    let (fixed_ratio, fixed_ckpts) = run(false);
    let (adaptive_ratio, adaptive_ckpts) = run(true);
    eprintln!(
        "FIXED 256MiB: {fixed_ckpts} checkpoints, final WAL/store = {fixed_ratio:.2}x\n\
         ADAPTIVE 4×store: {adaptive_ckpts} checkpoints, final WAL/store = {adaptive_ratio:.2}x"
    );

    // The fixed cadence never fires on this workload (WAL stays under 256 MiB), so the whole WAL is
    // retained — a high ratio. The adaptive cadence fires repeatedly and keeps the ratio bounded.
    assert_eq!(
        fixed_ckpts, 0,
        "the fixed 256 MiB cadence should not fire on a sub-256-MiB workload"
    );
    assert!(
        fixed_ratio > 5.0,
        "fixed cadence should leave a large WAL/store ratio, got {fixed_ratio:.2}x"
    );
    assert!(adaptive_ckpts > 0, "adaptive cadence must actually reclaim");
    // Bounded well under the target multiple + one interval's worth of tail (a checkpoint may have
    // just fired, or up to `RATIO×store` may have accrued since the last one).
    assert!(
        adaptive_ratio <= (WAL_STORE_RATIO_TARGET as f64) + 1.0,
        "adaptive cadence must bound the ratio to ~{WAL_STORE_RATIO_TARGET}x, got {adaptive_ratio:.2}x"
    );
    assert!(
        adaptive_ratio < 0.5 * fixed_ratio,
        "adaptive must materially beat fixed: {adaptive_ratio:.2}x vs {fixed_ratio:.2}x"
    );
}

// ============================================================================================
// #706 / #719 — the reclaim GRANULARITY, over a REAL FILE-BACKED WAL (real segments on disk).
// ============================================================================================

/// A unique temp directory holding a file-backed store + segmented WAL, removed on drop.
struct TempStore {
    path: PathBuf,
}

impl TempStore {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "graphus-walamp-{tag}-{nanos}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp store dir");
        Self { path }
    }
    fn device_path(&self) -> PathBuf {
        self.path.join("graph.db")
    }
    fn wal_dir(&self) -> PathBuf {
        self.path.join("wal")
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The REAL on-disk WAL footprint: the sum of the `anchor` + surviving `seg.<base>` file sizes. This is
/// the number that SHRINKS when a sealed segment below the reclaim floor is physically deleted — the
/// only direct evidence that WAL disk actually came back (`graphus_maintenance_versions_reclaimed_total`
/// counts MVCC versions in the STORE, not WAL segments, so it climbs while zero WAL bytes are freed).
fn on_disk_wal_bytes(wal_dir: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(rd) = std::fs::read_dir(wal_dir) {
        for e in rd.flatten() {
            if let Ok(m) = e.metadata() {
                if m.is_file() {
                    total += m.len();
                }
            }
        }
    }
    total
}

/// One file-backed churn run's measured facts — the file-backed analogue of
/// `graphus_iot_gen::wire_samples::WireStorage`, measured off a REAL segmented WAL on disk.
#[derive(Debug, Clone)]
struct WalAmpObservation {
    /// Committed write transactions driven over the run.
    commits: u64,
    /// The live store size (data image) in bytes — the denominator of the #706 proportionality.
    store_bytes: u64,
    /// The size at which the WAL seals its active segment and rolls — i.e. the granularity at which WAL
    /// disk can be reclaimed. Read straight off the sink (`FileLogSink::segment_target`).
    segment_target_bytes: u64,
    /// How much WAL was allowed to accumulate between the driver's reclaiming checkpoints — the reclaim
    /// cadence this run emulated (the store-proportional maintenance interval of #556).
    reclaim_cadence_bytes: u64,
    /// Cumulative WAL bytes ever written (the WAL's absolute lifetime length = `wal_durable_len`, which
    /// reclamation never resets). The durable-sync volume; independent of what survives on disk.
    wal_written_bytes: u64,
    /// The PEAK on-disk WAL observed across the run — the top of the sawtooth, the disk a deployment
    /// must actually provision.
    wal_peak_bytes: u64,
    /// The on-disk WAL at the end of the run — the trough it stopped at.
    wal_final_bytes: u64,
    /// How many checkpoints physically shrank the on-disk WAL (deleted a sealed segment below the floor).
    /// The direct, observable proof that WAL disk came back.
    wal_reclaim_events: u64,
}

/// The physical bounds [`WalAmpObservation::gate`] holds a file-backed run to. Every constant is an
/// INDEPENDENT copy of the production value (documented), on purpose: reverting the production formula
/// must not silently weaken the guard — the guard encodes what the physics REQUIRES, not whatever the
/// engine currently does.
#[derive(Debug, Clone, Copy)]
struct WalAmpGate {
    /// Floor on WAL bytes per commit (ARIES). Independent of store size, so it cannot be satisfied by
    /// coincidence: N commits imply >= N fsynced redo records, one `LogRecord` header alone ~53 B
    /// (`graphus-wal/src/record.rs`, `REC_FIXED_PREFIX = 45`, `MIN_RECORD_LEN = 57`).
    min_wal_bytes_per_commit: u64,
    /// The `rmp` #706 segment floor (an independent copy of `graphus_wal::WAL_SEGMENT_MIN_TARGET_BYTES`).
    /// The segment seal size must not exceed `max(store_bytes, this)`.
    segment_floor_bytes: u64,
    /// A run that wrote at least this many of its OWN segments' worth of WAL must have reclaimed.
    reclaim_expect_segments: u64,
    /// The on-disk WAL peak must stay within `reclaim_cadence + this×segment + store`.
    peak_slack_segments: u64,
}

impl Default for WalAmpGate {
    fn default() -> Self {
        Self {
            min_wal_bytes_per_commit: 64,
            segment_floor_bytes: WAL_SEGMENT_MIN_TARGET_BYTES,
            reclaim_expect_segments: 3,
            peak_slack_segments: 4,
        }
    }
}

impl WalAmpObservation {
    /// The pure gate: one human-readable failure per violated rule, empty when every invariant held.
    /// Pure so the unit tests can mutate an observation and prove the exact rule fires.
    fn gate(&self, g: &WalAmpGate) -> Vec<String> {
        let mut f = Vec::new();

        // 1. THE ARIES PER-COMMIT REDO FLOOR — catches a zeroed / under-counted WAL. Store-size
        //    independent: a commit is not acknowledged until its redo record is fsynced (Mohan et al.
        //    1992, §3), so N commits imply >= N redo records and one record header alone is ~53 B. A run
        //    reporting fewer bytes than this per commit has not found an impossibly efficient engine — it
        //    has stopped counting bytes the engine is still writing. (A ceiling cannot catch this: an
        //    under-counted WAL makes every amplification figure FALL, sailing under any ceiling.)
        if self.commits > 0 && self.wal_written_bytes / self.commits < g.min_wal_bytes_per_commit {
            f.push(format!(
                "WAL VOLUME IS PHYSICALLY IMPOSSIBLE: {} B across {} commits = {} B/commit (floor {} B). \
                 A commit is not durable — and is not acknowledged — until its redo record is fsynced, \
                 and one WAL record header alone is ~53 B. This is a MEASUREMENT defect (a zeroed or \
                 under-counted WAL), not an efficient engine.",
                self.wal_written_bytes,
                self.commits,
                self.wal_written_bytes / self.commits.max(1),
                g.min_wal_bytes_per_commit,
            ));
        }

        // 2. STORE-PROPORTIONAL SEGMENT GRANULARITY — the #706 invariant, DIRECTLY, and the rule that
        //    catches the reverted fix. WAL disk is freed only in whole SEGMENT units, so the segment seal
        //    size IS the reclaim granularity. It must not exceed the live data image (floored at 1 MiB),
        //    or a small database's WAL climbs to the segment size before a single byte is freed. A fixed
        //    64 MiB seal threshold on a small store is exactly the #706 defect the iot example measured
        //    (346x the graph on disk). This rule is store-size relative, so it fires on the defect at ANY
        //    scale and passes the fix at any scale.
        let seg_ceiling = self.store_bytes.max(g.segment_floor_bytes);
        if self.segment_target_bytes > seg_ceiling {
            f.push(format!(
                "WAL SEGMENT GRANULARITY IS NOT STORE-PROPORTIONAL (rmp #706): segments seal at {} B for \
                 a {} B data image (ceiling max(store, {} B) = {} B). WAL disk is freed only in whole \
                 segment units and the active segment is never reclaimed, so a segment larger than the \
                 store climbs to that size before ANY WAL disk is reclaimed. A fixed 64 MiB seal \
                 threshold on a small store is the #706 defect.",
                self.segment_target_bytes, self.store_bytes, g.segment_floor_bytes, seg_ceiling,
            ));
        }

        // 3. RECLAMATION ACTUALLY HAPPENED — a run that wrote enough WAL to seal several segments AT ITS
        //    OWN segment size must have returned WAL disk. Note the asymmetry that keeps this MONOTONE
        //    UNDER A FIX: the demand is keyed to the run's own segment size, and a run too short to seal
        //    that many segments is asked nothing — so when #706 lands and segments shrink, short runs
        //    start sealing AND reclaiming, and still pass. A gate that failed on an improvement would be
        //    worse than no gate at all.
        let reclaim_threshold = g
            .reclaim_expect_segments
            .saturating_mul(self.segment_target_bytes);
        if self.wal_written_bytes >= reclaim_threshold && self.wal_reclaim_events == 0 {
            f.push(format!(
                "NO WAL DISK WAS EVER RECLAIMED: the run wrote {} B — past {}x its {} B segment size, so \
                 it sealed several segments — yet the on-disk WAL never once shrank across {} commits. \
                 Sealed segments below the reclaim floor are not being deleted.",
                self.wal_written_bytes,
                g.reclaim_expect_segments,
                self.segment_target_bytes,
                self.commits,
            ));
        }

        // 4. THE ON-DISK WAL SAWTOOTHS WITHIN A BOUNDED BAND — with store-proportional segments and a
        //    store-proportional reclaim cadence, the peak is bounded by ~one cadence of growth plus a few
        //    segments of trough (plus the store the WAL is interleaved with on disk). Only checked when
        //    reclamation was expected (rule 3's premise), so a run too short to form a sawtooth is never
        //    held to one. Catches a reclaim that lags the write rate even with small segments.
        if self.wal_written_bytes >= reclaim_threshold {
            let peak_ceiling = self.reclaim_cadence_bytes
                + g.peak_slack_segments
                    .saturating_mul(self.segment_target_bytes)
                + self.store_bytes;
            if self.wal_peak_bytes > peak_ceiling {
                f.push(format!(
                    "THE ON-DISK WAL DID NOT SAWTOOTH WITHIN A BOUNDED BAND: peak {} B exceeds the bound \
                     {} B (reclaim cadence {} B + {} segments of {} B + store {} B). Reclamation is \
                     lagging the write rate.",
                    self.wal_peak_bytes,
                    peak_ceiling,
                    self.reclaim_cadence_bytes,
                    g.peak_slack_segments,
                    self.segment_target_bytes,
                    self.store_bytes,
                ));
            }
        }

        f
    }
}

/// Configuration for one file-backed churn run.
struct FileRun {
    /// The WAL segment seal size the sink is opened with.
    segment_target: u64,
    /// Whether the store auto-sizes the segment target store-proportionally (`rmp` #706, the fix). When
    /// `false` the sink keeps `segment_target` (reproducing the pre-#706 fixed behaviour).
    adaptive: bool,
    /// Stop once the cumulative WAL reaches this many bytes.
    target_wal: u64,
    /// Drive a reclaiming checkpoint every this-many WAL bytes of growth (the emulated maintenance
    /// cadence).
    checkpoint_cadence: u64,
}

/// Drives a real file-backed churn run and measures a [`WalAmpObservation`] off the on-disk segmented
/// WAL. The driver controls checkpoints explicitly (disabling the store's own redo-bounding cadence),
/// exactly as the engine maintenance loop does — this is the DST-style deterministic emulation of the
/// production reclaim path over the REAL device.
fn run_file_backed(cfg: &FileRun) -> WalAmpObservation {
    let tmp = TempStore::new("run");
    let device = FileBlockDevice::open(tmp.device_path()).expect("open device");
    let wal_dir = tmp.wal_dir();
    let sink =
        FileLogSink::open_with_segment_target(&wal_dir, cfg.segment_target).expect("open sink");
    let wal = WalManager::create(sink).expect("create wal");
    let store = RecordStore::create(device, wal, 4096, 1).expect("create store");
    let mut coord: FileCoord = TxnCoordinator::new(store);
    coord.with_store_mut(|s| {
        s.set_checkpoint_interval_bytes(0);
        s.set_wal_segment_sizing_adaptive(cfg.adaptive);
        // `create()` already applied the default-on adaptive sizing, clobbering the sink's initial
        // target down to the fresh store's (tiny) proportional value. For a NON-adaptive run that
        // reproduces a FIXED segment size, restore the explicit target so it truly stays put.
        if !cfg.adaptive {
            s.with_wal(|w| w.set_segment_target(cfg.segment_target));
        }
    });

    let inserter = NodeInserter::new();
    let mut id = 0i64;
    let mut commits = 0u64;
    let mut wal_at_last_ckpt = coord.wal_durable_len();
    let mut peak = on_disk_wal_bytes(&wal_dir);
    let mut reclaim_events = 0u64;
    // A hard safety cap so a pathologically tiny per-commit WAL can never spin: the cypher `CREATE`
    // writes several hundred bytes per commit, so this is never reached for any realistic `target_wal`.
    const MAX_COMMITS: u64 = 200_000;

    while coord.wal_durable_len() < cfg.target_wal && commits < MAX_COMMITS {
        inserter.insert_committed(&mut coord, id);
        id += 1;
        commits += 1;
        let durable = coord.wal_durable_len();
        if durable.saturating_sub(wal_at_last_ckpt) >= cfg.checkpoint_cadence {
            let before = on_disk_wal_bytes(&wal_dir); // top of the sawtooth (pre-reclaim)
            peak = peak.max(before);
            coord.checkpoint().expect("maintenance checkpoint");
            wal_at_last_ckpt = coord.wal_durable_len();
            let after = on_disk_wal_bytes(&wal_dir); // trough (post-reclaim)
            if after < before {
                reclaim_events += 1;
            }
        }
    }
    // A final checkpoint (a real server checkpoints on the way down / at shutdown too).
    let before = on_disk_wal_bytes(&wal_dir);
    peak = peak.max(before);
    coord.checkpoint().expect("final checkpoint");
    let final_on_disk = on_disk_wal_bytes(&wal_dir);
    if final_on_disk < before {
        reclaim_events += 1;
    }

    let segment_target_bytes = coord.with_store_mut(|s| s.with_wal(|w| w.sink().segment_target()));
    WalAmpObservation {
        commits,
        store_bytes: coord.store_byte_len(),
        segment_target_bytes,
        reclaim_cadence_bytes: cfg.checkpoint_cadence,
        wal_written_bytes: coord.wal_durable_len(),
        wal_peak_bytes: peak,
        wal_final_bytes: final_on_disk,
        wal_reclaim_events: reclaim_events,
    }
}

/// A fabricated observation shaped like a healthy file-backed FIX run: small (store-proportional)
/// segments, a WAL that sawtooths within a bounded band and comes back on every checkpoint. Every
/// mutation test below starts here and breaks exactly ONE thing, so a failing gate names the rule it
/// caught rather than "something is wrong somewhere".
fn healthy() -> WalAmpObservation {
    WalAmpObservation {
        commits: 2_000,
        store_bytes: 480 * 1024, // < 1 MiB, so the segment floor governs the ceiling
        segment_target_bytes: 64 * 1024, // small, store-proportional (well under max(store, 1 MiB))
        reclaim_cadence_bytes: 256 * 1024,
        wal_written_bytes: 1_048_576, // 1 MiB cumulative (~524 B / commit)
        wal_peak_bytes: 320 * 1024,   // ~one cadence of growth on a ~64 KiB trough
        wal_final_bytes: 96 * 1024,
        wal_reclaim_events: 4,
    }
}

// -------------------------------------------------------------- REAL file-backed runs --------------

#[cfg_attr(
    miri,
    ignore = "real filesystem I/O + fdatasync are outside miri's isolation/UB scope"
)]
#[test]
fn file_backed_small_segments_reclaim_and_pass_the_gate() {
    // Small (64 KiB) segments, driven WITHOUT the store's auto-sizing so the target is exactly what we
    // set — this isolates the reclaim-GRANULARITY variable. A real segmented WAL on a real disk.
    let obs = run_file_backed(&FileRun {
        segment_target: 64 * 1024,
        adaptive: false,
        target_wal: 640 * 1024, // ~10 segments — enough to seal and reclaim several times
        checkpoint_cadence: 192 * 1024,
    });
    eprintln!("FIX (64 KiB segments): {obs:#?}");

    // It genuinely wrote a WAL, sealed segments and got disk back.
    assert!(
        obs.wal_written_bytes >= 640 * 1024,
        "must have written the target WAL"
    );
    assert!(
        obs.wal_reclaim_events > 0,
        "small segments below the floor MUST be reclaimed; got 0 events"
    );
    assert!(
        obs.wal_peak_bytes < obs.wal_written_bytes,
        "the on-disk WAL must be far below the cumulative volume — it sawtooths, not climbs"
    );

    let failures = obs.gate(&WalAmpGate::default());
    assert!(
        failures.is_empty(),
        "a healthy small-segment file-backed run must pass its own gate, got: {failures:#?}"
    );
}

#[cfg_attr(
    miri,
    ignore = "real filesystem I/O + fdatasync are outside miri's isolation/UB scope"
)]
#[test]
fn file_backed_reverted_granularity_never_reclaims_and_fails_the_gate() {
    // THE REVERTED #706 DEFECT ON THE REAL DEVICE. Adaptive sizing OFF and a segment far larger than the
    // store (8 MiB) — the pre-#706 shape where the seal size is fixed regardless of store size. The
    // workload writes well under one segment, so NOTHING seals and NO WAL disk ever comes back, exactly
    // as a 229 KB store's WAL climbed to 64 MiB before the fix. The guard MUST fail it.
    let obs = run_file_backed(&FileRun {
        segment_target: 8 * 1024 * 1024,
        adaptive: false,
        target_wal: 448 * 1024, // well under one 8 MiB segment: nothing can seal
        checkpoint_cadence: 192 * 1024,
    });
    eprintln!("REVERTED (8 MiB segment on a small store): {obs:#?}");

    // The defect's fingerprint on the real device: a big fixed segment, nothing sealed, nothing freed.
    assert!(
        obs.store_bytes < obs.segment_target_bytes,
        "the store must be smaller than the (fixed) segment — that is the #706 shape"
    );
    assert_eq!(
        obs.wal_reclaim_events, 0,
        "an over-large segment cannot seal, so no WAL disk can come back"
    );

    let failures = obs.gate(&WalAmpGate::default());
    assert!(
        failures
            .iter()
            .any(|m| m.contains("SEGMENT GRANULARITY IS NOT STORE-PROPORTIONAL")),
        "a fixed 8 MiB segment on a sub-MiB store MUST fail the #706 granularity rule; got: {failures:#?}"
    );
}

#[cfg_attr(
    miri,
    ignore = "real filesystem I/O + fdatasync are outside miri's isolation/UB scope"
)]
#[test]
fn the_production_adaptive_path_sizes_the_segment_to_the_store() {
    // THE ACTUAL #706 FIX, end to end through the real store: with adaptive sizing ON (the default), a
    // checkpoint must set the WAL segment seal size to `segment_target_for_store(store_bytes)`. Opened
    // with the production 64 MiB default so the store has to actively shrink it.
    let tmp = TempStore::new("adaptive");
    let device = FileBlockDevice::open(tmp.device_path()).expect("open device");
    let wal_dir = tmp.wal_dir();
    let sink = FileLogSink::open(&wal_dir).expect("open sink"); // 64 MiB default
    let wal = WalManager::create(sink).expect("create wal");
    let store = RecordStore::create(device, wal, 4096, 1).expect("create store");
    let mut coord: FileCoord = TxnCoordinator::new(store);
    coord.with_store_mut(|s| s.set_checkpoint_interval_bytes(0));

    // Even on a FRESH store, create() already sized the segment away from the sink's 64 MiB default down
    // to the (tiny) data image — the adaptive sizing runs at open/create, not only at checkpoint.
    let seg_after_create = coord.with_store_mut(|s| s.with_wal(|w| w.sink().segment_target()));
    assert!(
        seg_after_create < graphus_wal::DEFAULT_SEGMENT_TARGET_BYTES,
        "create() must already size the segment below the 64 MiB default; got {seg_after_create}"
    );

    let inserter = NodeInserter::new();
    for i in 0..120 {
        inserter.insert_committed(&mut coord, i);
    }
    coord.checkpoint().expect("checkpoint");

    let store_bytes = coord.store_byte_len();
    let expected = segment_target_for_store(store_bytes);
    let effective = coord.with_store_mut(|s| s.with_wal(|w| w.sink().segment_target()));
    eprintln!(
        "adaptive path: store={store_bytes} B => expected segment {expected} B, effective {effective} B"
    );
    assert_eq!(
        effective, expected,
        "the store must size the WAL segment to segment_target_for_store(store) on checkpoint (#706)"
    );
    // For this small store that is the 1 MiB floor, NOT the 64 MiB default it was opened with.
    assert_eq!(
        effective, WAL_SEGMENT_MIN_TARGET_BYTES,
        "a sub-MiB store must seal 1 MiB segments, not the sink's 64 MiB default"
    );
    assert!(
        effective < graphus_wal::DEFAULT_SEGMENT_TARGET_BYTES,
        "the adaptive target must be strictly below the fixed 64 MiB default"
    );
}

// -------------------------------------------------------- PURE-GATE mutation proofs (mirror #713) ----

/// The fabricated healthy run passes its own gate — without this, every mutation test below could be
/// satisfied by a gate that simply always fails.
#[test]
fn the_healthy_observation_passes_the_gate() {
    let failures = healthy().gate(&WalAmpGate::default());
    assert!(
        failures.is_empty(),
        "the healthy fix-shaped observation must pass its own gate, got: {failures:#?}"
    );
}

/// **THE #706 DEFECT THE IOT EXAMPLE MEASURED, caught by this guard.** A fixed 64 MiB segment on a
/// 229 KB store — the exact shape that made the iot database occupy 346x its graph on disk — is caught
/// DIRECTLY by the granularity rule, even though that run reclaimed twice (at 64 MiB). This is the proof
/// that #719's guard would have caught #706, which the old `MemLogSink` guard could not.
#[test]
fn the_iot_scale_706_defect_is_caught_by_the_gate() {
    let mut o = healthy();
    o.store_bytes = 229_376;
    o.segment_target_bytes = 64 * 1024 * 1024; // the pre-#706 fixed 64 MiB seal threshold
    o.wal_written_bytes = 150_000_000;
    o.wal_peak_bytes = 70_000_000;
    o.wal_final_bytes = 16_000_000;
    o.wal_reclaim_events = 2; // it DID free ~63 MiB twice — but only after climbing to 64 MiB each time

    let failures = o.gate(&WalAmpGate::default());
    assert!(
        failures
            .iter()
            .any(|m| m.contains("SEGMENT GRANULARITY IS NOT STORE-PROPORTIONAL")),
        "the 64 MiB-segment-on-a-229 KB-store #706 defect MUST be caught even though it reclaimed twice; \
         got: {failures:#?}"
    );
}

/// A zeroed WAL alongside committed writes MUST fail — a commit is not durable until its redo record is
/// fsynced, so a file-backed run that committed thousands of writes and wrote no WAL is a broken
/// instrument, not a measurement. The `MemLogSink` guard could never observe this on the real device.
#[test]
fn a_zeroed_wal_with_committed_writes_fails_the_gate() {
    let mut o = healthy();
    o.wal_written_bytes = 0;
    o.wal_peak_bytes = 0;
    o.wal_final_bytes = 0;
    o.wal_reclaim_events = 0;

    let failures = o.gate(&WalAmpGate::default());
    assert!(
        failures
            .iter()
            .any(|m| m.contains("WAL VOLUME IS PHYSICALLY IMPOSSIBLE")),
        "a zeroed WAL over {} commits must fail the per-commit redo floor; got: {failures:#?}",
        o.commits,
    );
}

/// The under-count a "is it exactly zero?" check cannot see: the WAL is measured, but only partially
/// (say one segment classified out of many). It is non-zero, yet still far below the physical floor.
/// Only a per-commit FLOOR catches it — a ceiling cannot, because under-counting makes amplification
/// FALL and read like a triumph.
#[test]
fn an_undercounted_wal_fails_the_gate_even_though_it_is_not_zero() {
    let mut o = healthy();
    o.wal_written_bytes = o.commits * 10; // 10 B/commit — non-zero, but physically impossible
    o.wal_peak_bytes = 1_024;
    o.wal_final_bytes = 512;

    let failures = o.gate(&WalAmpGate::default());
    assert!(
        o.wal_written_bytes > 0,
        "the WAL is NOT zero here — the point is the zero-check cannot help"
    );
    assert!(
        failures
            .iter()
            .any(|m| m.contains("WAL VOLUME IS PHYSICALLY IMPOSSIBLE")),
        "10 B/commit is below the ~53 B one-record floor and must be caught; got: {failures:#?}"
    );
}

/// A run that DID seal segments but never got any WAL disk back is a reclamation failure, and is caught.
#[test]
fn sealing_segments_without_reclaiming_any_wal_fails_the_gate() {
    let mut o = healthy();
    o.wal_reclaim_events = 0; // wrote 1 MiB at 64 KiB segments = 16 segments, but never freed one

    let failures = o.gate(&WalAmpGate::default());
    assert!(
        failures
            .iter()
            .any(|m| m.contains("NO WAL DISK WAS EVER RECLAIMED")),
        "sealing many segments but freeing none must fail; got: {failures:#?}"
    );
}

/// A ballooning on-disk WAL peak (reclaim lagging the write rate) is caught even when segments are
/// small and some reclamation happened.
#[test]
fn a_ballooning_on_disk_peak_fails_the_gate() {
    let mut o = healthy();
    o.wal_peak_bytes = 32 * 1024 * 1024; // 32 MiB peak for a 480 KB store with 64 KiB segments

    let failures = o.gate(&WalAmpGate::default());
    assert!(
        failures
            .iter()
            .any(|m| m.contains("DID NOT SAWTOOTH WITHIN A BOUNDED BAND")),
        "a peak far past cadence + a few segments + store must fail; got: {failures:#?}"
    );
}

/// **A gate that fires on an IMPROVEMENT is worse than no gate.** An even better run — smaller segments,
/// a lower peak, more frequent reclamation — must PASS. This is the monotone-under-a-fix property that
/// let the #706 fix land in the first place.
#[test]
fn an_improvement_does_not_fail_the_gate() {
    let mut o = healthy();
    o.segment_target_bytes = 32 * 1024; // even smaller segments
    o.wal_peak_bytes = 160 * 1024; // a tighter band
    o.wal_final_bytes = 48 * 1024;
    o.wal_reclaim_events = 12; // freed WAL disk more often

    let failures = o.gate(&WalAmpGate::default());
    assert!(
        failures.is_empty(),
        "an improvement (smaller segments, lower peak, more reclamation) must NOT fail; got: {failures:#?}"
    );
}

/// The reclaim demand is MONOTONE UNDER A FIX: a run too short to seal `reclaim_expect_segments`
/// segments is asked nothing about reclamation, so `0` reclaim events is fine for it. This is what stops
/// the gate demanding the impossible of a short run — and what lets short runs start passing once #706
/// shrinks segments so they DO seal and reclaim.
#[test]
fn a_run_too_short_to_seal_enough_segments_is_not_asked_to_reclaim() {
    let mut o = healthy();
    // Wrote under 2 segments — below the 3-segment reclaim expectation — and freed nothing.
    o.wal_written_bytes = 2 * o.segment_target_bytes - 1;
    o.wal_peak_bytes = o.segment_target_bytes;
    o.wal_final_bytes = o.segment_target_bytes;
    o.wal_reclaim_events = 0;
    o.commits = 100; // keep the per-commit floor satisfied (2*64KiB/100 = ~1.3 KB/commit)

    let failures = o.gate(&WalAmpGate::default());
    assert!(
        !failures
            .iter()
            .any(|m| m.contains("NO WAL DISK WAS EVER RECLAIMED")),
        "a run too short to seal enough segments must not be failed for not reclaiming; got: {failures:#?}"
    );
    assert!(
        failures.is_empty(),
        "the short run is otherwise healthy and must pass; got: {failures:#?}"
    );
}
