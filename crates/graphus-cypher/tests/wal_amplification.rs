//! Regression tests for the WAL on-disk write-amplification / reclamation bounds (`rmp` #556, #706,
//! #719) and for **what a commit's WAL is actually made of** (`rmp` #745).
//!
//! Three findings, two devices, three parts of this file:
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
//!
//! # `rmp` #745 — the per-commit WAL PROFILE (the residual, decoded record by record)
//!
//! Where #556/#706 bound what the WAL *retains*, this part measures what one commit *writes*, because
//! `examples/iot-timeseries` shipped an UNMEASURED mechanism for its write-amplification residual
//! ("a commit's redo is dominated by the page images of every page it dirtied") that the WAL format
//! flatly contradicts. Decoding the durable WAL of the example's own ingest shape settles it: the
//! per-commit record profile by type, the distinct pages a commit touches, the redo/undo split, the
//! index-maintenance term (by controlled experiment) and the batching claim are all MEASURED here, and
//! nothing the example says about its residual may exceed what these tests print.

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
use graphus_storage::{
    ConstraintKind, ConstraintTypeDescriptor, RecordStore, StoreKind, StorePages,
};
use graphus_wal::record::MIN_RECORD_LEN;
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
    let store = RecordStore::create(device, wal, 256, 1).expect("create store");
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

// ============================================================================================
// `rmp` #745 — WHAT A COMMIT'S WAL IS ACTUALLY MADE OF (decoded, record by record).
//
// `examples/iot-timeseries` measures that one commit per 32-byte reading costs ~830x write
// amplification while batching ~25 readings per commit costs ~224x, and it must EXPLAIN the residual.
// The explanation it shipped — "a commit's redo is dominated by the PAGE IMAGES of every page it
// dirtied (~22 kB = three 8 KiB pages), so cutting it would need a WAL-FORMAT change" — was never
// measured, and it is FALSE: the engine logs byte-range PATCHES (`paging::encode_patch`: a 2-byte
// offset plus only the changed bytes), and `RecordType::FullPageImage` is emitted nowhere in it.
//
// The tests below replace that story with measurements, taken by decoding the durable WAL of the
// example's OWN ingest statements (`iot_wire::INGEST_CYPHER_SINGLE` / `INGEST_CYPHER_BATCH`), its own
// reading stream (a real `ZONED DATETIME` `ts`) and its own declared schema. What they measure, and
// what the example is therefore permitted to say (steady state, per single-reading commit):
//
//   * 20.07 records — 19.07 byte-range `Update` page deltas plus the one `Commit` record. No `Begin`
//     record per commit (the WAL's begin is lazy) and NOT ONE `FullPageImage`.
//   * 3 839 B, over 5.68 distinct pages (3.35 records per page): 1 402 B redo + 1 293 B undo + a
//     fixed 57 B frame per record. The mean page-changing record is 198 B against an 8 192 B page —
//     a commit's ENTIRE WAL is less than ONE page image, let alone one image per page it dirties.
//   * where those bytes go, by the store owning the dirtied page: node 904 B, relationship 406 B,
//     property 530 B, string heap 456 B — and the CATALOG 1 479 B, in ONE record, every commit.
//   * the schema's cost, by CONTROLLED EXPERIMENT (declared schema ON vs no secondary indexes): index
//     maintenance appends ZERO records and ZERO bytes (Graphus's indexes are DERIVED and ephemeral);
//     the schema's whole effect is +526 B/commit of BIGGER CATALOG IMAGE.
//   * what batching amortises: at 25 readings/commit the data-store bytes per reading are UNCHANGED
//     to within 0.1 % (904/406/530/456 B), and the 1 481 B/reading it saves is accounted for, to the
//     byte, by exactly two per-commit terms — the catalog image (1 479 B -> 60 B per reading) and the
//     `Commit` record (65 B -> 3 B). That is the whole 1.63x, and it is why a 25x drop in commit count
//     buys only 1.63x in durable bytes.
// ============================================================================================

/// The iot example's **per-reading** ingest statement, verbatim (`INGEST_CYPHER_SINGLE`,
/// `crates/graphus-iot-gen/src/bin/iot_wire.rs`): one commit per 32-byte reading — the CONTROL shape
/// whose durability bill the example's headline number describes.
const IOT_INGEST_SINGLE: &str = "MATCH (s:Sensor {id: $sid}) \
     CREATE (s)-[:EMITTED]->(:Reading {sensor: $sid, seq: $seq, ts: $ts, value: $value})";

/// The iot example's **batched** ingest statement, verbatim (`INGEST_CYPHER_BATCH`): ONE commit for
/// `$rows` readings — what a real gateway flushes.
const IOT_INGEST_BATCH: &str = "UNWIND $rows AS row \
     MATCH (s:Sensor {id: row.sensor}) \
     CREATE (s)-[:EMITTED]->(:Reading {sensor: row.sensor, seq: row.seq, ts: row.ts, value: row.value})";

/// The sensor fleet both ingest shapes write to. Reading `seq` is emitted by sensor `seq % SENSORS`,
/// so the two shapes ingest the IDENTICAL reading stream and the only variable between them is the
/// transaction grouping (the example shards its gateway clients by sensor for the same reason).
const SENSORS: i64 = 4;

/// The example's sensor ids (`Generator::sensor_id`).
fn sensor_id(i: i64) -> String {
    format!("s-{i}")
}

/// Reading `seq`'s instant as the example stores it: a real `ZONED DATETIME` in UTC — offset 0, empty
/// zone id — derived from epoch milliseconds exactly as `graphus_iot_gen::ReadingRow::ts_datetime`
/// does. Using the example's real temporal (not an epoch-ms integer) keeps the measured property
/// payload the example's own, and is what lets the `Reading.ts IS :: ZONED DATETIME` property-type
/// constraint be declared faithfully below.
fn reading_ts(seq: i64) -> Value {
    let ts_millis = 1_704_067_200_000_i64 + seq * 1_000;
    Value::zoned_date_time(graphus_core::ZonedDateTime {
        local: graphus_core::LocalDateTime {
            epoch_seconds: ts_millis / 1_000,
            nanos: u32::try_from((ts_millis % 1_000) * 1_000_000).expect("sub-second nanos < 1e9"),
        },
        offset_seconds: 0,
        zone_id: String::new(),
    })
}

/// The `$sid` / `$seq` / `$ts` / `$value` parameters of [`IOT_INGEST_SINGLE`] for reading `seq`
/// (`iot_wire::single_row_params`).
fn single_row_params(seq: i64) -> Parameters {
    Parameters::new()
        .with("sid", Value::String(sensor_id(seq % SENSORS)))
        .with("seq", Value::Integer(seq))
        .with("ts", reading_ts(seq))
        .with("value", Value::Integer(seq % 1000))
}

/// The `$rows` parameter of [`IOT_INGEST_BATCH`] for readings `seqs` (`iot_wire::batch_rows_param`):
/// a list of `{sensor, seq, ts, value}` maps carrying the SAME values [`single_row_params`] binds.
fn batch_rows_params(seqs: &[i64]) -> Parameters {
    let rows = seqs
        .iter()
        .map(|&seq| {
            Value::Map(vec![
                ("sensor".to_owned(), Value::String(sensor_id(seq % SENSORS))),
                ("seq".to_owned(), Value::Integer(seq)),
                ("ts".to_owned(), reading_ts(seq)),
                ("value".to_owned(), Value::Integer(seq % 1000)),
            ])
        })
        .collect();
    Parameters::new().with("rows", Value::List(rows))
}

/// One statement compiled once against a given [`IndexCatalog`], run per commit with fresh parameters
/// (so a long run is not dominated by re-planning, and so the schema-ON run really does plan against
/// the declared indexes — the planner sees the catalog, exactly as the server's engine hands it one).
struct Statement {
    plan: PhysicalPlan,
}

impl Statement {
    fn compile(src: &str, catalog: &IndexCatalog) -> Self {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        Self {
            plan: plan_physical(&lower(&validated), catalog),
        }
    }

    /// Binds `params`, runs the statement in its own serializable transaction, and commits it.
    /// Generic over the device / sink, so the SAME workload drives the in-memory coordinator and the
    /// REAL file-backed one (`rmp` #745 follow-up: the example publishes file-backed numbers, so the
    /// decomposition has to be measurable on the device the server actually runs).
    fn run_committed<D, S>(&self, coord: &mut TxnCoordinator<D, S>, params: &Parameters)
    where
        D: BlockDevice + Send + Sync + 'static,
        S: LogSink + Send + Sync + 'static,
    {
        let bound = bind_parameters(&self.plan, params).expect("bind");
        let t = coord.begin_serializable();
        {
            let mut graph = coord.statement(t).expect("statement");
            let mut cursor = execute(&self.plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect");
            assert!(!graph.has_error(), "ingest error: {:?}", graph.take_error());
        }
        coord.commit(t).expect("commit");
    }
}

/// Creates the [`SENSORS`]-strong fleet, each sensor exactly as the example's bootstrap does
/// (`Generator::sensor_cypher`: an id, a kind, a site and a Cartesian `location` point).
fn create_sensor_fleet<D, S>(coord: &mut TxnCoordinator<D, S>, catalog: &IndexCatalog)
where
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
{
    for i in 0..SENSORS {
        let kind = match i % 3 {
            0 => "temperature",
            1 => "humidity",
            _ => "pressure",
        };
        let src = format!(
            "CREATE (:Sensor {{id: '{}', kind: '{kind}', site: {}, \
             location: point({{x: {}.0, y: {}.0}})}})",
            sensor_id(i),
            i % 4,
            (i % 2) * 1000,
            (i / 2) * 1000,
        );
        Statement::compile(&src, catalog).run_committed(coord, &Parameters::new());
    }
}

/// Applies the iot example's **declared schema** — every index and constraint of
/// `Generator::schema_ddl` — through the coordinator's typed DDL seam. These are the exact calls
/// `graphus_iot_gen::churn::apply_schema` makes (and the ones the server's admin-DDL surface
/// dispatches to after parsing the equivalent `CREATE INDEX` / `CREATE CONSTRAINT` text).
///
/// This is the ONE variable of the controlled experiment below: the same ingest runs with this schema
/// and with no secondary indexes at all, and the difference IS the index-maintenance term.
fn apply_iot_schema<D, S>(coord: &mut TxnCoordinator<D, S>)
where
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
{
    coord
        .create_point_index("sensor_location_point", "Sensor", "location", true)
        .expect("POINT index on Sensor.location");
    coord
        .begin_online_node_composite_index_named(
            Some("reading_sensor_seq"),
            "Reading",
            &["sensor".to_owned(), "seq".to_owned()],
            true,
        )
        .expect("composite RANGE index on Reading(sensor, seq)");
    coord
        .begin_online_node_property_index_named(Some("reading_seq"), "Reading", "seq", true)
        .expect("RANGE index on Reading.seq");
    coord
        .begin_online_node_property_index_named(Some("reading_ts"), "Reading", "ts", true)
        .expect("RANGE index on the temporal Reading.ts");
    coord
        .create_constraint_general(
            "sensor_id_key",
            "Sensor",
            &["id"],
            ConstraintKind::NodeKey,
            None,
        )
        .expect("NODE KEY on Sensor.id");
    coord
        .create_constraint_general(
            "reading_value_exists",
            "Reading",
            &["value"],
            ConstraintKind::Existence,
            None,
        )
        .expect("existence constraint on Reading.value");
    coord
        .create_constraint_general(
            "reading_ts_datetime",
            "Reading",
            &["ts"],
            ConstraintKind::PropertyType,
            Some(ConstraintTypeDescriptor::ZonedDateTime),
        )
        .expect("property-type constraint on Reading.ts");
    // The online builds are non-blocking: drive them to `Online` (the store is still empty, so this
    // completes instantly) exactly as the engine loop pumps them — a `Populating` index is withheld
    // from the planner, so an un-pumped queue would silently leave the schema-ON run un-indexed.
    while coord.advance_index_builds(usize::MAX) {}
}

// ------------------------------------------------------------------ the WAL decode ----------------

/// Per-record-type totals over a decoded WAL window.
#[derive(Debug, Default, Clone, Copy)]
struct TypeStat {
    count: usize,
    /// Encoded bytes on the wire (`LogRecord::encoded_len`).
    bytes: usize,
    /// Bytes of the `redo` image only.
    redo: usize,
    /// Bytes of the `undo` image only.
    undo: usize,
}

/// One transaction's decoded WAL records.
#[derive(Debug, Default, Clone)]
struct TxnProfile {
    records: usize,
    bytes: usize,
    redo: usize,
    undo: usize,
    /// Records that change a page ([`RecordType::is_page_change`]).
    page_records: usize,
    /// Device page id -> (page-changing records this transaction wrote to it, their encoded bytes).
    pages: BTreeMap<u64, (usize, usize)>,
}

/// A decoded slice of the durable WAL: everything appended after a marked offset.
#[derive(Debug, Default, Clone)]
struct WalWindow {
    bytes: usize,
    by_type: BTreeMap<u8, TypeStat>,
    /// Keyed by `txn_id` — the coordinator issues a fresh id per transaction, so one entry per commit.
    txns: BTreeMap<u64, TxnProfile>,
}

/// The durable WAL bytes from byte offset `from` (an LSN, i.e. a record boundary), read back through
/// the sink's own [`LogSink::read_durable`]. Generic over the sink, so the identical decode runs over
/// the in-memory log and over the REAL segmented files on disk.
fn wal_durable_from<D, S>(coord: &TxnCoordinator<D, S>, from: u64) -> Vec<u8>
where
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
{
    coord.with_store_mut(|s| {
        s.with_wal(|w| {
            let mut buf = Vec::new();
            w.sink()
                .read_durable(from, &mut buf)
                .expect("read the durable WAL back");
            buf
        })
    })
}

/// Decodes every record appended to `img` at or after byte offset `from` (a record boundary: it is a
/// WAL image length captured earlier, and the log is an append-only sequence of whole records).
fn decode_window(img: &[u8], from: usize) -> WalWindow {
    let mut w = WalWindow::default();
    let mut cursor = from;
    while cursor < img.len() {
        let Ok((rec, n)) = LogRecord::decode(&img[cursor..]) else {
            break;
        };
        cursor += n;
        w.bytes += n;

        let e = w.by_type.entry(rec.rec_type as u8).or_default();
        e.count += 1;
        e.bytes += n;
        e.redo += rec.redo.len();
        e.undo += rec.undo.len();

        let t = w.txns.entry(rec.txn_id.0).or_default();
        t.records += 1;
        t.bytes += n;
        t.redo += rec.redo.len();
        t.undo += rec.undo.len();
        if rec.rec_type.is_page_change() {
            t.page_records += 1;
            let p = t.pages.entry(rec.page_id.0).or_default();
            p.0 += 1;
            p.1 += n;
        }
    }
    // Structural self-check of the decode against the encoder (`graphus-wal/src/record.rs`): every
    // record is `REC_FIXED_PREFIX(45) + 4 + redo + 4 + undo + 4` bytes, so the images plus a fixed
    // 57-byte frame per record must account for every byte counted. If this ever fails, the numbers
    // below are being read out of a format that is not the one on disk.
    let images: usize = w.by_type.values().map(|s| s.redo + s.undo).sum();
    let records: usize = w.by_type.values().map(|s| s.count).sum();
    assert_eq!(
        w.bytes,
        images + records * MIN_RECORD_LEN,
        "decoded WAL bytes must equal redo+undo images plus a {MIN_RECORD_LEN} B frame per record"
    );
    w
}

/// Which store a device page belongs to. Established from the store itself (its per-kind page maps and
/// its durable page list), never guessed: `MetaSnapshot::device_page(kind, rel_page)` is the very map
/// the read path resolves a record id through, and `RecordStore::mapped_pages` is the durable image
/// (the meta page + catalog chain + every store's data pages).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PageOwner {
    Node,
    Rel,
    Prop,
    Strings,
    /// `undo.store` — one MVCC version-delta per record (`rmp` #966, `05 §12`).
    Undo,
    /// `commit.store` — one commit-info slot per writing transaction (`rmp` #966, `05 §12`).
    Commit,
    /// The meta page + its catalog continuation chain.
    Catalog,
}

impl PageOwner {
    fn name(self) -> &'static str {
        match self {
            Self::Node => "node store",
            Self::Rel => "rel store",
            Self::Prop => "prop store",
            Self::Strings => "strings heap",
            Self::Undo => "undo deltas",
            Self::Commit => "commit slots",
            Self::Catalog => "catalog",
        }
    }
}

/// The device-page -> owning-store map, read off the live store.
fn page_owners<D, S>(coord: &TxnCoordinator<D, S>) -> BTreeMap<u64, PageOwner>
where
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
{
    coord.with_store_mut(|s| {
        let mut map: BTreeMap<u64, PageOwner> = BTreeMap::new();
        let view = s.read_view();
        let meta = view.meta();
        // Attributing EVERY store explicitly is load-bearing: the fallback below labels anything no
        // record store owns as "catalog", so a store missing from this list has its records silently
        // charged to the catalog term. That is precisely what happened when `rmp` #966 added the undo
        // area and this list still named four stores — every version-delta and commit-slot record was
        // reported as catalog, which both overstated the catalog and hid the undo area's own cost
        // inside it. The length assertion makes the omission impossible to repeat.
        let attribution = [
            (StoreKind::Node, PageOwner::Node),
            (StoreKind::Rel, PageOwner::Rel),
            (StoreKind::Prop, PageOwner::Prop),
            (StoreKind::Strings, PageOwner::Strings),
            (StoreKind::Undo, PageOwner::Undo),
            (StoreKind::Commit, PageOwner::Commit),
        ];
        assert_eq!(
            attribution.len(),
            graphus_storage::STORE_COUNT,
            "every fixed-record store must be attributed to a `PageOwner`; an unattributed store's \
             pages fall through to the catalog fallback and are reported as catalog bytes"
        );
        for (kind, owner) in attribution {
            for rel_page in 0..meta.mapped_page_count(kind) {
                let dev = meta.device_page(kind, rel_page).expect("mapped store page");
                map.insert(dev.0, owner);
            }
        }
        // Whatever the durable image maps and no record store owns is the catalog: the meta page and
        // its continuation chain (`RecordStore::mapped_pages`).
        for p in s.mapped_pages() {
            map.entry(p.0).or_insert(PageOwner::Catalog);
        }
        map
    })
}

/// What one commit costs, on average, in the pages of ONE store (or of the catalog).
#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct OwnerStat {
    /// Page-changing WAL records per commit landing on this owner's pages.
    records: f64,
    /// Distinct pages of this owner touched per commit.
    pages: f64,
    /// Encoded WAL bytes per commit landing on this owner's pages.
    bytes: f64,
}

/// The measured per-commit profile of one ingest window, printed in full and returned for assertions.
/// `readings` is how many readings the window's commits carried in total (the batch factor is
/// `readings / commits`).
#[derive(Debug, Clone)]
struct CommitProfile {
    commits: usize,
    readings: usize,
    bytes_per_commit: f64,
    bytes_per_reading: f64,
    records_per_commit: f64,
    page_records_per_commit: f64,
    distinct_pages_per_commit: f64,
    records_per_touched_page: f64,
    redo_per_commit: f64,
    undo_per_commit: f64,
    mean_page_record_bytes: f64,
    full_page_images: usize,
    /// Bytes of `Commit` records per commit — the transaction-control term, the OTHER thing (besides
    /// the catalog image) that a batch pays once instead of once per reading.
    commit_record_bytes_per_commit: f64,
    /// The per-commit cost broken down by the store that owns the dirtied page — the decomposition
    /// that says WHERE a commit's WAL goes, and the one that localises the schema's cost below.
    by_owner: BTreeMap<PageOwner, OwnerStat>,
}

/// Reduces a decoded window to its per-commit profile and prints every measured number: the record
/// breakdown by type, the redo/undo split, the distinct pages a commit touches (attributed to the
/// store that owns them) and the records it writes per page.
fn report(
    label: &str,
    w: &WalWindow,
    readings: usize,
    owners: &BTreeMap<u64, PageOwner>,
) -> CommitProfile {
    let commits = w.txns.len();
    assert!(commits > 0, "{label}: the window contains no transaction");
    let c = commits as f64;

    let records: usize = w.by_type.values().map(|s| s.count).sum();
    let page_records: usize = w
        .by_type
        .iter()
        .filter(|(k, _)| RecordType::from_u8(**k).is_some_and(RecordType::is_page_change))
        .map(|(_, s)| s.count)
        .sum();
    let page_bytes: usize = w
        .by_type
        .iter()
        .filter(|(k, _)| RecordType::from_u8(**k).is_some_and(RecordType::is_page_change))
        .map(|(_, s)| s.bytes)
        .sum();
    let redo: usize = w.by_type.values().map(|s| s.redo).sum();
    let undo: usize = w.by_type.values().map(|s| s.undo).sum();
    let distinct_pages: usize = w.txns.values().map(|t| t.pages.len()).sum();

    eprintln!(
        "\n=== {label}: {commits} commits carrying {readings} readings \
         ({:.1} readings/commit) ===",
        readings as f64 / c
    );
    eprintln!(
        "  {} B of WAL total => {:.0} B per commit, {:.0} B per reading",
        w.bytes,
        w.bytes as f64 / c,
        w.bytes as f64 / readings.max(1) as f64
    );
    eprintln!(
        "  records by type (a WAL record frames its images with a fixed {MIN_RECORD_LEN} B):"
    );
    for (k, s) in &w.by_type {
        eprintln!(
            "    {:<16} {:>6.2}/commit  mean {:>5} B = {:>4} B redo + {:>4} B undo + {MIN_RECORD_LEN} B frame",
            type_name(*k),
            s.count as f64 / c,
            s.bytes / s.count.max(1),
            s.redo / s.count.max(1),
            s.undo / s.count.max(1),
        );
    }
    eprintln!(
        "  => {:.2} records/commit ({:.2} page-changing, mean {:.0} B each — a page is {} B)",
        records as f64 / c,
        page_records as f64 / c,
        page_bytes as f64 / page_records.max(1) as f64,
        graphus_io::PAGE_SIZE,
    );
    eprintln!(
        "  => {:.0} B redo + {:.0} B undo per commit (dual imaging: physiological redo + logical undo)",
        redo as f64 / c,
        undo as f64 / c,
    );
    eprintln!(
        "  => {:.2} DISTINCT pages touched per commit, {:.2} page-changing records per touched page",
        distinct_pages as f64 / c,
        page_records as f64 / distinct_pages.max(1) as f64,
    );

    // Attribute every page-changing record — and every byte of it — to the store that owns its page.
    let mut raw: BTreeMap<Option<PageOwner>, (usize, usize, usize)> = BTreeMap::new();
    for t in w.txns.values() {
        for (page, (hits, bytes)) in &t.pages {
            let e = raw.entry(owners.get(page).copied()).or_default();
            e.0 += *hits; // page-changing records
            e.1 += 1; // one distinct (txn, page) pair = one page this commit touched
            e.2 += *bytes; // their encoded WAL bytes
        }
    }
    // Every page the WAL patches must be a page the store maps. An unattributable page id would mean
    // this attribution is reading a map that is not the one the engine writes through.
    assert!(
        !raw.contains_key(&None),
        "{label}: a page-changing WAL record names a device page no store maps"
    );
    let mut by_owner: BTreeMap<PageOwner, OwnerStat> = BTreeMap::new();
    for (owner, (recs, pages, bytes)) in raw {
        let owner = owner.expect("attributed above");
        let stat = OwnerStat {
            records: recs as f64 / c,
            pages: pages as f64 / c,
            bytes: bytes as f64 / c,
        };
        eprintln!(
            "     {:<13} {:>5.2} records/commit over {:>4.2} pages/commit, {:>6.0} B/commit",
            owner.name(),
            stat.records,
            stat.pages,
            stat.bytes,
        );
        by_owner.insert(owner, stat);
    }

    CommitProfile {
        commits,
        readings,
        bytes_per_commit: w.bytes as f64 / c,
        bytes_per_reading: w.bytes as f64 / readings.max(1) as f64,
        records_per_commit: records as f64 / c,
        page_records_per_commit: page_records as f64 / c,
        distinct_pages_per_commit: distinct_pages as f64 / c,
        records_per_touched_page: page_records as f64 / distinct_pages.max(1) as f64,
        redo_per_commit: redo as f64 / c,
        undo_per_commit: undo as f64 / c,
        mean_page_record_bytes: page_bytes as f64 / page_records.max(1) as f64,
        full_page_images: w
            .by_type
            .get(&(RecordType::FullPageImage as u8))
            .map_or(0, |s| s.count),
        commit_record_bytes_per_commit: w
            .by_type
            .get(&(RecordType::Commit as u8))
            .map_or(0.0, |s| s.bytes as f64 / c),
        by_owner,
    }
}

/// Drives the example's ingest shape and returns the per-commit profile of the STEADY-STATE window.
///
/// `schema`: apply the example's declared indexes/constraints (and plan against them) or run with no
/// secondary indexes at all. `batch`: readings per statement and per commit.
///
/// A short warm-up runs BEFORE the WAL is marked, so the measured window excludes the one-off costs of
/// a cold store (interning the label/property-key tokens, mapping the first store pages) and measures
/// the repeating, steady-state cost of a commit — the term the example's amplification figure is made
/// of. Both arms of every comparison below warm up identically, so the comparison is of like with like.
fn measure_ingest(
    schema: bool,
    batch: usize,
    readings: usize,
) -> (CommitProfile, WalWindow, BTreeMap<u64, PageOwner>) {
    let mut coord = fresh_mem();
    let (profile, window, owners, _) =
        drive_ingest(&mut coord, "in-memory", schema, batch, readings, 0);
    (profile, window, owners)
}

/// The one ingest driver, generic over the device / sink. Applies the schema (or not), creates the
/// sensor fleet, runs `warm_extra + WARMUP_READINGS` readings OUTSIDE the measured window, then marks
/// the WAL and ingests `readings` more, decoding everything the window appended.
///
/// The warm-up matters: it excludes the one-off costs of a cold store (interning the label /
/// property-key tokens, mapping the first store pages) so the window measures the repeating,
/// steady-state cost of a commit — the term the example's amplification figure is made of. Every arm of
/// every comparison warms up identically, so each comparison is of like with like.
///
/// Returns the profile, the decoded window, the page-owner map, and the WAL's `[from, to)` LSN range —
/// the last so a file-backed caller can compare the LOGICAL encoded bytes against the FILE's own length
/// growth (the quantity the example's instrument actually reports).
fn drive_ingest<D, S>(
    coord: &mut TxnCoordinator<D, S>,
    device: &str,
    schema: bool,
    batch: usize,
    readings: usize,
    warm_extra: i64,
) -> (
    CommitProfile,
    WalWindow,
    BTreeMap<u64, PageOwner>,
    (u64, u64),
)
where
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
{
    const WARMUP_READINGS: i64 = 40;

    if schema {
        apply_iot_schema(coord);
    }
    let catalog = coord.catalog();
    assert_eq!(
        schema,
        !catalog.indexes().is_empty(),
        "the planner's catalog must reflect the declared schema (and be EMPTY when none was declared) \
         — a silently empty catalog would make the schema-ON arm a second copy of the schema-OFF arm"
    );
    create_sensor_fleet(coord, &catalog);

    let single = Statement::compile(IOT_INGEST_SINGLE, &catalog);
    let batched = Statement::compile(IOT_INGEST_BATCH, &catalog);
    let mut seq = 0i64;
    let ingest = |coord: &mut TxnCoordinator<D, S>, seq: i64| {
        if batch == 1 {
            single.run_committed(coord, &single_row_params(seq));
        } else {
            let seqs: Vec<i64> = (seq..seq + batch as i64).collect();
            batched.run_committed(coord, &batch_rows_params(&seqs));
        }
    };

    // Warm-up: the same shape, outside the measured window.
    let warm_target = WARMUP_READINGS + warm_extra;
    while seq < warm_target {
        ingest(coord, seq);
        seq += batch as i64;
    }

    let from = coord.wal_durable_len();
    let target = seq + readings as i64;
    while seq < target {
        ingest(coord, seq);
        seq += batch as i64;
    }
    let to = coord.wal_durable_len();

    let img = wal_durable_from(coord, from);
    let window = decode_window(&img, 0);
    let owners = page_owners(coord);
    let ingested = (seq - (target - readings as i64)) as usize;
    let label = format!(
        "iot ingest [{device}], batch={batch}, schema {}",
        if schema { "ON" } else { "OFF" }
    );
    let profile = report(&label, &window, ingested, &owners);
    (profile, window, owners, (from, to))
}

/// THE MEASUREMENT the iot-timeseries example's headline explanation rests on: what ONE commit of ONE
/// reading actually writes to the WAL.
///
/// It establishes, by decoding the durable WAL of the example's own `batch = 1` ingest shape:
///
/// - **no full page image is written** — `FullPageImage` is the torn-write fallback and this workload
///   never triggers it, so the shipped "a commit's redo is dominated by the page images of every page
///   it dirtied" is false;
/// - the page-changing records are **small byte-range deltas**, orders of magnitude below a page;
/// - a commit costs **strictly less than one image of even a single page it touches** — the sharpest
///   falsification of the page-image story, and the one that would fail the moment redo became
///   page-sized.
///
/// The full profile it prints (records per commit by type, distinct pages per commit, records per page,
/// redo vs undo bytes, and every page attributed to the store that owns it) is the ONLY thing the
/// example is permitted to say about its residual.
#[test]
fn a_single_reading_commit_writes_small_delta_records_not_page_images() {
    let (p, _w, _owners) = measure_ingest(true, 1, 200);

    // 1. NOT ONE FULL PAGE IMAGE.
    assert_eq!(
        p.full_page_images, 0,
        "this workload wrote {} FullPageImage record(s); the example's explanation claims a commit's \
         redo is dominated by page images, and it must not say so if it is false",
        p.full_page_images
    );

    // 2. The page-changing records are SMALL — nowhere near a page. If redo ever regresses to
    //    page-sized images, the "~22 kB = three 8 KiB pages" story would become true, and this fails.
    assert!(
        p.mean_page_record_bytes < 1024.0,
        "page-changing WAL records average {:.0} B — that is page-image territory, not a byte-range \
         delta; the iot-timeseries explanation of write amplification depends on these being small",
        p.mean_page_record_bytes
    );

    // 3. THE DIRECT FALSIFICATION. A commit's ENTIRE WAL (every record, both images, all framing) is
    //    smaller than a single image of ONE of the pages it dirties — let alone one image per page.
    //    Any regression to page-image redo makes the whole-commit cost >= pages x 8192 B and fails here.
    let one_image = graphus_io::PAGE_SIZE as f64;
    assert!(
        p.bytes_per_commit < one_image,
        "a commit wrote {:.0} B across {:.2} distinct pages — that is at or past ONE {one_image:.0} B \
         page image, so redo is no longer a byte-range delta",
        p.bytes_per_commit,
        p.distinct_pages_per_commit,
    );

    // 4. A commit really is a MULTI-RECORD, MULTI-PAGE transaction (the shape the report describes):
    //    it touches several pages and writes several small records to each. Guards the profile itself —
    //    if a commit collapsed to one record on one page, the report's mechanism would be wrong.
    assert!(
        p.distinct_pages_per_commit > 1.0,
        "a single-reading commit touched {:.2} distinct pages",
        p.distinct_pages_per_commit
    );
    assert!(
        p.records_per_touched_page > 1.0,
        "a commit wrote {:.2} page-changing records per page it touched — the report says several",
        p.records_per_touched_page
    );

    // 5. EVERY record of a commit is a byte-range page delta EXCEPT its one `Commit` record. (There is
    //    no `Begin` record per commit: the WAL's begin is lazy, `rmp` #529.) This is the sharpest
    //    statement of what a commit's WAL IS, and it is what the example may say.
    assert!(
        (p.records_per_commit - p.page_records_per_commit - 1.0).abs() < 0.001,
        "a commit wrote {:.2} records of which {:.2} were page deltas — the report says exactly one \
         record per commit (its `Commit` record) is not a page delta",
        p.records_per_commit,
        p.page_records_per_commit,
    );

    // 6. A reading's OWN records dominate: the node/relationship/property/string-heap writes it makes
    //    are the bulk of the commit, and the catalog re-image is a single record. This is the term
    //    batching CANNOT remove, and the reason batching pays far less than the commit-count ratio.
    //
    //    `PageOwner::Undo` BELONGS IN THIS SUM (`rmp` #966). A reading creates a node and an
    //    `:EMITTED` relationship, and creating an entity writes one `DeleteObject` version delta —
    //    so a reading writes exactly two delta records, per READING, in the same way and for the same
    //    reason it writes its own node and relationship records. MEASURED: 237 B/commit at every store
    //    size, and invariant under batching (asserted in
    //    `a_batched_commit_writes_strictly_fewer_wal_bytes_per_reading`, which is what proves it is a
    //    per-reading and not a per-commit term). `PageOwner::Commit` is deliberately NOT here: the
    //    commit-info slot is allocated once per TRANSACTION and published once at commit, so it
    //    amortises with the catalog image and belongs with the per-commit terms.
    let data_bytes: f64 = [
        PageOwner::Node,
        PageOwner::Rel,
        PageOwner::Prop,
        PageOwner::Strings,
        PageOwner::Undo,
    ]
    .iter()
    .filter_map(|o| p.by_owner.get(o))
    .map(|s| s.bytes)
    .sum();
    assert!(
        data_bytes > 0.5 * p.bytes_per_commit,
        "the reading's own node/rel/property/string/version-delta records are {data_bytes:.0} B of a \
         {:.0} B commit — the report describes them as the bulk of it",
        p.bytes_per_commit
    );

    // 5. Both images are carried: physiological redo AND logical undo (ARIES dual imaging). A record
    //    with no undo could not roll back; a commit whose undo vanished would silently break atomicity.
    assert!(
        p.redo_per_commit > 0.0 && p.undo_per_commit > 0.0,
        "a commit carried {:.0} B redo and {:.0} B undo — a WAL record carries BOTH images",
        p.redo_per_commit,
        p.undo_per_commit
    );
}

/// **THE CONTROLLED EXPERIMENT (`rmp` #745, item 4): what a single-reading commit's ~19 page-changing
/// records are, and what they are NOT.** Two fresh stores, the SAME reading stream, the SAME
/// statements, differing in exactly ONE variable — the example's declared schema (its `POINT` index,
/// its composite `RANGE` index, its two single-property `RANGE` indexes, its `NODE KEY`, existence and
/// property-type constraints) versus no secondary indexes at all. Whatever the two runs differ by IS
/// the schema's cost in the durable WAL, measured rather than narrated.
///
/// Two things are measured, and they are different things:
///
/// 1. **Index MAINTENANCE costs the WAL nothing at all.** The two runs write the identical number of
///    records, of the identical types, to the identical pages of the identical stores — index
///    maintenance appends no record. That is structural: Graphus's secondary indexes are DERIVED —
///    every backing tree lives on an in-memory device behind a [`graphus_wal::DiscardingLogSink`], is
///    rebuilt from the record store on open, and is never recovered (`graphus-cypher/src/index_set.rs`,
///    `rmp` #313/#321). Their cost is CPU and RAM, not durability.
///
/// 2. **A declared schema still makes each commit bigger — entirely through the CATALOG.** Every write
///    commit re-images the durable catalog page (the store's counts and free lists live there), and a
///    schema makes that catalog bigger, so the one catalog record per commit carries more bytes. The
///    measured difference is confined to the catalog: the node, relationship, property and string-heap
///    bytes per commit are byte-identical across the two runs.
///
/// Both halves are falsifiable. Were index maintenance ever made durable (a WAL-logged index), the
/// record counts would diverge and this fails. Were the schema's cost ever to leak into the data
/// stores, the per-store byte equalities would fail.
#[test]
fn the_declared_schema_adds_no_index_maintenance_records_only_a_bigger_catalog_image() {
    let (with_schema, _, _) = measure_ingest(true, 1, 200);
    let (no_schema, _, _) = measure_ingest(false, 1, 200);

    eprintln!(
        "\nTHE SCHEMA'S COST IN THE WAL (schema ON minus schema OFF, per single-reading commit):\n  \
         records {:.2} - {:.2} = {:+.2}   (index maintenance appends NO record)\n  \
         pages   {:.2} - {:.2} = {:+.2}\n  \
         bytes   {:.0} - {:.0} = {:+.0} B",
        with_schema.records_per_commit,
        no_schema.records_per_commit,
        with_schema.records_per_commit - no_schema.records_per_commit,
        with_schema.distinct_pages_per_commit,
        no_schema.distinct_pages_per_commit,
        with_schema.distinct_pages_per_commit - no_schema.distinct_pages_per_commit,
        with_schema.bytes_per_commit,
        no_schema.bytes_per_commit,
        with_schema.bytes_per_commit - no_schema.bytes_per_commit,
    );
    for owner in [
        PageOwner::Node,
        PageOwner::Rel,
        PageOwner::Prop,
        PageOwner::Strings,
        PageOwner::Catalog,
    ] {
        let on = with_schema
            .by_owner
            .get(&owner)
            .copied()
            .unwrap_or_default();
        let off = no_schema.by_owner.get(&owner).copied().unwrap_or_default();
        eprintln!(
            "    {:<13} {:>6.0} B - {:>6.0} B = {:+6.0} B/commit  ({:.2} vs {:.2} records)",
            owner.name(),
            on.bytes,
            off.bytes,
            on.bytes - off.bytes,
            on.records,
            off.records,
        );
    }

    // 1. INDEX MAINTENANCE IS NOT IN THE WAL: identical records, identical pages — per store.
    assert_eq!(
        with_schema.records_per_commit, no_schema.records_per_commit,
        "declaring the example's indexes/constraints changed the NUMBER of WAL records a commit \
         writes; Graphus's secondary indexes are DERIVED (in-memory, DiscardingLogSink, rebuilt on \
         open), so maintaining them must append nothing to the durable WAL"
    );
    assert_eq!(
        with_schema.distinct_pages_per_commit, no_schema.distinct_pages_per_commit,
        "declaring the example's indexes/constraints changed the PAGES a commit dirties"
    );
    for owner in [
        PageOwner::Node,
        PageOwner::Rel,
        PageOwner::Prop,
        PageOwner::Strings,
    ] {
        let on = with_schema
            .by_owner
            .get(&owner)
            .copied()
            .unwrap_or_default();
        let off = no_schema.by_owner.get(&owner).copied().unwrap_or_default();
        assert_eq!(
            on,
            off,
            "the declared schema changed what a commit writes to the {} — it must not: an index is \
             a DERIVED structure and a constraint is a CHECK, so neither can alter the record writes \
             the data stores log",
            owner.name()
        );
    }

    // 2. THE SCHEMA'S WHOLE COST IS THE CATALOG IMAGE. Every write commit re-images the durable
    //    catalog once; a schema makes that catalog bigger, so that one record carries more bytes. The
    //    entire measured difference must be accounted for by that record, to the byte.
    let cat_on = with_schema
        .by_owner
        .get(&PageOwner::Catalog)
        .copied()
        .unwrap_or_default();
    let cat_off = no_schema
        .by_owner
        .get(&PageOwner::Catalog)
        .copied()
        .unwrap_or_default();
    let total_delta = with_schema.bytes_per_commit - no_schema.bytes_per_commit;
    let catalog_delta = cat_on.bytes - cat_off.bytes;
    assert!(
        catalog_delta > 0.0,
        "a declared schema must make the durable catalog bigger, yet the catalog record cost \
         {catalog_delta:+.0} B/commit"
    );
    assert!(
        (total_delta - catalog_delta).abs() < 1.0,
        "the schema cost {total_delta:+.0} B/commit but only {catalog_delta:+.0} B/commit of that is \
         the catalog image — the rest is unexplained, and an unexplained term must not be shipped as \
         an explanation"
    );
    assert_eq!(
        cat_on.records, cat_off.records,
        "the catalog is re-imaged by the same number of records either way — the schema makes the \
         image bigger, it does not add records"
    );
}

/// **THE BATCHING CLAIM ITSELF (`rmp` #745, item 5), measured where the WAL can be decoded.** The
/// example asserts that batching readings into one commit cuts write amplification (its `~830x` per
/// reading vs `~224x` batched); that is a claim about durable bytes per reading, and it is settled
/// here by decoding both windows of the SAME reading stream — identical readings, identical sensors,
/// identical statements — with the ONLY difference being how many readings share a commit.
///
/// It also decomposes WHERE the saving comes from — measured, per store, per reading — so the example
/// can state the mechanism instead of asserting one. The measurement is unambiguous: batching amortises
/// exactly ONE term, the **per-commit catalog re-image** (every durable commit re-encodes the store's
/// catalog — `RecordStore::commit_prepare` calls `checkpoint_meta` — and 25 readings sharing a commit
/// pay for it once instead of 25 times). Every OTHER term is untouched: the node, relationship,
/// property and string-heap bytes each reading costs are the SAME to within a fraction of a percent
/// whether it commits alone or with 24 others. That is why a 25x drop in commit count buys only ~1.6x
/// in durable bytes — and it is the residual the example must own rather than explain away.
#[test]
fn a_batched_commit_writes_strictly_fewer_wal_bytes_per_reading() {
    const BATCH: usize = 25; // the example's `--batch 25` gateway flush buffer
    const READINGS: usize = 200;

    let (single, _, _) = measure_ingest(true, 1, READINGS);
    let (batched, _, _) = measure_ingest(true, BATCH, READINGS);

    let saving = single.bytes_per_reading / batched.bytes_per_reading;
    eprintln!(
        "\nBATCHING (the example's claim, measured):\n  \
         batch=1  : {:.0} B/commit over {} commits => {:.0} B per reading\n  \
         batch={BATCH} : {:.0} B/commit over {} commits => {:.0} B per reading\n  \
         => batching {BATCH} readings per commit writes {saving:.2}x FEWER durable bytes per reading \
         (the commit COUNT fell {BATCH}x)",
        single.bytes_per_commit,
        single.commits,
        single.bytes_per_reading,
        batched.bytes_per_commit,
        batched.commits,
        batched.bytes_per_reading,
    );

    // WHERE THE SAVING COMES FROM, per store, per READING (not per commit) — the only comparison that
    // holds the workload fixed. Whatever term shrinks here is what batching amortises; whatever term
    // does not is the residual the example must own.
    eprintln!("  per-READING WAL bytes by store (batch=1 -> batch={BATCH}):");
    let per_reading = |p: &CommitProfile, o: PageOwner| -> f64 {
        p.by_owner.get(&o).map_or(0.0, |s| s.bytes) * p.commits as f64 / p.readings as f64
    };
    for owner in [
        PageOwner::Node,
        PageOwner::Rel,
        PageOwner::Prop,
        PageOwner::Strings,
        PageOwner::Catalog,
    ] {
        let a = per_reading(&single, owner);
        let b = per_reading(&batched, owner);
        eprintln!(
            "    {:<13} {:>6.0} B -> {:>6.0} B  ({:+6.0} B, {:.2}x)",
            owner.name(),
            a,
            b,
            b - a,
            if b > 0.0 { a / b } else { f64::INFINITY },
        );
    }

    // Same readings on both sides — otherwise this compares two different workloads.
    assert_eq!(single.readings, batched.readings, "same reading stream");
    assert_eq!(
        batched.commits * BATCH,
        batched.readings,
        "the batched arm must really carry {BATCH} readings per commit"
    );

    // THE CLAIM: strictly fewer durable bytes per reading. Falsifiable and directional — if batching
    // ever stopped paying, the example would have to stop saying it does.
    assert!(
        batched.bytes_per_reading < single.bytes_per_reading,
        "batching {BATCH} readings per commit wrote {:.0} B per reading vs {:.0} B for per-reading \
         commits — batching must write strictly FEWER durable bytes per reading",
        batched.bytes_per_reading,
        single.bytes_per_reading,
    );

    // AND THE HONEST BOUND: the saving is NOT the commit-count ratio. Most of a reading's WAL is the
    // reading's OWN records (its node, its relationship, its four properties), which batching cannot
    // remove — so a 25x drop in commits buys far less than 25x in bytes. An example that claimed
    // otherwise would be caught here.
    assert!(
        saving < BATCH as f64,
        "batching cannot save more than the commit-count ratio: measured {saving:.2}x for a {BATCH}x \
         drop in commits, which would mean a reading's own records vanished"
    );

    // THE MECHANISM, ASSERTED — not narrated.
    //
    // (a) A reading's OWN durable records are UNTOUCHED by batching. Its node, its `:EMITTED`
    //     relationship, its four properties and its string-heap blocks cost the same whether it
    //     commits alone or with 24 others. This is the irreducible floor of the example's residual: a
    //     32-byte reading is stored as several MVCC-versioned, chained, byte-addressed records, and
    //     every one of them is logged with a redo AND an undo image.
    //     `Undo` is in this list (`rmp` #966): a reading creates a node and a relationship, and each
    //     creation writes one `DeleteObject` version delta, so its deltas are a per-READING cost like
    //     its records. This assertion is what PROVES that classification rather than assuming it — if
    //     the delta term ever started amortising with batching it would be a per-commit term, and the
    //     decomposition in `a_single_reading_commit_writes_small_delta_records_not_page_images` (which
    //     counts it as a reading's own record) would be wrong.
    for owner in [
        PageOwner::Node,
        PageOwner::Rel,
        PageOwner::Prop,
        PageOwner::Strings,
        PageOwner::Undo,
    ] {
        let a = per_reading(&single, owner);
        let b = per_reading(&batched, owner);
        assert!(
            a > 0.0 && (a - b).abs() / a < 0.02,
            "batching changed the {} bytes a reading costs ({a:.0} B -> {b:.0} B); a reading's own \
             records are written per READING, so batching must not move them — if this ever became \
             true, the example's mechanism would have to be rewritten again",
            owner.name(),
        );
    }

    // (b) The ONE term batching amortises is the per-commit CATALOG re-image: every durable commit
    //     re-encodes the store's catalog (`RecordStore::commit_prepare` -> `checkpoint_meta`), so a
    //     batch of N readings pays it once instead of N times. It must fall by ~the batch factor.
    let cat_single = per_reading(&single, PageOwner::Catalog);
    let cat_batched = per_reading(&batched, PageOwner::Catalog);
    let cat_ratio = cat_single / cat_batched;
    assert!(
        cat_ratio > 0.9 * BATCH as f64,
        "the per-commit catalog image is the term batching amortises: it fell only {cat_ratio:.1}x \
         for a {BATCH}x drop in commits ({cat_single:.0} B -> {cat_batched:.0} B per reading)"
    );

    // (c) THE SAVING IS FULLY ACCOUNTED FOR — to the byte — by exactly THREE per-commit terms: the
    //     catalog re-image, the **commit-info slot**, and the `Commit` record itself. Nothing else
    //     amortises. This is the complete mechanism, and if any other term ever started amortising
    //     (or stopped), this fails and the example's explanation would have to be re-measured rather
    //     than reused.
    //
    //     THE COMMIT-SLOT TERM IS NEW (`rmp` #966) and it is a genuine third term, not a re-pin to
    //     make an old number fit. A writing transaction allocates ONE commit-info slot — the commit
    //     indirection point through which every one of its version deltas resolves its commit status
    //     (`05-storage-format.md` §12.4) — and publishes it with two writes at commit (`delta_count`,
    //     then `commit_ts`). That is three records per TRANSACTION regardless of how many readings the
    //     transaction carries, so it amortises exactly like the catalog image, for exactly the same
    //     reason. MEASURED: ~248 B/commit, and it is the 238 B/reading this accounting was previously
    //     unable to explain.
    let commit_rec_single =
        single.commit_record_bytes_per_commit * single.commits as f64 / single.readings as f64;
    let commit_rec_batched =
        batched.commit_record_bytes_per_commit * batched.commits as f64 / batched.readings as f64;
    let slot_single = per_reading(&single, PageOwner::Commit);
    let slot_batched = per_reading(&batched, PageOwner::Commit);
    let total_saved = single.bytes_per_reading - batched.bytes_per_reading;
    let catalog_saved = cat_single - cat_batched;
    let commit_saved = commit_rec_single - commit_rec_batched;
    let slot_saved = slot_single - slot_batched;
    eprintln!(
        "  => the {total_saved:.0} B/reading batching saved = {catalog_saved:.0} B catalog image \
         + {slot_saved:.0} B commit-info slot + {commit_saved:.0} B commit record; the reading's OWN \
         records ({:.0} B, version deltas included) did not move",
        per_reading(&batched, PageOwner::Node)
            + per_reading(&batched, PageOwner::Rel)
            + per_reading(&batched, PageOwner::Prop)
            + per_reading(&batched, PageOwner::Strings)
            + per_reading(&batched, PageOwner::Undo),
    );
    // The commit slot must really amortise — otherwise it is not a per-commit term and putting it in
    // this sum would be curve-fitting rather than mechanism.
    assert!(
        slot_saved > 0.9 * slot_single,
        "the commit-info slot is claimed to be a per-TRANSACTION term, so batching {BATCH} readings \
         per commit must amortise essentially all of it: {slot_single:.0} B -> {slot_batched:.0} B \
         per reading"
    );
    assert!(
        (total_saved - (catalog_saved + slot_saved + commit_saved)).abs() < 0.01 * total_saved,
        "batching saved {total_saved:.0} B per reading, but its three per-commit terms — the catalog \
         image ({catalog_saved:.0} B), the commit-info slot ({slot_saved:.0} B) and the commit record \
         ({commit_saved:.0} B) — account for only {:.0} B of it. The remainder is unexplained, and an \
         unexplained term must not be shipped as an explanation",
        catalog_saved + slot_saved + commit_saved,
    );
}

// ============================================================================================
// `rmp` #745 (follow-up) — THE SAME DECOMPOSITION ON THE **REAL FILE-BACKED ENGINE**, and the
// SCALING LAW that reconciles it with the example's published, file-backed numbers.
//
// The measurements above run over `MemBlockDevice` + `MemLogSink`. The example publishes numbers from a
// REAL file-backed server, and they disagree in MAGNITUDE (~23.5 kB per single-reading commit against
// the ~3.8 kB measured above). An example may not explain its file-backed numbers with in-memory
// magnitudes, so the gap is measured here rather than assumed away. Two candidate causes are TESTED:
//
//   (a) the file-backed WAL pads / aligns what it writes, so the FILE grows by more than its records
//       encode (the example's instrument sums WAL FILE LENGTHS, not decoded record bytes);
//   (b) the file-backed engine writes DIFFERENT records than the in-memory one.
//
// Both are FALSE, and the tests below prove it: the WAL directory's file bytes equal its LSN space to
// the byte (`FileLogSink::write_pending` appends its buffer verbatim — no padding, no alignment, no
// per-flush framing), and the file-backed engine writes byte-identical records to the in-memory one
// (20.07 records / 3 839 B per single-reading commit on both).
//
// The gap is (c), and the last two tests name it: **a commit's WAL is not a constant — its catalog term
// scales with the SIZE OF THE STORE.** Every durable commit re-images the whole durable catalog
// (`RecordStore::commit_prepare` -> `checkpoint_meta`), and that catalog encodes each record store's
// `device_pages: Vec<u64>` page map (`StoreMeta`, `graphus-storage/src/meta.rs`) — 8 bytes per store
// page — which the WAL then logs with BOTH a redo and an undo image. MEASURED: every store page costs
// **16 B in EVERY commit**, exactly. A single-reading commit costs 3 789 B on an 11-page store and
// 7 852 B on a 265-page one, entirely because its catalog image went 1 428 B -> 5 492 B while its data
// records did not move (905 / 406 / 529 / 455 B throughout).
//
// The catalog carries a SECOND store-dependent term: each store's FREE LIST (`StoreMeta::free_list`, a
// `Vec<u64>` of reclaimed ids — 8 B each, imaged twice = 16 B per freed id in EVERY commit). It is not
// a footnote: MEASURED, a retention purge of 500 readings (the example's own `DETACH DELETE` shape,
// followed by one GC pass) leaves ~3 600 ids on the free lists and inflates the catalog image of every
// LATER single-reading commit from 2 202 B to 60 137 B — a 13.7x blow-up of an unrelated commit's WAL,
// paid until those ids are reused.
//
// That is also why the batching saving is not a constant of the engine: batching amortises the catalog
// term and NOT the data term, so it pays 1.61x on a small store and 3.12x on a 265-page one — and far
// more on a large, churning database. A hermetic fixture therefore UNDERSTATES both a real deployment's
// per-commit cost and its batching win, and neither may be quoted for the other.
// ============================================================================================

/// The number of device pages the four record stores map — the EXACT quantity the durable catalog
/// encodes as a `Vec<u64>` page map per store (`StoreMeta::device_pages`, `graphus-storage/src/meta.rs`),
/// read off the store's own metadata snapshot.
fn store_pages<D, S>(coord: &TxnCoordinator<D, S>) -> u64
where
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
{
    coord.with_store_mut(|s| {
        let view = s.read_view();
        let meta = view.meta();
        // EVERY record store, the undo area included (`rmp` #966). The 16 B-per-store-page law below
        // is a ratio whose DENOMINATOR is this count, so omitting a store the catalog DOES image
        // inflates the measured slope and turns the law into a false alarm — which is exactly what
        // happened when #966 added `undo.store` and `commit.store` and this list still named four:
        // the slope read 20.5 B/page and the law looked broken when only the instrument was.
        //
        // The assertion below makes the list structurally impossible to leave stale: it must name
        // every store the catalog images, and `STORE_COUNT` is that number.
        let kinds = [
            StoreKind::Node,
            StoreKind::Rel,
            StoreKind::Prop,
            StoreKind::Strings,
            StoreKind::Undo,
            StoreKind::Commit,
        ];
        assert_eq!(
            kinds.len(),
            graphus_storage::STORE_COUNT,
            "this measurement enumerates the stores the durable catalog images; a new store must be \
             added here (and to `page_owners`) or the per-store-page law it measures becomes a lie"
        );
        kinds.iter().map(|k| meta.mapped_page_count(*k)).sum()
    })
}

/// Builds a REAL file-backed coordinator (a `FileBlockDevice` + a real segmented `FileLogSink` on disk)
/// in `tmp`, with the store's own redo-bounding auto-checkpoint disabled so the workload's RAW WAL is
/// measured and no reclamation moves the file lengths under the window.
fn fresh_file(tmp: &TempStore) -> FileCoord {
    let device = FileBlockDevice::open(tmp.device_path()).expect("open device");
    let sink = FileLogSink::open(tmp.wal_dir()).expect("open sink");
    let wal = WalManager::create(sink).expect("create wal");
    let store = RecordStore::create(device, wal, 4096, 1).expect("create store");
    let coord: FileCoord = TxnCoordinator::new(store);
    coord.with_store_mut(|s| s.set_checkpoint_interval_bytes(0));
    coord
}

/// **THE FILE-BACKED CONTROL (`rmp` #745 follow-up).** The example's numbers come from a file-backed
/// server; this runs the identical decomposition on a real `FileBlockDevice` + a real segmented
/// `FileLogSink` on disk, and reconciles two quantities that are NOT the same thing:
///
/// - the **logical** bytes the WAL records encode (what the tests above decode), and
/// - the **file length growth** of the WAL directory (what the example's instrument actually sums).
///
/// They are measured to be **exactly equal**: `FileLogSink::write_pending` appends the pending buffer
/// verbatim — no padding, no block alignment, no per-flush framing (`graphus-wal/src/sink.rs`) — so a
/// commit's file growth IS its records. And the file-backed engine writes the same records, on the same
/// stores, as the in-memory one. Whatever makes the example's published per-commit figure larger than
/// this one, it is therefore NEITHER durable framing overhead NOR a different write path.
#[cfg_attr(
    miri,
    ignore = "real filesystem I/O + fdatasync are outside miri's isolation/UB scope"
)]
#[test]
fn the_file_backed_wal_grows_by_exactly_what_its_records_encode() {
    const READINGS: usize = 200;

    let tmp = TempStore::new("filebacked-1");
    let mut coord = fresh_file(&tmp);
    let (file_p, _w, _o, (from, to)) =
        drive_ingest(&mut coord, "FILE-BACKED", true, 1, READINGS, 0);
    let on_disk = on_disk_wal_bytes(&tmp.wal_dir());

    // Three quantities that are NOT a priori the same: the bytes the window's records DECODE to, the
    // window's LSN growth, and the total FILE length of the WAL directory (the example's instrument
    // sums exactly this). LSN == byte offset and nothing is reclaimed here, so all three must agree.
    let decoded = file_p.bytes_per_commit * file_p.commits as f64;
    let lsn_growth = to - from;
    eprintln!(
        "\nFILE-BACKED vs the WAL FILES (what the example's instrument measures):\n  \
         window: decoded records {decoded:.0} B == LSN growth {lsn_growth} B \
         ({:.0} B per commit)\n  \
         whole log: LSN space {to} B == WAL FILE bytes on disk {on_disk} B \
         (anchor + segments; NO padding, NO alignment, NO per-flush framing)",
        lsn_growth as f64 / file_p.commits as f64,
    );
    assert_eq!(
        lsn_growth, decoded as u64,
        "every byte of LSN space must be a decoded record — a gap would mean the log carries framing \
         the decode cannot see"
    );
    assert_eq!(
        on_disk, to,
        "the WAL FILES must hold exactly the bytes the records encode: `FileLogSink::write_pending` \
         appends its pending buffer verbatim, with no padding, no block alignment and no per-flush \
         framing. If this ever differs, THAT difference is a real durable-framing overhead — and the \
         example's file-length instrument would then be measuring something the record decode cannot \
         explain"
    );

    // And the file-backed engine writes the SAME records as the in-memory one — same count, same
    // stores, same bytes. So an in-memory measurement of the RECORD PROFILE is faithful to the file
    // engine (what is NOT faithful is the store's SIZE — see the scaling test below).
    let (mem_p, _, _) = measure_ingest(true, 1, READINGS);
    eprintln!(
        "  file-backed {:.2} records/commit, {:.0} B/commit  vs  in-memory {:.2} records/commit, \
         {:.0} B/commit",
        file_p.records_per_commit,
        file_p.bytes_per_commit,
        mem_p.records_per_commit,
        mem_p.bytes_per_commit,
    );
    assert_eq!(
        file_p.records_per_commit, mem_p.records_per_commit,
        "the file-backed engine must log the same records as the in-memory one"
    );
    assert_eq!(
        file_p.bytes_per_commit, mem_p.bytes_per_commit,
        "the file-backed engine must log the same BYTES as the in-memory one"
    );
    for owner in [
        PageOwner::Node,
        PageOwner::Rel,
        PageOwner::Prop,
        PageOwner::Strings,
        PageOwner::Catalog,
    ] {
        assert_eq!(
            file_p.by_owner.get(&owner).copied().unwrap_or_default(),
            mem_p.by_owner.get(&owner).copied().unwrap_or_default(),
            "the file-backed engine must write the same {} bytes as the in-memory one",
            owner.name(),
        );
    }
    assert_eq!(
        file_p.full_page_images, 0,
        "not one FullPageImage on the real device either"
    );
}

/// The file-backed batching claim, on the device the server actually runs.
#[cfg_attr(
    miri,
    ignore = "real filesystem I/O + fdatasync are outside miri's isolation/UB scope"
)]
#[test]
fn file_backed_batching_saves_exactly_the_per_commit_terms() {
    const BATCH: usize = 25;
    const READINGS: usize = 200;

    let tmp1 = TempStore::new("filebacked-b1");
    let mut c1 = fresh_file(&tmp1);
    let (single, _, _, _) = drive_ingest(&mut c1, "FILE-BACKED", true, 1, READINGS, 0);

    let tmp2 = TempStore::new("filebacked-b25");
    let mut c2 = fresh_file(&tmp2);
    let (batched, _, _, _) = drive_ingest(&mut c2, "FILE-BACKED", true, BATCH, READINGS, 0);

    let saving = single.bytes_per_reading / batched.bytes_per_reading;
    let per_reading = |p: &CommitProfile, o: PageOwner| -> f64 {
        p.by_owner.get(&o).map_or(0.0, |s| s.bytes) * p.commits as f64 / p.readings as f64
    };
    eprintln!(
        "\nFILE-BACKED BATCHING: batch=1 {:.0} B/reading -> batch={BATCH} {:.0} B/reading = {saving:.2}x\n  \
         catalog per reading: {:.0} B -> {:.0} B",
        single.bytes_per_reading,
        batched.bytes_per_reading,
        per_reading(&single, PageOwner::Catalog),
        per_reading(&batched, PageOwner::Catalog),
    );
    assert!(
        batched.bytes_per_reading < single.bytes_per_reading,
        "batching must write strictly fewer durable bytes per reading on the real device too"
    );
    for owner in [
        PageOwner::Node,
        PageOwner::Rel,
        PageOwner::Prop,
        PageOwner::Strings,
    ] {
        let a = per_reading(&single, owner);
        let b = per_reading(&batched, owner);
        assert!(
            a > 0.0 && (a - b).abs() / a < 0.02,
            "on the real device too, batching must not move the {} bytes a reading costs \
             ({a:.0} B -> {b:.0} B)",
            owner.name(),
        );
    }
}

/// **THE SCALING LAW THAT RECONCILES THE HERMETIC NUMBERS WITH THE EXAMPLE'S (`rmp` #745 follow-up).**
///
/// A commit's WAL is not a constant. Every durable commit re-images the whole durable catalog
/// (`RecordStore::commit_prepare` -> `checkpoint_meta`), and that catalog encodes, per record store,
/// its **`device_pages: Vec<u64>` page map** and its **free list** (`graphus-storage/src/meta.rs`,
/// `StoreMeta`). Both grow with the database. So the per-commit catalog record — logged with a redo
/// AND an undo image — grows with the SIZE OF THE STORE, for a term that has nothing to do with what
/// the commit changed.
///
/// This test measures that law directly: the same single-reading commit, profiled at increasing store
/// sizes, and it reports bytes per commit against the store's mapped page count. It is the reason a
/// small hermetic store measures ~3.8 kB per commit while a large, long-running file-backed database
/// measures several times that: the DATA term is constant and the CATALOG term is not.
///
/// It is also a real engine finding — per-commit WAL is O(store pages) — and the assertion below is
/// the falsifiable statement of it: make the catalog image constant-size (an incremental catalog, or a
/// catalog that is not re-imaged per commit) and this test fails, which is exactly what should happen,
/// because the example's explanation would then have to change.
#[test]
fn the_per_commit_catalog_image_grows_with_the_store() {
    const READINGS: usize = 100;

    // Profile the SAME single-reading commit at three store sizes, by varying only how much data was
    // already ingested before the measured window opens.
    let mut samples: Vec<(u64, u64, f64, f64)> = Vec::new(); // (store pages, store B, catalog B, total B)
    for warm_extra in [0i64, 1_000, 4_000] {
        let mut coord = fresh_mem();
        let (p, _w, _o, _) = drive_ingest(
            &mut coord,
            &format!("store warmed with {warm_extra} extra readings"),
            true,
            1,
            READINGS,
            warm_extra,
        );
        let store = coord.store_byte_len();
        let catalog = p.by_owner.get(&PageOwner::Catalog).map_or(0.0, |s| s.bytes);
        samples.push((store_pages(&coord), store, catalog, p.bytes_per_commit));
    }

    eprintln!("\nTHE CATALOG IMAGE SCALES WITH THE STORE (same single-reading commit throughout):");
    eprintln!("   store pages | store bytes | catalog B/commit | total B/commit | catalog share");
    for (pages, store, catalog, total) in &samples {
        eprintln!(
            "   {pages:>11} | {store:>11} | {catalog:>16.0} | {total:>14.0} | {:>12.0}%",
            100.0 * catalog / total
        );
    }
    let (p0, _, cat0, tot0) = samples[0];
    let (p2, _, cat2, tot2) = samples[samples.len() - 1];
    let pages_grew = p2 as f64 / p0 as f64;
    let catalog_grew = cat2 / cat0;
    eprintln!(
        "  => the store grew {pages_grew:.1}x in pages; the per-commit CATALOG image grew \
         {catalog_grew:.1}x ({cat0:.0} B -> {cat2:.0} B), while the commit's DATA records did not \
         move. Total: {tot0:.0} B -> {tot2:.0} B per commit."
    );

    // THE LAW: a bigger store makes every commit's catalog image bigger. Strictly monotone in the
    // store's mapped page count.
    for w in samples.windows(2) {
        assert!(
            w[1].0 > w[0].0,
            "the store must actually have grown between samples ({} -> {} pages)",
            w[0].0,
            w[1].0
        );
        assert!(
            w[1].2 > w[0].2,
            "the per-commit catalog image must grow with the store: {:.0} B at {} pages, but \
             {:.0} B at {} pages",
            w[0].2,
            w[0].0,
            w[1].2,
            w[1].0,
        );
    }

    // AND THE LAW IS EXACT, WITH A MECHANISM. The catalog encodes each store's page map as a
    // `Vec<u64>` — 8 bytes per store page (`StoreMeta::device_pages`) — and the WAL logs the catalog
    // patch with BOTH a redo and an undo image, so each store page costs **16 B in EVERY commit**.
    // Fit the slope across the samples and assert it: this is the sharpest possible statement of the
    // finding, it names the byte, and it fails the moment the catalog stops being re-imaged per commit
    // or stops carrying the page map.
    let slope = (cat2 - cat0) / (p2 - p0) as f64;
    eprintln!(
        "  => MEASURED SLOPE: {slope:.1} B of WAL per store page, in EVERY commit \
         (= an 8 B `u64` page id in `StoreMeta::device_pages`, imaged twice: redo + undo). \
         Model: per-commit WAL ~= {:.0} B + {slope:.0} B x store_pages.",
        cat0 - slope * p0 as f64 + (tot0 - cat0),
    );
    assert!(
        (14.0..=18.0).contains(&slope),
        "the per-commit catalog image must grow by ~16 B per store page (an 8 B page id in the \
         catalog's `device_pages` vector, logged as both a redo and an undo image); measured \
         {slope:.1} B/page"
    );
    // The linear model must actually PREDICT the middle sample (it was not used to fit the line), or
    // the "law" is just two points joined by a ruler.
    let (p1, _, cat1, _) = samples[1];
    let predicted = cat0 + slope * (p1 - p0) as f64;
    assert!(
        (predicted - cat1).abs() < 0.05 * cat1,
        "the 16 B/page law must predict the un-fitted middle sample: predicted {predicted:.0} B at \
         {p1} pages, measured {cat1:.0} B"
    );

    // …and the DATA term does NOT move: the same reading costs the same node/rel/prop/string bytes in
    // a big store as in a small one. This is what makes the catalog the ONLY store-size-dependent term
    // — and therefore the whole explanation of why a large database's commits cost more.
    assert!(
        tot2 - tot0 > 0.0,
        "a bigger store must cost more per commit; total went {tot0:.0} B -> {tot2:.0} B"
    );
    let data_delta = (tot2 - tot0) - (cat2 - cat0);
    assert!(
        data_delta.abs() < 0.1 * (tot2 - tot0),
        "the growth in per-commit WAL must be the CATALOG image: total grew {:.0} B but the catalog \
         only grew {:.0} B — the remaining {data_delta:.0} B is unexplained",
        tot2 - tot0,
        cat2 - cat0,
    );
}

/// **THE CONSEQUENCE THAT RECONCILES THE HERMETIC RUN WITH THE EXAMPLE'S PUBLISHED, FILE-BACKED
/// NUMBERS (`rmp` #745 follow-up).**
///
/// Because a commit's WAL is `DATA(constant) + CATALOG(grows with the store)`, and because batching
/// amortises the catalog term and NOT the data term, the batching saving is **not a constant of the
/// engine — it is a function of how big the database is**:
///
/// ```text
///   saving(B) = (DATA + CATALOG) / (DATA + CATALOG / B)
/// ```
///
/// A small store (catalog ~38 % of a commit) barely benefits; a large store (catalog ~70 % and rising)
/// benefits enormously. This test measures both ends and asserts the saving GROWS with the store — the
/// property that explains why the example's file-backed run, on a database far larger than any hermetic
/// fixture, reports a much bigger batching win than a small store can ever show.
#[test]
fn the_batching_saving_grows_with_the_store() {
    const BATCH: usize = 25;
    const READINGS: usize = 100;
    const BIG: i64 = 4_000;

    let measure = |batch: usize, warm_extra: i64| -> (CommitProfile, u64) {
        let mut coord = fresh_mem();
        let (p, _w, _o, _) = drive_ingest(
            &mut coord,
            &format!("batch={batch}, store warmed +{warm_extra}"),
            true,
            batch,
            READINGS,
            warm_extra,
        );
        (p, store_pages(&coord))
    };

    let (small_1, small_pages) = measure(1, 0);
    let (small_n, _) = measure(BATCH, 0);
    let (big_1, big_pages) = measure(1, BIG);
    let (big_n, big_n_pages) = measure(BATCH, BIG);

    let small_saving = small_1.bytes_per_reading / small_n.bytes_per_reading;
    let big_saving = big_1.bytes_per_reading / big_n.bytes_per_reading;
    let cat = |p: &CommitProfile| -> f64 {
        p.by_owner.get(&PageOwner::Catalog).map_or(0.0, |s| s.bytes) * p.commits as f64
            / p.readings as f64
    };
    eprintln!(
        "\nTHE BATCHING SAVING IS A FUNCTION OF STORE SIZE (batch=1 vs batch={BATCH}):\n  \
         SMALL store ({small_pages} store pages): {:.0} -> {:.0} B/reading = {small_saving:.2}x \
         (catalog {:.0} -> {:.0} B/reading)\n  \
         BIG   store ({big_pages} store pages): {:.0} -> {:.0} B/reading = {big_saving:.2}x \
         (catalog {:.0} -> {:.0} B/reading)\n  \
         => the saving grew {:.2}x purely because the store did — the DATA term is constant and the \
         CATALOG term is not.",
        small_1.bytes_per_reading,
        small_n.bytes_per_reading,
        cat(&small_1),
        cat(&small_n),
        big_1.bytes_per_reading,
        big_n.bytes_per_reading,
        cat(&big_1),
        cat(&big_n),
        big_saving / small_saving,
    );

    // The two BIG arms must be comparable stores (the batched warm-up rounds to whole batches), or the
    // comparison is between two different databases.
    assert!(
        (big_pages as f64 - big_n_pages as f64).abs() < 0.05 * big_pages as f64,
        "the two BIG arms must be the same size of database: {big_pages} vs {big_n_pages} store pages"
    );
    assert!(
        big_pages > small_pages,
        "the BIG store must actually be bigger: {big_pages} vs {small_pages} pages"
    );

    // THE CLAIM: the batching saving grows with the store. This is the falsifiable statement of the
    // reconciliation — and if the catalog image were ever made constant-size, batching would stop
    // paying more on a big database, this would fail, and the example's explanation would have to be
    // re-measured rather than reused.
    assert!(
        big_saving > small_saving * 1.2,
        "the batching saving must grow materially with the store: {small_saving:.2}x on a \
         {small_pages}-page store vs {big_saving:.2}x on a {big_pages}-page one"
    );
    // …and it grows for exactly one reason: the term that batching amortises is the one that grew.
    assert!(
        cat(&big_1) > cat(&small_1) * 1.5,
        "the catalog term per reading must be much larger on the big store: {:.0} B vs {:.0} B",
        cat(&big_1),
        cat(&small_1),
    );
}

/// Runs `commits` single-reading commits on `coord` and profiles exactly the WAL they append.
fn window_profile(
    coord: &mut MemCoord,
    stmt: &Statement,
    seq: &mut i64,
    commits: usize,
    label: &str,
) -> CommitProfile {
    let from = coord.wal_durable_len();
    for _ in 0..commits {
        stmt.run_committed(coord, &single_row_params(*seq));
        *seq += 1;
    }
    let img = wal_durable_from(coord, from);
    let window = decode_window(&img, 0);
    let owners = page_owners(coord);
    report(label, &window, commits, &owners)
}

/// **THE SECOND STORE-SIZE-DEPENDENT CATALOG TERM: THE FREE LIST (`rmp` #745 follow-up).**
///
/// The durable catalog carries, per record store, not only the page map but also the **free list** of
/// reclaimed physical ids (`StoreMeta::free_list`, a `Vec<u64>` — 8 bytes per freed id,
/// `graphus-storage/src/idalloc.rs`). Since every durable commit re-images the catalog with a redo AND
/// an undo image, **each id sitting on a free list costs 16 B in every commit** until it is reused.
///
/// This matters because the iot example is a RETENTION workload: it `DETACH DELETE`s aged-out readings.
/// A purge that frees many records therefore inflates every subsequent commit's WAL — a cost the purge
/// pays forward, invisibly, into unrelated transactions. This test measures it: the same single-reading
/// commit, profiled before and after a retention purge, on a store whose PAGE COUNT does not change (so
/// the page-map term is held constant and the free list is the only variable).
#[test]
fn a_retention_purge_inflates_every_later_commit_through_the_catalog_free_list() {
    const PRELOAD: i64 = 800;
    const PURGE_BELOW: i64 = 500;
    const WINDOW: usize = 100;

    let mut coord = fresh_mem();
    apply_iot_schema(&mut coord);
    let catalog = coord.catalog();
    create_sensor_fleet(&mut coord, &catalog);
    let single = Statement::compile(IOT_INGEST_SINGLE, &catalog);

    let mut seq = 0i64;
    while seq < PRELOAD {
        single.run_committed(&mut coord, &single_row_params(seq));
        seq += 1;
    }

    let before = window_profile(
        &mut coord,
        &single,
        &mut seq,
        WINDOW,
        "BEFORE the retention purge",
    );
    let pages_before = store_pages(&coord);

    // The example's retention statement, verbatim in shape (`Generator::tick`): drop every reading
    // older than the window, node + relationship + properties together. Then a GC pass, which is what
    // actually reclaims the dead versions and pushes their physical ids onto the free lists.
    let purge = Statement::compile(
        &format!("MATCH (r:Reading) WHERE r.seq < {PURGE_BELOW} DETACH DELETE r"),
        &catalog,
    );
    purge.run_committed(&mut coord, &Parameters::new());
    let gc_report = coord.gc().expect("gc pass");
    eprintln!(
        "\nretention purge: DETACH DELETEd every Reading with seq < {PURGE_BELOW}, then one GC pass \
         reclaimed {} physical versions",
        gc_report.reclaimed
    );

    let after = window_profile(
        &mut coord,
        &single,
        &mut seq,
        WINDOW,
        "AFTER the retention purge",
    );
    let pages_after = store_pages(&coord);

    let cat =
        |p: &CommitProfile| -> f64 { p.by_owner.get(&PageOwner::Catalog).map_or(0.0, |s| s.bytes) };
    let delta = cat(&after) - cat(&before);
    // 8 B per freed id in the catalog, imaged twice (redo + undo) => 16 B per id in every commit.
    let implied_ids = delta / 16.0;
    eprintln!(
        "\nTHE FREE-LIST TERM (same single-reading commit, same {pages_before}-page store):\n  \
         catalog image: {:.0} B/commit BEFORE -> {:.0} B/commit AFTER the purge ({delta:+.0} B)\n  \
         total WAL    : {:.0} B/commit BEFORE -> {:.0} B/commit AFTER\n  \
         => at 16 B per freed id per commit (an 8 B id in `StoreMeta::free_list`, imaged redo + undo), \
         that is ~{implied_ids:.0} ids sitting on the free lists — and EVERY commit pays for them \
         until they are reused.",
        cat(&before),
        cat(&after),
        before.bytes_per_commit,
        after.bytes_per_commit,
    );

    // The page-map term is SUBTRACTED OUT rather than held at zero, so what remains is the free-list
    // term and only the free-list term.
    //
    // WHY THIS CHANGED (`rmp` #966). This used to assert `pages_before == pages_after`: the purge
    // frees record *slots*, not pages, and the measured window's readings reused them, so no store
    // grew. That is no longer true, and the reason is a real property of the engine rather than noise:
    // every write transaction allocates one commit-info slot in `commit.store` and every created
    // entity one delta in `undo.store`, so ANY window of commits grows the undo area — and page maps
    // never shrink. Holding the page count at zero growth is therefore no longer a precondition this
    // measurement can establish, and asserting it would only be asserting that the undo area does not
    // exist.
    //
    // Subtracting `16 B x Δpages` (the page-map law this file measures and pins in
    // `the_per_commit_catalog_image_grows_with_the_store`) is strictly sharper than the old equality:
    // it isolates the free-list term explicitly instead of relying on a confound happening to be zero,
    // and it keeps working for any future store that also grows during the window.
    assert!(
        pages_after >= pages_before,
        "page maps only ever grow: {pages_before} -> {pages_after}"
    );
    let page_map_term = 16.0 * (pages_after - pages_before) as f64;
    let free_list_term = delta - page_map_term;
    eprintln!(
        "  of the {delta:+.0} B, {page_map_term:.0} B is the page-map term ({} new pages x 16 B) and \
         {free_list_term:.0} B is the FREE LIST",
        pages_after - pages_before
    );
    assert!(
        free_list_term > 0.9 * delta,
        "the purge's inflation of every later commit must be the FREE LIST, not the page map: of \
         {delta:+.0} B only {free_list_term:.0} B is attributable to freed ids ({page_map_term:.0} B \
         is page-map growth across the window)"
    );
    assert!(
        gc_report.reclaimed > 0,
        "the GC pass must actually have reclaimed the purged versions"
    );
    assert!(
        delta > 0.0,
        "a retention purge must inflate the per-commit catalog image through the free list: \
         {:.0} B -> {:.0} B",
        cat(&before),
        cat(&after),
    );
    // The data records a reading writes are unchanged — the purge did not make the READING more
    // expensive, it made every COMMIT more expensive.
    for owner in [
        PageOwner::Node,
        PageOwner::Rel,
        PageOwner::Prop,
        PageOwner::Strings,
    ] {
        let a = before
            .by_owner
            .get(&owner)
            .copied()
            .unwrap_or_default()
            .bytes;
        let b = after
            .by_owner
            .get(&owner)
            .copied()
            .unwrap_or_default()
            .bytes;
        assert!(
            a > 0.0 && (a - b).abs() / a < 0.10,
            "the purge must not change the {} bytes a reading costs ({a:.0} B -> {b:.0} B); it \
             inflates the CATALOG, not the data",
            owner.name(),
        );
    }
    // And the freed ids really are being counted in 8-byte units: the implied count must be on the
    // order of the records the purge reclaimed, not orders of magnitude away.
    assert!(
        implied_ids > 0.25 * gc_report.reclaimed as f64,
        "the catalog growth implies only ~{implied_ids:.0} freed ids, but the GC pass reclaimed {} \
         versions — the free-list attribution does not hold and must not be reported",
        gc_report.reclaimed,
    );
}
