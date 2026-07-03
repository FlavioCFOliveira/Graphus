//! Regression tests for the WAL on-disk write-amplification bound (`rmp` #556).
//!
//! The finding: the on-disk WAL was 7–60x the store size on every workload because the *only*
//! reclaiming maintenance checkpoint fired at a fixed absolute 256 MiB threshold, independent of
//! store size — so any store smaller than that was left with a WAL up to `256 MiB / store` times its
//! size. The empirical breakdown (measured through this exact coordinator seam) showed the entire
//! ratio is un-reclaimed *transient* WAL: after one checkpoint the retained WAL collapses to the
//! anchor header (`rmp` #315 made reclamation *work*; #556 makes its *cadence* proportional to the
//! store so the ratio stays bounded).
//!
//! These tests pin both halves:
//!  1. `reclamation_collapses_the_retained_wal` — a checkpoint physically frees the whole transient
//!     WAL prefix (guards the #315 reclamation property against a regression).
//!  2. `adaptive_cadence_bounds_the_wal_store_ratio` — under a sustained OLTP write stream, the
//!     adaptive `WAL_STORE_RATIO_TARGET × store` cadence keeps the on-disk WAL/store ratio bounded,
//!     where the historical fixed 256 MiB cadence let it grow unbounded (guards the #556 bound).
//!
//! The adaptive-interval formula is replicated here from `graphus-server`'s `maintenance_interval_bytes`
//! (`WAL_STORE_RATIO_TARGET = 4`, floor 8 MiB, cap 256 MiB); the production wiring itself is pinned by
//! `graphus_server::engine::maintenance_tests::ordinary_cadence_is_adaptive_and_loading_stays_wide`.

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
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{HEADER_LEN, LogRecord, MemLogSink, RecordType, WalManager};

use std::collections::BTreeMap;

type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

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

fn fresh() -> Coord {
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

    fn insert_committed(&self, coord: &mut Coord, id: i64) {
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

fn store_bytes(coord: &Coord) -> u64 {
    coord.store_byte_len()
}

fn wal_retained(coord: &Coord) -> usize {
    coord.with_store_mut(|s| s.with_wal(|w| w.sink().retained_bytes()))
}

fn wal_image(coord: &Coord) -> Vec<u8> {
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
    let mut coord = fresh();
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
        let mut coord = fresh();
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
