//! A full-text index that is **not `Online`** must never answer a query (`rmp` task #733).
//!
//! # The defect these tests pin
//!
//! `CREATE FULLTEXT INDEX` over a populated store registers the index [`IndexState::Populating`] and
//! builds it **incrementally** — bounded chunks of nodes between engine commands, so a build never
//! monopolises the single engine thread. The inline query seam
//! (`RecordStoreGraph::fulltext_query`) resolved the index **by name and read its postings without ever
//! consulting the index state**, so a query arriving before the build finished read an empty (or
//! half-filled) inverted index and returned a *strict subset* of the true matches — **silently**, as an
//! ordinary empty result. Reproduced in production against a 53k-node store: a query that must return
//! 230 rows returned `0` immediately after the bulk import + `CREATE FULLTEXT INDEX`, and 230 rows five
//! seconds later, with no write in between.
//!
//! That is a silent false negative — a committed row a query cannot see — which is an ACID-correctness
//! defect, not a performance wrinkle. It was also a divergence *between execution paths*: the off-thread
//! reader (`ReadOnlyGraph::fulltext_query`) always recomputes from an MVCC scan and was therefore
//! correct, so the same query returned different answers depending on which thread ran it.
//!
//! # The contract these tests enforce
//!
//! An index that is not `Online` is **not used** — the engine falls back to the snapshot-correct
//! full-text scan, which is declaredly equivalent (same rows, same SSI footprint). This is exactly the
//! contract the planner already applies to every other index kind (`TxnCoordinator::catalog()` exposes
//! only `Online` indexes, so a `Populating` one degrades to a label scan + filter), and the same one
//! PostgreSQL applies with `indisvalid = false`. The procedure surface bypasses the planner, so it must
//! apply the contract itself.
//!
//! The harness mirrors `tests/fulltext_coordinator.rs`: a real storage-backed [`TxnCoordinator`] over a
//! `MemBlockDevice` / `MemLogSink`, which is the path the bug lives on (the inline seam).

use graphus_core::{TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_index::fulltext::Analyzer;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

/// Matching articles: every one carries the term `investigadores` as a standalone word.
const MATCHING: usize = 230;
/// Non-matching articles, so the build has plenty of work and the true set is a strict subset.
const NON_MATCHING: usize = 420;
/// Articles that share only the SECOND search term, so a two-term search yields two distinct scores.
const PARTIAL: usize = 40;

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, 64, 1).expect("create store");
    TxnCoordinator::new(store)
}

/// Compiles against the coordinator's **real catalog** (`rmp` task #733), never `IndexCatalog::empty()`:
/// an empty catalog means the planner emits no index seek at all, so a test can pass on an engine whose
/// seek gates do not exist. The queries here are `CALL` procedures and label scans (which bypass the
/// planner's index selection anyway), but the harness must not model an engine that cannot plan.
fn compile(coord: &Coord, src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &coord.catalog())
}

fn run_plan(coord: &Coord, txn: TxnId, plan: &PhysicalPlan) -> Vec<Row> {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    assert!(
        !graph.has_error(),
        "statement captured an error: {:?}",
        graph.take_error()
    );
    rows
}

fn write(coord: &mut Coord, src: &str) {
    let plan = compile(coord, src);
    let txn = coord.begin_serializable();
    let _ = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("commit write");
}

fn read(coord: &mut Coord, src: &str) -> Vec<Row> {
    let plan = compile(coord, src);
    let txn = coord.begin_serializable();
    let rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("read commits");
    rows
}

fn ids_of(rows: &[Row], column: &str) -> Vec<u64> {
    let mut ids: Vec<u64> = rows
        .iter()
        .map(|r| match r.value(column) {
            Value::Integer(i) => i as u64,
            other => panic!("expected an integer id in {column:?}, got {other:?}"),
        })
        .collect();
    ids.sort_unstable();
    ids
}

/// Seeds the store in **three** bulk statements (one transaction each), so the build has far more nodes
/// than one chunk. `MATCHING` articles carry both search terms, `PARTIAL` carry only the second, and
/// `NON_MATCHING` carry neither.
fn seed(coord: &mut Coord) {
    write(
        coord,
        &format!(
            "UNWIND range(1, {MATCHING}) AS i \
             CREATE (:Article {{title: 'investigadores relatorio numero ' + toString(i), \
                                slug: 'match-' + toString(i)}})"
        ),
    );
    write(
        coord,
        &format!(
            "UNWIND range(1, {PARTIAL}) AS i \
             CREATE (:Article {{title: 'relatorio anual numero ' + toString(i), \
                                slug: 'partial-' + toString(i)}})"
        ),
    );
    write(
        coord,
        &format!(
            "UNWIND range(1, {NON_MATCHING}) AS i \
             CREATE (:Article {{title: 'noticia diversa numero ' + toString(i), \
                                slug: 'other-' + toString(i)}})"
        ),
    );
}

/// Declares the full-text index **without** driving its build: it stays `Populating`, its inverted
/// index empty. This is precisely the window the production repro hit.
fn declare_index(coord: &mut Coord) {
    coord
        .create_fulltext_index(
            "article_headline_fulltext",
            &["Article".to_owned()],
            &["title".to_owned()],
            Analyzer::Standard,
            false,
        )
        .expect("create fulltext index");
    assert!(
        coord.has_pending_index_builds(),
        "INVARIANT: a full-text index over a populated store must build incrementally, \
         so a build must be pending here — otherwise this test proves nothing"
    );
}

/// The ground truth, computed **without** the index: every visible `:Article` whose title carries the
/// term as a standalone word. `CONTAINS` and the analyzed term match coincide because the term is only
/// ever seeded as a whole word.
fn truth(coord: &mut Coord, term: &str) -> Vec<u64> {
    let rows = read(
        coord,
        &format!("MATCH (a:Article) WHERE a.title CONTAINS '{term}' RETURN id(a) AS id"),
    );
    ids_of(&rows, "id")
}

/// The full-text procedure's answer (node ids only).
fn fulltext_ids(coord: &mut Coord, search: &str) -> Vec<u64> {
    let rows = read(
        coord,
        &format!(
            "CALL db.index.fulltext.queryNodes('article_headline_fulltext', '{search}') \
             YIELD node RETURN id(node) AS id"
        ),
    );
    ids_of(&rows, "id")
}

/// The full-text procedure's answer **with scores**, in the procedure's own relevance order.
fn fulltext_scored(coord: &mut Coord, search: &str) -> Vec<(u64, i64)> {
    let rows = read(
        coord,
        &format!(
            "CALL db.index.fulltext.queryNodes('article_headline_fulltext', '{search}') \
             YIELD node, score RETURN id(node) AS id, score AS score"
        ),
    );
    rows.iter()
        .map(|r| {
            let id = match r.value("id") {
                Value::Integer(i) => i as u64,
                other => panic!("expected an integer id, got {other:?}"),
            };
            // The procedure emits the score as a Float (Neo4j-compatible); it is integral by
            // construction (a count of distinct matched terms).
            let score = match r.value("score") {
                Value::Float(f) => f as i64,
                Value::Integer(i) => i,
                other => panic!("expected a numeric score, got {other:?}"),
            };
            (id, score)
        })
        .collect()
}

fn drive_build_to_completion(coord: &mut Coord) {
    let mut iters = 0;
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(64);
        iters += 1;
        assert!(iters < 100_000, "the build must terminate");
    }
}

// =================================================================================================
// Node full-text
// =================================================================================================

/// **The headline regression** (`rmp` task #733): a query issued BEFORE the incremental build has
/// indexed a single node must still return the exact true set — never zero rows, never a subset.
///
/// Against the pre-fix engine this returned `0` rows while the truth was 230, exactly as reproduced in
/// production.
#[test]
fn query_before_the_build_starts_returns_the_true_set() {
    let mut coord = fresh_coord();
    seed(&mut coord);
    let expected = truth(&mut coord, "investigadores");
    assert_eq!(
        expected.len(),
        MATCHING,
        "the ground truth must be the seeded matching set"
    );

    declare_index(&mut coord);

    // NOT ONE chunk of the build has run: the inverted index is empty. The query must therefore be
    // served by the snapshot-correct scan fallback, which returns exactly the true set.
    let got = fulltext_ids(&mut coord, "investigadores");
    assert!(
        !got.is_empty(),
        "a Populating full-text index must never answer with a silently-empty result"
    );
    assert_eq!(
        got, expected,
        "a query against a not-yet-built full-text index must return the SAME rows the scan returns"
    );
}

/// The most treacherous phase: the build has indexed *some* nodes, so the inverted index would answer
/// with a plausible-looking — but strictly partial — result set.
#[test]
fn query_mid_build_returns_the_true_set() {
    let mut coord = fresh_coord();
    seed(&mut coord);
    let expected = truth(&mut coord, "investigadores");

    declare_index(&mut coord);

    // One bounded chunk: the index now holds a PREFIX of the build snapshot — the partial state that
    // makes this defect so easy to miss (a non-empty, wrong answer).
    coord.advance_index_builds(64);
    assert!(
        coord.has_pending_index_builds(),
        "INVARIANT: one 64-node chunk must not finish a build over {} nodes",
        MATCHING + PARTIAL + NON_MATCHING
    );

    let got = fulltext_ids(&mut coord, "investigadores");
    assert_eq!(
        got, expected,
        "a half-built full-text index must not answer with a partial row set"
    );
}

/// Once the build completes the index is `Online` and serves the query from its postings — and must
/// agree, row for row, with what the fallback returned while it was `Populating`.
#[test]
fn the_online_index_agrees_with_the_populating_fallback() {
    let mut coord = fresh_coord();
    seed(&mut coord);
    let expected = truth(&mut coord, "investigadores");

    declare_index(&mut coord);
    let while_populating = fulltext_ids(&mut coord, "investigadores");
    drive_build_to_completion(&mut coord);
    let when_online = fulltext_ids(&mut coord, "investigadores");

    assert_eq!(while_populating, expected);
    assert_eq!(
        when_online, expected,
        "the Online index must return the same rows as the scan fallback"
    );
}

/// The **score** needs the same gate as the rows (`rmp` task #733). With only the row path fixed, a
/// query against a `Populating` index would return the right rows (via the fallback) but score every
/// one of them `0` — the inverted index has no terms for them — silently destroying the relevance order
/// the procedure sorts by, and any `ORDER BY score` the caller writes.
#[test]
fn scores_while_populating_match_the_online_scores() {
    let mut coord = fresh_coord();
    seed(&mut coord);
    declare_index(&mut coord);

    // A two-term search: the MATCHING articles carry both terms (score 2), the PARTIAL ones only
    // `relatorio` (score 1). So a correct score is discriminating, and a broken one collapses to 0.
    let while_populating = fulltext_scored(&mut coord, "investigadores relatorio");
    drive_build_to_completion(&mut coord);
    let when_online = fulltext_scored(&mut coord, "investigadores relatorio");

    assert_eq!(
        while_populating.len(),
        MATCHING + PARTIAL,
        "both term groups must match under the `Or` semantics"
    );
    assert_eq!(
        while_populating, when_online,
        "the scores (and the relevance order) served while Populating must equal the Online ones"
    );

    // The scores must actually discriminate: two distinct values, ordered descending.
    let scores: Vec<i64> = while_populating.iter().map(|(_, s)| *s).collect();
    assert!(
        scores.contains(&2) && scores.contains(&1),
        "expected both a two-term and a one-term match, got {scores:?}"
    );
    assert!(
        scores.windows(2).all(|w| w[0] >= w[1]),
        "the procedure must order by descending relevance, got {scores:?}"
    );
    assert!(
        !scores.contains(&0),
        "a score of 0 means the postings were read from an index that has none — the defect"
    );
}

/// Writes performed *while* the index is `Populating` are maintained by the write path, so they must be
/// visible to the query too — through the fallback, at this snapshot.
#[test]
fn a_write_during_the_build_is_visible_to_the_query() {
    let mut coord = fresh_coord();
    seed(&mut coord);
    declare_index(&mut coord);
    coord.advance_index_builds(64);

    write(
        &mut coord,
        "CREATE (:Article {title: 'investigadores recem chegados', slug: 'fresh'})",
    );

    let expected = truth(&mut coord, "investigadores");
    assert_eq!(expected.len(), MATCHING + 1);
    assert_eq!(
        fulltext_ids(&mut coord, "investigadores"),
        expected,
        "a node created during the build must be found by a query issued during the build"
    );
}

/// A deleted node must not resurface through the fallback either (the fallback re-checks MVCC
/// visibility exactly as the index path's candidate re-check does).
#[test]
fn a_delete_during_the_build_is_honoured_by_the_query() {
    let mut coord = fresh_coord();
    seed(&mut coord);
    declare_index(&mut coord);

    write(&mut coord, "MATCH (a:Article {slug: 'match-1'}) DELETE a");

    let expected = truth(&mut coord, "investigadores");
    assert_eq!(expected.len(), MATCHING - 1);
    assert_eq!(fulltext_ids(&mut coord, "investigadores"), expected);
}
