//! Vector indexing: an approximate-nearest-neighbour (ANN) index over dense float embeddings,
//! built on the **HNSW** (Hierarchical Navigable Small World) graph (`rmp` task #668).
//!
//! This is **Part A** of the `VECTOR` index: the self-contained graph data structure, with no
//! storage or DDL coupling. Like the full-text ([`crate::fulltext`]) and spatial
//! ([`crate::spatial`]) indexes it is a pure, store-independent structure — unit-testable in
//! isolation (no store, no WAL, no buffer pool). The transactional maintenance, MVCC re-check and
//! catalog durability are layered on later in `graphus-cypher`/`graphus-storage`; the graph itself
//! is ephemeral and rebuilt from the store on open, so it needs no separate crash-recovery path.
//!
//! Like every other index kind in this crate it is generic over the **element id** ([`u64`]), so it
//! serves both nodes and relationships without change.
//!
//! # Algorithm
//!
//! HNSW (Malkov & Yashunin, 2016, *"Efficient and robust approximate nearest neighbor search using
//! Hierarchical Navigable Small World graphs"*, IEEE TPAMI; arXiv:1603.09320) is a multi-layer
//! proximity graph. Each element lives on layer `0` and, with exponentially decaying probability, on
//! a tower of upper layers. A search enters at the single top-layer entry point, greedily descends
//! the sparse upper layers to home in on the query's neighbourhood, then does a wider best-first
//! search on the dense bottom layer. This gives poly-logarithmic expected search cost while keeping
//! recall high — the structure Neo4j's own vector index uses.
//!
//! ## Parameters
//!
//! - `m` — target out-degree per element per upper layer. Layer `0` uses `m_max0 = 2 * m` (denser
//!   base layer improves recall), following the paper's recommendation.
//! - `ef_construction` — the size of the dynamic candidate list kept while *inserting*. Larger =
//!   better-quality graph (higher recall) at higher build cost.
//! - `ef_search` — the candidate-list size at *query* time (passed per query). Larger = higher
//!   recall, slower query. Always raised to at least `k`.
//! - `m_l = 1 / ln(m)` — the level-generation normalisation factor. A new element's top layer is
//!   `floor(-ln(U) * m_l)` for `U` uniform in `(0, 1)`, i.e. a geometric distribution with the mean
//!   the paper prescribes.
//!
//! The RNG is a seeded [`SplitMix64`]: for a fixed seed and insertion order the level sequence — and
//! therefore the whole graph and every query result — is bit-for-bit reproducible. Determinism is a
//! hard requirement of this crate's tests (and useful for the project's deterministic simulator).
//!
//! # Distances and the similarity score
//!
//! Two metrics are supported via the [`Similarity`] enum. Internally the graph navigates by a
//! *distance* (smaller = closer); the public API returns a *score* in `(0, 1]` where higher = more
//! similar, matching the Neo4j convention.
//!
//! - **Cosine** — vectors are unit-normalised on insert, so the stored dot product *is* the cosine.
//!   Navigation distance is `1 - cos`. The returned score is
//!   `(1 + cos) / 2`.
//! - **Euclidean** — navigation distance is the squared L2 distance `‖v - u‖²` (monotonic with the
//!   true distance, so it preserves k-NN order, and cheaper — no `sqrt`). The returned score is
//!   `1 / (1 + ‖v - u‖²)`.
//!
//! Both score formulas are taken verbatim from the Neo4j Cypher manual, vector index documentation:
//! <https://neo4j.com/docs/cypher-manual/current/indexes/semantic-indexes/vector-indexes/>
//! (cosine: "half of the quantity 1 plus the scalar product of v̂ û"; euclidean: "1 over the quantity
//! 1 plus the square of the l2-norm of vector v subtract vector u"). This is what
//! `vector.similarity.cosine` / `vector.similarity.euclidean` return.

use std::cmp::Ordering;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::collections::HashSet;

/// Default target out-degree per layer (`m`). `16` is the common HNSW default (also Neo4j's).
pub const DEFAULT_M: usize = 16;

/// Default construction-time candidate-list size (`ef_construction`).
pub const DEFAULT_EF_CONSTRUCTION: usize = 200;

/// Default query-time candidate-list size (`ef_search`).
pub const DEFAULT_EF_SEARCH: usize = 100;

/// Hard cap on an element's top layer, guarding against a pathological RNG draw producing an absurd
/// tower. The geometric level distribution makes a level this high astronomically unlikely (for
/// `m = 16`, `P(level >= 32)` is ~`10⁻⁷`), so the cap never affects recall in practice; it only
/// bounds worst-case memory per element.
const MAX_LEVEL: usize = 32;

/// The similarity metric a [`VectorIndex`] uses. Fixed at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Similarity {
    /// Cosine similarity. Vectors are unit-normalised on insert; the score is `(1 + cos) / 2`.
    Cosine,
    /// Euclidean similarity. The score is `1 / (1 + ‖v - u‖²)`.
    Euclidean,
}

/// Errors returned by [`VectorIndex`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VectorIndexError {
    /// The index was constructed with a zero dimension, which is meaningless.
    ZeroDimension,
    /// A vector passed to `insert`/`update`/`query_knn` did not match the index's dimension.
    DimensionMismatch {
        /// The dimension the index was built with.
        expected: usize,
        /// The dimension of the offending vector.
        got: usize,
    },
}

impl std::fmt::Display for VectorIndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VectorIndexError::ZeroDimension => {
                write!(f, "vector index dimension must be greater than zero")
            }
            VectorIndexError::DimensionMismatch { expected, got } => {
                write!(
                    f,
                    "vector dimension mismatch: index expects {expected}, got {got}"
                )
            }
        }
    }
}

impl std::error::Error for VectorIndexError {}

/// A `(distance, slot)` pair with a total order by distance (ascending), ties broken by slot.
///
/// The slot tie-break makes every comparison total and deterministic — essential because the whole
/// index's determinism guarantee rests on heap and sort operations being reproducible. `f32`
/// distances are compared with [`f32::total_cmp`], so `NaN` never poisons the order.
#[derive(Debug, Clone, Copy)]
struct Candidate {
    dist: f32,
    slot: u32,
}

impl PartialEq for Candidate {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Candidate {}
impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.dist
            .total_cmp(&other.dist)
            .then_with(|| self.slot.cmp(&other.slot))
    }
}

/// One indexed element: its external id, its stored vector, and its per-layer adjacency.
#[derive(Debug, Clone)]
struct Element {
    /// The external element id (node or relationship).
    id: u64,
    /// The stored vector: unit-normalised for [`Similarity::Cosine`], raw for [`Similarity::Euclidean`].
    vector: Vec<f32>,
    /// `neighbours[layer]` = the element's adjacency (internal slots) at that layer. The element
    /// exists on layers `0..neighbours.len()`, so `neighbours.len() - 1` is its top layer.
    neighbours: Vec<Vec<u32>>,
}

/// A seedable [`SplitMix64`] PRNG (Steele, Lea & Flood, 2014).
///
/// Chosen over the `rand` crate to keep `graphus-index` dependency-free: it is a few lines, has no
/// `unsafe`, and — being fully seeded — gives the reproducible level sequence the determinism tests
/// require. Statistical quality is more than adequate for HNSW level assignment (its only use here).
#[derive(Debug, Clone)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A `f64` strictly inside the open interval `(0, 1)`.
    ///
    /// 53 random mantissa bits are mapped by `(bits + 0.5) / 2^53`, which keeps the result strictly
    /// away from both `0` (so `ln` never yields `-inf`) and `1`.
    fn open_unit(&mut self) -> f64 {
        let bits = self.next_u64() >> 11; // top 53 bits
        (bits as f64 + 0.5) * (1.0 / ((1u64 << 53) as f64))
    }
}

/// The navigation distance between two prepared vectors under `similarity` (smaller = closer).
///
/// For [`Similarity::Cosine`] the inputs are already unit-normalised, so `1 - dot` is the cosine
/// distance. For [`Similarity::Euclidean`] this is the *squared* L2 distance, which is monotonic
/// with the true distance (so k-NN order is preserved) and avoids a `sqrt`.
#[inline]
fn distance(similarity: Similarity, a: &[f32], b: &[f32]) -> f32 {
    match similarity {
        Similarity::Cosine => {
            let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
            1.0 - dot
        }
        Similarity::Euclidean => a
            .iter()
            .zip(b)
            .map(|(x, y)| {
                let d = x - y;
                d * d
            })
            .sum(),
    }
}

/// Maps a navigation [`distance`] to the Neo4j similarity score in `(0, 1]` (higher = more similar).
///
/// See the module docs for the source: cosine `(1 + cos) / 2`, euclidean `1 / (1 + ‖v - u‖²)`.
#[inline]
fn score(similarity: Similarity, dist: f32) -> f32 {
    match similarity {
        // dist = 1 - cos  =>  cos = 1 - dist  =>  (1 + cos) / 2 = 1 - dist/2.
        Similarity::Cosine => (1.0 - dist * 0.5).clamp(0.0, 1.0),
        // dist is the squared L2 distance = ‖v - u‖².
        Similarity::Euclidean => 1.0 / (1.0 + dist),
    }
}

/// Unit-normalises `v` for cosine (leaving a zero/degenerate/non-finite-norm vector untouched — its dot
/// product with anything is `0`).
///
/// Shared by [`VectorIndex::prepare_vector`] (the query/insert path) and [`similarity_score`] (the
/// `vector.similarity.cosine` function), so both fold the identical arithmetic and can never drift.
#[inline]
fn normalize_cosine(v: &[f32]) -> Vec<f32> {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 && norm.is_finite() {
        v.iter().map(|x| x / norm).collect()
    } else {
        v.to_vec()
    }
}

/// The Neo4j vector-similarity **score** in `[0, 1]` between two raw (un-normalised) vectors `a` and
/// `b` under `similarity` — the exact value the `vector.similarity.cosine` /
/// `vector.similarity.euclidean` Cypher functions return (`rmp` task #671).
///
/// This is the standalone-function twin of the score a [`VectorIndex::query_knn`] hit carries: it
/// reuses the index's own [`distance`] + [`score`] arithmetic, so a function call and an index hit can
/// never drift. For [`Similarity::Cosine`] both vectors are unit-normalised first (a zero/degenerate
/// vector is left untouched, its dot product with anything being `0`, so its score is `0.5`); the
/// result is `(1 + cos) / 2`. For [`Similarity::Euclidean`] the raw squared L2 distance is used; the
/// result is `1 / (1 + ‖a - b‖²)`.
///
/// `a` and `b` must have the same length — the caller (the function body) validates the dimension and
/// element finiteness before calling; a length mismatch here would silently zip to the shorter vector.
///
/// # Examples
///
/// ```
/// use graphus_index::{Similarity, similarity_score};
///
/// // Identical vectors: cosine score is 1.0.
/// assert!((similarity_score(Similarity::Cosine, &[3.0, 4.0], &[3.0, 4.0]) - 1.0).abs() < 1e-6);
/// // Orthogonal vectors: cosine score is 0.5.
/// assert!((similarity_score(Similarity::Cosine, &[1.0, 0.0], &[0.0, 1.0]) - 0.5).abs() < 1e-6);
/// // Squared L2 distance 4: euclidean score is 1/(1+4) = 0.2.
/// assert!((similarity_score(Similarity::Euclidean, &[0.0], &[2.0]) - 0.2).abs() < 1e-6);
/// ```
#[must_use]
pub fn similarity_score(similarity: Similarity, a: &[f32], b: &[f32]) -> f32 {
    match similarity {
        Similarity::Cosine => {
            let (na, nb) = (normalize_cosine(a), normalize_cosine(b));
            score(similarity, distance(similarity, &na, &nb))
        }
        Similarity::Euclidean => score(similarity, distance(similarity, a, b)),
    }
}

/// An HNSW approximate-nearest-neighbour index over fixed-dimension `f32` embeddings.
///
/// See the [module docs](self) for the algorithm, parameters and score formulas.
///
/// # Examples
///
/// ```
/// use graphus_index::{Similarity, VectorIndex};
///
/// let mut idx = VectorIndex::new(3, Similarity::Cosine, 16, 200, 42).unwrap();
/// idx.insert(1, &[1.0, 0.0, 0.0]).unwrap();
/// idx.insert(2, &[0.0, 1.0, 0.0]).unwrap();
/// idx.insert(3, &[0.9, 0.1, 0.0]).unwrap();
///
/// let hits = idx.query_knn(&[1.0, 0.0, 0.0], 2, 50).unwrap();
/// assert_eq!(hits[0].0, 1); // exact match ranks first
/// assert!(hits[0].1 >= hits[1].1); // scores are descending
/// ```
#[derive(Debug, Clone)]
pub struct VectorIndex {
    dim: usize,
    similarity: Similarity,
    /// Target out-degree on layers `>= 1`.
    m: usize,
    /// Out-degree cap on layer `0` (`2 * m`).
    m_max0: usize,
    ef_construction: usize,
    /// Level-generation factor `1 / ln(m)`.
    m_l: f64,
    /// The current top-layer entry point (an internal slot), or `None` when empty.
    entry: Option<u32>,
    /// The highest layer currently occupied (only meaningful when `entry` is `Some`).
    max_layer: usize,
    /// Slab of elements; `None` marks a freed slot. Slots are never shifted, so adjacency slots stay
    /// valid across removals.
    slab: Vec<Option<Element>>,
    /// Free list of reusable slots (freed by [`VectorIndex::remove`]).
    free: Vec<u32>,
    /// External id -> internal slot.
    id_to_slot: HashMap<u64, u32>,
    rng: SplitMix64,
    len: usize,
}

impl VectorIndex {
    /// Creates an empty index.
    ///
    /// - `dim` — the embedding dimension (must be `> 0`).
    /// - `similarity` — the metric ([`Similarity::Cosine`] or [`Similarity::Euclidean`]).
    /// - `m` — target out-degree per layer; clamped up to a minimum of `2` (`m_l = 1/ln(m)` requires
    ///   `m >= 2`). Layer `0` uses `2 * m`.
    /// - `ef_construction` — construction candidate-list size; clamped up to a minimum of `1`.
    /// - `seed` — RNG seed; a fixed seed makes builds reproducible.
    ///
    /// # Errors
    ///
    /// Returns [`VectorIndexError::ZeroDimension`] if `dim == 0`.
    pub fn new(
        dim: usize,
        similarity: Similarity,
        m: usize,
        ef_construction: usize,
        seed: u64,
    ) -> Result<Self, VectorIndexError> {
        if dim == 0 {
            return Err(VectorIndexError::ZeroDimension);
        }
        let m = m.max(2);
        let ef_construction = ef_construction.max(1);
        Ok(Self {
            dim,
            similarity,
            m,
            m_max0: m * 2,
            ef_construction,
            m_l: 1.0 / (m as f64).ln(),
            entry: None,
            max_layer: 0,
            slab: Vec::new(),
            free: Vec::new(),
            id_to_slot: HashMap::new(),
            rng: SplitMix64::new(seed),
            len: 0,
        })
    }

    /// Creates an empty index with the default tuning ([`DEFAULT_M`], [`DEFAULT_EF_CONSTRUCTION`]).
    ///
    /// # Errors
    ///
    /// Returns [`VectorIndexError::ZeroDimension`] if `dim == 0`.
    pub fn with_defaults(
        dim: usize,
        similarity: Similarity,
        seed: u64,
    ) -> Result<Self, VectorIndexError> {
        Self::new(dim, similarity, DEFAULT_M, DEFAULT_EF_CONSTRUCTION, seed)
    }

    /// The embedding dimension this index was built with.
    #[must_use]
    pub fn dim(&self) -> usize {
        self.dim
    }

    /// The similarity metric this index uses.
    #[must_use]
    pub fn similarity(&self) -> Similarity {
        self.similarity
    }

    /// The number of elements currently indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the index holds no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether `id` is currently indexed.
    #[must_use]
    pub fn contains(&self, id: u64) -> bool {
        self.id_to_slot.contains_key(&id)
    }

    /// Removes every element, keeping the configured parameters and RNG position.
    pub fn clear(&mut self) {
        self.slab.clear();
        self.free.clear();
        self.id_to_slot.clear();
        self.entry = None;
        self.max_layer = 0;
        self.len = 0;
    }

    /// Inserts (or replaces) the embedding for `id`.
    ///
    /// If `id` is already present its old vector is removed first (**last write wins**), so this is
    /// also the in-place `update` primitive — see [`VectorIndex::update`].
    ///
    /// # Errors
    ///
    /// Returns [`VectorIndexError::DimensionMismatch`] if `vector.len() != self.dim()`.
    pub fn insert(&mut self, id: u64, vector: &[f32]) -> Result<(), VectorIndexError> {
        if vector.len() != self.dim {
            return Err(VectorIndexError::DimensionMismatch {
                expected: self.dim,
                got: vector.len(),
            });
        }
        // Last-wins: drop any prior version so the graph never holds two entries for one id.
        if self.id_to_slot.contains_key(&id) {
            self.remove(id);
        }

        let level = self.random_level();
        let prepared = self.prepare_vector(vector);
        let slot = self.alloc_slot(Element {
            id,
            vector: prepared,
            neighbours: vec![Vec::new(); level + 1],
        });
        self.id_to_slot.insert(id, slot);
        self.len += 1;

        let entry = match self.entry {
            None => {
                // First element becomes the entry point.
                self.entry = Some(slot);
                self.max_layer = level;
                return Ok(());
            }
            Some(e) => e,
        };

        // The query vector for this insertion (owned, so later mutations don't alias the slab).
        let q = self.slab[slot as usize]
            .as_ref()
            .expect("INVARIANT: slot just allocated")
            .vector
            .clone();

        let top = self.max_layer;

        // Phase 1: greedily descend the layers above the new element with ef = 1.
        let mut ep = entry;
        for lc in (level + 1..=top).rev() {
            let w = self.search_layer(&q, &[ep], 1, lc);
            if let Some(best) = w.first() {
                ep = best.slot;
            }
        }

        // Phase 2: from min(top, level) down to 0, search wide and wire up bidirectional links.
        let mut ep_set = vec![ep];
        for lc in (0..=top.min(level)).rev() {
            let w = self.search_layer(&q, &ep_set, self.ef_construction, lc);
            let selected = self.select_neighbours(&q, &w, self.m);

            let m_max = if lc == 0 { self.m_max0 } else { self.m };
            for &nb in &selected {
                self.add_link(slot, nb, lc);
                self.add_link(nb, slot, lc);
                // Keep the neighbour's degree bounded, re-selecting with the same heuristic.
                self.prune_neighbours(nb, lc, m_max);
            }

            ep_set = w.iter().map(|c| c.slot).collect();
            if ep_set.is_empty() {
                ep_set.push(ep);
            }
        }

        if level > self.max_layer {
            self.max_layer = level;
            self.entry = Some(slot);
        }
        Ok(())
    }

    /// Updates the embedding for `id` (an alias for [`VectorIndex::insert`], which is last-wins).
    ///
    /// # Errors
    ///
    /// Returns [`VectorIndexError::DimensionMismatch`] if `vector.len() != self.dim()`.
    pub fn update(&mut self, id: u64, vector: &[f32]) -> Result<(), VectorIndexError> {
        self.insert(id, vector)
    }

    /// Removes `id` from the index, returning whether it was present.
    ///
    /// The hole the removed element leaves in the proximity graph is *repaired*: its neighbours are
    /// cross-linked (bidirectionally) so the local neighbourhood stays connected, then each is pruned
    /// back to its degree cap with the same heuristic used on insert. The slot is returned to the
    /// free list, so memory is reclaimed (no tombstone build-up under update-heavy workloads).
    pub fn remove(&mut self, id: u64) -> bool {
        let slot = match self.id_to_slot.remove(&id) {
            Some(s) => s,
            None => return false,
        };
        let top = self.slab[slot as usize]
            .as_ref()
            .expect("INVARIANT: id_to_slot points at a live slot")
            .neighbours
            .len()
            - 1;

        for lc in 0..=top {
            let friends = self.slab[slot as usize]
                .as_ref()
                .expect("live slot")
                .neighbours[lc]
                .clone();

            // 1. Unlink the removed element from each friend.
            for &f in &friends {
                self.remove_link(f, slot, lc);
            }
            // 2. Bridge the hole: cross-link the removed element's friends to each other.
            for i in 0..friends.len() {
                for j in (i + 1)..friends.len() {
                    self.add_link(friends[i], friends[j], lc);
                    self.add_link(friends[j], friends[i], lc);
                }
            }
            // 3. Re-prune every friend back to its degree cap.
            let m_max = if lc == 0 { self.m_max0 } else { self.m };
            for &f in &friends {
                self.prune_neighbours(f, lc, m_max);
            }
        }

        self.slab[slot as usize] = None;
        self.free.push(slot);
        self.len -= 1;

        if self.entry == Some(slot) {
            self.reselect_entry();
        }
        true
    }

    /// Returns the `k` nearest indexed elements to `query`, as `(id, score)` pairs sorted by
    /// **descending score** (ties broken by ascending id for a stable order).
    ///
    /// `ef_search` is the candidate-list size; it is raised to at least `k`. Larger values trade
    /// query time for recall. Fewer than `k` results are returned when the index holds fewer than
    /// `k` elements (in particular an empty index, or `k == 0`, returns an empty vector).
    ///
    /// # Errors
    ///
    /// Returns [`VectorIndexError::DimensionMismatch`] if `query.len() != self.dim()`.
    #[must_use = "the k-NN result is the whole point of the query"]
    pub fn query_knn(
        &self,
        query: &[f32],
        k: usize,
        ef_search: usize,
    ) -> Result<Vec<(u64, f32)>, VectorIndexError> {
        if query.len() != self.dim {
            return Err(VectorIndexError::DimensionMismatch {
                expected: self.dim,
                got: query.len(),
            });
        }
        if self.len == 0 || k == 0 {
            return Ok(Vec::new());
        }

        let q = self.prepare_vector(query);
        let mut ep = self
            .entry
            .expect("INVARIANT: non-empty index has an entry point");

        // Descend the sparse upper layers with ef = 1.
        for lc in (1..=self.max_layer).rev() {
            let w = self.search_layer(&q, &[ep], 1, lc);
            if let Some(best) = w.first() {
                ep = best.slot;
            }
        }

        // Wide best-first search on the dense base layer.
        let ef = ef_search.max(k);
        let w = self.search_layer(&q, &[ep], ef, 0);

        // `w` is ascending by (distance, slot) — i.e. nearest first. Take the k nearest, then present
        // them by descending score with id as a stable tie-break.
        let mut out: Vec<(u64, f32)> = w
            .iter()
            .take(k)
            .map(|c| {
                let id = self.slab[c.slot as usize].as_ref().expect("live slot").id;
                (id, score(self.similarity, c.dist))
            })
            .collect();
        out.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        Ok(out)
    }

    // --- internals -------------------------------------------------------------------------------

    /// Unit-normalises for cosine (leaving a zero/degenerate vector untouched — its dot product with
    /// anything is `0`), or copies verbatim for euclidean.
    fn prepare_vector(&self, v: &[f32]) -> Vec<f32> {
        match self.similarity {
            Similarity::Cosine => normalize_cosine(v),
            Similarity::Euclidean => v.to_vec(),
        }
    }

    /// Draws a new element's top layer from the geometric distribution `floor(-ln(U) * m_l)`, capped
    /// at [`MAX_LEVEL`].
    fn random_level(&mut self) -> usize {
        let u = self.rng.open_unit();
        let level = (-u.ln() * self.m_l).floor();
        // `level` is finite and >= 0 here (u in (0,1) => -ln(u) > 0), so the cast is well-defined.
        (level as usize).min(MAX_LEVEL)
    }

    /// The stored vector for a live slot.
    #[inline]
    fn vector_of(&self, slot: u32) -> &[f32] {
        &self.slab[slot as usize]
            .as_ref()
            .expect("INVARIANT: slot must be live")
            .vector
    }

    /// Allocates a slot (reusing a freed one when available) and stores `element` in it.
    fn alloc_slot(&mut self, element: Element) -> u32 {
        if let Some(slot) = self.free.pop() {
            self.slab[slot as usize] = Some(element);
            slot
        } else {
            let slot = u32::try_from(self.slab.len())
                .expect("INVARIANT: vector index capped at u32::MAX elements");
            self.slab.push(Some(element));
            slot
        }
    }

    /// Adds a directed link `from -> to` at layer `lc` (no self-loops, no duplicates).
    fn add_link(&mut self, from: u32, to: u32, lc: usize) {
        if from == to {
            return;
        }
        let el = self.slab[from as usize].as_mut().expect("live slot");
        let list = &mut el.neighbours[lc];
        if !list.contains(&to) {
            list.push(to);
        }
    }

    /// Removes the directed link `from -> to` at layer `lc`, if present.
    fn remove_link(&mut self, from: u32, to: u32, lc: usize) {
        if let Some(el) = self.slab[from as usize].as_mut() {
            el.neighbours[lc].retain(|&x| x != to);
        }
    }

    /// Best-first search of a single layer (HNSW `SEARCH-LAYER`).
    ///
    /// Returns up to `ef` candidates nearest to `q` on layer `lc`, reachable from `entry_points`,
    /// sorted ascending by `(distance, slot)`.
    fn search_layer(
        &self,
        q: &[f32],
        entry_points: &[u32],
        ef: usize,
        lc: usize,
    ) -> Vec<Candidate> {
        let mut visited: HashSet<u32> = HashSet::new();
        // `to_visit`: min-heap (nearest first) of candidates still to expand.
        let mut to_visit: BinaryHeap<Reverse<Candidate>> = BinaryHeap::new();
        // `found`: max-heap (farthest first) of the best `ef` found so far.
        let mut found: BinaryHeap<Candidate> = BinaryHeap::new();

        for &ep in entry_points {
            if visited.insert(ep) {
                let c = Candidate {
                    dist: distance(self.similarity, q, self.vector_of(ep)),
                    slot: ep,
                };
                to_visit.push(Reverse(c));
                found.push(c);
            }
        }
        while found.len() > ef {
            found.pop();
        }

        while let Some(Reverse(current)) = to_visit.pop() {
            // Once the nearest unexpanded candidate is farther than the farthest kept result, no
            // closer element can remain — stop.
            if let Some(farthest) = found.peek() {
                if current.dist > farthest.dist {
                    break;
                }
            }

            // Clone the small adjacency list so the immutable borrow of `self` ends before the loop
            // body reads other slots.
            let neighbours = self.slab[current.slot as usize]
                .as_ref()
                .expect("live slot")
                .neighbours[lc]
                .clone();
            for e in neighbours {
                if visited.insert(e) {
                    let d = distance(self.similarity, q, self.vector_of(e));
                    let admit = found.len() < ef || found.peek().is_none_or(|f| d < f.dist);
                    if admit {
                        let c = Candidate { dist: d, slot: e };
                        to_visit.push(Reverse(c));
                        found.push(c);
                        if found.len() > ef {
                            found.pop();
                        }
                    }
                }
            }
        }

        let mut out = found.into_vec();
        out.sort_unstable();
        out
    }

    /// The neighbour-selection heuristic (HNSW `SELECT-NEIGHBORS-HEURISTIC`, Algorithm 4) with
    /// `keepPrunedConnections = true`.
    ///
    /// Given candidates with their distance to the base vector `q`, greedily keeps a candidate only
    /// when it is closer to `q` than to any already-selected neighbour — diversifying directions so
    /// the graph stays navigable (the plain "m nearest" rule clusters neighbours on one side). If
    /// fewer than `m` survive, the nearest discarded ones backfill.
    fn select_neighbours(&self, _q: &[f32], candidates: &[Candidate], m: usize) -> Vec<u32> {
        let mut working = candidates.to_vec();
        working.sort_unstable(); // nearest first
        let mut result: Vec<u32> = Vec::with_capacity(m);
        let mut discarded: Vec<u32> = Vec::new();

        for cand in working {
            if result.len() >= m {
                break;
            }
            let cand_vec = self.vector_of(cand.slot);
            // Keep `cand` unless some already-selected neighbour is strictly closer to it than `q` is.
            let dominated = result
                .iter()
                .any(|&r| distance(self.similarity, cand_vec, self.vector_of(r)) < cand.dist);
            if dominated {
                discarded.push(cand.slot);
            } else {
                result.push(cand.slot);
            }
        }

        // keepPrunedConnections: backfill from the nearest discarded candidates.
        for slot in discarded {
            if result.len() >= m {
                break;
            }
            result.push(slot);
        }
        result
    }

    /// Prunes slot `e`'s layer-`lc` adjacency back to `m_max` using [`Self::select_neighbours`].
    ///
    /// The adjacency graph is kept **strictly undirected**: whenever pruning drops a neighbour `g`
    /// from `e`, the back-link `g -> e` is dropped too. This invariant (every edge is bidirectional)
    /// is what makes hard removal correct — an element's neighbour list is then exactly the set of
    /// elements referencing it, so [`Self::remove`] can unlink it everywhere without a reverse index.
    fn prune_neighbours(&mut self, e: u32, lc: usize, m_max: usize) {
        let current = self.slab[e as usize]
            .as_ref()
            .expect("live slot")
            .neighbours[lc]
            .clone();
        if current.len() <= m_max {
            return;
        }
        let base = self.vector_of(e).to_vec();
        let cands: Vec<Candidate> = current
            .iter()
            .map(|&n| Candidate {
                dist: distance(self.similarity, &base, self.vector_of(n)),
                slot: n,
            })
            .collect();
        let kept = self.select_neighbours(&base, &cands, m_max);
        let kept_set: HashSet<u32> = kept.iter().copied().collect();
        for &g in &current {
            if !kept_set.contains(&g) {
                self.remove_link(g, e, lc);
            }
        }
        self.slab[e as usize]
            .as_mut()
            .expect("live slot")
            .neighbours[lc] = kept;
    }

    /// Rescans for the live element with the highest top layer (ties: lowest slot) to become the new
    /// entry point. Only invoked when the current entry point is removed.
    fn reselect_entry(&mut self) {
        let mut best: Option<(usize, u32)> = None;
        for (i, cell) in self.slab.iter().enumerate() {
            if let Some(el) = cell {
                let top = el.neighbours.len() - 1;
                let slot = i as u32;
                best = Some(match best {
                    Some((bt, bs)) if bt >= top => (bt, bs),
                    _ => (top, slot),
                });
            }
        }
        match best {
            Some((top, slot)) => {
                self.entry = Some(slot);
                self.max_layer = top;
            }
            None => {
                self.entry = None;
                self.max_layer = 0;
            }
        }
    }

    /// A deterministic fingerprint of the whole graph, for tests: each live element mapped to its
    /// per-layer neighbour **ids** (sorted), keyed and ordered by element id. Two builds with the
    /// same seed and insertion order produce equal fingerprints.
    #[cfg(test)]
    fn graph_fingerprint(&self) -> Vec<(u64, Vec<Vec<u64>>)> {
        let mut out: Vec<(u64, Vec<Vec<u64>>)> = self
            .slab
            .iter()
            .flatten()
            .map(|el| {
                let layers = el
                    .neighbours
                    .iter()
                    .map(|layer| {
                        let mut ids: Vec<u64> = layer
                            .iter()
                            .map(|&s| self.slab[s as usize].as_ref().expect("live slot").id)
                            .collect();
                        ids.sort_unstable();
                        ids
                    })
                    .collect();
                (el.id, layers)
            })
            .collect();
        out.sort_by_key(|(id, _)| *id);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny deterministic gaussian vector generator (Box-Muller over [`SplitMix64`]), for building
    /// realistic isotropic test datasets without pulling in `rand`.
    struct VecGen {
        rng: SplitMix64,
    }

    impl VecGen {
        fn new(seed: u64) -> Self {
            Self {
                rng: SplitMix64::new(seed),
            }
        }

        fn standard_normal(&mut self) -> f32 {
            let u1 = self.rng.open_unit();
            let u2 = self.rng.open_unit();
            let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
            z as f32
        }

        fn vector(&mut self, dim: usize) -> Vec<f32> {
            (0..dim).map(|_| self.standard_normal()).collect()
        }
    }

    /// Exact brute-force k-NN, returning the ids of the `k` best under `similarity`, best first.
    fn brute_force(
        data: &[(u64, Vec<f32>)],
        query: &[f32],
        k: usize,
        similarity: Similarity,
    ) -> Vec<u64> {
        // Cosine needs normalised vectors for a fair `dot`; euclidean uses the raw vectors.
        let prep = |v: &[f32]| -> Vec<f32> {
            match similarity {
                Similarity::Cosine => {
                    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
                    if n > 0.0 {
                        v.iter().map(|x| x / n).collect()
                    } else {
                        v.to_vec()
                    }
                }
                Similarity::Euclidean => v.to_vec(),
            }
        };
        let q = prep(query);
        let mut scored: Vec<(f32, u64)> = data
            .iter()
            .map(|(id, v)| (distance(similarity, &q, &prep(v)), *id))
            .collect();
        scored.sort_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        scored.into_iter().take(k).map(|(_, id)| id).collect()
    }

    fn build_index(
        data: &[(u64, Vec<f32>)],
        dim: usize,
        similarity: Similarity,
        seed: u64,
    ) -> VectorIndex {
        let mut idx = VectorIndex::new(dim, similarity, 16, 200, seed).unwrap();
        for (id, v) in data {
            idx.insert(*id, v).unwrap();
        }
        idx
    }

    fn recall_at_k(similarity: Similarity) -> f64 {
        let dim = 64;
        let n = 2500;
        let k = 10;
        let ef_search = 128;
        let n_queries = 200;

        let mut dgen = VecGen::new(0xA11CE);
        let data: Vec<(u64, Vec<f32>)> = (0..n).map(|i| (i as u64, dgen.vector(dim))).collect();
        let idx = build_index(&data, dim, similarity, 0xC0FFEE);
        assert_eq!(idx.len(), n);

        let mut qgen = VecGen::new(0xB0B);
        let mut hit = 0usize;
        let mut total = 0usize;
        for _ in 0..n_queries {
            let q = qgen.vector(dim);
            let truth = brute_force(&data, &q, k, similarity);
            let approx: Vec<u64> = idx
                .query_knn(&q, k, ef_search)
                .unwrap()
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            let truth_set: HashSet<u64> = truth.into_iter().collect();
            for id in approx {
                if truth_set.contains(&id) {
                    hit += 1;
                }
            }
            total += k;
        }
        hit as f64 / total as f64
    }

    #[test]
    fn recall_cosine_at_least_095() {
        let recall = recall_at_k(Similarity::Cosine);
        eprintln!("cosine recall@10 = {recall:.4}");
        assert!(
            recall >= 0.95,
            "cosine recall@10 = {recall:.4}, expected >= 0.95"
        );
    }

    #[test]
    fn recall_euclidean_at_least_095() {
        let recall = recall_at_k(Similarity::Euclidean);
        eprintln!("euclidean recall@10 = {recall:.4}");
        assert!(
            recall >= 0.95,
            "euclidean recall@10 = {recall:.4}, expected >= 0.95"
        );
    }

    #[test]
    fn deterministic_under_fixed_seed() {
        let dim = 48;
        let n = 800;
        let mut dgen = VecGen::new(0x5EED);
        let data: Vec<(u64, Vec<f32>)> = (0..n).map(|i| (i as u64, dgen.vector(dim))).collect();

        for similarity in [Similarity::Cosine, Similarity::Euclidean] {
            let a = build_index(&data, dim, similarity, 12345);
            let b = build_index(&data, dim, similarity, 12345);

            // Identical graphs: same id -> same per-layer neighbour-id sets.
            assert_eq!(a.graph_fingerprint(), b.graph_fingerprint());

            // Identical query results (ids and scores) across many queries.
            let mut qgen = VecGen::new(0x99);
            for _ in 0..50 {
                let q = qgen.vector(dim);
                assert_eq!(
                    a.query_knn(&q, 10, 64).unwrap(),
                    b.query_knn(&q, 10, 64).unwrap()
                );
            }
        }
    }

    #[test]
    fn different_seeds_still_recall() {
        // A different seed gives a different graph but comparable recall — sanity that determinism
        // is not achieved by degenerating the structure.
        let dim = 32;
        let n = 600;
        let mut dgen = VecGen::new(1);
        let data: Vec<(u64, Vec<f32>)> = (0..n).map(|i| (i as u64, dgen.vector(dim))).collect();
        let a = build_index(&data, dim, Similarity::Cosine, 7);
        let b = build_index(&data, dim, Similarity::Cosine, 8);
        assert_ne!(a.graph_fingerprint(), b.graph_fingerprint());
    }

    #[test]
    fn remove_drops_element_from_results() {
        let mut idx = VectorIndex::new(3, Similarity::Euclidean, 16, 200, 42).unwrap();
        idx.insert(1, &[0.0, 0.0, 0.0]).unwrap();
        idx.insert(2, &[10.0, 0.0, 0.0]).unwrap();
        idx.insert(3, &[0.0, 10.0, 0.0]).unwrap();

        let q = [0.1, 0.1, 0.0];
        let before: Vec<u64> = idx
            .query_knn(&q, 3, 50)
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert!(before.contains(&1), "element 1 is the nearest, must appear");
        assert_eq!(before[0], 1);

        assert!(idx.remove(1));
        assert!(!idx.contains(1));
        assert_eq!(idx.len(), 2);

        let after: Vec<u64> = idx
            .query_knn(&q, 3, 50)
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert!(
            !after.contains(&1),
            "removed element must not appear: {after:?}"
        );
        assert_eq!(after.len(), 2);
        assert!(!idx.remove(1), "removing an absent id returns false");
    }

    #[test]
    fn remove_keeps_recall_high() {
        // Repair after deletion must keep the graph navigable.
        let dim = 48;
        let n = 1500;
        let k = 10;
        let mut dgen = VecGen::new(0xDEAD);
        let mut data: Vec<(u64, Vec<f32>)> = (0..n).map(|i| (i as u64, dgen.vector(dim))).collect();
        let mut idx = build_index(&data, dim, Similarity::Cosine, 0xBEEF);

        // Delete a third of the elements.
        let mut rng = SplitMix64::new(0xF00D);
        let mut removed: HashSet<u64> = HashSet::new();
        while removed.len() < n / 3 {
            let id = rng.next_u64() % n as u64;
            if removed.insert(id) {
                assert!(idx.remove(id));
            }
        }
        data.retain(|(id, _)| !removed.contains(id));
        assert_eq!(idx.len(), data.len());

        let mut qgen = VecGen::new(0x1234);
        let mut hit = 0usize;
        let mut total = 0usize;
        for _ in 0..150 {
            let q = qgen.vector(dim);
            let truth: HashSet<u64> = brute_force(&data, &q, k, Similarity::Cosine)
                .into_iter()
                .collect();
            for (id, _) in idx.query_knn(&q, k, 128).unwrap() {
                assert!(!removed.contains(&id));
                if truth.contains(&id) {
                    hit += 1;
                }
            }
            total += k;
        }
        let recall = hit as f64 / total as f64;
        assert!(
            recall >= 0.90,
            "post-deletion recall@10 = {recall:.4}, expected >= 0.90"
        );
    }

    #[test]
    fn duplicate_id_last_wins() {
        let mut idx = VectorIndex::new(2, Similarity::Euclidean, 16, 200, 1).unwrap();
        idx.insert(7, &[0.0, 0.0]).unwrap();
        idx.insert(7, &[100.0, 100.0]).unwrap();
        assert_eq!(idx.len(), 1, "re-inserting an id must not grow the index");

        // The query near the *new* location returns 7; near the old one it is far.
        let hits = idx.query_knn(&[100.0, 100.0], 1, 50).unwrap();
        assert_eq!(hits[0].0, 7);
        assert!(hits[0].1 > 0.99, "near-exact match scores ~1.0");
    }

    #[test]
    fn k_greater_than_len_returns_all() {
        let mut idx = VectorIndex::new(2, Similarity::Cosine, 16, 200, 1).unwrap();
        idx.insert(1, &[1.0, 0.0]).unwrap();
        idx.insert(2, &[0.0, 1.0]).unwrap();
        let hits = idx.query_knn(&[1.0, 1.0], 10, 50).unwrap();
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn empty_index_returns_empty() {
        let idx = VectorIndex::new(4, Similarity::Cosine, 16, 200, 1).unwrap();
        assert!(idx.is_empty());
        assert_eq!(idx.query_knn(&[1.0, 0.0, 0.0, 0.0], 5, 50).unwrap(), vec![]);
    }

    #[test]
    fn zero_k_returns_empty() {
        let mut idx = VectorIndex::new(2, Similarity::Cosine, 16, 200, 1).unwrap();
        idx.insert(1, &[1.0, 0.0]).unwrap();
        assert_eq!(idx.query_knn(&[1.0, 0.0], 0, 50).unwrap(), vec![]);
    }

    #[test]
    fn dimension_mismatch_is_rejected() {
        let mut idx = VectorIndex::new(3, Similarity::Cosine, 16, 200, 1).unwrap();
        assert_eq!(
            idx.insert(1, &[1.0, 0.0]),
            Err(VectorIndexError::DimensionMismatch {
                expected: 3,
                got: 2
            })
        );
        idx.insert(1, &[1.0, 0.0, 0.0]).unwrap();
        assert_eq!(
            idx.query_knn(&[1.0, 0.0, 0.0, 0.0], 1, 50),
            Err(VectorIndexError::DimensionMismatch {
                expected: 3,
                got: 4
            })
        );
    }

    #[test]
    fn zero_dimension_is_rejected() {
        assert_eq!(
            VectorIndex::new(0, Similarity::Cosine, 16, 200, 1).err(),
            Some(VectorIndexError::ZeroDimension)
        );
    }

    #[test]
    fn scores_match_neo4j_formulas() {
        // Cosine: identical unit vectors => cos = 1 => score = 1.
        let mut c = VectorIndex::new(2, Similarity::Cosine, 16, 200, 1).unwrap();
        c.insert(1, &[3.0, 4.0]).unwrap(); // normalised to (0.6, 0.8)
        let hit = c.query_knn(&[3.0, 4.0], 1, 50).unwrap();
        assert!(
            (hit[0].1 - 1.0).abs() < 1e-6,
            "cosine self-score should be 1.0"
        );

        // Orthogonal => cos = 0 => score = 0.5.
        c.insert(2, &[-4.0, 3.0]).unwrap();
        let ortho = c.query_knn(&[-4.0, 3.0], 2, 50).unwrap();
        let s1 = ortho.iter().find(|(id, _)| *id == 1).unwrap().1;
        assert!(
            (s1 - 0.5).abs() < 1e-6,
            "orthogonal cosine score should be 0.5, got {s1}"
        );

        // Euclidean: distance 0 => score 1; squared distance d² => 1/(1+d²).
        let mut e = VectorIndex::new(1, Similarity::Euclidean, 16, 200, 1).unwrap();
        e.insert(1, &[0.0]).unwrap();
        e.insert(2, &[2.0]).unwrap(); // squared distance to query 0.0 is 4 => 1/5 = 0.2
        let eh = e.query_knn(&[0.0], 2, 50).unwrap();
        assert!((eh.iter().find(|(id, _)| *id == 1).unwrap().1 - 1.0).abs() < 1e-6);
        assert!((eh.iter().find(|(id, _)| *id == 2).unwrap().1 - 0.2).abs() < 1e-6);
    }

    #[test]
    fn similarity_score_matches_query_scores_and_neo4j_formulas() {
        // Cosine self-similarity: cos = 1 => (1 + 1) / 2 = 1.0 (independent of magnitude — the raw
        // vectors are unit-normalised first, exactly as the index normalises on insert).
        assert!(
            (similarity_score(Similarity::Cosine, &[3.0, 4.0], &[3.0, 4.0]) - 1.0).abs() < 1e-6
        );
        assert!(
            (similarity_score(Similarity::Cosine, &[3.0, 4.0], &[6.0, 8.0]) - 1.0).abs() < 1e-6
        );

        // Orthogonal: cos = 0 => (1 + 0) / 2 = 0.5. Opposite: cos = -1 => 0.0 (clamped floor).
        assert!(
            (similarity_score(Similarity::Cosine, &[1.0, 0.0], &[0.0, 1.0]) - 0.5).abs() < 1e-6
        );
        assert!(similarity_score(Similarity::Cosine, &[1.0, 0.0], &[-1.0, 0.0]).abs() < 1e-6);

        // Euclidean: squared L2 distance 4 => 1 / (1 + 4) = 0.2; distance 0 => 1.0.
        assert!((similarity_score(Similarity::Euclidean, &[0.0], &[2.0]) - 0.2).abs() < 1e-6);
        assert!(
            (similarity_score(Similarity::Euclidean, &[1.0, 2.0], &[1.0, 2.0]) - 1.0).abs() < 1e-6
        );

        // The function is the exact twin of the score a `query_knn` hit carries (no drift): build a
        // 1-element cosine index and compare the function to the seek score for the same pair.
        let mut c = VectorIndex::new(2, Similarity::Cosine, 16, 200, 7).unwrap();
        c.insert(1, &[2.0, 1.0]).unwrap();
        let seek = c.query_knn(&[1.0, 3.0], 1, 50).unwrap()[0].1;
        let func = similarity_score(Similarity::Cosine, &[1.0, 3.0], &[2.0, 1.0]);
        assert!(
            (seek - func).abs() < 1e-6,
            "function score {func} must equal the seek score {seek}"
        );
    }

    #[test]
    fn build_and_query_5k_is_fast() {
        // A wall-clock sanity check. Debug builds are far slower than release, so the assert bound is
        // generous (it only catches a catastrophic regression); the real "well under a second" target
        // is verified in release. The measured time is printed for the record.
        let dim = 64;
        let n = 5000;
        let mut dgen = VecGen::new(0x7777);
        let data: Vec<(u64, Vec<f32>)> = (0..n).map(|i| (i as u64, dgen.vector(dim))).collect();

        // A leaner `ef_construction` than the recall tests use: this is a pure speed sanity, so it
        // trades a little graph quality for build throughput (release build is well under a second).
        let t0 = std::time::Instant::now();
        let mut idx = VectorIndex::new(dim, Similarity::Cosine, 16, 100, 0x2222).unwrap();
        for (id, v) in &data {
            idx.insert(*id, v).unwrap();
        }
        let build = t0.elapsed();

        let mut qgen = VecGen::new(0x3333);
        let t1 = std::time::Instant::now();
        for _ in 0..200 {
            let q = qgen.vector(dim);
            let hits = idx.query_knn(&q, 10, 100).unwrap();
            assert_eq!(hits.len(), 10);
        }
        let query = t1.elapsed();

        eprintln!(
            "vector index: build {n} x dim {dim} in {build:?}; 200 queries in {query:?} \
             ({:?}/query)",
            query / 200
        );
        assert!(
            build < std::time::Duration::from_secs(60),
            "build regressed badly: {build:?}"
        );
    }
}
