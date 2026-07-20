//! Deterministic, seeded **product-recommendation graph generator** for the
//! `examples/product-recommendation` performance-evaluation demonstration.
//!
//! It models a product-recommendation service as a Label Property Graph (a **multigraph**, matching
//! Graphus's default): a population of `User`s, a catalogue of `Product`s, an **undirected** `FRIEND`
//! multigraph among users, and directed `PURCHASED` edges from users to products. The generator
//! streams the whole graph as `neo4j-admin import`-flavoured CSV suitable for the production
//! [`graphus_bulk::BulkImporter`], plus a one-line machine-readable summary — exactly the substrate
//! the example loads into the real engine to measure CPU / RAM / storage at scale (up to one million
//! users).
//!
//! # The recommendation graph model
//!
//! A Label Property Graph modelling a customer base and its purchasing behaviour:
//!
//! | Node label | Key properties | Meaning |
//! | --- | --- | --- |
//! | `(:User {id, name, country, signup})` | `id` (24 lowercase hex chars, unique) | a customer |
//! | `(:Product {id, name, category, price, embedding})` | `id` (24 lowercase hex chars, unique) | a catalogue item |
//!
//! `price` is always an **integer number of cents** — never a float, so the emitted bytes stay
//! platform-stable (see [Determinism](#determinism)).
//!
//! Each `Product` also carries an **`embedding`** — a fixed-length [`EMBED_DIM`]-dimensional
//! `LIST<FLOAT>` vector (emitted as a `float[]` CSV column) **clustered by category**: one orthogonal
//! axis per category, so a `Product`'s dominant component is its [category axis](Generator::product_category_index)
//! and different categories stay (cosine-)orthogonal. This is the substrate a `VECTOR` (HNSW) index and
//! a `db.index.vector.queryNodes` "customers who bought this might like…" **similar-products** ANN query
//! exercise. The embedding is emitted through **pure integer formatting** (fixed 3-decimal thousandths),
//! so — like `price` — no `f32` ever reaches the wire and the bytes stay platform-stable.
//!
//! Two relationship types:
//!
//! | Relationship | Direction | Meaning |
//! | --- | --- | --- |
//! | `:FRIEND {since}` | `(:User)-(:User)` (undirected) | a friendship; **multi-edges allowed** |
//! | `:PURCHASED {ts, qty}` | `(:User)->(:Product)` | the user bought the product |
//!
//! ## The FRIEND multigraph: the configuration model
//!
//! Each user is given a target degree (a **stub count**) drawn uniformly in
//! `[friend_min, friend_max]`. The classic **configuration model** then realises a graph with those
//! degrees: lay every user's stubs out in one array (`s_u` copies of user `u`), make the total even
//! (bump the last user's stubs by one if the sum is odd), apply a deterministic Fisher–Yates shuffle,
//! then pair consecutive stubs into `FRIEND` edges. Self-loops are avoided by a deterministic forward
//! re-probe (swap a self-pairing stub with the next non-self stub); **multi-edges between the same
//! pair are kept** — the model is a true multigraph. Each friendship is emitted exactly once, stored
//! as a single **directed** `(a)->(b)` relationship, and read back with the **undirected**
//! `-[:FRIEND]-` form so the friendship's symmetric semantics are preserved. The realised per-user
//! degree therefore lands within `[friend_min, friend_max]` (modulo at most the one-stub parity bump
//! on the final user), the construction is `O(E)`, and it scales to a million users. This is the same
//! construction `graphus-social-gen` uses, adopted here verbatim.
//!
//! ## The PURCHASED edges: a popularity-skewed distribution
//!
//! Each user buys a per-user count of **distinct** products drawn uniformly in
//! `[0, 2 * avg_purchases_per_user]` (a symmetric spread whose mean is `avg_purchases_per_user`).
//! Crucially, the product a purchase lands on is **not** uniform: it is drawn from a
//! **popularity-skewed** distribution so that a small set of "popular" products accrues a large share
//! of purchases and dense **co-purchase clusters** emerge — the structure a later
//! "customers with a similar consumption profile" recommendation query needs to be meaningful.
//!
//! The skew is implemented as a **min-of-K** draw: to pick a product index, draw `popularity_skew`
//! (`K`) independent uniform indices in `[0, products)` and take the **minimum**. Low indices (which
//! we treat as the "popular" products, index `0` the most popular) are then chosen far more often;
//! `K = 1` degenerates to uniform, `K >= 3` is strongly skewed. This is **integer-only** — no
//! `powf`/`ln`/`sqrt`/float anywhere in the emitted-byte path — so the distribution is deterministic
//! and byte-identical across platforms, unlike a Zipf sampler built on floating-point cumulative
//! weights. Distinct products per user are enforced by rejection sampling against an insertion-ordered
//! `Vec` seen-set (never a `HashSet`, whose iteration order would perturb the stream), with a bounded
//! attempt budget. `PURCHASED` is directed `(:User)->(:Product)`.
//!
//! # Determinism
//!
//! Generation is a pure function of [`GenConfig`]: the only randomness is an internal [`SplitMix64`]
//! PRNG seeded from `seed` (degree draws, the shuffle, name/country/category assembly, price + purchase
//! sampling, the category-clustered embedding, timestamps). For a given config the emitted CSV is
//! **byte-identical** across runs, hosts, and platforms (no floats on the wire — the `embedding` column
//! too is rendered by integer formatting — no `HashMap` iteration in any emitted-order path, no clock,
//! no thread scheduling). This is asserted by `tests/determinism.rs`, and the CSV is proven a valid
//! bulk-import artifact by `tests/bulk_import_validity.rs`.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

/// The canonical **recommendation read battery** — the parameterised Cypher the wire clients run
/// (`reco_load`'s correctness asserts and `reco_bench`'s concurrent load). Defined once so the loader
/// and the driver exercise byte-identical queries.
pub mod queries;

/// A synchronous **Bolt client over a Unix domain socket** (with `db` selection + parameters), reused
/// by the `reco_bench` concurrent read driver. Reuses the [`graphus_bolt`] symmetric wire codec.
pub mod client;

/// Pure, hermetic helpers for the `reco_bench` concurrent read driver: latency-percentile
/// summarisation, the `/proc/<pid>` field parsers, the concurrency-ladder CSV parser, and the
/// read-battery family-index lookup — all unit-testable without a running server.
pub mod bench;

/// The **read/write mix** seam shared by the over-the-wire example drivers (`rmp` #714): abort
/// classification (including the `rmp` #612 regression detector), managed retry with bounded
/// exponential backoff, the two-layer [`mix::WriteVector`] (engine contention vs application outcome),
/// the [`mix::ReadInvariant`] (an auto-commit read runs at SI and can never abort), and the paired
/// control/treatment [`mix::Arm`]s that measure what the mix COSTS.
pub mod mix;

/// The production-realistic **read-path schema** the example declares after the bulk load — a NODE KEY
/// + UNIQUE identity pair, a `price` property-type constraint, a `TEXT` name index, and a `VECTOR`
/// (HNSW) embedding index — as a single shared DDL block so `reco_load` and the hermetic server mirror
/// drive byte-identical statements.
pub mod schema;

/// A tiny, fast, fully-deterministic PRNG (SplitMix64 — Steele, Lea & Flood 2014). Chosen because it
/// is a *pure* integer mixing function: identical output for identical seeds on every platform, with
/// no global state, no float, and no allocation. We never use the standard library's `HashMap`-based
/// randomness or any clock, so the whole generator is reproducible byte-for-byte.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Seeds the generator. Any `u64` seed is valid.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Returns the next pseudo-random `u64`.
    pub fn next_u64(&mut self) -> u64 {
        // SplitMix64 reference constants.
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Returns a value in `[0, n)` (n > 0) with negligible modulo bias for our small ranges.
    pub fn below(&mut self, n: u64) -> u64 {
        debug_assert!(n > 0, "below(0) is undefined");
        self.next_u64() % n
    }

    /// Returns a value in the inclusive range `[lo, hi]` (requires `lo <= hi`).
    pub fn in_range(&mut self, lo: u64, hi: u64) -> u64 {
        debug_assert!(lo <= hi, "in_range requires lo <= hi");
        lo + self.below(hi - lo + 1)
    }
}

/// Epoch (seconds) the modelled timeline starts at — a fixed constant so timestamps are reproducible.
/// `2024-01-01T00:00:00Z` in Unix seconds.
pub const EPOCH_S: u64 = 1_704_067_200;

/// One year in seconds — signup and purchase timestamps are spread across `[EPOCH_S, EPOCH_S + SPAN_S)`.
pub const REG_SPAN_S: u64 = 365 * 24 * 60 * 60;

/// How many CSV data rows are packed into a single streamed chunk. Chunking keeps peak resident memory
/// bounded by one chunk (never the whole file) while amortising the per-`sink`-call overhead. A pure
/// constant so the output is a pure function of the config.
pub const BATCH: usize = 100;

/// The minimum product price, in **cents** (an integer — never a float). `1.99`.
pub const PRICE_MIN_CENTS: u64 = 199;
/// The maximum product price, in **cents**. `2500.00`.
pub const PRICE_MAX_CENTS: u64 = 250_000;

/// The minimum `PURCHASED` quantity, inclusive.
pub const QTY_MIN: u64 = 1;
/// The maximum `PURCHASED` quantity, inclusive.
pub const QTY_MAX: u64 = 5;

/// The `Product.embedding` dimensionality: **one orthogonal axis per product category**, so category
/// clusters are maximally (cosine-)separated — a `db.index.vector.queryNodes` seek at a category's
/// [centroid](Generator::category_centroid) retrieves that category's products with a wide score margin.
/// Small (equal to the number of categories) so the `VECTOR` index stays cheap in the `fast` profile.
pub const EMBED_DIM: usize = CATEGORIES.len();

/// The category-centroid component, in integer **thousandths** (`1000` ⇒ `1.000`): the dominant axis of
/// every embedding. Integer-only ⇒ byte-deterministic (see [Determinism](#determinism)).
const EMBED_CENTROID_MILLIS: u64 = 1000;
/// The maximum per-axis **jitter**, in integer thousandths (`50` ⇒ `0.050`). Small enough that the
/// category axis (`≥ 1.000`) always dominates every other axis (`≤ 0.050`), so clusters stay separable,
/// yet non-zero so same-category embeddings are distinct and realistic. Integer-only ⇒ byte-deterministic.
const EMBED_JITTER_MILLIS: u64 = 50;

// --- Deterministic Portuguese-name fragment pools -----------------------------------------------
//
// Realistic European-Portuguese given names, middle/connective particles, and surnames, all valid
// UTF-8 *including diacritics*. None contains a comma, double-quote, or newline, so the assembled
// `name` can never break a CSV field; we still escape defensively at emit time. Names are assembled
// deterministically from these pools so they "tend to contain real information" while remaining a
// pure function of the seed.

/// First (given) names.
const FIRST_NAMES: &[&str] = &[
    "José",
    "António",
    "Maria",
    "Joana",
    "Manuel",
    "Ana",
    "João",
    "Francisco",
    "Margarida",
    "Rita",
    "Tomás",
    "Beatriz",
    "Miguel",
    "Inês",
    "Rui",
    "Sofia",
    "Pedro",
    "Catarina",
    "Carlos",
    "Mariana",
    "Luís",
    "Matilde",
    "André",
    "Leonor",
    "Gonçalo",
    "Carolina",
    "Ricardo",
    "Patrícia",
    "Tiago",
    "Helena",
    "Fernando",
    "Cristina",
];

/// Surnames (and surname components). Multiple may be chained with connective particles.
const SURNAMES: &[&str] = &[
    "Silva",
    "Santos",
    "Ferreira",
    "Pereira",
    "Oliveira",
    "Costa",
    "Rodrigues",
    "Martins",
    "Jesus",
    "Sousa",
    "Fernandes",
    "Gonçalves",
    "Gomes",
    "Lopes",
    "Marques",
    "Almeida",
    "Carvalho",
    "Ribeiro",
    "Pinto",
    "Teixeira",
    "Moreira",
    "Correia",
    "Mendes",
    "Nunes",
    "Soares",
    "Vieira",
    "Monteiro",
    "Cardoso",
    "Rocha",
    "Antunes",
    "Coelho",
    "Cunha",
];

/// Connective particles used between surnames ("José da Silva e Carvalho").
const PARTICLES: &[&str] = &["da", "de", "do", "dos", "das", "e"];

/// The countries a `User` may belong to. Valid UTF-8 (diacritics included); none contains a comma,
/// double-quote, or newline, so each is a clean single CSV field.
const COUNTRIES: &[&str] = &[
    "Portugal",
    "Espanha",
    "França",
    "Alemanha",
    "Brasil",
    "Angola",
    "Reino Unido",
    "Itália",
    "Países Baixos",
    "Bélgica",
    "Suíça",
    "Irlanda",
];

// --- Deterministic product-name fragment pools --------------------------------------------------
//
// Product names are assembled as `<noun> <adjective>` with an optional brand-ish suffix, from these
// pools, so they "tend to contain real information". None contains a comma, double-quote, or newline,
// so each assembled name is a clean single CSV field; we still escape defensively at emit time.

/// Product nouns (the head of the assembled name).
const PRODUCT_NOUN: &[&str] = &[
    "Auscultadores",
    "Portátil",
    "Cafeteira",
    "Livro",
    "Bicicleta",
    "Telemóvel",
    "Teclado",
    "Rato",
    "Monitor",
    "Coluna",
    "Máquina de café",
    "Aspirador",
    "Ventoinha",
    "Candeeiro",
    "Mochila",
    "Relógio",
    "Câmara",
    "Tablet",
    "Impressora",
    "Frigorífico",
    "Torradeira",
    "Chaleira",
    "Ténis",
    "Casaco",
    "Garrafa",
];

/// Product adjectives / qualifiers.
const PRODUCT_ADJ: &[&str] = &[
    "sem fios",
    "profissional",
    "compacto",
    "portátil",
    "recarregável",
    "premium",
    "ecológico",
    "inteligente",
    "silencioso",
    "ultraligeiro",
    "clássico",
    "de alta resolução",
    "para viagem",
    "de bolso",
    "reforçado",
];

/// Optional brand-ish suffixes appended to roughly half the product names.
const PRODUCT_BRAND: &[&str] = &[
    "Lusitânia",
    "Atlântico",
    "Ibérico",
    "Douro",
    "Tejo",
    "Minho",
    "Nortada",
    "Serra",
    "Aurora",
    "Horizonte",
];

/// The product categories. Valid UTF-8 (diacritics included); none contains a comma, double-quote, or
/// newline, so each is a clean single CSV field.
const CATEGORIES: &[&str] = &[
    "Electrónica",
    "Livros",
    "Casa e Cozinha",
    "Desporto",
    "Moda",
    "Brinquedos",
    "Alimentação",
    "Beleza",
    "Jardim",
    "Automóvel",
];

/// The maximum number of bytes a node `name` may occupy. The model contract guarantees names are valid
/// UTF-8 (diacritics included) and at most this many bytes; the assembler truncates on a char boundary
/// if a chained name would overshoot.
pub const MAX_NAME_BYTES: usize = 64;

/// Configuration for one generation run. A pure value: identical configs yield identical graphs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenConfig {
    /// PRNG seed — the sole source of (reproducible) randomness.
    pub seed: u64,
    /// Number of `User` nodes.
    pub users: u64,
    /// Number of `Product` nodes.
    pub products: u64,
    /// Minimum `FRIEND` stub count (target degree) per user, inclusive.
    pub friend_min: u64,
    /// Maximum `FRIEND` stub count (target degree) per user, inclusive.
    pub friend_max: u64,
    /// Mean number of `PURCHASED` edges per user; the per-user purchase count is drawn uniformly in
    /// `[0, 2 * avg_purchases_per_user]`, so the population mean is `avg_purchases_per_user`.
    pub avg_purchases_per_user: u64,
    /// The popularity-skew strength `K` for the min-of-K product draw. `1` is uniform; `>= 3` is
    /// strongly skewed toward the low ("popular") product indices. A value of `0` is treated as `1`.
    pub popularity_skew: u64,
}

impl GenConfig {
    /// The **tiny** profile — a small graph for the **external attach** path (`rmp` #693). Sized so the
    /// whole graph (≈ 300 customers, degree band 3–9 ≈ 900 FRIEND edges, 50 products, ≈ 4
    /// purchases/user ≈ 1 200 PURCHASED edges, ≈ 2 100 relationships total) loads quickly over Bolt
    /// `UNWIND` writes even against a small/remote box (e.g. a Raspberry Pi) or an OLDER server whose
    /// planner does not index-seek on an `UNWIND`-row-valued anchor and falls back to a scan. It still
    /// has enough friend fan-out for a 3-hop traversal and enough co-purchase density for the
    /// collaborative-filtering query to return results — enough to exercise the reader-pool-scaling
    /// ladder. The full-size graph is exercised by the local `fast`/`large` profiles and against a
    /// current server.
    #[must_use]
    pub fn tiny() -> Self {
        Self {
            seed: 0x05EC_011E_C710_0001,
            users: 300,
            products: 50,
            friend_min: 3,
            friend_max: 9,
            avg_purchases_per_user: 4,
            popularity_skew: 3,
        }
    }

    /// The **fast** profile — small, CI-runnable: a couple of thousand customers with a modest friend
    /// fan-out and a small catalogue. Sized so the determinism test **and the bulk-import validity
    /// test** stay quick (a few seconds) under a default `cargo test`, including in the slower debug
    /// profile: ≈ 2 000 users, degree band 6–24 (≈ 15 000 FRIEND edges), 400 products, ≈ 8
    /// purchases/user (≈ 16 000 PURCHASED edges) — enough to exercise a real fan-out, multi-edges, a
    /// catalogue, and a non-trivial purchase load with a visible popularity skew.
    #[must_use]
    pub fn fast() -> Self {
        Self {
            seed: 0x05EC_011E_C710_0001,
            users: 2_000,
            products: 400,
            friend_min: 6,
            friend_max: 24,
            avg_purchases_per_user: 8,
            popularity_skew: 3,
        }
    }

    /// The **large** profile — evidence-scale: a hundred-thousand-plus customers with a substantial
    /// friend fan-out, a few thousand products, and a heavier purchase load. Sized to exercise the
    /// engine at a scale where CPU / RAM / storage trends are clearly observable while staying
    /// tractable.
    #[must_use]
    pub fn large() -> Self {
        Self {
            seed: 0x05EC_011E_C710_0001,
            users: 120_000,
            products: 8_000,
            friend_min: 20,
            friend_max: 120,
            avg_purchases_per_user: 25,
            popularity_skew: 3,
        }
    }

    /// The **huge** profile — the literal one-million-customer target: a massive friend fan-out and a
    /// large catalogue with a stronger popularity skew. Heavy and opt-in; intended for full-scale
    /// performance evaluation, not routine CI.
    #[must_use]
    pub fn huge() -> Self {
        Self {
            seed: 0x05EC_011E_C710_0001,
            users: 1_000_000,
            products: 40_000,
            friend_min: 60,
            friend_max: 600,
            avg_purchases_per_user: 30,
            popularity_skew: 4,
        }
    }

    /// Resolves a profile name (`"tiny"` / `"fast"` / `"large"` / `"huge"`) to its config, or `None`
    /// for an unknown name.
    #[must_use]
    pub fn profile(name: &str) -> Option<Self> {
        match name {
            "tiny" => Some(Self::tiny()),
            "fast" => Some(Self::fast()),
            "large" => Some(Self::large()),
            "huge" => Some(Self::huge()),
            _ => None,
        }
    }
}

/// A machine-readable summary of one generation run's realised shape. A pure function of the config:
/// the counts and degree statistics are computed from the same deterministic construction the emitted
/// CSV uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    /// Number of `User` nodes.
    pub users: u64,
    /// Number of `Product` nodes.
    pub products: u64,
    /// Number of (undirected) `FRIEND` edges emitted.
    pub friend_edges: u64,
    /// Number of `PURCHASED` edges emitted.
    pub purchased_edges: u64,
    /// Smallest realised per-user `FRIEND` degree.
    pub degree_min: u64,
    /// Largest realised per-user `FRIEND` degree.
    pub degree_max: u64,
    /// Mean realised per-user `FRIEND` degree, scaled by 1000 and floored (an integer, so it never
    /// puts a float on the wire). `degree_avg_x1000 / 1000` is the mean to three decimal places.
    pub degree_avg_x1000: u64,
}

/// The deterministic product-recommendation graph generator.
///
/// Construct with [`Generator::new`], then [`Generator::summary`] for the realised counts / degree
/// statistics (cheap — it materialises no CSV text) or the `stream_*_csv` family for the full
/// `neo4j-admin import`-flavoured CSV artifact, one chunk at a time.
#[derive(Debug, Clone)]
pub struct Generator {
    cfg: GenConfig,
}

impl Generator {
    /// Creates a generator for `cfg`.
    #[must_use]
    pub fn new(cfg: GenConfig) -> Self {
        Self { cfg }
    }

    /// The configuration this generator runs.
    #[must_use]
    pub fn config(&self) -> &GenConfig {
        &self.cfg
    }

    /// The deterministic 24-lowercase-hex-char id for entity `i` within a label-specific `salt`
    /// namespace (so `User 0` and `Product 0` get distinct ids). Built from two SplitMix64 draws keyed
    /// by `(salt, i)` and rendered as 24 hex nibbles (96 bits). Collisions across our scales are
    /// negligible, and the id is purely a function of `(salt, i)` (independent of `seed`, so a given
    /// entity keeps its id across seeds).
    #[must_use]
    pub fn entity_id(salt: u64, i: u64) -> String {
        // Two independent 48-bit halves → 96 bits → 24 hex chars.
        let mut r = SplitMix64::new(salt ^ i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let hi = r.next_u64() & 0x0000_FFFF_FFFF_FFFF; // 48 bits
        let lo = r.next_u64() & 0x0000_FFFF_FFFF_FFFF; // 48 bits
        format!("{hi:012x}{lo:012x}")
    }

    /// Salt namespace for `User` ids.
    const USER_SALT: u64 = 0x1111_1111_0000_0001;
    /// Salt namespace for `Product` ids.
    const PRODUCT_SALT: u64 = 0x2222_2222_0000_0002;

    /// The stable id of `User` `i`.
    #[must_use]
    pub fn user_id(i: u64) -> String {
        Self::entity_id(Self::USER_SALT, i)
    }

    /// The stable id of `Product` `i`.
    #[must_use]
    pub fn product_id(i: u64) -> String {
        Self::entity_id(Self::PRODUCT_SALT, i)
    }

    /// A deterministic, realistic Portuguese full name for `User` `i`, valid UTF-8 (diacritics
    /// included) and at most [`MAX_NAME_BYTES`] bytes. Assembled as a given name, one or two surnames,
    /// optionally joined by a connective particle. Never contains a comma, quote, or newline.
    #[must_use]
    pub fn user_name(seed: u64, i: u64) -> String {
        let mut r = SplitMix64::new(seed ^ Self::USER_SALT ^ i.wrapping_mul(0xD1B5_4A32_D192_ED03));
        let first = FIRST_NAMES[r.below(FIRST_NAMES.len() as u64) as usize];
        let s1 = SURNAMES[r.below(SURNAMES.len() as u64) as usize];

        let mut name = String::with_capacity(MAX_NAME_BYTES);
        name.push_str(first);
        name.push(' ');
        name.push_str(s1);

        // ~half the time, append a particle + a second surname ("da Silva e Carvalho").
        if r.below(2) == 1 {
            let particle = PARTICLES[r.below(PARTICLES.len() as u64) as usize];
            let s2 = SURNAMES[r.below(SURNAMES.len() as u64) as usize];
            // Only append if it stays within the byte budget.
            let extra = 1 + particle.len() + 1 + s2.len();
            if name.len() + extra <= MAX_NAME_BYTES {
                name.push(' ');
                name.push_str(particle);
                name.push(' ');
                name.push_str(s2);
            }
        }

        truncate_on_char_boundary(name, MAX_NAME_BYTES)
    }

    /// A deterministic product name for `Product` `i`, valid UTF-8 (diacritics included) and at most
    /// [`MAX_NAME_BYTES`] bytes. Assembled as `<noun> <adjective> [brand] <reference>`, where the trailing
    /// **reference code** ([`product_model_code`](Self::product_model_code)) is a high-entropy token,
    /// distinct per product at every generated catalogue size. Never contains a comma, quote, or newline.
    ///
    /// The reference code is what makes a `TEXT` `CONTAINS` search over the name **selective** (`rmp`
    /// #746): the `<noun> <adjective> [brand]` vocabulary is drawn from small shared pools, so every
    /// *trigram* of a bare-word fragment appears across a large fraction of the catalogue — a
    /// `CONTAINS '<noun>'` seek is then no more selective than a full scan (its candidate set is nearly
    /// the whole store, measured 801 ≈ 801 dbHits). The reference code's trigrams are rare (they derive
    /// from the product's unique id), so a `CONTAINS '<reference>'` seek reads a handful of products —
    /// a genuine, index-serviceable search, the way a real catalogue is queried by model/SKU. The base
    /// name is truncated first to reserve the code's bytes, so the code is ALWAYS present and the total
    /// stays within [`MAX_NAME_BYTES`].
    #[must_use]
    pub fn product_name(seed: u64, i: u64) -> String {
        let mut r =
            SplitMix64::new(seed ^ Self::PRODUCT_SALT ^ i.wrapping_mul(0xA076_1D64_78BD_642F));
        let noun = PRODUCT_NOUN[r.below(PRODUCT_NOUN.len() as u64) as usize];
        let adj = PRODUCT_ADJ[r.below(PRODUCT_ADJ.len() as u64) as usize];

        // Reserve room for the trailing " <reference>" so the selective code is never truncated away.
        let code = Self::product_model_code(i);
        let budget = MAX_NAME_BYTES.saturating_sub(code.len() + 1);

        let mut name = String::with_capacity(MAX_NAME_BYTES);
        name.push_str(noun);
        name.push(' ');
        name.push_str(adj);

        // ~half the time, append a brand-ish suffix (only if it still fits within the reserved budget).
        if r.below(2) == 1 {
            let brand = PRODUCT_BRAND[r.below(PRODUCT_BRAND.len() as u64) as usize];
            if name.len() + 1 + brand.len() <= budget {
                name.push(' ');
                name.push_str(brand);
            }
        }

        let mut name = truncate_on_char_boundary(name, budget);
        name.push(' ');
        name.push_str(&code);
        name
    }

    /// A high-entropy product **reference code** — `REF-` followed by the first six hex chars of the
    /// product's id, upper-cased (e.g. `REF-3F8A2B`) — carried inside
    /// [`product_name`](Self::product_name).
    ///
    /// Real catalogues have model / SKU numbers; here the code exists so a `TEXT` `CONTAINS` search over
    /// the product name is genuinely **selective** (`rmp` #746). Its trigrams derive from the product's
    /// id, so they are rare across the catalogue — unlike the shared `<noun>`/`<adjective>`/`[brand]`
    /// vocabulary, whose every trigram is common. That selectivity is what lets the `TEXT` index serve
    /// the search with a genuine seek (reading a handful of products) instead of a full scan. A pure
    /// function of the product index ⇒ byte-deterministic across platforms.
    ///
    /// The code is six hex chars — a 24-bit space — so it is **distinct for every product at the
    /// generated catalogue sizes** (measured: 0 collisions at 50 / 400 / 8 000 products, i.e. every
    /// profile this generator ships), but it is a hash prefix, NOT a guaranteed-unique key: at 40 000
    /// products 45 codes are shared by two products each. A shared code is harmless here — it widens a
    /// search from one matching product to two, which is still selective by three orders of magnitude,
    /// and both matches are real products — so the ground-truth check (the searched product's own id
    /// must appear among the matches) stays exact either way.
    #[must_use]
    pub fn product_model_code(i: u64) -> String {
        let id = Self::product_id(i);
        // `product_id` yields 24 lowercase hex chars, so the first six are always present and ASCII.
        format!("REF-{}", id[..6].to_uppercase())
    }

    /// A deterministic country for `User` `i`, from the [`COUNTRIES`] pool.
    ///
    /// Exposed (alongside [`user_name`](Self::user_name)) so a read-result verifier can recompute the
    /// exact `(:User {id}).country` the loaded graph carries — the ground truth an over-the-wire
    /// `MATCH (u:User {id: $id}) RETURN u.name, u.country` reply must match (`rmp` #744).
    #[must_use]
    pub fn user_country(seed: u64, i: u64) -> &'static str {
        let mut r = SplitMix64::new(seed ^ Self::USER_SALT ^ i.wrapping_mul(0xC2B2_AE3D_27D4_EB4F));
        COUNTRIES[r.below(COUNTRIES.len() as u64) as usize]
    }

    /// The deterministic **category index** (into [`CATEGORIES`], `0..EMBED_DIM`) for `Product` `i` — the
    /// single draw [`product_category`](Self::product_category) resolves to a name, exposed so the
    /// embedding can cluster by it and a reader can map a category name back to its centroid axis.
    #[must_use]
    pub fn product_category_index(seed: u64, i: u64) -> usize {
        let mut r =
            SplitMix64::new(seed ^ Self::PRODUCT_SALT ^ i.wrapping_mul(0xEBCA_1A6C_6D8B_2F17));
        r.below(CATEGORIES.len() as u64) as usize
    }

    /// A deterministic category for `Product` `i`, from the [`CATEGORIES`] pool.
    fn product_category(seed: u64, i: u64) -> &'static str {
        CATEGORIES[Self::product_category_index(seed, i)]
    }

    /// The name of category index `c` (into [`CATEGORIES`]) — the inverse of
    /// [`product_category_index`](Self::product_category_index) for asserting a k-NN hit's category.
    ///
    /// # Panics
    /// If `c >= EMBED_DIM` (there are exactly [`EMBED_DIM`] categories).
    #[must_use]
    pub fn category_name(c: usize) -> &'static str {
        CATEGORIES[c]
    }

    /// The **centroid** (query vector) for category index `c`: a unit one-hot on axis `c`. A
    /// `db.index.vector.queryNodes` cosine seek with this vector retrieves category `c`'s products
    /// (they cluster tightly around it), the "similar products" recommendation query.
    ///
    /// # Panics
    /// If `c >= EMBED_DIM`.
    #[must_use]
    pub fn category_centroid(c: usize) -> Vec<f32> {
        assert!(
            c < EMBED_DIM,
            "category index {c} out of range 0..{EMBED_DIM}"
        );
        let mut v = vec![0.0_f32; EMBED_DIM];
        v[c] = 1.0;
        v
    }

    /// The deterministic embedding for `Product` `i` as integer **thousandths** (component `d` is
    /// `millis[d] / 1000.0`): a one-hot [`EMBED_CENTROID_MILLIS`] centroid on the product's
    /// [category axis](Self::product_category_index) plus a small per-axis [`EMBED_JITTER_MILLIS`]
    /// jitter, so same-category products cluster tightly while different categories stay orthogonal.
    /// Integer-only ⇒ byte-deterministic across platforms.
    fn product_embedding_millis(seed: u64, i: u64) -> Vec<u64> {
        let cat = Self::product_category_index(seed, i);
        let mut r =
            SplitMix64::new(seed ^ Self::PRODUCT_SALT ^ i.wrapping_mul(0x2F72_D9B1_A2B8_C31D));
        (0..EMBED_DIM)
            .map(|d| {
                let base = if d == cat { EMBED_CENTROID_MILLIS } else { 0 };
                base + r.below(EMBED_JITTER_MILLIS + 1)
            })
            .collect()
    }

    /// The deterministic embedding for `Product` `i` as `f32` components (component `d` is
    /// `millis[d] / 1000.0`) — the value the `embedding:float[]` column
    /// [`stream_product_csv`](Self::stream_product_csv) emits (and the vector index stores). Used off the
    /// wire only (the hermetic mirror / building query vectors); the emitted CSV is integer-formatted.
    #[must_use]
    pub fn product_embedding(seed: u64, i: u64) -> Vec<f32> {
        Self::product_embedding_millis(seed, i)
            .into_iter()
            .map(milli_to_f32)
            .collect()
    }

    /// The `embedding` CSV cell for `Product` `i`: the [`EMBED_DIM`] integer-thousandths components
    /// joined by `;` (the bulk importer's `float[]` element separator), each a fixed 3-decimal string
    /// (`1023` ⇒ `"1.023"`). Pure integer formatting ⇒ byte-deterministic; contains no comma / quote /
    /// newline, so it is a clean single CSV field.
    fn product_embedding_cell(seed: u64, i: u64) -> String {
        let millis = Self::product_embedding_millis(seed, i);
        let mut cell = String::with_capacity(millis.len() * 6);
        for (k, m) in millis.iter().enumerate() {
            if k > 0 {
                cell.push(';');
            }
            cell.push_str(&fmt_milli(*m));
        }
        cell
    }

    /// A deterministic price for `Product` `i`, in **integer cents** in `[PRICE_MIN_CENTS,
    /// PRICE_MAX_CENTS]`. Integer-only — never a float — so the emitted bytes stay platform-stable.
    fn product_price_cents(seed: u64, i: u64) -> u64 {
        let mut r =
            SplitMix64::new(seed ^ Self::PRODUCT_SALT ^ i.wrapping_mul(0x1D8E_4E27_C47D_124F));
        r.in_range(PRICE_MIN_CENTS, PRICE_MAX_CENTS)
    }

    /// A deterministic signup timestamp (Unix seconds) for user `i`, spread across the timeline span.
    fn signup_ts(seed: u64, i: u64) -> u64 {
        let mut r = SplitMix64::new(seed ^ Self::USER_SALT ^ i.wrapping_mul(0x2545_F491_4F6C_DD1D));
        EPOCH_S + r.below(REG_SPAN_S)
    }

    /// Builds the realised `FRIEND` multigraph via the configuration model, returning the list of
    /// undirected edges `(u, v)` (each once) and the realised per-user degree histogram.
    ///
    /// The PRNG stream is keyed off `seed` so the whole construction is a pure function of the config.
    /// Adopted verbatim from `graphus-social-gen` — the configuration model is model-agnostic.
    fn build_friend_edges(&self) -> (Vec<(u64, u64)>, Vec<u64>) {
        let users = self.cfg.users;
        let mut degree = vec![0u64; users as usize];
        if users < 2 || self.cfg.friend_max == 0 {
            return (Vec::new(), degree);
        }

        // 1) Draw each user's stub count (target degree) and build the stub array.
        //    Stubs are keyed by a dedicated PRNG so they are independent of name/id/purchase streams.
        let mut stub_rng = SplitMix64::new(self.cfg.seed ^ 0x5731_0000_0000_0001);
        let mut stub_counts = Vec::with_capacity(users as usize);
        let mut total: u64 = 0;
        for _ in 0..users {
            let s = stub_rng.in_range(self.cfg.friend_min, self.cfg.friend_max);
            stub_counts.push(s);
            total = total.saturating_add(s);
        }
        // Make the total even so every stub gets a partner (bump the last user by one if odd).
        if total % 2 == 1 {
            *stub_counts.last_mut().expect("users >= 2 ⇒ non-empty") += 1;
            total += 1;
        }

        let mut stubs: Vec<u64> = Vec::with_capacity(total as usize);
        for (u, &count) in stub_counts.iter().enumerate() {
            for _ in 0..count {
                stubs.push(u as u64);
            }
        }

        // 2) Deterministic Fisher–Yates shuffle (a fresh, independent PRNG stream).
        let mut shuf_rng = SplitMix64::new(self.cfg.seed ^ 0x5348_5546_0000_0002);
        let n = stubs.len();
        if n > 1 {
            for i in (1..n).rev() {
                let j = shuf_rng.below((i + 1) as u64) as usize;
                stubs.swap(i, j);
            }
        }

        // 3) Pair consecutive stubs into FRIEND edges. Self-loops are avoided by a deterministic
        //    forward re-probe: if a pair is a self-loop, swap the second stub with the next non-self
        //    stub. Multi-edges between the same pair are kept (true multigraph).
        let mut edges = Vec::with_capacity(n / 2);
        let mut idx = 0usize;
        while idx + 1 < n {
            let a = stubs[idx];
            // Find a partner != a from position idx+1 onward.
            let b_pos = idx + 1;
            if stubs[b_pos] == a {
                let mut probe = b_pos + 1;
                while probe < n {
                    if stubs[probe] != a {
                        stubs.swap(b_pos, probe);
                        break;
                    }
                    probe += 1;
                }
                // If no non-self partner exists in the tail, leave it self-paired (negligible/rare:
                // only when all remaining stubs belong to `a`); skip emitting a self-loop.
            }
            let b = stubs[b_pos];
            if a != b {
                degree[a as usize] += 1;
                degree[b as usize] += 1;
                edges.push((a, b));
            }
            idx += 2;
        }

        (edges, degree)
    }

    /// Builds the realised `PURCHASED` edges: for each user, a per-user count drawn uniformly in
    /// `[0, 2 * avg_purchases_per_user]` of **distinct** product indices, each product index drawn from
    /// the **popularity-skewed** min-of-K distribution (see the module docs). Returns `(user, product)`
    /// pairs in user-then-sample order. Pure function of the config, integer-only.
    fn build_purchased_edges(&self) -> Vec<(u64, u64)> {
        let users = self.cfg.users;
        let products = self.cfg.products;
        if products == 0 {
            return Vec::new();
        }
        // K >= 1: K == 1 is uniform; a configured 0 is treated as 1 (uniform) rather than a no-op.
        let skew = self.cfg.popularity_skew.max(1);
        let max_purchases = self.cfg.avg_purchases_per_user.saturating_mul(2);
        let mut buy_rng = SplitMix64::new(self.cfg.seed ^ 0x5055_5243_0000_0003);
        let mut edges = Vec::new();
        for u in 0..users {
            let want = if max_purchases == 0 {
                0
            } else {
                buy_rng.in_range(0, max_purchases)
            };
            // Cap by the number of distinct products available.
            let want = want.min(products);
            // Sample `want` DISTINCT product indices from the skewed distribution. Rejection sampling
            // against a tiny insertion-ordered seen-set keeps emitted order stable across platforms (a
            // `Vec`, never a `HashSet`); the attempt budget bounds the loop when `want` ~ `products`.
            let mut chosen: Vec<u64> = Vec::with_capacity(want as usize);
            let mut attempts = 0u64;
            let attempt_budget = want.saturating_mul(8).saturating_add(products);
            while (chosen.len() as u64) < want && attempts < attempt_budget {
                // POPULARITY-SKEWED product index: the minimum of K independent uniform draws. Low
                // indices (the "popular" products, index 0 the most popular) win far more often.
                let mut p = buy_rng.below(products);
                for _ in 1..skew {
                    let q = buy_rng.below(products);
                    if q < p {
                        p = q;
                    }
                }
                if !chosen.contains(&p) {
                    chosen.push(p);
                }
                attempts += 1;
            }
            for p in chosen {
                edges.push((u, p));
            }
        }
        edges
    }

    /// The realised **undirected `FRIEND` degree** of every user, indexed by user index — the exact
    /// answer a `MATCH (u:User {id: $id})-[:FRIEND]-(f) RETURN count(f)` reply must return.
    ///
    /// Counts every incident edge (a multi-edge between the same pair is counted once per edge, and the
    /// undirected read matches the directed-stored edge from either endpoint), so it is byte-equivalent
    /// to the ground truth the [`stream_friend_csv`](Self::stream_friend_csv) bytes encode — it is the
    /// *same* [`build_friend_edges`](Self::build_friend_edges) construction, just index-keyed and
    /// without the id round-trip. Ground truth for the read-result verifier (`rmp` #744).
    #[must_use]
    pub fn friend_degrees(&self) -> Vec<u64> {
        self.build_friend_edges().1
    }

    /// The set of **distinct product indices** each user purchased, indexed by user index — the ground
    /// truth for a `MATCH (:User {id: $id})-[:PURCHASED]->(p) RETURN p.id` reply.
    ///
    /// The inner lists are the distinct products of [`build_purchased_edges`](Self::build_purchased_edges)
    /// in sample order (distinctness is already enforced by the generator); a caller that needs
    /// membership tests should sort each list. Index-keyed and byte-equivalent to the
    /// [`stream_purchased_csv`](Self::stream_purchased_csv) bytes (same construction, no id round-trip).
    #[must_use]
    pub fn purchases_by_user(&self) -> Vec<Vec<u64>> {
        let mut out = vec![Vec::new(); self.cfg.users as usize];
        for (u, p) in self.build_purchased_edges() {
            out[u as usize].push(p);
        }
        out
    }

    /// Computes the run summary (counts + realised degree statistics) WITHOUT materialising any CSV
    /// text. Still builds the edge lists (the only way to know the *realised* degrees), but emits no
    /// rows.
    #[must_use]
    pub fn summary(&self) -> Summary {
        let (friend_edges, degree) = self.build_friend_edges();
        let purchased_edges = self.build_purchased_edges();

        let (degree_min, degree_max, degree_sum) = if degree.is_empty() {
            (0, 0, 0u128)
        } else {
            let mut min = u64::MAX;
            let mut max = 0u64;
            let mut sum: u128 = 0;
            for &d in &degree {
                min = min.min(d);
                max = max.max(d);
                sum += u128::from(d);
            }
            (min, max, sum)
        };
        let degree_avg_x1000 = if degree.is_empty() {
            0
        } else {
            // (sum / count) * 1000, computed as integer to keep floats off the wire.
            u64::try_from(degree_sum.saturating_mul(1000) / degree.len() as u128)
                .unwrap_or(u64::MAX)
        };

        Summary {
            users: self.cfg.users,
            products: self.cfg.products,
            friend_edges: friend_edges.len() as u64,
            purchased_edges: purchased_edges.len() as u64,
            degree_min,
            degree_max,
            degree_avg_x1000,
        }
    }

    // --- Streaming, chunk-by-chunk CSV emission for the BULK loader ------------------------------
    //
    // The generator feeds `graphus-bulk`'s `BulkImporter`, which consumes `neo4j-admin import`-flavoured
    // CSV: a node file is `<id>:ID,:LABEL,<key>:<type>,…` and a rel file is
    // `:START_ID,:END_ID,:TYPE,<key>:<type>,…`. The importer resolves each relationship endpoint through
    // an internal external-id→internal-id hash map (O(1) per endpoint ⇒ O(E) total), so the ingest scales
    // to the `huge` profile.
    //
    // Each method streams one `Vec<u8>` chunk at a time to a `FnMut(Vec<u8>)` sink (the header first,
    // then up to [`BATCH`] data rows per chunk), in a deterministic order. The byte stream is therefore
    // byte-identical per seed (asserted by `tests/determinism.rs`), and peak resident memory is one chunk
    // regardless of total graph size — exactly the streaming contract the `huge` profile needs.
    //
    // IMPORTANT: the importer's `:ID` column is the external **join key** and is NOT stored as a node
    // property (it is consumed to resolve `:START_ID`/`:END_ID`). A read battery, however, anchors its
    // traversals on `(:User {id: …})`, which needs a real `id` *property*. So each node row carries the
    // 24-hex id **twice**: once in the reserved `:ID` join-key column and once in a stored `id:string`
    // property column — the standard neo4j-admin-import recipe for "join key that is also a queryable
    // property".

    /// The header row of the `User` node CSV: `:ID` join key + `:LABEL` + a stored `id` property +
    /// `name` + `country` + `signup`.
    pub const USER_CSV_HEADER: &'static str =
        ":ID,:LABEL,id:string,name:string,country:string,signup:long\n";
    /// The header row of the `Product` node CSV: `:ID` + `:LABEL` + stored `id` + `name` + `category`
    /// + `price` (integer cents) + `embedding` (a `float[]` list column: `;`-separated floats parsed
    ///   by the bulk importer into a `LIST<FLOAT>` property the `VECTOR` index covers).
    pub const PRODUCT_CSV_HEADER: &'static str =
        ":ID,:LABEL,id:string,name:string,category:string,price:long,embedding:float[]\n";
    /// The header row of the `FRIEND` relationship CSV.
    pub const FRIEND_CSV_HEADER: &'static str = ":START_ID,:END_ID,:TYPE,since:long\n";
    /// The header row of the `PURCHASED` relationship CSV.
    pub const PURCHASED_CSV_HEADER: &'static str = ":START_ID,:END_ID,:TYPE,ts:long,qty:long\n";

    /// Streams the `User` node CSV to `sink`, one chunk at a time: the header chunk first, then chunks
    /// of up to [`BATCH`] data rows `<id>,User,<id>,<name>,<country>,<signup>`. No edge list is built;
    /// peak memory is one chunk.
    pub fn stream_user_csv<F: FnMut(Vec<u8>)>(&self, mut sink: F) {
        sink(Self::USER_CSV_HEADER.as_bytes().to_vec());
        let mut buf = String::new();
        let mut in_chunk = 0usize;
        for i in 0..self.cfg.users {
            let id = Self::user_id(i);
            let name = escape_csv(&Self::user_name(self.cfg.seed, i));
            let country = escape_csv(Self::user_country(self.cfg.seed, i));
            let signup = Self::signup_ts(self.cfg.seed, i);
            // `id` appears twice: the `:ID` join key (col 0) and the stored `id` property (col 2).
            let _ = writeln!(buf, "{id},User,{id},{name},{country},{signup}");
            in_chunk += 1;
            if in_chunk == BATCH || i + 1 == self.cfg.users {
                sink(std::mem::take(&mut buf).into_bytes());
                in_chunk = 0;
            }
        }
    }

    /// Streams the `Product` node CSV to `sink`, one chunk at a time: the header chunk first, then
    /// chunks of up to [`BATCH`] data rows `<id>,Product,<id>,<name>,<category>,<price>,<embedding>`
    /// (the `embedding` a `;`-separated `float[]` cell). No edge list is built; peak memory is one chunk.
    pub fn stream_product_csv<F: FnMut(Vec<u8>)>(&self, mut sink: F) {
        sink(Self::PRODUCT_CSV_HEADER.as_bytes().to_vec());
        let mut buf = String::new();
        let mut in_chunk = 0usize;
        for i in 0..self.cfg.products {
            let id = Self::product_id(i);
            let name = escape_csv(&Self::product_name(self.cfg.seed, i));
            let category = escape_csv(Self::product_category(self.cfg.seed, i));
            let price = Self::product_price_cents(self.cfg.seed, i);
            let embedding = Self::product_embedding_cell(self.cfg.seed, i);
            let _ = writeln!(
                buf,
                "{id},Product,{id},{name},{category},{price},{embedding}"
            );
            in_chunk += 1;
            if in_chunk == BATCH || i + 1 == self.cfg.products {
                sink(std::mem::take(&mut buf).into_bytes());
                in_chunk = 0;
            }
        }
    }

    /// Streams the `FRIEND` relationship CSV to `sink`: the header chunk, then chunks of up to [`BATCH`]
    /// rows `<start_id>,<end_id>,FRIEND,<since>`. Each unordered friendship is emitted **once** (stored
    /// directed; read back undirected in queries). Returns the number of `FRIEND` edges emitted
    /// (== [`Summary::friend_edges`]). The (linear-size) edge list is built once; the text streams a
    /// chunk at a time.
    pub fn stream_friend_csv<F: FnMut(Vec<u8>)>(&self, mut sink: F) -> u64 {
        sink(Self::FRIEND_CSV_HEADER.as_bytes().to_vec());
        let (edges, _degree) = self.build_friend_edges();
        let total = edges.len() as u64;
        let mut buf = String::new();
        let mut in_chunk = 0usize;
        let n = edges.len();
        for (k, &(a, b)) in edges.iter().enumerate() {
            let ida = Self::user_id(a);
            let idb = Self::user_id(b);
            // Deterministic `since` timestamp keyed on the (ordered) endpoint pair.
            let mut r = SplitMix64::new(
                self.cfg.seed
                    ^ 0xF111_0000_0000_0004
                    ^ a.wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    ^ b.rotate_left(17),
            );
            let since = EPOCH_S + r.below(REG_SPAN_S);
            let _ = writeln!(buf, "{ida},{idb},FRIEND,{since}");
            in_chunk += 1;
            if in_chunk == BATCH || k + 1 == n {
                sink(std::mem::take(&mut buf).into_bytes());
                in_chunk = 0;
            }
        }
        total
    }

    /// Streams the `PURCHASED` relationship CSV to `sink`: the header chunk, then chunks of up to
    /// [`BATCH`] rows `<user_id>,<product_id>,PURCHASED,<ts>,<qty>`. Returns the number of `PURCHASED`
    /// edges emitted (== [`Summary::purchased_edges`]). The (linear-size) edge list is built once; the
    /// text streams a chunk at a time.
    pub fn stream_purchased_csv<F: FnMut(Vec<u8>)>(&self, mut sink: F) -> u64 {
        sink(Self::PURCHASED_CSV_HEADER.as_bytes().to_vec());
        let edges = self.build_purchased_edges();
        let total = edges.len() as u64;
        let mut buf = String::new();
        let mut in_chunk = 0usize;
        let n = edges.len();
        for (k, &(u, prod)) in edges.iter().enumerate() {
            let idu = Self::user_id(u);
            let idp = Self::product_id(prod);
            // Deterministic `ts` + `qty` keyed on the (user, product) pair: `ts` drawn first, `qty`
            // second, from one integer-only PRNG stream.
            let mut r = SplitMix64::new(
                self.cfg.seed
                    ^ 0x5453_0000_0000_0006
                    ^ u.wrapping_mul(0xA076_1D64_78BD_642F)
                    ^ prod.rotate_left(23),
            );
            let ts = EPOCH_S + r.below(REG_SPAN_S);
            let qty = r.in_range(QTY_MIN, QTY_MAX);
            let _ = writeln!(buf, "{idu},{idp},PURCHASED,{ts},{qty}");
            in_chunk += 1;
            if in_chunk == BATCH || k + 1 == n {
                sink(std::mem::take(&mut buf).into_bytes());
                in_chunk = 0;
            }
        }
        total
    }

    /// A sample `User` id by index, for a loader's read-query probes. Convenience over
    /// [`user_id`](Self::user_id).
    #[must_use]
    pub fn sample_user_id(&self, i: u64) -> String {
        Self::user_id(i % self.cfg.users.max(1))
    }

    /// A machine-readable one-line summary of the run's realised shape (the `reco_gen` binary prints
    /// it; an example's `run.sh` parses it for dataset sizing).
    #[must_use]
    pub fn summary_line(&self) -> String {
        let s = self.summary();
        format!(
            "users={} products={} friend_edges={} purchased_edges={} \
             degree_min={} degree_max={} degree_avg_x1000={} \
             friend_min={} friend_max={} avg_purchases_per_user={} popularity_skew={}",
            s.users,
            s.products,
            s.friend_edges,
            s.purchased_edges,
            s.degree_min,
            s.degree_max,
            s.degree_avg_x1000,
            self.cfg.friend_min,
            self.cfg.friend_max,
            self.cfg.avg_purchases_per_user,
            self.cfg.popularity_skew,
        )
    }
}

/// Formats an integer-thousandths embedding component as a fixed 3-decimal string (`1023` ⇒ `"1.023"`,
/// `7` ⇒ `"0.007"`), using **pure integer arithmetic** so no `f32` ever reaches the wire (the module's
/// platform-stability contract). The bulk importer parses it back as a `float[]` element.
fn fmt_milli(m: u64) -> String {
    format!("{}.{:03}", m / 1000, m % 1000)
}

/// An `f32` view of an integer-thousandths component (`1023` ⇒ `1.023`). Used only off the wire (query
/// vectors / the hermetic mirror), never in the emitted CSV bytes.
fn milli_to_f32(m: u64) -> f32 {
    m as f32 / 1000.0
}

/// Truncates a `String` to at most `max_bytes`, never splitting a UTF-8 char. Cheap when already
/// within budget (the common path).
fn truncate_on_char_boundary(mut s: String, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s
}

/// Defensively escapes a string for inclusion as one field of a comma-delimited CSV row (RFC 4180):
/// a field containing a comma, a double-quote, or a newline is wrapped in double-quotes with each
/// embedded double-quote doubled. Our name / country / category pools contain none of these, so the
/// common path returns the input untouched (and the stream stays byte-identical per seed); we still
/// escape so the emitted CSV is always well-formed regardless of the pools.
fn escape_csv(s: &str) -> String {
    if !s.contains(',') && !s.contains('"') && !s.contains('\n') && !s.contains('\r') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> GenConfig {
        GenConfig {
            seed: 42,
            users: 300,
            products: 40,
            friend_min: 3,
            friend_max: 10,
            avg_purchases_per_user: 4,
            popularity_skew: 3,
        }
    }

    /// Collects a full CSV stream (header + all data chunks) into one byte buffer.
    fn collect_csv(stream: impl FnOnce(&mut dyn FnMut(Vec<u8>))) -> Vec<u8> {
        let mut out = Vec::new();
        let mut sink = |chunk: Vec<u8>| out.extend_from_slice(&chunk);
        stream(&mut sink);
        out
    }

    #[test]
    fn csv_streams_are_byte_identical_per_config() {
        let g = Generator::new(cfg());
        let g2 = Generator::new(cfg());
        for (a, b) in [
            (
                collect_csv(|s| g.stream_user_csv(s)),
                collect_csv(|s| g2.stream_user_csv(s)),
            ),
            (
                collect_csv(|s| g.stream_product_csv(s)),
                collect_csv(|s| g2.stream_product_csv(s)),
            ),
            (
                collect_csv(|s| {
                    g.stream_friend_csv(s);
                }),
                collect_csv(|s| {
                    g2.stream_friend_csv(s);
                }),
            ),
            (
                collect_csv(|s| {
                    g.stream_purchased_csv(s);
                }),
                collect_csv(|s| {
                    g2.stream_purchased_csv(s);
                }),
            ),
        ] {
            assert_eq!(a, b, "same config => byte-identical CSV stream");
        }
    }

    #[test]
    fn a_different_seed_changes_the_graph() {
        let mut c2 = cfg();
        c2.seed = 43;
        let base = collect_csv(|s| Generator::new(cfg()).stream_user_csv(s));
        let other = collect_csv(|s| Generator::new(c2).stream_user_csv(s));
        assert_ne!(base, other, "a different seed must change the user stream");
    }

    #[test]
    fn ids_are_24_lowercase_hex() {
        for i in 0..50 {
            for id in [Generator::user_id(i), Generator::product_id(i)] {
                assert_eq!(id.len(), 24, "id must be 24 chars: {id}");
                assert!(
                    id.chars()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                    "id must be lowercase hex: {id}"
                );
            }
        }
    }

    #[test]
    fn names_are_bounded_and_csv_clean() {
        for i in 0..500 {
            for name in [
                Generator::user_name(cfg().seed, i),
                Generator::product_name(cfg().seed, i),
            ] {
                assert!(name.len() <= MAX_NAME_BYTES, "name too long: {name:?}");
                assert!(!name.is_empty(), "name is empty at index {i}");
                assert!(!name.contains(','), "name must not contain a comma: {name}");
                assert!(!name.contains('"'), "name must not contain a quote: {name}");
                assert!(
                    !name.contains('\n'),
                    "name must not contain a newline: {name}"
                );
            }
        }
    }

    #[test]
    fn realised_degrees_are_within_band() {
        let c = cfg();
        let g = Generator::new(c.clone());
        let (_edges, degree) = g.build_friend_edges();
        for (u, &d) in degree.iter().enumerate() {
            assert!(
                d >= c.friend_min && d <= c.friend_max,
                "user {u} degree {d} outside [{}, {}]",
                c.friend_min,
                c.friend_max
            );
        }
    }

    #[test]
    fn headers_are_exactly_the_importer_schema() {
        assert_eq!(
            Generator::USER_CSV_HEADER,
            ":ID,:LABEL,id:string,name:string,country:string,signup:long\n"
        );
        assert_eq!(
            Generator::PRODUCT_CSV_HEADER,
            ":ID,:LABEL,id:string,name:string,category:string,price:long,embedding:float[]\n"
        );
        assert_eq!(
            Generator::FRIEND_CSV_HEADER,
            ":START_ID,:END_ID,:TYPE,since:long\n"
        );
        assert_eq!(
            Generator::PURCHASED_CSV_HEADER,
            ":START_ID,:END_ID,:TYPE,ts:long,qty:long\n"
        );
    }

    #[test]
    fn csv_streams_match_the_summary_counts_and_shape() {
        let g = Generator::new(cfg());
        let s = g.summary();

        let users_csv = String::from_utf8(collect_csv(|sink| g.stream_user_csv(sink))).unwrap();
        let products_csv =
            String::from_utf8(collect_csv(|sink| g.stream_product_csv(sink))).unwrap();
        let mut friend_total = 0u64;
        let friend_csv = String::from_utf8(collect_csv(|sink| {
            friend_total = g.stream_friend_csv(sink);
        }))
        .unwrap();
        let mut purchased_total = 0u64;
        let purchased_csv = String::from_utf8(collect_csv(|sink| {
            purchased_total = g.stream_purchased_csv(sink);
        }))
        .unwrap();

        // Data-row count == header + body, minus the one header line.
        let body_rows = |csv: &str| csv.lines().count() as u64 - 1;
        assert_eq!(body_rows(&users_csv), s.users, "User rows");
        assert_eq!(body_rows(&products_csv), s.products, "Product rows");
        assert_eq!(body_rows(&friend_csv), s.friend_edges, "FRIEND rows");
        assert_eq!(
            body_rows(&purchased_csv),
            s.purchased_edges,
            "PURCHASED rows"
        );
        assert_eq!(friend_total, s.friend_edges, "FRIEND stream return");
        assert_eq!(
            purchased_total, s.purchased_edges,
            "PURCHASED stream return"
        );

        // The headers are exactly the importer-flavoured schema.
        assert!(users_csv.starts_with(Generator::USER_CSV_HEADER));
        assert!(products_csv.starts_with(Generator::PRODUCT_CSV_HEADER));
        assert!(friend_csv.starts_with(Generator::FRIEND_CSV_HEADER));
        assert!(purchased_csv.starts_with(Generator::PURCHASED_CSV_HEADER));

        // Every User data row carries the User label and the `:ID` join key (col 0) equals the stored
        // `id` property (col 2) — the join-key-as-property recipe.
        for line in users_csv.lines().skip(1) {
            let cols: Vec<&str> = line.split(',').collect();
            assert_eq!(cols.len(), 6, "User row has 6 columns: {line}");
            assert_eq!(cols[1], "User", "User :LABEL column: {line}");
            assert_eq!(
                cols[0], cols[2],
                "ID join key == stored id property: {line}"
            );
        }
        // ...and likewise for every Product data row (now 7 columns: the `embedding:float[]` cell is a
        // single `;`-separated field with no comma, so `split(',')` still yields exactly 7).
        for line in products_csv.lines().skip(1) {
            let cols: Vec<&str> = line.split(',').collect();
            assert_eq!(cols.len(), 7, "Product row has 7 columns: {line}");
            assert_eq!(cols[1], "Product", "Product :LABEL column: {line}");
            assert_eq!(
                cols[0], cols[2],
                "ID join key == stored id property: {line}"
            );
            // The `embedding` cell (col 6) is a `;`-separated float[] of exactly EMBED_DIM elements.
            let embedding: Vec<&str> = cols[6].split(';').collect();
            assert_eq!(
                embedding.len(),
                EMBED_DIM,
                "embedding has EMBED_DIM components: {line}"
            );
            for e in embedding {
                assert!(
                    e.parse::<f64>().is_ok(),
                    "each embedding component parses as a float: {e:?} in {line}"
                );
            }
        }
    }

    #[test]
    fn purchased_distribution_is_popularity_skewed() {
        // With the min-of-K skew and K >= 3, product index 0 (the global minimum of every draw) must
        // appear strictly more often across the whole PURCHASED edge set than the highest-index
        // ("least popular") product. This is the property that makes co-purchase clusters emerge.
        let g = Generator::new(cfg());
        let edges = g.build_purchased_edges();
        let products = cfg().products;
        let mut counts = vec![0u64; products as usize];
        for &(_, p) in &edges {
            counts[p as usize] += 1;
        }
        let popular = counts[0];
        let unpopular = counts[(products - 1) as usize];
        assert!(
            popular > unpopular,
            "popularity skew must make product 0 dominant: product 0 appeared {popular} times, \
             product {} appeared {unpopular} times",
            products - 1
        );
    }

    /// The embedding's dominant (max) component is exactly the product's category axis, so a query at a
    /// category centroid retrieves that category — the property the `VECTOR` "similar products" query
    /// relies on. Also asserts the cell round-trips to [`EMBED_DIM`] finite floats.
    #[test]
    fn embeddings_cluster_by_category() {
        let c = cfg();
        for i in 0..c.products {
            let cat = Generator::product_category_index(c.seed, i);
            let emb = Generator::product_embedding(c.seed, i);
            assert_eq!(
                emb.len(),
                EMBED_DIM,
                "embedding {i} has EMBED_DIM components"
            );

            // The category axis is the strict argmax (centroid ≥ 1.0 dominates every ≤ 0.05 jitter axis).
            let argmax = emb
                .iter()
                .enumerate()
                .max_by(|(_, a), (_, b)| a.partial_cmp(b).expect("finite"))
                .map(|(d, _)| d)
                .expect("EMBED_DIM > 0");
            assert_eq!(
                argmax, cat,
                "product {i}: the embedding's dominant axis ({argmax}) must be its category axis ({cat})"
            );
            assert!(
                emb[cat] >= 1.0,
                "product {i}: the category axis component ({}) must be ≥ 1.0",
                emb[cat]
            );
            for (d, &v) in emb.iter().enumerate() {
                assert!(v.is_finite(), "component {d} is finite");
                if d != cat {
                    assert!(
                        v <= 0.05 + f32::EPSILON,
                        "product {i}: non-category axis {d} component ({v}) must be ≤ 0.05 jitter"
                    );
                }
            }
        }
    }

    /// Two products in **different** categories are cosine-orthogonal-ish (near 0), while a product and
    /// its own category centroid are near-parallel (near 1) — the wide margin the k-NN seek depends on.
    #[test]
    fn cross_category_embeddings_are_well_separated() {
        let c = cfg();
        let cos = |a: &[f32], b: &[f32]| -> f32 {
            let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
            let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
            let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
            dot / (na * nb)
        };
        // Find one product per category to compare across clusters.
        let mut rep: Vec<Option<u64>> = vec![None; EMBED_DIM];
        for i in 0..c.products {
            let cat = Generator::product_category_index(c.seed, i);
            rep[cat].get_or_insert(i);
        }
        for (cat, &maybe_i) in rep.iter().enumerate() {
            let Some(i) = maybe_i else { continue };
            let emb = Generator::product_embedding(c.seed, i);
            let centroid = Generator::category_centroid(cat);
            let self_sim = cos(&emb, &centroid);
            assert!(
                self_sim > 0.9,
                "product {i} (category {cat}) must align with its own centroid: cos = {self_sim}"
            );
            // Its similarity to any *other* category's centroid is far lower.
            for other in 0..EMBED_DIM {
                if other == cat {
                    continue;
                }
                let cross = cos(&emb, &Generator::category_centroid(other));
                assert!(
                    cross < 0.2,
                    "product {i} (category {cat}) must be far from centroid {other}: cos = {cross}"
                );
                assert!(
                    self_sim > cross + 0.5,
                    "product {i}: own-centroid margin too small ({self_sim} vs {cross})"
                );
            }
        }
    }
}
