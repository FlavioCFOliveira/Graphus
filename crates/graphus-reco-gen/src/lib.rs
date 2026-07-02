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
//! | `(:Product {id, name, category, price})` | `id` (24 lowercase hex chars, unique) | a catalogue item |
//!
//! `price` is always an **integer number of cents** — never a float, so the emitted bytes stay
//! platform-stable (see [Determinism](#determinism)).
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
//! sampling, timestamps). For a given config the emitted CSV is **byte-identical** across runs, hosts,
//! and platforms (no floats on the wire, no `HashMap` iteration in any emitted-order path, no clock,
//! no thread scheduling). This is asserted by `tests/determinism.rs`, and the CSV is proven a valid
//! bulk-import artifact by `tests/bulk_import_validity.rs`.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

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

    /// Resolves a profile name (`"fast"` / `"large"` / `"huge"`) to its config, or `None` for an
    /// unknown name.
    #[must_use]
    pub fn profile(name: &str) -> Option<Self> {
        match name {
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
    /// [`MAX_NAME_BYTES`] bytes. Assembled as `<noun> <adjective>` with, roughly half the time, a
    /// brand-ish suffix. Never contains a comma, quote, or newline.
    #[must_use]
    pub fn product_name(seed: u64, i: u64) -> String {
        let mut r =
            SplitMix64::new(seed ^ Self::PRODUCT_SALT ^ i.wrapping_mul(0xA076_1D64_78BD_642F));
        let noun = PRODUCT_NOUN[r.below(PRODUCT_NOUN.len() as u64) as usize];
        let adj = PRODUCT_ADJ[r.below(PRODUCT_ADJ.len() as u64) as usize];

        let mut name = String::with_capacity(MAX_NAME_BYTES);
        name.push_str(noun);
        name.push(' ');
        name.push_str(adj);

        // ~half the time, append a brand-ish suffix.
        if r.below(2) == 1 {
            let brand = PRODUCT_BRAND[r.below(PRODUCT_BRAND.len() as u64) as usize];
            let extra = 1 + brand.len();
            if name.len() + extra <= MAX_NAME_BYTES {
                name.push(' ');
                name.push_str(brand);
            }
        }

        truncate_on_char_boundary(name, MAX_NAME_BYTES)
    }

    /// A deterministic country for `User` `i`, from the [`COUNTRIES`] pool.
    fn country_of(seed: u64, i: u64) -> &'static str {
        let mut r = SplitMix64::new(seed ^ Self::USER_SALT ^ i.wrapping_mul(0xC2B2_AE3D_27D4_EB4F));
        COUNTRIES[r.below(COUNTRIES.len() as u64) as usize]
    }

    /// A deterministic category for `Product` `i`, from the [`CATEGORIES`] pool.
    fn product_category(seed: u64, i: u64) -> &'static str {
        let mut r =
            SplitMix64::new(seed ^ Self::PRODUCT_SALT ^ i.wrapping_mul(0xEBCA_1A6C_6D8B_2F17));
        CATEGORIES[r.below(CATEGORIES.len() as u64) as usize]
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
    /// + `price` (integer cents).
    pub const PRODUCT_CSV_HEADER: &'static str =
        ":ID,:LABEL,id:string,name:string,category:string,price:long\n";
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
            let country = escape_csv(Self::country_of(self.cfg.seed, i));
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
    /// chunks of up to [`BATCH`] data rows `<id>,Product,<id>,<name>,<category>,<price>`. No edge list
    /// is built; peak memory is one chunk.
    pub fn stream_product_csv<F: FnMut(Vec<u8>)>(&self, mut sink: F) {
        sink(Self::PRODUCT_CSV_HEADER.as_bytes().to_vec());
        let mut buf = String::new();
        let mut in_chunk = 0usize;
        for i in 0..self.cfg.products {
            let id = Self::product_id(i);
            let name = escape_csv(&Self::product_name(self.cfg.seed, i));
            let category = escape_csv(Self::product_category(self.cfg.seed, i));
            let price = Self::product_price_cents(self.cfg.seed, i);
            let _ = writeln!(buf, "{id},Product,{id},{name},{category},{price}");
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
            ":ID,:LABEL,id:string,name:string,category:string,price:long\n"
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
        // ...and likewise for every Product data row.
        for line in products_csv.lines().skip(1) {
            let cols: Vec<&str> = line.split(',').collect();
            assert_eq!(cols.len(), 6, "Product row has 6 columns: {line}");
            assert_eq!(cols[1], "Product", "Product :LABEL column: {line}");
            assert_eq!(
                cols[0], cols[2],
                "ID join key == stored id property: {line}"
            );
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
}
