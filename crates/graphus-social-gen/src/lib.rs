//! Deterministic, seeded **large social-network graph generator** for the
//! `examples/social-network` performance-evaluation demonstration.
//!
//! It models a social network as a Label Property Graph (a **multigraph**, matching Graphus's
//! default): a population of `USER`s, a catalogue of `ARTICLE`s, an **undirected** `FRIEND`
//! multigraph among users, and directed `LIKE` edges from users to articles. The generator emits the
//! whole graph as batched Cypher text suitable for a loader, plus a one-line machine-readable
//! summary — exactly the substrate the example loads into the real engine to measure CPU / RAM /
//! storage at scale (up to one million users).
//!
//! # The social-network graph model
//!
//! A Label Property Graph modelling a population and its relationships:
//!
//! | Node label | Key properties | Meaning |
//! | --- | --- | --- |
//! | `(:USER {id, name, registered})` | `id` (24 lowercase hex chars, unique) | a member |
//! | `(:ARTICLE {id, name, registered})` | `id` (24 lowercase hex chars, unique) | a news item |
//!
//! Two relationship types:
//!
//! | Relationship | Direction | Meaning |
//! | --- | --- | --- |
//! | `:FRIEND {since}` | `(:USER)-(:USER)` (undirected) | a friendship; **multi-edges allowed** |
//! | `:LIKE {date}` | `(:USER)->(:ARTICLE)` | the user liked the article |
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
//! as a single **directed** `(a)-[:FRIEND]->(b)` relationship (a Cypher `CREATE` relationship must
//! carry a direction — the TCK's `RequiresDirectedRelationship` rule), and read back with the
//! **undirected** `-[:FRIEND]-` form so the friendship's symmetric semantics are preserved.
//! The realised per-user degree therefore lands within `[friend_min, friend_max]` (modulo at most the
//! one-stub parity bump on the final user), the construction is `O(E)`, and it scales to a million
//! users.
//!
//! ## The LIKE edges
//!
//! Each user likes a per-user count of **distinct** articles drawn uniformly in
//! `[0, 2 * avg_likes_per_user]` (a symmetric spread whose mean is `avg_likes_per_user`); the liked
//! article indices are sampled distinctly via the PRNG. `LIKE` is directed `(:USER)->(:ARTICLE)`.
//!
//! # Determinism
//!
//! Generation is a pure function of [`GenConfig`]: the only randomness is an internal [`SplitMix64`]
//! PRNG seeded from `seed` (degree draws, the shuffle, name/title assembly, like sampling,
//! timestamps). For a given config the emitted Cypher is **byte-identical** across runs, hosts, and
//! platforms (no floats in the wire text, no `HashMap` iteration in any emitted-order path, no clock,
//! no thread scheduling). This is asserted by `tests/determinism.rs`.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

/// The engine-driving load + traversal workload (behind the `engine` feature). It builds an on-disk
/// store and loads the deterministic graph into the REAL Graphus engine over the production
/// command-dispatch path, then runs the read-query battery and meters CPU/wall time + durable
/// footprint. See the module docs for the "why in-process / why on-disk" rationale.
#[cfg(feature = "engine")]
pub mod load;

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

/// One year in seconds — registration timestamps are spread across `[EPOCH_S, EPOCH_S + REG_SPAN_S)`.
pub const REG_SPAN_S: u64 = 365 * 24 * 60 * 60;

/// How many `CREATE`/`MATCH` clauses are packed into a single emitted statement. Batching keeps the
/// per-statement parse/plan overhead amortised when the loader replays the stream, while staying
/// small enough that any one statement is human-inspectable. A pure constant so the output is a pure
/// function of the config.
pub const BATCH: usize = 100;

// --- Deterministic Portuguese-name fragment pools -----------------------------------------------
//
// Realistic European-Portuguese given names, middle/connective particles, and surnames, all valid
// UTF-8 *including diacritics*. None contains a single-quote, so the assembled `name` can never break
// a Cypher string literal; we still escape defensively at emit time. Names are assembled
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

// --- Deterministic news-headline fragment pools -------------------------------------------------
//
// Headline-style fragments assembled into article titles so they "tend to contain real information".
// None contains a single-quote; we still escape defensively at emit time.

/// Headline subjects.
const HEAD_SUBJECT: &[&str] = &[
    "Governo",
    "Câmara Municipal",
    "Universidade",
    "Selecção Nacional",
    "Banco Central",
    "Ministério da Saúde",
    "Comissão Europeia",
    "Empresa tecnológica",
    "Investigadores",
    "Autarquia",
    "Mercado imobiliário",
    "Sector automóvel",
    "Comunidade científica",
    "Federação",
    "Associação de moradores",
];

/// Headline verbs / actions.
const HEAD_VERB: &[&str] = &[
    "anuncia",
    "aprova",
    "investe em",
    "lança",
    "estuda",
    "reforça",
    "apresenta",
    "regula",
    "moderniza",
    "expande",
    "reduz",
    "duplica",
];

/// Headline objects / topics.
const HEAD_OBJECT: &[&str] = &[
    "nova linha de metro",
    "rede de energia renovável",
    "programa de habitação acessível",
    "plano de digitalização",
    "centro de investigação",
    "medidas de mobilidade urbana",
    "apoio às pequenas empresas",
    "infraestrutura de dados",
    "estratégia para a saúde",
    "rede de transportes públicos",
    "projecto de reflorestação",
    "incentivos à inovação",
];

/// Headline qualifiers / closers.
const HEAD_TAIL: &[&str] = &[
    "até 2030",
    "na região norte",
    "em todo o país",
    "com fundos europeus",
    "para o próximo ano",
    "em parceria com privados",
    "após meses de negociação",
    "com impacto nacional",
];

/// The maximum number of bytes a `USER` name may occupy. The model contract guarantees names are
/// valid UTF-8 (diacritics included) and at most this many bytes; the assembler truncates on a char
/// boundary if a chained name would overshoot.
pub const MAX_NAME_BYTES: usize = 64;

/// Configuration for one generation run. A pure value: identical configs yield identical graphs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenConfig {
    /// PRNG seed — the sole source of (reproducible) randomness.
    pub seed: u64,
    /// Number of `USER` nodes.
    pub users: u64,
    /// Number of `ARTICLE` nodes.
    pub articles: u64,
    /// Minimum `FRIEND` stub count (target degree) per user, inclusive.
    pub friend_min: u64,
    /// Maximum `FRIEND` stub count (target degree) per user, inclusive.
    pub friend_max: u64,
    /// Mean number of `LIKE` edges per user; the per-user like count is drawn uniformly in
    /// `[0, 2 * avg_likes_per_user]`, so the population mean is `avg_likes_per_user`.
    pub avg_likes_per_user: u64,
}

impl GenConfig {
    /// The **fast** profile — small, CI-runnable: a couple of thousand users with a modest friend
    /// fan-out and a small article catalogue. Sized so the determinism test **and the engine-driving
    /// `load_fast` test** stay quick (a few seconds) under a default `cargo test`, including in the
    /// slower debug profile.
    ///
    /// # Why these numbers
    ///
    /// The engine loader now ingests via the **production bulk path** (`graphus-bulk`'s
    /// `BulkImporter`), which resolves both relationship endpoints through an internal
    /// external-id→internal-id hash map — O(1) per endpoint, **O(E) total** — so the ingest scales
    /// independently of `N` (unlike per-edge Cypher `CREATE`, which the planner can only index-seek on
    /// one of the two anchors, making it O(E·N); see `load.rs`). The `fast` size is therefore chosen
    /// for *test wall-time*, not an ingest-asymptote ceiling: ≈ 2 000 users, degree band 6–24
    /// (≈ 30 000 FRIEND edges), 200 articles, ≈ 5 likes/user (≈ 10 000 LIKE edges) — enough to
    /// exercise a real fan-out, multi-edges, a catalogue, and a non-trivial like load while bulk-loading
    /// and running the read-query battery in a few seconds in debug.
    #[must_use]
    pub fn fast() -> Self {
        Self {
            seed: 0x50C1_A150_600D_5EED,
            users: 2_000,
            articles: 200,
            friend_min: 6,
            friend_max: 24,
            avg_likes_per_user: 5,
        }
    }

    /// The **large** profile — evidence-scale: tens of thousands of users with a substantial friend
    /// fan-out, a few thousand articles, and a heavier like load. Sized to exercise the engine at a
    /// scale where CPU / RAM / storage trends are clearly observable while staying tractable.
    #[must_use]
    pub fn large() -> Self {
        Self {
            seed: 0x50C1_A150_600D_5EED,
            users: 50_000,
            articles: 3_000,
            friend_min: 20,
            friend_max: 120,
            avg_likes_per_user: 20,
        }
    }

    /// The **huge** profile — the literal one-million-user target: a massive friend fan-out and a
    /// large article catalogue. Heavy and opt-in; intended for full-scale performance evaluation, not
    /// routine CI.
    #[must_use]
    pub fn huge() -> Self {
        Self {
            seed: 0x50C1_A150_600D_5EED,
            users: 1_000_000,
            articles: 30_000,
            friend_min: 200,
            friend_max: 2_000,
            avg_likes_per_user: 30,
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
/// Cypher uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    /// Number of `USER` nodes.
    pub users: u64,
    /// Number of `ARTICLE` nodes.
    pub articles: u64,
    /// Number of (undirected) `FRIEND` edges emitted.
    pub friend_edges: u64,
    /// Number of `LIKE` edges emitted.
    pub like_edges: u64,
    /// Smallest realised per-user `FRIEND` degree.
    pub degree_min: u64,
    /// Largest realised per-user `FRIEND` degree.
    pub degree_max: u64,
    /// Mean realised per-user `FRIEND` degree, scaled by 1000 and floored (an integer, so it never
    /// puts a float on the wire). `degree_avg_x1000 / 1000` is the mean to three decimal places.
    pub degree_avg_x1000: u64,
}

/// The deterministic social-network graph generator.
///
/// Construct with [`Generator::new`], then [`Generator::summary`] for the realised counts/degree
/// statistics (cheap — it does not materialise the Cypher text) or [`Generator::emit_all`] for the
/// full batched Cypher artifact.
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
    /// namespace (so `USER 0` and `ARTICLE 0` get distinct ids). Built from two SplitMix64 draws
    /// keyed by `(salt, i)` and rendered as 24 hex nibbles (96 bits). Collisions across our scales
    /// are negligible, and the id is purely a function of `(salt, i)`.
    #[must_use]
    pub fn entity_id(salt: u64, i: u64) -> String {
        // Two independent 48-bit halves → 96 bits → 24 hex chars.
        let mut r = SplitMix64::new(salt ^ i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let hi = r.next_u64() & 0x0000_FFFF_FFFF_FFFF; // 48 bits
        let lo = r.next_u64() & 0x0000_FFFF_FFFF_FFFF; // 48 bits
        format!("{hi:012x}{lo:012x}")
    }

    /// Salt namespace for `USER` ids.
    const USER_SALT: u64 = 0x1111_1111_0000_0001;
    /// Salt namespace for `ARTICLE` ids.
    const ARTICLE_SALT: u64 = 0x2222_2222_0000_0002;

    /// The stable id of `USER` `i`.
    #[must_use]
    pub fn user_id(i: u64) -> String {
        Self::entity_id(Self::USER_SALT, i)
    }

    /// The stable id of `ARTICLE` `i`.
    #[must_use]
    pub fn article_id(i: u64) -> String {
        Self::entity_id(Self::ARTICLE_SALT, i)
    }

    /// A deterministic, realistic Portuguese full name for `USER` `i`, valid UTF-8 (diacritics
    /// included) and at most [`MAX_NAME_BYTES`] bytes. Assembled as a given name, one or two
    /// surnames, optionally joined by a connective particle. Never contains a single-quote.
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

    /// A deterministic, headline-style article title for `ARTICLE` `i`. Assembled from the headline
    /// fragment pools so it "tends to contain real information". Never contains a single-quote;
    /// bounded in length by construction.
    #[must_use]
    pub fn article_name(seed: u64, i: u64) -> String {
        let mut r = SplitMix64::new(seed ^ Self::ARTICLE_SALT ^ i.wrapping_mul(0xA0761D6478BD642F));
        let subject = HEAD_SUBJECT[r.below(HEAD_SUBJECT.len() as u64) as usize];
        let verb = HEAD_VERB[r.below(HEAD_VERB.len() as u64) as usize];
        let object = HEAD_OBJECT[r.below(HEAD_OBJECT.len() as u64) as usize];
        let tail = HEAD_TAIL[r.below(HEAD_TAIL.len() as u64) as usize];
        format!("{subject} {verb} {object} {tail}")
    }

    /// A deterministic registration timestamp (Unix seconds) for entity `i` in `salt`'s namespace,
    /// spread across the registration span.
    fn registered_ts(seed: u64, salt: u64, i: u64) -> u64 {
        let mut r = SplitMix64::new(seed ^ salt ^ i.wrapping_mul(0x2545_F491_4F6C_DD1D));
        EPOCH_S + r.below(REG_SPAN_S)
    }

    /// Builds the realised `FRIEND` multigraph via the configuration model, returning the list of
    /// undirected edges `(u, v)` (each once) and the realised per-user degree histogram.
    ///
    /// The PRNG stream is keyed off `seed` so the whole construction is a pure function of the config.
    fn build_friend_edges(&self) -> (Vec<(u64, u64)>, Vec<u64>) {
        let users = self.cfg.users;
        let mut degree = vec![0u64; users as usize];
        if users < 2 || self.cfg.friend_max == 0 {
            return (Vec::new(), degree);
        }

        // 1) Draw each user's stub count (target degree) and build the stub array.
        //    Stubs are keyed by a dedicated PRNG so they are independent of name/id/like streams.
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

    /// Builds the realised `LIKE` edges: for each user, a per-user count drawn uniformly in
    /// `[0, 2 * avg_likes_per_user]` of **distinct** article indices. Returns `(user, article)`
    /// pairs in user-then-sample order. Pure function of the config.
    fn build_like_edges(&self) -> Vec<(u64, u64)> {
        let users = self.cfg.users;
        let articles = self.cfg.articles;
        if articles == 0 {
            return Vec::new();
        }
        let max_likes = self.cfg.avg_likes_per_user.saturating_mul(2);
        let mut like_rng = SplitMix64::new(self.cfg.seed ^ 0x4C49_4B45_0000_0003);
        let mut edges = Vec::new();
        for u in 0..users {
            let want = if max_likes == 0 {
                0
            } else {
                like_rng.in_range(0, max_likes)
            };
            // Cap by the number of distinct articles available.
            let want = want.min(articles);
            // Sample `want` DISTINCT article indices. For small `want` relative to `articles`,
            // rejection sampling against a tiny seen-set is cheap and order-deterministic; we keep
            // insertion order (a Vec, not a HashSet) so emitted order is stable across platforms.
            let mut chosen: Vec<u64> = Vec::with_capacity(want as usize);
            let mut attempts = 0u64;
            // Bound attempts to avoid pathological loops when `want` ~ `articles`.
            let attempt_budget = want.saturating_mul(8).saturating_add(articles);
            while (chosen.len() as u64) < want && attempts < attempt_budget {
                let a = like_rng.below(articles);
                if !chosen.contains(&a) {
                    chosen.push(a);
                }
                attempts += 1;
            }
            for a in chosen {
                edges.push((u, a));
            }
        }
        edges
    }

    /// Computes the run summary (counts + realised degree statistics) WITHOUT materialising the
    /// Cypher text. Still builds the edge lists (the only way to know the *realised* degrees), but
    /// emits no strings.
    #[must_use]
    pub fn summary(&self) -> Summary {
        let (friend_edges, degree) = self.build_friend_edges();
        let like_edges = self.build_like_edges();

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
            articles: self.cfg.articles,
            friend_edges: friend_edges.len() as u64,
            like_edges: like_edges.len() as u64,
            degree_min,
            degree_max,
            degree_avg_x1000,
        }
    }

    /// Materialises the **entire** graph as a single deterministic Cypher text artifact: the `USER`
    /// nodes, the `ARTICLE` nodes, the `FRIEND` edges, then the `LIKE` edges — all batched (up to
    /// [`BATCH`] clauses per statement), each statement `;`-terminated.
    ///
    /// Nodes are emitted as inline literal-batched `CREATE` statements. Edges are emitted as
    /// `MATCH … CREATE` batches keyed on the entity ids. This is the artifact the `social_gen` binary
    /// writes and the determinism test hashes.
    #[must_use]
    pub fn emit_all(&self) -> String {
        let summary = self.summary();
        let (friend_edges, _degree) = self.build_friend_edges();
        let like_edges = self.build_like_edges();

        // Generous capacity estimate to avoid reallocation churn at scale.
        let approx = 64
            * (self.cfg.users + self.cfg.articles + summary.friend_edges + summary.like_edges)
                as usize
            + 512;
        let mut out = String::with_capacity(approx);

        out.push_str("// graphus-social-gen — deterministic social-network graph\n");
        let _ = writeln!(
            out,
            "// seed={} users={} articles={} friend_min={} friend_max={} avg_likes_per_user={}",
            self.cfg.seed,
            self.cfg.users,
            self.cfg.articles,
            self.cfg.friend_min,
            self.cfg.friend_max,
            self.cfg.avg_likes_per_user,
        );
        let _ = writeln!(
            out,
            "// friend_edges={} like_edges={} degree_min={} degree_max={} degree_avg_x1000={}",
            summary.friend_edges,
            summary.like_edges,
            summary.degree_min,
            summary.degree_max,
            summary.degree_avg_x1000,
        );

        // --- USER nodes (batched inline CREATE) ---
        out.push_str("// --- USER nodes ---\n");
        self.emit_user_nodes(&mut out);

        // --- ARTICLE nodes (batched inline CREATE) ---
        out.push_str("// --- ARTICLE nodes ---\n");
        self.emit_article_nodes(&mut out);

        // --- FRIEND edges (batched MATCH … CREATE) ---
        out.push_str("// --- FRIEND edges (undirected multigraph) ---\n");
        self.emit_friend_edges(&mut out, &friend_edges);

        // --- LIKE edges (batched MATCH … CREATE) ---
        out.push_str("// --- LIKE edges ---\n");
        self.emit_like_edges(&mut out, &like_edges);

        out
    }

    fn emit_user_nodes(&self, out: &mut String) {
        let mut batch = 0usize;
        for i in 0..self.cfg.users {
            let id = Self::user_id(i);
            let name = escape_cypher(&Self::user_name(self.cfg.seed, i));
            let reg = Self::registered_ts(self.cfg.seed, Self::USER_SALT, i);
            let _ = write!(
                out,
                "CREATE (:USER {{id: '{id}', name: '{name}', registered: {reg}}})"
            );
            batch += 1;
            if batch == BATCH || i + 1 == self.cfg.users {
                out.push_str(";\n");
                batch = 0;
            } else {
                out.push('\n');
            }
        }
    }

    fn emit_article_nodes(&self, out: &mut String) {
        let mut batch = 0usize;
        for i in 0..self.cfg.articles {
            let id = Self::article_id(i);
            let name = escape_cypher(&Self::article_name(self.cfg.seed, i));
            let reg = Self::registered_ts(self.cfg.seed, Self::ARTICLE_SALT, i);
            let _ = write!(
                out,
                "CREATE (:ARTICLE {{id: '{id}', name: '{name}', registered: {reg}}})"
            );
            batch += 1;
            if batch == BATCH || i + 1 == self.cfg.articles {
                out.push_str(";\n");
                batch = 0;
            } else {
                out.push('\n');
            }
        }
    }

    fn emit_friend_edges(&self, out: &mut String, edges: &[(u64, u64)]) {
        for &(a, b) in edges {
            let ida = Self::user_id(a);
            let idb = Self::user_id(b);
            // Deterministic `since` timestamp keyed on the (ordered) endpoint pair + position.
            let mut r = SplitMix64::new(
                self.cfg.seed
                    ^ 0xF111_0000_0000_0004
                    ^ a.wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    ^ b.rotate_left(17),
            );
            let since = EPOCH_S + r.below(REG_SPAN_S);
            // ONE statement per edge (NOT many per statement): packing N `MATCH … CREATE` clauses
            // into one statement would either rebind the shared `a`/`b` variables (one edge per
            // batch) or form an N-way cartesian product. Stored DIRECTED `(a)->(b)` once per
            // friendship (Cypher `CREATE` requires a direction — the TCK's
            // `RequiresDirectedRelationship` rule); read back undirected (`-[:FRIEND]-`) so the
            // symmetric semantics hold.
            let _ = writeln!(
                out,
                "MATCH (a:USER {{id: '{ida}'}}), (b:USER {{id: '{idb}'}}) CREATE (a)-[:FRIEND {{since: {since}}}]->(b);"
            );
        }
    }

    fn emit_like_edges(&self, out: &mut String, edges: &[(u64, u64)]) {
        for &(u, art) in edges {
            let idu = Self::user_id(u);
            let ida = Self::article_id(art);
            let mut r = SplitMix64::new(
                self.cfg.seed
                    ^ 0x11CE_0000_0000_0005
                    ^ u.wrapping_mul(0xA0761D6478BD642F)
                    ^ art.rotate_left(23),
            );
            let date = EPOCH_S + r.below(REG_SPAN_S);
            // ONE statement per edge (see `emit_friend_edges`).
            let _ = writeln!(
                out,
                "MATCH (u:USER {{id: '{idu}'}}), (a:ARTICLE {{id: '{ida}'}}) CREATE (u)-[:LIKE {{date: {date}}}]->(a);"
            );
        }
    }

    // --- Streaming, batch-by-batch emission for the engine loader --------------------------------
    //
    // The `emit_all` artifact above materialises the *entire* graph as one `String`. At the `huge`
    // profile (a million users, a colossal friend fan-out) that text would be many gigabytes — far
    // too large to hold in RAM. The engine loader (`load.rs`, behind the `engine` feature) instead
    // pulls the graph **one batched statement at a time** through the four methods below: it executes
    // each batch in its own committed transaction and drops it before asking for the next, so peak
    // resident memory stays bounded by a single batch regardless of the total graph size.
    //
    // Each method takes a `FnMut(String)` sink invoked once per batched statement (up to [`BATCH`]
    // clauses), in the same deterministic order `emit_all` uses. The node phases stream without ever
    // building an edge list; the edge phases build the (linear-size) edge list once and stream from
    // it. The friend/like edge statements are keyed on the **indexed** `id` property so the loader's
    // planner turns each `MATCH (:USER {id: …})` into an index *seek* (the loader creates the
    // `:USER(id)` / `:ARTICLE(id)` indexes first), keeping edge creation `O(E · log N)` rather than
    // the `O(E · N)` a scan-per-endpoint would cost — see `load.rs` for the empirical justification.

    /// Streams the `USER`-node `CREATE` batches to `sink`, one batched statement at a time. No edge
    /// list is built; peak memory is one batch.
    pub fn stream_user_node_batches<F: FnMut(String)>(&self, mut sink: F) {
        use std::fmt::Write as _;
        let mut buf = String::new();
        let mut batch = 0usize;
        for i in 0..self.cfg.users {
            let id = Self::user_id(i);
            let name = escape_cypher(&Self::user_name(self.cfg.seed, i));
            let reg = Self::registered_ts(self.cfg.seed, Self::USER_SALT, i);
            if batch > 0 {
                buf.push('\n');
            }
            let _ = write!(
                buf,
                "CREATE (:USER {{id: '{id}', name: '{name}', registered: {reg}}})"
            );
            batch += 1;
            if batch == BATCH || i + 1 == self.cfg.users {
                sink(std::mem::take(&mut buf));
                batch = 0;
            }
        }
    }

    /// Streams the `ARTICLE`-node `CREATE` batches to `sink`, one batched statement at a time.
    pub fn stream_article_node_batches<F: FnMut(String)>(&self, mut sink: F) {
        use std::fmt::Write as _;
        let mut buf = String::new();
        let mut batch = 0usize;
        for i in 0..self.cfg.articles {
            let id = Self::article_id(i);
            let name = escape_cypher(&Self::article_name(self.cfg.seed, i));
            let reg = Self::registered_ts(self.cfg.seed, Self::ARTICLE_SALT, i);
            if batch > 0 {
                buf.push('\n');
            }
            let _ = write!(
                buf,
                "CREATE (:ARTICLE {{id: '{id}', name: '{name}', registered: {reg}}})"
            );
            batch += 1;
            if batch == BATCH || i + 1 == self.cfg.articles {
                sink(std::mem::take(&mut buf));
                batch = 0;
            }
        }
    }

    /// Streams the `FRIEND`-edge `MATCH … CREATE` statements to `sink`, **one statement per edge**.
    /// Returns the number of `FRIEND` edges emitted (== [`Summary::friend_edges`]). The edge list is
    /// built once (linear in `E`); the text is streamed one edge at a time.
    ///
    /// Unlike the node phases, edges are **not** packed many-per-statement: each edge is its own
    /// `MATCH (a), (b) CREATE (a)->(b)` statement. Packing N such clauses into one statement is wrong
    /// — they would either rebind the shared `a`/`b` variables (creating a single edge per batch) or,
    /// with distinct variables, form an N-way cartesian product. One statement per edge keeps each
    /// `MATCH` an index seek and the semantics exact.
    pub fn stream_friend_edge_batches<F: FnMut(String)>(&self, mut sink: F) -> u64 {
        use std::fmt::Write as _;
        let (edges, _degree) = self.build_friend_edges();
        let total = edges.len();
        let mut buf = String::new();
        for &(a, b) in &edges {
            let ida = Self::user_id(a);
            let idb = Self::user_id(b);
            let mut r = SplitMix64::new(
                self.cfg.seed
                    ^ 0xF111_0000_0000_0004
                    ^ a.wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    ^ b.rotate_left(17),
            );
            let since = EPOCH_S + r.below(REG_SPAN_S);
            buf.clear();
            // Stored DIRECTED `(a)->(b)` once per friendship (Cypher `CREATE` requires a direction);
            // read back undirected (`-[:FRIEND]-`) to preserve the friendship's symmetric semantics.
            let _ = write!(
                buf,
                "MATCH (a:USER {{id: '{ida}'}}), (b:USER {{id: '{idb}'}}) CREATE (a)-[:FRIEND {{since: {since}}}]->(b)"
            );
            sink(buf.clone());
        }
        total as u64
    }

    /// Streams the `LIKE`-edge `MATCH … CREATE` statements to `sink`, **one statement per edge** (see
    /// [`stream_friend_edge_batches`](Self::stream_friend_edge_batches) for why edges are not packed).
    /// Returns the number of `LIKE` edges emitted (== [`Summary::like_edges`]).
    pub fn stream_like_edge_batches<F: FnMut(String)>(&self, mut sink: F) -> u64 {
        use std::fmt::Write as _;
        let edges = self.build_like_edges();
        let total = edges.len();
        let mut buf = String::new();
        for &(u, art) in &edges {
            let idu = Self::user_id(u);
            let ida = Self::article_id(art);
            let mut r = SplitMix64::new(
                self.cfg.seed
                    ^ 0x11CE_0000_0000_0005
                    ^ u.wrapping_mul(0xA0761D6478BD642F)
                    ^ art.rotate_left(23),
            );
            let date = EPOCH_S + r.below(REG_SPAN_S);
            buf.clear();
            let _ = write!(
                buf,
                "MATCH (u:USER {{id: '{idu}'}}), (a:ARTICLE {{id: '{ida}'}}) CREATE (u)-[:LIKE {{date: {date}}}]->(a)"
            );
            sink(buf.clone());
        }
        total as u64
    }

    // --- Streaming, batch-by-batch CSV emission for the BULK loader ------------------------------
    //
    // The Cypher streams above feed a per-statement loader; the BULK loader (`load.rs`, the production
    // O(E) ingest path) instead feeds `graphus-bulk`'s `BulkImporter`, which consumes
    // `neo4j-admin import`-flavoured CSV: a node file is `<id>:ID,:LABEL,<key>:<type>,…` and a rel file
    // is `:START_ID,:END_ID,:TYPE,<key>:<type>,…`. The importer resolves each relationship endpoint
    // through an internal external-id→internal-id hash map (O(1) per endpoint ⇒ O(E) total), so unlike
    // per-edge Cypher `CREATE` (which the planner can only index-seek on *one* of the two anchors,
    // making it O(E·N)) the bulk path scales to the `huge` profile.
    //
    // Each method streams one `Vec<u8>` chunk at a time to a `FnMut(Vec<u8>)` sink (the header first,
    // then up to [`BATCH`] data rows per chunk), in the same deterministic order as the Cypher emitter.
    // The byte stream is therefore byte-identical per seed (asserted by `tests/determinism.rs`), and
    // peak resident memory is one chunk regardless of total graph size — exactly the streaming
    // contract the `huge` profile needs.

    // IMPORTANT: the importer's `:ID` column is the external **join key** and is NOT stored as a node
    // property (it is consumed to resolve `:START_ID`/`:END_ID`). The read battery, however, anchors
    // its traversals on `(:USER {id: …})`, which needs a real `id` *property*. So each node row carries
    // the 24-hex id **twice**: once in the reserved `:ID` join-key column and once in a stored
    // `id:string` property column — the standard neo4j-admin-import recipe for "join key that is also a
    // queryable property".

    /// The header row of the USER node CSV: `:ID` join key + `:LABEL` + a stored `id` property +
    /// `name` + `registered`.
    pub const USER_CSV_HEADER: &'static str = ":ID,:LABEL,id:string,name:string,registered:long\n";
    /// The header row of the ARTICLE node CSV (same shape as users).
    pub const ARTICLE_CSV_HEADER: &'static str =
        ":ID,:LABEL,id:string,name:string,registered:long\n";
    /// The header row of the FRIEND relationship CSV.
    pub const FRIEND_CSV_HEADER: &'static str = ":START_ID,:END_ID,:TYPE,since:long\n";
    /// The header row of the LIKE relationship CSV.
    pub const LIKE_CSV_HEADER: &'static str = ":START_ID,:END_ID,:TYPE,date:long\n";

    /// Streams the USER node CSV to `sink`, one chunk at a time: the header chunk first, then chunks of
    /// up to [`BATCH`] data rows. Each row is `<id>,USER,<name>,<registered>`. No edge list is built;
    /// peak memory is one chunk.
    pub fn stream_user_csv<F: FnMut(Vec<u8>)>(&self, mut sink: F) {
        sink(Self::USER_CSV_HEADER.as_bytes().to_vec());
        self.stream_node_csv_rows(
            self.cfg.users,
            Self::USER_SALT,
            "USER",
            &Self::user_name,
            &mut sink,
        );
    }

    /// Streams the ARTICLE node CSV to `sink` (see [`stream_user_csv`](Self::stream_user_csv)).
    pub fn stream_article_csv<F: FnMut(Vec<u8>)>(&self, mut sink: F) {
        sink(Self::ARTICLE_CSV_HEADER.as_bytes().to_vec());
        self.stream_node_csv_rows(
            self.cfg.articles,
            Self::ARTICLE_SALT,
            "ARTICLE",
            &Self::article_name,
            &mut sink,
        );
    }

    /// Shared node-CSV row streamer: emits `count` rows of `<id>,<label>,<name>,<registered>` in
    /// [`BATCH`]-row chunks, deterministic in index order. `name_fn` produces the per-index name.
    fn stream_node_csv_rows<F: FnMut(Vec<u8>)>(
        &self,
        count: u64,
        salt: u64,
        label: &str,
        name_fn: &dyn Fn(u64, u64) -> String,
        sink: &mut F,
    ) {
        let mut buf = String::new();
        let mut in_chunk = 0usize;
        for i in 0..count {
            let id = Self::entity_id(salt, i);
            let name = escape_csv(&name_fn(self.cfg.seed, i));
            let reg = Self::registered_ts(self.cfg.seed, salt, i);
            // `id` appears twice: the `:ID` join key (col 0) and the stored `id` property (col 2).
            let _ = writeln!(buf, "{id},{label},{id},{name},{reg}");
            in_chunk += 1;
            if in_chunk == BATCH || i + 1 == count {
                sink(std::mem::take(&mut buf).into_bytes());
                in_chunk = 0;
            }
        }
    }

    /// Streams the FRIEND relationship CSV to `sink`: the header chunk, then chunks of up to [`BATCH`]
    /// rows `<start_id>,<end_id>,FRIEND,<since>`. Each unordered friendship is emitted **once** (stored
    /// directed; read back undirected in queries). Returns the number of FRIEND edges emitted
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

    /// Streams the LIKE relationship CSV to `sink`: the header chunk, then chunks of up to [`BATCH`]
    /// rows `<user_id>,<article_id>,LIKE,<date>`. Returns the number of LIKE edges emitted
    /// (== [`Summary::like_edges`]).
    pub fn stream_like_csv<F: FnMut(Vec<u8>)>(&self, mut sink: F) -> u64 {
        sink(Self::LIKE_CSV_HEADER.as_bytes().to_vec());
        let edges = self.build_like_edges();
        let total = edges.len() as u64;
        let mut buf = String::new();
        let mut in_chunk = 0usize;
        let n = edges.len();
        for (k, &(u, art)) in edges.iter().enumerate() {
            let idu = Self::user_id(u);
            let ida = Self::article_id(art);
            let mut r = SplitMix64::new(
                self.cfg.seed
                    ^ 0x11CE_0000_0000_0005
                    ^ u.wrapping_mul(0xA0761D6478BD642F)
                    ^ art.rotate_left(23),
            );
            let date = EPOCH_S + r.below(REG_SPAN_S);
            let _ = writeln!(buf, "{idu},{ida},LIKE,{date}");
            in_chunk += 1;
            if in_chunk == BATCH || k + 1 == n {
                sink(std::mem::take(&mut buf).into_bytes());
                in_chunk = 0;
            }
        }
        total
    }

    /// A sample `USER` id by index, for the loader's read-query probes. Convenience over
    /// [`user_id`](Self::user_id).
    #[must_use]
    pub fn sample_user_id(&self, i: u64) -> String {
        Self::user_id(i % self.cfg.users.max(1))
    }

    /// A machine-readable one-line summary of the run's realised shape (the `social_gen` binary
    /// prints it; an example's `run.sh` parses it for dataset sizing).
    #[must_use]
    pub fn summary_line(&self) -> String {
        let s = self.summary();
        format!(
            "seed={} users={} articles={} friend_edges={} like_edges={} \
             friend_min={} friend_max={} degree_min={} degree_max={} degree_avg_x1000={} \
             avg_likes_per_user={}",
            self.cfg.seed,
            s.users,
            s.articles,
            s.friend_edges,
            s.like_edges,
            self.cfg.friend_min,
            self.cfg.friend_max,
            s.degree_min,
            s.degree_max,
            s.degree_avg_x1000,
            self.cfg.avg_likes_per_user,
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

/// Defensively escapes a string for inclusion inside a single-quoted Cypher string literal. Our name
/// and title pools never contain single-quotes or backslashes, but we escape both to guarantee the
/// emitted Cypher is always well-formed regardless of the pools.
fn escape_cypher(s: &str) -> String {
    if !s.contains('\'') && !s.contains('\\') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        match c {
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            other => out.push(other),
        }
    }
    out
}

/// Defensively escapes a string for inclusion as one field of a comma-delimited CSV row (RFC 4180):
/// a field containing a comma, a double-quote, or a newline is wrapped in double-quotes with each
/// embedded double-quote doubled. Our name and title pools contain none of these, so the common path
/// returns the input untouched (and the stream stays byte-identical per seed); we still escape so the
/// emitted CSV is always well-formed regardless of the pools.
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
            articles: 40,
            friend_min: 3,
            friend_max: 10,
            avg_likes_per_user: 4,
        }
    }

    #[test]
    fn emit_all_is_byte_identical_per_config() {
        let g = Generator::new(cfg());
        assert_eq!(g.emit_all(), g.emit_all(), "same config => identical text");
        let g2 = Generator::new(cfg());
        assert_eq!(g.emit_all(), g2.emit_all(), "fresh generator, same config");
    }

    #[test]
    fn a_different_seed_changes_the_graph() {
        let mut c2 = cfg();
        c2.seed = 43;
        assert_ne!(
            Generator::new(cfg()).emit_all(),
            Generator::new(c2).emit_all()
        );
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
    fn ids_are_24_lowercase_hex() {
        for i in 0..50 {
            for id in [Generator::user_id(i), Generator::article_id(i)] {
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
    fn user_names_are_bounded_utf8() {
        for i in 0..500 {
            let name = Generator::user_name(cfg().seed, i);
            assert!(name.len() <= MAX_NAME_BYTES, "name too long: {name:?}");
            assert!(!name.is_empty());
            assert!(
                !name.contains('\''),
                "name must not contain a quote: {name}"
            );
        }
    }

    #[test]
    fn summary_counts_match_emitted() {
        let g = Generator::new(cfg());
        let s = g.summary();
        let text = g.emit_all();
        let friend = text.matches("[:FRIEND").count() as u64;
        let like = text.matches("[:LIKE").count() as u64;
        let users = text.matches("(:USER ").count() as u64;
        let articles = text.matches("(:ARTICLE ").count() as u64;
        assert_eq!(friend, s.friend_edges, "FRIEND count");
        assert_eq!(like, s.like_edges, "LIKE count");
        assert_eq!(users, s.users, "USER count");
        assert_eq!(articles, s.articles, "ARTICLE count");
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
                collect_csv(|s| g.stream_article_csv(s)),
                collect_csv(|s| g2.stream_article_csv(s)),
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
                    g.stream_like_csv(s);
                }),
                collect_csv(|s| {
                    g2.stream_like_csv(s);
                }),
            ),
        ] {
            assert_eq!(a, b, "same config => byte-identical CSV stream");
        }
    }

    #[test]
    fn csv_streams_match_the_summary_counts() {
        let g = Generator::new(cfg());
        let s = g.summary();

        let users_csv = String::from_utf8(collect_csv(|sink| g.stream_user_csv(sink))).unwrap();
        let articles_csv =
            String::from_utf8(collect_csv(|sink| g.stream_article_csv(sink))).unwrap();
        let mut friend_total = 0u64;
        let friend_csv = String::from_utf8(collect_csv(|sink| {
            friend_total = g.stream_friend_csv(sink);
        }))
        .unwrap();
        let mut like_total = 0u64;
        let like_csv = String::from_utf8(collect_csv(|sink| {
            like_total = g.stream_like_csv(sink);
        }))
        .unwrap();

        // Data-row count == header + body, minus the one header line.
        let body_rows = |csv: &str| csv.lines().count() as u64 - 1;
        assert_eq!(body_rows(&users_csv), s.users, "USER rows");
        assert_eq!(body_rows(&articles_csv), s.articles, "ARTICLE rows");
        assert_eq!(body_rows(&friend_csv), s.friend_edges, "FRIEND rows");
        assert_eq!(body_rows(&like_csv), s.like_edges, "LIKE rows");
        assert_eq!(friend_total, s.friend_edges, "FRIEND stream return");
        assert_eq!(like_total, s.like_edges, "LIKE stream return");

        // The headers are exactly the importer-flavoured schema.
        assert!(users_csv.starts_with(":ID,:LABEL,id:string,name:string,registered:long\n"));
        assert!(friend_csv.starts_with(":START_ID,:END_ID,:TYPE,since:long\n"));
        // Every USER data row carries the USER label in the :LABEL column, and the :ID join key (col 0)
        // equals the stored `id` property (col 2) — the join-key-as-property recipe.
        for line in users_csv.lines().skip(1) {
            let cols: Vec<&str> = line.split(',').collect();
            assert_eq!(cols.len(), 5, "USER row has 5 columns: {line}");
            assert_eq!(cols[1], "USER", "USER :LABEL column: {line}");
            assert_eq!(
                cols[0], cols[2],
                "ID join key == stored id property: {line}"
            );
        }
    }

    #[test]
    fn article_titles_have_no_quotes() {
        for i in 0..100 {
            let t = Generator::article_name(cfg().seed, i);
            assert!(!t.contains('\''), "title must not contain a quote: {t}");
            assert!(!t.is_empty());
        }
    }
}
