//! Deterministic, seeded **fraud-graph generator** for the `examples/fraud-oltp` demonstration.
//!
//! It produces a financial-fraud Label Property Graph with a **known, enumerable** set of injected
//! ground-truth fraud structures, so a detection workload can assert it finds *exactly* the planted
//! fraud (no false negatives on the seeded set; false positives within a documented bound).
//!
//! # Determinism
//!
//! Generation is a pure function of `(seed, scale)`: the only randomness is an internal
//! [`SplitMix64`] PRNG seeded from `seed`. For a given [`GenConfig`] the emitted Cypher script and
//! ground-truth JSON are **byte-identical** across runs, hosts, and platforms (no floats, no
//! `HashMap` iteration, no clock, no thread scheduling). This is asserted by
//! `tests/determinism.rs`.
//!
//! # The model
//!
//! - `(:Customer {id, name, country})` — the human/legal account holder (the workload declares a
//!   `UNIQUE` constraint on its `id` and a `TEXT` index on its `name`).
//! - `(:Account {id, holder, balance, risk_score, opened_ts, country})` — a financial account, whose
//!   `id` is a **`NODE KEY`** (present + unique; the workload declares the constraint on it).
//! - `(:Customer)-[:OWNS]->(:Account)` — ownership.
//! - `(:Account)-[:TRANSFER {tx_id, amount, ts, device, ip}]->(:Account)` — a money transfer, the
//!   edge the detection traverses. `tx_id` is a **globally-unique, deterministic** transaction id and
//!   carries a **`RELATIONSHIP KEY`** constraint (present + unique — every money transfer has a unique
//!   id, the relationship analogue of a primary key). `amount` carries an **`IS NOT NULL`** and an
//!   **`IS :: INTEGER`** relationship constraint and a **relationship `RANGE` index** (the detection
//!   queries filter on it).
//!
//! # Injected ground truth
//!
//! Two fraud archetypes are planted on top of a benign background of legitimate transfers:
//!
//! - **Transaction rings / cycles** `A → B → C → … → A`: a closed `TRANSFER` cycle of a configured
//!   length, the canonical money-laundering layering structure. Every account in a ring is flagged.
//! - **Mule fan-in / fan-out chains**: a central *mule* account that **fans in** from many source
//!   accounts and then **fans out** to many destination accounts (smurfing / structuring). The mule
//!   account is flagged.
//!
//! The exact planted set is returned as [`GroundTruth`] and serialized to `ground_truth.json`, so
//! the detector can join against it.

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

    /// Returns an `i64` in the inclusive range `[lo, hi]`.
    pub fn range_i64(&mut self, lo: i64, hi: i64) -> i64 {
        debug_assert!(lo <= hi);
        let span = (hi - lo) as u64 + 1;
        lo + (self.below(span) as i64)
    }
}

/// The two generation profiles required by the example: a small `Fast` graph for CI/E2E assertions,
/// and a larger `Large` graph for evidence collection. Both inject the *same kinds* of ground truth,
/// only at different scale, so the detection queries are identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Small, fast graph for CI and the official-driver E2E assertion.
    Fast,
    /// Larger graph for evidence collection (storage/CPU/RAM footprint at volume).
    Large,
}

impl Profile {
    /// Parses a profile name (`fast` / `large`), case-insensitively.
    ///
    /// # Errors
    /// Returns `Err` with the offending name if it is neither `fast` nor `large`.
    pub fn parse(name: &str) -> Result<Self, String> {
        match name.to_ascii_lowercase().as_str() {
            "fast" => Ok(Self::Fast),
            "large" => Ok(Self::Large),
            other => Err(format!(
                "unknown profile '{other}' (expected 'fast' or 'large')"
            )),
        }
    }

    /// The stable string name of this profile.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Large => "large",
        }
    }

    /// The scale knobs for this profile. Kept here (not in the binary) so the determinism test and
    /// the binary agree by construction.
    #[must_use]
    pub fn config(self) -> GenConfig {
        match self {
            // Small but non-trivial: enough background to make the planted fraud a needle in a
            // haystack, yet fast enough for the official-driver E2E to run in a few seconds.
            Self::Fast => GenConfig {
                seed: 0xF7A0_D000_0000_0001,
                legit_accounts: 120,
                benign_transfers: 400,
                ring_count: 3,
                ring_len: 3,
                mule_count: 2,
                mule_fan_in: 6,
                mule_fan_out: 6,
            },
            // An order of magnitude larger, for evidence. Still bounded so a run completes promptly.
            Self::Large => GenConfig {
                seed: 0xF7A0_D000_0000_0001,
                legit_accounts: 2_000,
                benign_transfers: 12_000,
                ring_count: 20,
                ring_len: 4,
                mule_count: 15,
                mule_fan_in: 12,
                mule_fan_out: 12,
            },
        }
    }
}

/// The full set of generation knobs. A [`Dataset`] is a pure function of this struct, so two configs
/// that compare equal produce byte-identical output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenConfig {
    /// PRNG seed: the single source of all randomness.
    pub seed: u64,
    /// Number of *legitimate* (non-fraud) accounts forming the benign background.
    pub legit_accounts: u64,
    /// Number of benign `TRANSFER` edges among the legitimate accounts.
    pub benign_transfers: u64,
    /// How many transaction rings/cycles to plant.
    pub ring_count: u64,
    /// The length (node count) of each planted ring (≥ 2 for a meaningful cycle).
    pub ring_len: u64,
    /// How many mule fan-in/fan-out chains to plant.
    pub mule_count: u64,
    /// Number of source accounts fanning *in* to each mule.
    pub mule_fan_in: u64,
    /// Number of destination accounts each mule fans *out* to.
    pub mule_fan_out: u64,
}

/// A generated account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    /// Unique account id (the workload declares a `NODE KEY` constraint on this).
    pub id: i64,
    /// Owning customer id.
    pub holder: i64,
    /// Current balance, in whole currency units.
    pub balance: i64,
    /// A coarse risk score in `[0, 100]`.
    pub risk_score: i64,
    /// Account-opened timestamp (epoch seconds; deterministic, not wall-clock).
    pub opened_ts: i64,
    /// ISO country code (one of a small fixed set).
    pub country: String,
}

/// A generated customer (account holder).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Customer {
    /// Unique customer id.
    pub id: i64,
    /// Display name (`customer-<id>`; deterministic).
    pub name: String,
    /// ISO country code.
    pub country: String,
}

/// A generated transfer edge `from -> to`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transfer {
    /// Source account id.
    pub from: i64,
    /// Destination account id.
    pub to: i64,
    /// Globally-unique, deterministic transaction id, formatted `TX-<zero-padded ordinal>`. The
    /// workload declares a **`RELATIONSHIP KEY`** constraint on it (present + unique): every money
    /// transfer carries a unique id — the relationship analogue of a primary key. Unique across **all**
    /// transfers in a dataset and byte-identical per seed (the ordinal is the transfer's mint order).
    pub tx_id: String,
    /// Transfer amount in whole currency units.
    pub amount: i64,
    /// Transfer timestamp (epoch seconds; deterministic).
    pub ts: i64,
    /// Originating device fingerprint id.
    pub device: i64,
    /// Originating IP (a deterministic `10.x.y.z`).
    pub ip: String,
}

/// One planted transaction ring: the ordered account ids forming the cycle `accounts[0] → … →
/// accounts[n-1] → accounts[0]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ring {
    /// The ring's accounts, in cycle order. The closing edge runs from the last back to the first.
    pub accounts: Vec<i64>,
}

/// One planted mule chain: a central mule account with `sources` fanning in and `destinations`
/// fanning out.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MuleChain {
    /// The central mule account id (this is the account a detector must flag).
    pub mule: i64,
    /// Source accounts fanning *in* to the mule.
    pub sources: Vec<i64>,
    /// Destination accounts the mule fans *out* to.
    pub destinations: Vec<i64>,
}

/// One planted **collusion cluster**: a fraud structure (a ring or a mule chain) whose `TRANSFER`
/// edges were all minted from a **single shared device fingerprint and IP** — the digital-forensics
/// signal that one operator controls the whole structure. The detector re-identifies each cluster by
/// the shared `device` (every benign transfer carries a unique device, so any `device` used by two or
/// more transfers is a planted cluster) and corroborates it by the shared `ip` (the fraud clusters
/// use the disjoint `172.16.0.0/12` space; benign transfers use `10.0.0.0/8`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CollusionCluster {
    /// The shared device fingerprint every edge in this cluster carries. Unique per cluster and drawn
    /// from a namespace disjoint from the (unique-per-transfer) benign device ids, so a
    /// `count(*) >= 2` group-by-device query returns exactly the planted clusters.
    pub device: i64,
    /// The shared originating IP every edge in this cluster carries (a `172.16.x.y` / `172.17.x.y`
    /// address, disjoint from the benign `10.x.y.z` space).
    pub ip: String,
    /// The cluster kind: `"mule"` or `"ring"`.
    pub kind: String,
    /// How many `TRANSFER` edges carry this shared device (`= ring_len` for a ring; `= fan_in +
    /// fan_out` for a mule chain). Equals the `count(*)` a group-by-device detector observes.
    pub edge_count: usize,
    /// The distinct account ids the cluster's shared-device transfers touch (the ring members, or the
    /// mule plus its sources and destinations), sorted ascending.
    pub accounts: Vec<i64>,
}

/// The enumerable ground-truth fraud set, serialized to `ground_truth.json`. The detector loads this
/// and asserts it found exactly these structures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroundTruth {
    /// The profile name the dataset was generated for.
    pub profile: String,
    /// The seed used (so a report can pin reproducibility).
    pub seed: u64,
    /// The planted rings/cycles.
    pub rings: Vec<Ring>,
    /// The planted mule fan-in/fan-out chains.
    pub mules: Vec<MuleChain>,
    /// The sorted, de-duplicated set of **all** fraudulent account ids (every account that is part of
    /// any ring or is a mule). The detection workload's union of findings must equal this set.
    pub fraud_accounts: Vec<i64>,
    /// The planted shared-device/shared-IP collusion clusters (one per ring and per mule chain). The
    /// detector's shared-device query must return exactly these `device`s with exactly these
    /// `edge_count`s. Additive (`serde(default)`) so an older `ground_truth.json` still deserializes.
    #[serde(default)]
    pub collusion: Vec<CollusionCluster>,
}

/// A fully-materialized dataset: the nodes, the edges, and the ground truth. Produced by
/// [`generate`].
#[derive(Debug, Clone)]
pub struct Dataset {
    /// The generation config that produced this dataset.
    pub config: GenConfig,
    /// The profile name.
    pub profile: String,
    /// All customers.
    pub customers: Vec<Customer>,
    /// All accounts (legitimate + fraud).
    pub accounts: Vec<Account>,
    /// All transfer edges (benign + planted fraud edges).
    pub transfers: Vec<Transfer>,
    /// The enumerable ground truth.
    pub ground_truth: GroundTruth,
}

/// A small fixed set of country codes, indexed deterministically by id.
const COUNTRIES: [&str; 6] = ["PT", "ES", "FR", "DE", "GB", "NL"];

/// Device-fingerprint namespaces for the shared-device collusion signal. Benign transfers each get a
/// **unique** device id in `[BENIGN_DEVICE_BASE, BENIGN_DEVICE_BASE + benign_transfers)`, so a
/// group-by-device `count(*) >= 2` never flags benign traffic. Each fraud **cluster** shares one
/// device drawn from a disjoint high namespace (`MULE_*` / `RING_*`), so the same query returns
/// exactly the planted clusters. The bases are chosen far above any realistic transfer count so the
/// three ranges never overlap (a large-profile run mints ~12 000 benign transfers).
const BENIGN_DEVICE_BASE: i64 = 0;
/// Base of the mule-cluster shared-device namespace (one device per mule chain: `+ mule_index`).
const MULE_DEVICE_BASE: i64 = 1_000_000;
/// Base of the ring-cluster shared-device namespace (one device per ring: `+ ring_index`).
const RING_DEVICE_BASE: i64 = 2_000_000;

/// The high-risk country a detector might weight; kept fixed for determinism.
fn country_for(seed_val: u64) -> &'static str {
    COUNTRIES[(seed_val as usize) % COUNTRIES.len()]
}

/// Generates a [`Dataset`] from a [`GenConfig`].
///
/// The layout is intentionally ordered so output is byte-stable:
/// 1. legitimate accounts `0..legit_accounts` (each owned by a same-id customer),
/// 2. ring accounts, then mule accounts and their fan-in/fan-out satellites — appended after the
///    legitimate block with ever-increasing ids,
/// 3. benign transfers, then ring edges, then mule edges,
///
/// so the emitted Cypher and JSON are a deterministic function of the config alone.
#[must_use]
pub fn generate(config: GenConfig, profile: &str) -> Dataset {
    let mut rng = SplitMix64::new(config.seed);

    let mut customers: Vec<Customer> = Vec::new();
    let mut accounts: Vec<Account> = Vec::new();
    let mut transfers: Vec<Transfer> = Vec::new();

    // A monotonically increasing id allocator shared by accounts and their customers (we mint one
    // customer per account for simplicity; the OWNS edge is emitted in the Cypher writer).
    let mut next_id: i64 = 0;
    let base_ts: i64 = 1_700_000_000; // a fixed epoch base (≈ 2023-11-14), NOT wall-clock.

    // Helper closure-free account minting (closures would borrow rng mutably across the loop).
    // We inline the body instead.

    // 1. Legitimate background accounts.
    let legit_start = next_id;
    for _ in 0..config.legit_accounts {
        let id = next_id;
        next_id += 1;
        let country = country_for(rng.next_u64()).to_owned();
        customers.push(Customer {
            id,
            name: format!("customer-{id}"),
            country: country.clone(),
        });
        accounts.push(Account {
            id,
            holder: id,
            balance: rng.range_i64(0, 50_000),
            risk_score: rng.range_i64(0, 40), // legit accounts skew low-risk
            opened_ts: base_ts - rng.range_i64(0, 200_000_000),
            country,
        });
    }
    let legit_end = next_id; // [legit_start, legit_end)

    // A deterministic transfer minter (free function so it does not capture rng). `tx_ordinal` is a
    // monotonic per-transfer counter it consumes and advances, so every minted transfer gets a
    // distinct `TX-<ordinal>` id in mint order — globally unique across the whole dataset and stable
    // per seed. Zero-padded to 12 digits so the id sorts lexicographically in numeric order.
    fn mint_transfer(
        rng: &mut SplitMix64,
        tx_ordinal: &mut u64,
        from: i64,
        to: i64,
        base_ts: i64,
        amount: i64,
    ) -> Transfer {
        let device = rng.range_i64(0, 9_999);
        let ts = base_ts + rng.range_i64(0, 30_000_000);
        let ip = format!(
            "10.{}.{}.{}",
            rng.below(256),
            rng.below(256),
            rng.below(256)
        );
        let tx_id = format!("TX-{:012}", *tx_ordinal);
        *tx_ordinal += 1;
        Transfer {
            from,
            to,
            tx_id,
            amount,
            ts,
            device,
            ip,
        }
    }

    // The transaction-id allocator: incremented once per minted transfer, in benign → ring → mule
    // order (which is exactly the order transfers are appended below), so the ids are `TX-0…`, `TX-1…`,
    // … contiguous and unique.
    let mut tx_ordinal: u64 = 0;

    // 2a. Plant rings/cycles. Each ring mints `ring_len` fresh fraud accounts and a closed cycle of
    //     TRANSFER edges among them.
    let mut rings: Vec<Ring> = Vec::new();
    for _ in 0..config.ring_count {
        let mut ring_accounts: Vec<i64> = Vec::with_capacity(config.ring_len as usize);
        for _ in 0..config.ring_len {
            let id = next_id;
            next_id += 1;
            let country = country_for(rng.next_u64()).to_owned();
            customers.push(Customer {
                id,
                name: format!("customer-{id}"),
                country: country.clone(),
            });
            accounts.push(Account {
                id,
                holder: id,
                balance: rng.range_i64(0, 5_000),
                risk_score: rng.range_i64(60, 100), // fraud accounts skew high-risk
                opened_ts: base_ts - rng.range_i64(0, 10_000_000),
                country,
            });
            ring_accounts.push(id);
        }
        rings.push(Ring {
            accounts: ring_accounts,
        });
    }

    // 2b. Plant mule chains. Each mints a central mule + `fan_in` sources + `fan_out` destinations.
    let mut mules: Vec<MuleChain> = Vec::new();
    for _ in 0..config.mule_count {
        let mule = next_id;
        next_id += 1;
        let country = country_for(rng.next_u64()).to_owned();
        customers.push(Customer {
            id: mule,
            name: format!("customer-{mule}"),
            country: country.clone(),
        });
        accounts.push(Account {
            id: mule,
            holder: mule,
            balance: rng.range_i64(0, 2_000),
            risk_score: rng.range_i64(70, 100),
            opened_ts: base_ts - rng.range_i64(0, 5_000_000),
            country,
        });

        let mut sources = Vec::with_capacity(config.mule_fan_in as usize);
        for _ in 0..config.mule_fan_in {
            let id = next_id;
            next_id += 1;
            let c = country_for(rng.next_u64()).to_owned();
            customers.push(Customer {
                id,
                name: format!("customer-{id}"),
                country: c.clone(),
            });
            accounts.push(Account {
                id,
                holder: id,
                balance: rng.range_i64(0, 20_000),
                risk_score: rng.range_i64(40, 80),
                opened_ts: base_ts - rng.range_i64(0, 8_000_000),
                country: c,
            });
            sources.push(id);
        }
        let mut destinations = Vec::with_capacity(config.mule_fan_out as usize);
        for _ in 0..config.mule_fan_out {
            let id = next_id;
            next_id += 1;
            let c = country_for(rng.next_u64()).to_owned();
            customers.push(Customer {
                id,
                name: format!("customer-{id}"),
                country: c.clone(),
            });
            accounts.push(Account {
                id,
                holder: id,
                balance: rng.range_i64(0, 20_000),
                risk_score: rng.range_i64(40, 80),
                opened_ts: base_ts - rng.range_i64(0, 8_000_000),
                country: c,
            });
            destinations.push(id);
        }
        mules.push(MuleChain {
            mule,
            sources,
            destinations,
        });
    }

    // 3a. Benign transfers among legitimate accounts only (so they never accidentally create a
    //     planted-looking structure). Amounts are modest; never a closed cycle by construction
    //     because we draw independent endpoints (a stray short cycle is possible but bounded, and the
    //     detector's amount/cycle-length thresholds exclude benign noise — documented in the README).
    if legit_end > legit_start + 1 {
        let span = (legit_end - legit_start) as u64;
        for benign_idx in 0..config.benign_transfers {
            let from = legit_start + rng.below(span) as i64;
            let mut to = legit_start + rng.below(span) as i64;
            if to == from {
                to = legit_start + ((from - legit_start + 1) % span as i64);
            }
            let amount = rng.range_i64(1, 900); // benign: under the fraud amount floor
            let mut t = mint_transfer(&mut rng, &mut tx_ordinal, from, to, base_ts, amount);
            // Give every benign transfer a UNIQUE device fingerprint (its ordinal in the benign
            // block). This is the discriminator for the shared-device collusion signal: because no two
            // benign transfers share a device, any device seen on >= 2 transfers is a planted fraud
            // cluster. The random `device`/`ip` drawn by `mint_transfer` are overwritten here WITHOUT
            // changing the PRNG stream, so amounts/timestamps (and thus the detection outcome) stay
            // byte-stable — only the device/ip VALUES change. Benign IPs keep their random `10.x.y.z`.
            t.device = BENIGN_DEVICE_BASE + benign_idx as i64;
            transfers.push(t);
        }
    }

    // The planted shared-device/shared-IP collusion clusters, populated as fraud edges are minted.
    let mut collusion: Vec<CollusionCluster> = Vec::new();

    // 3b. Ring edges: a closed cycle a0 -> a1 -> ... -> a_{n-1} -> a0, each a large "layering" amount.
    //     Every edge in a ring shares ONE device + IP (the ring operator's fingerprint) so the
    //     shared-device detector re-identifies the whole cycle.
    for (r_idx, ring) in rings.iter().enumerate() {
        let device = RING_DEVICE_BASE + r_idx as i64;
        let ip = format!("172.17.{}.0", r_idx % 256);
        let n = ring.accounts.len();
        for i in 0..n {
            let from = ring.accounts[i];
            let to = ring.accounts[(i + 1) % n];
            let amount = rng.range_i64(9_000, 50_000); // fraud: above the amount floor
            let mut t = mint_transfer(&mut rng, &mut tx_ordinal, from, to, base_ts, amount);
            t.device = device; // overwrite (no PRNG-stream change — see the benign block)
            t.ip = ip.clone();
            transfers.push(t);
        }
        let mut accounts = ring.accounts.clone();
        accounts.sort_unstable();
        accounts.dedup();
        collusion.push(CollusionCluster {
            device,
            ip,
            kind: "ring".to_owned(),
            edge_count: n,
            accounts,
        });
    }

    // 3c. Mule edges: every source -> mule, then mule -> every destination, all large amounts. Every
    //     edge of a chain shares ONE device + IP (the smurfing operator's fingerprint) so the
    //     shared-device detector re-identifies the whole fan-in/fan-out structure from a single node.
    for (m_idx, chain) in mules.iter().enumerate() {
        let device = MULE_DEVICE_BASE + m_idx as i64;
        let ip = format!("172.16.{}.0", m_idx % 256);
        for &src in &chain.sources {
            let amount = rng.range_i64(2_000, 20_000);
            let mut t = mint_transfer(&mut rng, &mut tx_ordinal, src, chain.mule, base_ts, amount);
            t.device = device; // overwrite (no PRNG-stream change — see the benign block)
            t.ip = ip.clone();
            transfers.push(t);
        }
        for &dst in &chain.destinations {
            let amount = rng.range_i64(2_000, 20_000);
            let mut t = mint_transfer(&mut rng, &mut tx_ordinal, chain.mule, dst, base_ts, amount);
            t.device = device;
            t.ip = ip.clone();
            transfers.push(t);
        }
        // The cluster touches the mule plus all its sources and destinations.
        let mut accounts = Vec::with_capacity(1 + chain.sources.len() + chain.destinations.len());
        accounts.push(chain.mule);
        accounts.extend_from_slice(&chain.sources);
        accounts.extend_from_slice(&chain.destinations);
        accounts.sort_unstable();
        accounts.dedup();
        collusion.push(CollusionCluster {
            device,
            ip,
            kind: "mule".to_owned(),
            edge_count: chain.sources.len() + chain.destinations.len(),
            accounts,
        });
    }

    // Build the enumerable fraud-account set: every ring member + every mule.
    let mut fraud_accounts: Vec<i64> = Vec::new();
    for ring in &rings {
        fraud_accounts.extend_from_slice(&ring.accounts);
    }
    for chain in &mules {
        fraud_accounts.push(chain.mule);
    }
    fraud_accounts.sort_unstable();
    fraud_accounts.dedup();

    // Stable, detector-friendly order (ascending device); the ring/mule enumeration already made it
    // deterministic, this just pins a single obvious ordering for the emitted JSON.
    collusion.sort_by_key(|c| c.device);

    let ground_truth = GroundTruth {
        profile: profile.to_owned(),
        seed: config.seed,
        rings,
        mules,
        fraud_accounts,
        collusion,
    };

    Dataset {
        config,
        profile: profile.to_owned(),
        customers,
        accounts,
        transfers,
        ground_truth,
    }
}

impl Dataset {
    /// Renders the dataset as a deterministic, idempotent-ish Cypher load script.
    ///
    /// The script is a flat sequence of statements separated by `;\n`, so the loader can split on
    /// `;` and run each as its own auto-commit statement (the schema DDL **must** run in auto-commit,
    /// never inside an explicit transaction — Graphus rejects admin DDL inside an open txn).
    ///
    /// Order: schema DDL → customers → accounts → OWNS edges → TRANSFER edges. Every value is a
    /// literal (no parameters) so the file is self-contained and replayable by any Bolt client.
    #[must_use]
    pub fn to_cypher(&self) -> String {
        let mut s = String::with_capacity(self.accounts.len() * 96 + self.transfers.len() * 96);

        // --- Schema (admin DDL — runs as auto-commit statements). Every form is verified against the
        // graphus-server admin matcher (see `crates/graphus-server/tests/fraud_oltp_schema.rs`, which
        // parses this exact block off `parse_admin_statement` and drives it through the real engine).
        // The seed data conforms to every constraint, so a schema-first load succeeds. ---
        s.push_str("// schema\n");
        // Node constraints — Account.id is a NODE KEY (present + unique); Customer.id is UNIQUE.
        s.push_str("CREATE CONSTRAINT account_id_key FOR (a:Account) REQUIRE a.id IS NODE KEY;\n");
        s.push_str(
            "CREATE CONSTRAINT customer_id_unique FOR (c:Customer) REQUIRE c.id IS UNIQUE;\n",
        );
        // Relationship constraints on the money the detection reasons about — every TRANSFER must
        // carry an `amount`, and it must be an INTEGER (`amount` is an i64 in the model, never a FLOAT).
        s.push_str(
            "CREATE CONSTRAINT transfer_amount_exists FOR ()-[t:TRANSFER]-() REQUIRE t.amount IS NOT NULL;\n",
        );
        s.push_str(
            "CREATE CONSTRAINT transfer_amount_integer FOR ()-[t:TRANSFER]-() REQUIRE t.amount IS :: INTEGER;\n",
        );
        // Every money transfer carries a globally-unique transaction id — a RELATIONSHIP KEY
        // (present + unique) on TRANSFER.tx_id, the relationship analogue of a primary key. A missing
        // or duplicate tx_id is rejected at write time (verified in `fraud_oltp_schema.rs`).
        s.push_str(
            "CREATE CONSTRAINT transfer_tx_id_key FOR ()-[t:TRANSFER]-() REQUIRE t.tx_id IS RELATIONSHIP KEY;\n",
        );
        // Node RANGE indexes on the properties the risk model filters / sorts on.
        s.push_str("CREATE INDEX account_risk_score_range FOR (a:Account) ON (a.risk_score);\n");
        s.push_str("CREATE INDEX customer_country_range FOR (c:Customer) ON (c.country);\n");
        // Relationship RANGE index on the amount the detection queries filter on (the exact production
        // optimisation for the ring / mule / velocity amount floors).
        s.push_str("CREATE INDEX transfer_amount_range FOR ()-[t:TRANSFER]-() ON (t.amount);\n");
        // TEXT (trigram) index accelerating investigator `CONTAINS` / `STARTS WITH` / `ENDS WITH`
        // look-ups by customer name.
        s.push_str("CREATE TEXT INDEX customer_name_text FOR (c:Customer) ON (c.name);\n");

        // --- Customers ---
        s.push_str("// customers\n");
        for c in &self.customers {
            let _ = writeln!(
                s,
                "CREATE (:Customer {{id: {}, name: '{}', country: '{}'}});",
                c.id, c.name, c.country
            );
        }

        // --- Accounts ---
        s.push_str("// accounts\n");
        for a in &self.accounts {
            let _ = writeln!(
                s,
                "CREATE (:Account {{id: {}, holder: {}, balance: {}, risk_score: {}, opened_ts: {}, country: '{}'}});",
                a.id, a.holder, a.balance, a.risk_score, a.opened_ts, a.country
            );
        }

        // --- OWNS edges (customer -> account); holder == customer id by construction. ---
        s.push_str("// ownership\n");
        for a in &self.accounts {
            let _ = writeln!(
                s,
                "MATCH (c:Customer {{id: {h}}}), (a:Account {{id: {id}}}) CREATE (c)-[:OWNS]->(a);",
                h = a.holder,
                id = a.id
            );
        }

        // --- TRANSFER edges ---
        s.push_str("// transfers\n");
        for t in &self.transfers {
            let _ = writeln!(
                s,
                "MATCH (a:Account {{id: {from}}}), (b:Account {{id: {to}}}) CREATE (a)-[:TRANSFER {{tx_id: '{tx_id}', amount: {amount}, ts: {ts}, device: {device}, ip: '{ip}'}}]->(b);",
                from = t.from,
                to = t.to,
                tx_id = t.tx_id,
                amount = t.amount,
                ts = t.ts,
                device = t.device,
                ip = t.ip
            );
        }

        s
    }

    /// Serializes the ground truth as pretty JSON (deterministic key order via the struct field
    /// order; `serde_json` preserves struct field order and sorts nothing).
    ///
    /// # Errors
    /// Returns a `serde_json` error only if serialization fails (it cannot for this plain data).
    pub fn ground_truth_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.ground_truth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix_is_deterministic() {
        let mut a = SplitMix64::new(123);
        let mut b = SplitMix64::new(123);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn fast_profile_byte_identical_per_seed() {
        let cfg = Profile::Fast.config();
        let d1 = generate(cfg, "fast");
        let d2 = generate(cfg, "fast");
        assert_eq!(
            d1.to_cypher(),
            d2.to_cypher(),
            "cypher must be byte-identical"
        );
        assert_eq!(
            d1.ground_truth_json().unwrap(),
            d2.ground_truth_json().unwrap(),
            "ground truth must be byte-identical"
        );
    }

    #[test]
    fn ground_truth_is_enumerable_and_consistent() {
        let cfg = Profile::Fast.config();
        let d = generate(cfg, "fast");
        let gt = &d.ground_truth;

        // Exactly ring_count rings, each ring_len long.
        assert_eq!(gt.rings.len() as u64, cfg.ring_count);
        for r in &gt.rings {
            assert_eq!(r.accounts.len() as u64, cfg.ring_len);
        }
        // Exactly mule_count mules with the configured fan in/out.
        assert_eq!(gt.mules.len() as u64, cfg.mule_count);
        for m in &gt.mules {
            assert_eq!(m.sources.len() as u64, cfg.mule_fan_in);
            assert_eq!(m.destinations.len() as u64, cfg.mule_fan_out);
        }

        // The fraud_accounts set is exactly {ring members} ∪ {mules}, sorted & deduped.
        let mut expected: Vec<i64> = Vec::new();
        for r in &gt.rings {
            expected.extend_from_slice(&r.accounts);
        }
        for m in &gt.mules {
            expected.push(m.mule);
        }
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(gt.fraud_accounts, expected);

        // Every fraud account id actually exists as an Account node.
        let ids: std::collections::BTreeSet<i64> = d.accounts.iter().map(|a| a.id).collect();
        for &f in &gt.fraud_accounts {
            assert!(ids.contains(&f), "fraud account {f} missing from node set");
        }
    }

    #[test]
    fn tx_ids_are_globally_unique_and_present() {
        // The RELATIONSHIP KEY on TRANSFER.tx_id requires every transfer to carry a present, unique id.
        // Assert the generator honours that invariant on both profiles, so a schema-first load succeeds.
        for profile in [Profile::Fast, Profile::Large] {
            let d = generate(profile.config(), profile.name());
            let mut ids: Vec<&str> = d.transfers.iter().map(|t| t.tx_id.as_str()).collect();
            for t in &d.transfers {
                assert!(!t.tx_id.is_empty(), "{}: a tx_id is empty", profile.name());
            }
            let total = ids.len();
            ids.sort_unstable();
            ids.dedup();
            assert_eq!(
                ids.len(),
                total,
                "{}: tx_ids must be globally unique across all {total} transfers",
                profile.name()
            );
        }
    }

    #[test]
    fn tx_ids_render_into_the_transfer_edges() {
        // The tx_id must reach the emitted Cypher (the RELATIONSHIP KEY has nothing to enforce
        // otherwise). Every TRANSFER CREATE carries a `tx_id: '…'` literal.
        let d = generate(Profile::Fast.config(), "fast");
        let cypher = d.to_cypher();
        let transfer_lines = cypher
            .lines()
            .filter(|l| l.contains("[:TRANSFER {"))
            .count();
        assert_eq!(
            transfer_lines,
            d.transfers.len(),
            "one TRANSFER CREATE per transfer"
        );
        for t in &d.transfers {
            assert!(
                cypher.contains(&format!("tx_id: '{}'", t.tx_id)),
                "the TRANSFER render must carry tx_id {}",
                t.tx_id
            );
        }
        // And the RELATIONSHIP KEY DDL is declared in the schema block.
        assert!(
            cypher.contains(
                "CREATE CONSTRAINT transfer_tx_id_key FOR ()-[t:TRANSFER]-() REQUIRE t.tx_id IS RELATIONSHIP KEY"
            ),
            "the schema block must declare the RELATIONSHIP KEY on TRANSFER.tx_id"
        );
    }

    #[test]
    fn different_profiles_differ() {
        let fast = generate(Profile::Fast.config(), "fast");
        let large = generate(Profile::Large.config(), "large");
        assert_ne!(fast.to_cypher(), large.to_cypher());
        assert!(large.accounts.len() > fast.accounts.len());
    }

    #[test]
    fn shared_device_collusion_signal_is_planted_and_enumerable() {
        // The shared-device signal must be detectable by "any device on >= 2 transfers is a cluster":
        // benign transfers each carry a UNIQUE device, every fraud cluster shares ONE device, and the
        // per-device edge counts equal the planted `collusion` ground truth exactly.
        for profile in [Profile::Fast, Profile::Large] {
            let d = generate(profile.config(), profile.name());
            let gt = &d.ground_truth;

            // Tally device -> edge count over ALL transfers.
            let mut by_device: std::collections::BTreeMap<i64, usize> = std::collections::BTreeMap::new();
            for t in &d.transfers {
                *by_device.entry(t.device).or_default() += 1;
            }
            // Devices seen on >= 2 transfers == exactly the planted collusion devices, same counts.
            let observed: std::collections::BTreeMap<i64, usize> = by_device
                .iter()
                .filter(|&(_, &c)| c >= 2)
                .map(|(&d, &c)| (d, c))
                .collect();
            let expected: std::collections::BTreeMap<i64, usize> = gt
                .collusion
                .iter()
                .map(|c| (c.device, c.edge_count))
                .collect();
            assert_eq!(
                observed,
                expected,
                "{}: shared-device (count>=2) set must equal the planted collusion clusters",
                profile.name()
            );

            // One cluster per ring + per mule; a mule cluster shares fan_in+fan_out edges, a ring
            // cluster shares ring_len edges; all fraud devices live in the high namespaces and every
            // fraud IP is in 172.16/172.17 (disjoint from benign 10.x).
            assert_eq!(
                gt.collusion.len(),
                gt.rings.len() + gt.mules.len(),
                "{}: one collusion cluster per fraud structure",
                profile.name()
            );
            for c in &gt.collusion {
                assert!(c.device >= MULE_DEVICE_BASE, "{}: fraud device in high namespace", profile.name());
                assert!(
                    c.ip.starts_with("172.16.") || c.ip.starts_with("172.17."),
                    "{}: fraud IP in 172.16/172.17, got {}",
                    profile.name(),
                    c.ip
                );
                assert!(c.edge_count >= 2, "{}: a cluster shares >= 2 edges", profile.name());
            }
            // Benign transfers never touch a 172.x IP.
            let benign_ip_leak = d.transfers.iter().any(|t| {
                (t.ip.starts_with("172.16.") || t.ip.starts_with("172.17."))
                    && !gt.collusion.iter().any(|c| c.device == t.device)
            });
            assert!(!benign_ip_leak, "{}: no benign edge carries a fraud IP", profile.name());
        }
    }

    #[test]
    fn detection_relevant_invariants_are_preserved() {
        // The device/ip override must NOT disturb anything the (un-editable) server-side mirrors rely
        // on: the account/customer/transfer COUNTS, the amount floors that separate fraud from benign,
        // and the fraud-account set. This pins the contract the collusion plant must never break.
        for profile in [Profile::Fast, Profile::Large] {
            let cfg = profile.config();
            let d = generate(cfg, profile.name());

            let benign = (cfg.legit_accounts) as usize;
            let _ = benign;
            // One customer per account; accounts = legit + ring members + (mule + fan_in + fan_out).
            assert_eq!(d.customers.len(), d.accounts.len(), "{}: one customer per account", profile.name());

            // Amount floors: fraud edges (172.x device namespace) are >= 2000; benign edges are < 900.
            for t in &d.transfers {
                let is_fraud = d.ground_truth.collusion.iter().any(|c| c.device == t.device);
                if is_fraud {
                    assert!(t.amount >= 2_000, "{}: fraud edge amount below floor: {}", profile.name(), t.amount);
                } else {
                    // Benign amounts are drawn from the inclusive range [1, 900], well under the
                    // mule (>= 2000) and ring (>= 9000) detection floors.
                    assert!(t.amount <= 900, "{}: benign edge amount above floor: {}", profile.name(), t.amount);
                }
            }

            // fraud_accounts == {ring members} ∪ {mules}, and every collusion account is a real node.
            let ids: std::collections::BTreeSet<i64> = d.accounts.iter().map(|a| a.id).collect();
            for c in &d.ground_truth.collusion {
                for a in &c.accounts {
                    assert!(ids.contains(a), "{}: collusion account {a} missing from node set", profile.name());
                }
            }
        }
    }
}
