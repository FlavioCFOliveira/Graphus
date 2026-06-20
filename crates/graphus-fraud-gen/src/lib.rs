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
//! - `(:Customer {id, name, country})` — the human/legal account holder.
//! - `(:Account {id, holder, balance, risk_score, opened_ts, country})` — a financial account, with
//!   a **unique `id`** (the workload declares a `UNIQUE` constraint on it).
//! - `(:Customer)-[:OWNS]->(:Account)` — ownership.
//! - `(:Account)-[:TRANSFER {amount, ts, device, ip}]->(:Account)` — a money transfer, the edge the
//!   detection traverses.
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
    /// Unique account id (the workload declares a `UNIQUE` constraint on this).
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

    // A deterministic transfer minter (free function so it does not capture rng).
    fn mint_transfer(
        rng: &mut SplitMix64,
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
        Transfer {
            from,
            to,
            amount,
            ts,
            device,
            ip,
        }
    }

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
        for _ in 0..config.benign_transfers {
            let from = legit_start + rng.below(span) as i64;
            let mut to = legit_start + rng.below(span) as i64;
            if to == from {
                to = legit_start + ((from - legit_start + 1) % span as i64);
            }
            let amount = rng.range_i64(1, 900); // benign: under the fraud amount floor
            transfers.push(mint_transfer(&mut rng, from, to, base_ts, amount));
        }
    }

    // 3b. Ring edges: a closed cycle a0 -> a1 -> ... -> a_{n-1} -> a0, each a large "layering" amount.
    for ring in &rings {
        let n = ring.accounts.len();
        for i in 0..n {
            let from = ring.accounts[i];
            let to = ring.accounts[(i + 1) % n];
            let amount = rng.range_i64(9_000, 50_000); // fraud: above the amount floor
            transfers.push(mint_transfer(&mut rng, from, to, base_ts, amount));
        }
    }

    // 3c. Mule edges: every source -> mule, then mule -> every destination, all large amounts.
    for chain in &mules {
        for &src in &chain.sources {
            let amount = rng.range_i64(2_000, 20_000);
            transfers.push(mint_transfer(&mut rng, src, chain.mule, base_ts, amount));
        }
        for &dst in &chain.destinations {
            let amount = rng.range_i64(2_000, 20_000);
            transfers.push(mint_transfer(&mut rng, chain.mule, dst, base_ts, amount));
        }
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

    let ground_truth = GroundTruth {
        profile: profile.to_owned(),
        seed: config.seed,
        rings,
        mules,
        fraud_accounts,
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

        // --- Schema (admin DDL — runs as auto-commit statements). Forms verified against the
        // graphus-server admin matcher: `CREATE CONSTRAINT <name> FOR (n:L) REQUIRE n.p IS UNIQUE`
        // and `CREATE INDEX FOR (n:L) ON (n.p)`. ---
        s.push_str("// schema\n");
        s.push_str("CREATE CONSTRAINT account_id_unique FOR (a:Account) REQUIRE a.id IS UNIQUE;\n");
        s.push_str(
            "CREATE CONSTRAINT customer_id_unique FOR (c:Customer) REQUIRE c.id IS UNIQUE;\n",
        );
        s.push_str("CREATE INDEX FOR (a:Account) ON (a.risk_score);\n");
        s.push_str("CREATE INDEX FOR (c:Customer) ON (c.country);\n");

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
                "MATCH (a:Account {{id: {from}}}), (b:Account {{id: {to}}}) CREATE (a)-[:TRANSFER {{amount: {amount}, ts: {ts}, device: {device}, ip: '{ip}'}}]->(b);",
                from = t.from,
                to = t.to,
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
    fn different_profiles_differ() {
        let fast = generate(Profile::Fast.config(), "fast");
        let large = generate(Profile::Large.config(), "large");
        assert_ne!(fast.to_cypher(), large.to_cypher());
        assert!(large.accounts.len() > fast.accounts.len());
    }
}
